//! CLI and service helpers for the meow-rs proxy kernel.
//!
//! Library surface used by the `meow` binary: systemd unit and launchd
//! plist generation, geodata fetch, and subscription refresh. The binary
//! wires configuration, the tunnel, listeners, DNS, and the REST API
//! together.

#[cfg(any(target_os = "linux", test))]
pub mod arp;
pub mod geodata_fetch;
pub mod subscription_refresh;

/// launchd label for the macOS user agent plist.
pub const LAUNCHD_LABEL: &str = "com.meow.proxy";

/// True when `a` and `b` resolve to the same directory entry, with `..`,
/// repeated separators, and symlinks (e.g. macOS `/var` → `/private/var`)
/// normalized away. Returns false when either path cannot be resolved.
/// Used by the macOS `uninstall` guard to admit only a literal
/// `$HOME` == `/var/root` without a prefix-match bypass like
/// `/var/root/../Users/x` (issue #678).
pub fn same_resolved_path(a: &std::path::Path, b: &std::path::Path) -> bool {
    matches!(
        (std::fs::canonicalize(a), std::fs::canonicalize(b)),
        (Ok(x), Ok(y)) if x == y
    )
}

/// Escape a value for interpolation into a plist `<string>` node
/// (issue #677): `&`, `<`, `>` are required and `"`/`'` are escaped too —
/// a stray `]]>` or a quote in a HOME-derived path must not break the XML.
fn plist_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Reject characters XML 1.0 cannot represent — escaping is not an option
/// for them (issue #677). POSIX allows control chars in filenames, so a
/// deliberately weird `$HOME` could still produce an invalid plist; the
/// only correct handling is a clear error. `\r` is rejected too: XML
/// line-ending normalization rewrites it to `\n`, silently diverging from
/// the real path. `\n`/`\t` round-trip unharmed and are allowed.
fn check_plist_char(field: &str, value: &str) -> anyhow::Result<()> {
    let bad = value.chars().find(|&ch| {
        (ch < ' ' && ch != '\n' && ch != '\t') || matches!(ch, '\u{FFFE}' | '\u{FFFF}')
    });
    if let Some(ch) = bad {
        anyhow::bail!(
            "{field} contains a character XML cannot represent (U+{:04X}): {value:?}",
            ch as u32
        );
    }
    Ok(())
}

/// Generate a launchd user-agent plist for the meow service (macOS).
///
/// Every interpolated path goes through `plist_escape` — the plist is
/// XML, so an unescaped `&`/`<`/`"` in the binary, config, work, or log
/// path would produce a malformed file `launchctl bootstrap` rejects.
///
/// Returns an error when a path contains characters XML 1.0 cannot
/// represent at all (see `check_plist_char`).
///
/// # Arguments
/// * `exe_path` - Absolute path to the meow binary
/// * `config_path` - Absolute path to the installed configuration file
/// * `work_dir` - `WorkingDirectory` for the service
/// * `log_dir` - Directory receiving `Standard{Out,Error}Path` logs
pub fn generate_launchd_plist(
    exe_path: &str,
    config_path: &str,
    work_dir: &str,
    log_dir: &str,
) -> anyhow::Result<String> {
    check_plist_char("exe_path", exe_path)?;
    check_plist_char("config_path", config_path)?;
    check_plist_char("work_dir", work_dir)?;
    check_plist_char("log_dir", log_dir)?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>-f</string>
        <string>{config}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{work_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>{log_dir}/meow.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/meow.err.log</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        exe = plist_escape(exe_path),
        config = plist_escape(config_path),
        work_dir = plist_escape(work_dir),
        log_dir = plist_escape(log_dir),
    ))
}

/// Reject C0 control characters in a path bound for a systemd unit
/// (issue #689). `allow_ws` permits `\n`/`\r`/`\t`, which only the
/// `ExecStart=` argv grammar can represent via C-escapes — every other
/// directive here has no escape mechanism, so all C0 is rejected.
fn systemd_check_char(field: &str, value: &str, allow_ws: bool) -> anyhow::Result<()> {
    let bad = value
        .chars()
        .find(|&ch| ch < ' ' && !(allow_ws && matches!(ch, '\n' | '\r' | '\t')));
    if let Some(ch) = bad {
        anyhow::bail!(
            "{field} contains a control character a systemd unit cannot represent (U+{:04X}): {value:?}",
            ch as u32
        );
    }
    Ok(())
}

fn systemd_check_absolute(field: &str, value: &str) -> anyhow::Result<()> {
    let p = std::path::Path::new(value);
    if !p.is_absolute()
        || p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        anyhow::bail!("{field} must be an absolute path without `..` components: {value:?}");
    }
    Ok(())
}

/// Quote one word for the `ExecStart=` line (program or `-f` argument).
///
/// ExecStart argv is unquoted with `EXTRACT_UNQUOTE|CUNESCAPE`, so `\"`,
/// `\\`, and the `\n`/`\r`/`\t` C-escapes all decode; `%%` defeats the
/// specifier expansion applied per-word. `$$` collapses to a literal `$`
/// under environment substitution — but only in the argv *arguments*:
/// `command->path` is substituted separately and never env-expanded, so
/// the program word must emit `$` verbatim.
///
/// `program` additionally rejects `"`, `'`, `\`, `\x7f`, all C0, and a
/// trailing `/`: systemd's `string_is_safe` refuses them in the unquoted
/// first word, so escaping could only ever produce a unit with no
/// runnable ExecStart (and a directory is not an executable).
fn systemd_quote_exec_arg(field: &str, value: &str, program: bool) -> anyhow::Result<String> {
    systemd_check_char(field, value, !program)?;
    if program {
        if value.ends_with('/') {
            anyhow::bail!("{field} is a directory, not an executable: {value:?}");
        }
        if let Some(ch) = value
            .chars()
            .find(|&ch| matches!(ch, '"' | '\'' | '\\' | '\x7f'))
        {
            anyhow::bail!(
                "{field} contains a character systemd refuses in the ExecStart program path (U+{:04X}): {value:?}",
                ch as u32
            );
        }
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '%' => out.push_str("%%"),
            // $$ collapses to $ in argv, but command->path is not argv.
            '$' if !program => out.push_str("$$"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    Ok(out)
}

/// Quote one entry for a whitespace-separated path list
/// (`ReadWritePaths=`). systemd unquotes such lists WITHOUT CUNESCAPE, so
/// only `\"`/`\\` round-trip and every C0 is rejected. `:` is rejected
/// too — an unquoted `src:dst` would silently become a bind pair.
fn systemd_quote_path_list(field: &str, value: &str) -> anyhow::Result<String> {
    systemd_check_char(field, value, false)?;
    if value.contains(':') {
        anyhow::bail!("{field} must not contain ':' (bind-pair syntax): {value:?}");
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '%' => out.push_str("%%"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    Ok(out)
}

/// Emit a raw single-path setting (`WorkingDirectory=`). systemd takes
/// the whole rvalue as the path — it does NOT unquote, so interior
/// spaces and quotes are legal verbatim and only `%` needs escaping.
/// All C0, leading/trailing whitespace, `#`, `;`, and a trailing `\`
/// (line-continuation) are rejected because they cannot be represented.
fn systemd_raw_path(field: &str, value: &str) -> anyhow::Result<String> {
    systemd_check_char(field, value, false)?;
    if value.trim() != value || value.ends_with('\\') {
        anyhow::bail!(
            "{field} must not have leading/trailing whitespace or end in a backslash: {value:?}"
        );
    }
    if let Some(ch) = value.chars().find(|&ch| matches!(ch, '#' | ';')) {
        anyhow::bail!(
            "{field} contains a character that can start a unit comment/separator (U+{:04X}): {value:?}",
            ch as u32
        );
    }
    Ok(value.replace('%', "%%"))
}

/// Generate a systemd unit file for the meow service.
///
/// Each interpolated path is emitted per its directive's grammar
/// (issue #689): `ExecStart=` argv words are quoted and escaped,
/// `ReadWritePaths=` entries are quoted, and `WorkingDirectory=` is
/// emitted raw — systemd does not unquote that setting, so quoting it
/// would produce a unit it refuses to load.
///
/// Returns an error when a path is not absolute/normalized or contains
/// a character the setting cannot represent.
///
/// # Arguments
/// * `exe_path` - Absolute path to the meow binary
/// * `config_path` - Absolute path to the configuration file
pub fn generate_systemd_unit(exe_path: &str, config_path: &str) -> anyhow::Result<String> {
    systemd_check_absolute("exe_path", exe_path)?;
    systemd_check_absolute("config_path", config_path)?;
    let work_dir_raw = std::path::Path::new(config_path)
        .parent()
        .unwrap_or(std::path::Path::new("/"))
        .to_string_lossy()
        .to_string();
    if work_dir_raw.is_empty() {
        anyhow::bail!("config_path has no parent directory: {config_path:?}");
    }

    let exe = systemd_quote_exec_arg("exe_path", exe_path, true)?;
    let config = systemd_quote_exec_arg("config_path", config_path, false)?;
    let work_dir_list = systemd_quote_path_list("work_dir", &work_dir_raw)?;
    let work_dir_raw = systemd_raw_path("work_dir", &work_dir_raw)?;

    Ok(format!(
        r#"[Unit]
Description=meow-rs proxy service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} -f {config}
WorkingDirectory={work_dir_raw}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={work_dir_list}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"#,
    ))
}
