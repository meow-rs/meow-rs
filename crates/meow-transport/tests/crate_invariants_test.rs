//! Structural guardrail tests — cases F1..F4 from the transport-layer test plan,
//! plus F5, the workspace-wide outbound-socket chokepoint guard (issue #695).
//!
//! These tests enforce ADR-0001 crate boundary invariants mechanically so that
//! PR reviewers see failing *tests* (not just a lint warning) when an invariant
//! is violated.

use meow_transport::TransportError;
use std::collections::HashSet;

// ─── F1: no_proxy_dep ────────────────────────────────────────────────────────

/// Verify that `meow-transport` does not depend on `meow-proxy`,
/// `meow-dns`, or `meow-config`.  Only `meow-common` is allowed.
///
/// Runs `cargo tree -p meow-transport --edges normal` and asserts the output
/// contains no lines mentioning the forbidden crates.
#[test]
fn no_proxy_dep() {
    let output = std::process::Command::new("cargo")
        .args(["tree", "-p", "meow-transport", "--edges", "normal"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree failed");

    let tree = String::from_utf8_lossy(&output.stdout);

    let forbidden = ["meow-proxy", "meow-dns", "meow-config"];
    for crate_name in &forbidden {
        // Each line of `cargo tree` looks like:
        //   meow-proxy v0.3.0 (/path/to/crate)
        // We just look for the name substring.
        let offending: Vec<&str> = tree.lines().filter(|l| l.contains(crate_name)).collect();
        assert!(
            offending.is_empty(),
            "meow-transport must not depend on '{}' (ADR-0001 §1).\n\
             Offending lines in `cargo tree`:\n{}",
            crate_name,
            offending.join("\n")
        );
    }
}

// ─── F2: no_server_side_symbols_in_src ───────────────────────────────────────

/// Walk `src/**/*.rs` and assert that no production source file contains
/// server-side binding keywords (`accept`, `bind`, `listen`, `Server`,
/// `Acceptor`, `TcpListener`).
///
/// `tests/` is intentionally excluded — `tests/support/loopback.rs` uses
/// these legitimately.  `#[cfg(test)]` items inside `src/` are excluded for
/// the same reason: they are stripped from the published library, and
/// ADR-0001 §1 (implementation plan, M1.A-3) explicitly prescribes driving
/// these client layers against "a loopback `h2` server in-process".
///
/// `simple_obfs/server.rs` is an intentional exception: it is the server
/// side of the simple-obfs transport, consumed by the `listener-shadowsocks`
/// inbound.  Only the fake HTTP header string `"Server: nginx"` trips the
/// `\bServer\b` heuristic — the module does not use `accept`, `bind`, or
/// `listen`.
#[test]
fn no_server_side_symbols_in_src() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    // Files exempt from the check (relative to `src/`).
    let exempt: &[&str] = &["simple_obfs/server.rs"];

    // Patterns that indicate server-side code.
    let forbidden_patterns = [
        r"\baccept\b",
        r"\bbind\b",
        r"\blisten\b",
        r"\bServer\b",
        r"\bAcceptor\b",
        r"\bTcpListener\b",
    ];

    // Compile patterns once.
    let regexes: Vec<regex::Regex> = forbidden_patterns
        .iter()
        .map(|p| regex::Regex::new(p).expect("valid regex"))
        .collect();

    let mut violations: Vec<String> = Vec::new();

    walk_rs_files(&src_dir, &mut |path, content| {
        // Skip exempt files (e.g. `simple_obfs/server.rs`). Normalise path
        // separators so the check works on both Unix and Windows.
        if let Ok(rel) = path.strip_prefix(&src_dir) {
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if exempt.contains(&rel_str.as_str()) {
                return;
            }
        }
        let test_only = test_only_lines(path, content);
        for (line_no, line) in content.lines().enumerate() {
            // Skip comment lines — doc comments that *describe* the restriction
            // are not violations.  Only live code is checked.
            if line.trim().starts_with("//") {
                continue;
            }
            // Skip `#[cfg(test)]` items — test scaffolding, not shipped code.
            if test_only.contains(&line_no) {
                continue;
            }
            for (re, pat) in regexes.iter().zip(forbidden_patterns.iter()) {
                if re.is_match(line) {
                    violations.push(format!(
                        "{}:{}: '{}' matches pattern '{}'",
                        path.display(),
                        line_no + 1,
                        line.trim(),
                        pat
                    ));
                }
            }
        }
    });

    assert!(
        violations.is_empty(),
        "Server-side symbols found in src/ (ADR-0001 §1, acceptance criterion #8):\n{}",
        violations.join("\n")
    );
}

fn walk_rs_files(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path, &str)) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs_files(&path, f);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                f(&path, &content);
            }
        }
    }
}

// ─── shared scan helpers ─────────────────────────────────────────────────────

/// Line indices (0-based) covered by a `#[cfg(test)]` item.
///
/// `#[cfg(test)]` code is compiled out of the published library, so in-crate
/// unit tests are scaffolding rather than shipped surface — the same reason
/// `tests/` is excluded from both `src/` scans.  A mock server used to drive a
/// *client* transport is therefore not an ADR-0001 §1 violation.
///
/// The span runs from the attribute line to the line that closes the item's
/// block, tracked by brace depth.  An item with no block (`#[cfg(test)] use
/// …;`) ends at its semicolon.  A span that never terminates is a panic, not a
/// silent skip: failing loudly beats disabling the guard for the rest of the
/// file.
fn test_only_lines(path: &std::path::Path, content: &str) -> HashSet<usize> {
    let lines: Vec<&str> = content.lines().collect();
    let mut test_only = HashSet::new();
    let mut i = 0;

    while i < lines.len() {
        if !opens_cfg_test_attr(&lines, i) {
            i += 1;
            continue;
        }

        let start = i;
        let mut depth: usize = 0;
        let mut opened = false;
        let mut terminated = false;

        while i < lines.len() {
            let code = strip_literals_and_comments(lines[i]);
            for ch in code.chars() {
                match ch {
                    '{' => {
                        depth += 1;
                        opened = true;
                    }
                    '}' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
            i += 1;

            if opened {
                if depth == 0 {
                    terminated = true;
                    break;
                }
            } else if code.trim_end().ends_with(';') {
                // Block-less item: `#[cfg(test)] use …;`, `const …;`, etc.
                terminated = true;
                break;
            }
        }

        assert!(
            terminated,
            "unterminated #[cfg(test)] item at {}:{} — the ADR-0001 scan cannot tell \
             where test-only code ends, so it refuses to guess",
            path.display(),
            start + 1
        );
        test_only.extend(start..i);
    }

    test_only
}

/// Whether the attribute opening at `lines[i]` is a `#[cfg(test)]`-family
/// attribute ([`is_cfg_test_attr`]), joining one that rustfmt split across
/// lines (`#[cfg(all(` / `    test,` / `    target_os = "linux"` / `))]`).
fn opens_cfg_test_attr(lines: &[&str], i: usize) -> bool {
    if !lines[i].trim_start().starts_with("#[cfg(") {
        return false;
    }
    let mut joined = String::new();
    for line in &lines[i..] {
        joined.extend(line.chars().filter(|c| !c.is_whitespace()));
        if joined.contains(']') {
            break;
        }
    }
    is_cfg_test_attr(&joined)
}

/// Whether `line` opens a `#[cfg(test)]` (or `all(test, …)` / `any(test, …)`)
/// attribute.  Deliberately narrow: a feature named `"test-utils"` must not
/// match.
fn is_cfg_test_attr(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("#[cfg(test)]")
        || trimmed.starts_with("#[cfg(all(test")
        || trimmed.starts_with("#[cfg(any(test")
}

/// Drop string/char literals and any trailing `//` comment from `line` so that
/// braces inside them cannot skew the block-depth count.
fn strip_literals_and_comments(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut code = String::with_capacity(line.len());
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        // Trailing line comment — nothing after it affects depth.
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            break;
        }

        // Raw string: r"…", r#"…"#, r##"…"## … (also the tail of br"…").
        if c == 'r' && matches!(chars.get(i + 1), Some('"') | Some('#')) {
            if let Some(end) = raw_string_end(&chars, i) {
                i = end;
                continue;
            }
        }

        // Ordinary string literal.
        if c == '"' {
            i = string_end(&chars, i);
            continue;
        }

        // Char literal — but `'a` (lifetime) and `'outer:` (label) are code.
        if c == '\'' {
            if let Some(end) = char_literal_end(&chars, i) {
                i = end;
                continue;
            }
        }

        code.push(c);
        i += 1;
    }

    code
}

/// End index (exclusive) of the `"…"` literal opening at `start`.
fn string_end(chars: &[char], start: usize) -> usize {
    let mut i = start + 1;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 2,
            '"' => return i + 1,
            _ => i += 1,
        }
    }
    // Unterminated on this line (a multi-line string): the rest is literal.
    chars.len()
}

/// End index (exclusive) of the raw string opening at `start`, or `None` when
/// `start` is a raw *identifier* (`r#type`) rather than a raw string.
fn raw_string_end(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start + 1;
    let mut hashes = 0;
    while chars.get(i) == Some(&'#') {
        hashes += 1;
        i += 1;
    }
    if chars.get(i) != Some(&'"') {
        return None; // raw identifier, not a raw string
    }
    i += 1;
    while i < chars.len() {
        if chars[i] == '"'
            && chars[i + 1..]
                .iter()
                .take(hashes)
                .filter(|c| **c == '#')
                .count()
                == hashes
        {
            return Some(i + 1 + hashes);
        }
        i += 1;
    }
    Some(chars.len())
}

/// End index (exclusive) of the `'c'` literal opening at `start`, or `None`
/// when the quote opens a lifetime or a loop label.
fn char_literal_end(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start + 1;
    if chars.get(i) == Some(&'\\') {
        i += 1;
        if chars.get(i) == Some(&'u') {
            // '\u{7f}' — run to the closing quote.
            while i < chars.len() && chars[i] != '\'' {
                i += 1;
            }
            return (chars.get(i) == Some(&'\'')).then_some(i + 1);
        }
    }
    (chars.get(i + 1) == Some(&'\'')).then_some(i + 2)
}

// ─── F2/F4 helper self-tests ─────────────────────────────────────────────────

/// The scan exemption must cover exactly the `#[cfg(test)]` item — no more,
/// no less.  A guard that over-reaches silently stops guarding.
#[test]
fn cfg_test_spans_cover_only_test_items() {
    let src = "\
fn client() {}
#[cfg(test)]
mod tests {
    fn helper() {
        let _ = \"} not a brace {\";
    }
}
fn also_client() {}
";
    let span = test_only_lines(std::path::Path::new("<memory>"), src);
    assert_eq!(span, (1..7).collect::<HashSet<usize>>());
}

#[test]
fn cfg_test_span_ends_at_a_block_less_item() {
    let src = "\
#[cfg(test)]
use std::net::TcpListener;
fn client() {}
";
    let span = test_only_lines(std::path::Path::new("<memory>"), src);
    assert_eq!(span, (0..2).collect::<HashSet<usize>>());
}

#[test]
fn cfg_test_span_survives_braces_in_literals() {
    let src = "\
#[cfg(test)]
mod tests {
    fn f() {
        let _ = '{';
        let _ = r#\"raw } brace\"#;
        let _ = format!(\"{}\", 1); // }
    }
}
";
    let span = test_only_lines(std::path::Path::new("<memory>"), src);
    assert_eq!(span, (0..8).collect::<HashSet<usize>>());
}

#[test]
fn cfg_test_span_covers_a_multi_line_attribute() {
    let src = "\
fn client() {}
#[cfg(all(
    test,
    target_os = \"linux\"
))]
mod tests {
    fn f() {}
}
";
    let span = test_only_lines(std::path::Path::new("<memory>"), src);
    assert_eq!(span, (1..8).collect::<HashSet<usize>>());
}

#[test]
fn non_test_cfg_attributes_are_not_exempt() {
    let src = "\
#[cfg(feature = \"test-utils\")]
mod helpers {
    fn f() {}
}
";
    assert!(test_only_lines(std::path::Path::new("<memory>"), src).is_empty());
}

#[test]
fn lifetimes_do_not_swallow_braces() {
    let code = strip_literals_and_comments("fn f<'a>(x: &'a str) -> Foo { bar }");
    assert_eq!(code.matches('{').count(), 1);
    assert_eq!(code.matches('}').count(), 1);
}

// ─── F3: transport_error_is_non_exhaustive ───────────────────────────────────

/// `TransportError` must be `#[non_exhaustive]` so that adding variants is
/// a minor (not major) semver bump.
///
/// We assert this at compile time by ensuring a wildcard arm is needed for
/// exhaustive matching.  If the `_` arm were not needed (i.e. the enum were
/// exhaustive), the compiler would emit `unreachable_patterns`.  We rely on
/// the fact that `#[non_exhaustive]` *requires* a wildcard in match
/// expressions outside the defining crate.
#[test]
fn transport_error_is_non_exhaustive() {
    let err = TransportError::Config("test".into());
    // This match must compile with a wildcard because TransportError is
    // #[non_exhaustive].  If it were exhaustive, the `_` arm would generate
    // a compile-time `unreachable_patterns` warning (not an error), which
    // would not catch the regression.  We keep the wildcard and document why.
    #[allow(clippy::match_same_arms)] // arms are distinct variants; bodies coincidentally identical
    let _display = match err {
        TransportError::Io(e) => e.to_string(),
        TransportError::Tls(s) => s,
        TransportError::WebSocket(s) => s,
        TransportError::Grpc(s) => s,
        TransportError::HttpUpgrade(s) => s,
        TransportError::Config(s) => s,
        // Required by #[non_exhaustive] — future variants land here.
        _ => "unknown variant".into(),
    };
    // If this test compiles outside the defining crate, #[non_exhaustive] is
    // working.  (A test binary is a separate crate, so the constraint applies.)
}

// ─── F4: no_anyhow_at_boundary ───────────────────────────────────────────────

/// Walk `src/**/*.rs` and assert that no public function signature uses
/// `anyhow` types.  Private helper internals may use anyhow (engineer's
/// call), but `TransportError` is the only type allowed to cross the crate
/// boundary.
#[test]
fn no_anyhow_at_boundary() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let anyhow_re = regex::Regex::new(r"\banyhow\b").expect("regex");

    let mut violations: Vec<String> = Vec::new();

    walk_rs_files(&src_dir, &mut |path, content| {
        let test_only = test_only_lines(path, content);
        for (line_no, line) in content.lines().enumerate() {
            // Skip comment lines — doc comments explaining *why* anyhow is
            // banned are not themselves violations.
            if line.trim().starts_with("//") {
                continue;
            }
            // `#[cfg(test)]` items never cross the crate boundary.
            if test_only.contains(&line_no) {
                continue;
            }
            if anyhow_re.is_match(line) {
                violations.push(format!(
                    "{}:{}: {}",
                    path.display(),
                    line_no + 1,
                    line.trim()
                ));
            }
        }
    });

    assert!(
        violations.is_empty(),
        "anyhow references found in src/ (spec §Error taxonomy).\n\
         TransportError is the only error type allowed at the crate boundary:\n{}",
        violations.join("\n")
    );
}

// ─── F5: outbound sockets go through meow_common's chokepoints (#695) ───────

/// Raw socket-creation primitives. Production code must create outbound
/// sockets through `meow_common::{connect_tcp, connect_tcp_host, bind_udp}`
/// (or the DNS `SocketFactory`, which wraps them): only those apply the TUN
/// global-route interface binding (`SO_BINDTODEVICE`) and the Android
/// `protect()` hook. A raw socket escapes both and, under
/// `tun.auto-route: global`, loops back into the TUN (issue #695 — the
/// Hysteria2 QUIC socket was one).
const RAW_SOCKET_PRIMITIVES: &[&str] = &[
    "UdpSocket::bind(",
    "TcpStream::connect(",
    "TcpStream::connect_timeout(",
    "TcpSocket::new(",
    "TcpSocket::new_v4(",
    "TcpSocket::new_v6(",
    "Socket::new(",
    "Socket::new_raw(",
    "libc::socket(",
];

/// Production raw-socket sites that are correct as they are:
/// `(path from the workspace root, primitive, exact count, why)`. The count
/// is exact so a *new* raw call in an allowlisted file still fails, and a
/// removed one forces the entry to be trimmed.
const RAW_SOCKET_ALLOWLIST: &[(&str, &str, usize, &str)] = &[
    // The chokepoints themselves.
    (
        "crates/meow-common/src/socket_protect.rs",
        "Socket::new(",
        4,
        "the chokepoints: Android protect() + SO_BINDTODEVICE paths",
    ),
    (
        "crates/meow-common/src/socket_protect.rs",
        "TcpStream::connect(",
        1,
        "connect_tcp's fall-through when no binding/protector is installed",
    ),
    (
        "crates/meow-common/src/socket_protect.rs",
        "UdpSocket::bind(",
        1,
        "bind_udp's fall-through when no binding/protector is installed",
    ),
    (
        "crates/meow-proxy/src/direct.rs",
        "Socket::new(",
        1,
        "routing-mark dial; applies meow_common::apply_outbound_interface itself",
    ),
    // Vendored anytls: its own protect helper and its server side.
    (
        "crates/meow-anytls/src/util/socket_protect.rs",
        "Socket::new(",
        2,
        "anytls protect helper (Android); session dials go through meow's \
         DialBridge (meow-proxy anytls_adapter.rs install_anytls_bridges)",
    ),
    (
        "crates/meow-anytls/src/util/socket_protect.rs",
        "TcpStream::connect(",
        1,
        "fallback only when no TcpDialer is installed; meow installs \
         DialBridge -> meow_common::connect_tcp_host before any dial",
    ),
    (
        "crates/meow-anytls/src/util/socket_protect.rs",
        "UdpSocket::bind(",
        1,
        "only reached via UdpClient::create_udp_proxy, which meow never calls",
    ),
    (
        "crates/meow-anytls/src/server/handler.rs",
        "TcpStream::connect(",
        1,
        "anytls server side; meow only runs it in tests",
    ),
    (
        "crates/meow-anytls/src/server/udp_proxy.rs",
        "UdpSocket::bind(",
        1,
        "anytls server side; meow only runs it in tests",
    ),
    // Not outbound: inbound listeners and client-facing reply sockets.
    (
        "crates/meow-dns/src/client.rs",
        "UdpSocket::bind(",
        1,
        "loopback upstream: bound to 127.0.0.1/::1, never routed into the TUN, \
         and must not be bound to the physical interface",
    ),
    (
        "crates/meow-dns/src/server.rs",
        "UdpSocket::bind(",
        1,
        "inbound DNS listener",
    ),
    (
        "crates/meow-listener/src/socks5_udp.rs",
        "UdpSocket::bind(",
        1,
        "inbound SOCKS5 UDP relay socket facing the client",
    ),
    (
        "crates/meow-listener/src/tproxy/udp.rs",
        "libc::socket(",
        1,
        "IP_TRANSPARENT reply socket towards the inbound client",
    ),
    (
        "crates/meow-listener/src/tun/local_dns.rs",
        "UdpSocket::bind(",
        2,
        "loopback DNS listener (127.0.0.1:53 / [::1]:53)",
    ),
    (
        "crates/meow-app/src/arp.rs",
        "libc::socket(",
        1,
        "AF_PACKET ARP frame on an explicit interface; not IP-routed",
    ),
];

/// No production source in the workspace creates an outbound socket with a
/// raw primitive outside [`RAW_SOCKET_ALLOWLIST`]. `#[cfg(test)]` items and
/// files whose `mod` declaration is `#[cfg(test)]`-gated are test
/// scaffolding and exempt; `meow-bench` is a standalone benchmark tool, not
/// part of the shipped binary.
#[test]
fn outbound_sockets_use_meow_common_chokepoints() {
    let Some(root) = workspace_root() else {
        eprintln!("workspace sources not available — skipping the F5 socket scan");
        return;
    };

    let mut sources: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut crates: Vec<_> = std::fs::read_dir(root.join("crates"))
        .expect("read crates/")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir() && !p.ends_with("meow-bench"))
        .collect();
    crates.sort();
    for krate in &crates {
        // `rust/` is meow-lwip's source root.
        for dir in ["src", "rust"] {
            walk_rs_files(&krate.join(dir), &mut |path, content| {
                sources.push((path.to_path_buf(), content.to_owned()));
            });
        }
    }
    assert!(
        sources.len() > 100,
        "F5 found only {} source files under {} — the scan is not looking \
         where the code is",
        sources.len(),
        root.display()
    );

    let sources: Vec<Source> = sources
        .into_iter()
        .map(|(path, raw)| Source {
            code: blank_literals_and_comments(&raw),
            path,
            raw,
        })
        .collect();
    let test_files = test_only_module_files(&sources);
    let mut counts: std::collections::BTreeMap<(String, &str), Vec<usize>> = Default::default();
    for src in &sources {
        if test_files.contains(&src.path) {
            continue;
        }
        let rel = src
            .path
            .strip_prefix(&root)
            .unwrap_or(&src.path)
            .to_string_lossy()
            .replace('\\', "/");
        let test_only = test_only_lines(&src.path, &src.code);
        for (line_no, code) in src.code.lines().enumerate() {
            if test_only.contains(&line_no) {
                continue;
            }
            for &prim in RAW_SOCKET_PRIMITIVES {
                let hits = find_path_calls(code, prim).count();
                if hits > 0 {
                    counts
                        .entry((rel.clone(), prim))
                        .or_default()
                        .extend(std::iter::repeat_n(line_no + 1, hits));
                }
            }
        }
    }

    let mut problems = Vec::new();
    for ((file, prim), lines) in &counts {
        let allowed = RAW_SOCKET_ALLOWLIST
            .iter()
            .find(|(f, p, _, _)| *f == file.as_str() && p == prim)
            .map_or(0, |(_, _, n, _)| *n);
        if lines.len() > allowed {
            problems.push(format!(
                "{file}: {} raw `{prim}…)` call(s) at line(s) {lines:?}, {allowed} \
                 allowlisted — create outbound sockets with meow_common::connect_tcp / \
                 connect_tcp_host / bind_udp instead (TUN global-route binding + \
                 Android protect, issue #695); if the socket is not outbound, \
                 allowlist it with the reason",
                lines.len()
            ));
        }
    }
    for (file, prim, n, _) in RAW_SOCKET_ALLOWLIST {
        let found = counts.get(&((*file).to_owned(), *prim)).map_or(0, Vec::len);
        if found < *n {
            problems.push(format!(
                "stale allowlist entry: {file} `{prim}…)` expects {n}, found {found} — \
                 lower the count or drop the entry"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "raw outbound socket creation outside meow_common's chokepoints:\n{}",
        problems.join("\n")
    );
}

/// One scanned source file: `raw` as read, `code` with every comment and
/// literal blanked ([`blank_literals_and_comments`]) — same line layout.
struct Source {
    path: std::path::PathBuf,
    raw: String,
    code: String,
}

/// `content` with every comment and string/char literal blanked to spaces,
/// newlines kept so line numbers survive. Whole-file, unlike the per-line
/// [`strip_literals_and_comments`]: workspace sources carry multi-line
/// literals (YAML fixtures, `\`-continued messages) whose braces would
/// derail the `#[cfg(test)]` span tracking, and block comments whose prose
/// would read as code.
fn blank_literals_and_comments(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let mut out = String::with_capacity(content.len());
    let mut i = 0;
    while i < chars.len() {
        let next = chars.get(i + 1).copied();
        let end = match chars[i] {
            '/' if next == Some('/') => Some(
                chars[i..]
                    .iter()
                    .position(|&c| c == '\n')
                    .map_or(chars.len(), |p| i + p),
            ),
            '/' if next == Some('*') => Some(block_comment_end(&chars, i)),
            'r' if matches!(next, Some('"' | '#')) => raw_string_end(&chars, i),
            '"' => Some(string_end(&chars, i)),
            '\'' => char_literal_end(&chars, i),
            _ => None,
        };
        if let Some(end) = end {
            out.extend(
                chars[i..end]
                    .iter()
                    .map(|&c| if c == '\n' { '\n' } else { ' ' }),
            );
            i = end;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// End index (exclusive) of the (possibly nested) block comment opening at
/// `start`.
fn block_comment_end(chars: &[char], start: usize) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    while i + 1 < chars.len() {
        match (chars[i], chars[i + 1]) {
            ('/', '*') => {
                depth += 1;
                i += 2;
            }
            ('*', '/') => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    chars.len()
}

/// The workspace root, or `None` when this test runs from a packaged crate
/// with no sibling sources.
fn workspace_root() -> Option<std::path::PathBuf> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    root.join("crates/meow-common/src/socket_protect.rs")
        .is_file()
        .then(|| root.canonicalize().unwrap_or(root))
}

/// Byte offsets of `prim` in `code` where it starts a path segment — i.e.
/// not the tail of a longer identifier (`PacketConnSocket::new(` is not
/// `Socket::new(`).
fn find_path_calls<'a>(code: &'a str, prim: &'a str) -> impl Iterator<Item = usize> + 'a {
    code.match_indices(prim).filter_map(move |(at, _)| {
        let prev = code[..at].chars().next_back();
        (!prev.is_some_and(|c| c.is_alphanumeric() || c == '_')).then_some(at)
    })
}

/// Files compiled only into test builds: the targets of
/// `#[cfg(test)] mod x;` declarations (honouring `#[path = "…"]`), and
/// every out-of-line module declared inside such a file.
fn test_only_module_files(sources: &[Source]) -> HashSet<std::path::PathBuf> {
    let mut test_files: HashSet<std::path::PathBuf> = HashSet::new();
    for src in sources {
        test_files.extend(mod_decl_files(src, true));
    }
    loop {
        let mut grown = false;
        for src in sources {
            if test_files.contains(&src.path) {
                for child in mod_decl_files(src, false) {
                    grown |= test_files.insert(child);
                }
            }
        }
        if !grown {
            return test_files;
        }
    }
}

/// Resolved files of the out-of-line `mod x;` declarations in `src` (only
/// the `#[cfg(test)]`-gated ones when `test_gated_only`).
fn mod_decl_files(src: &Source, test_gated_only: bool) -> Vec<std::path::PathBuf> {
    let path = src.path.as_path();
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let is_mod_rs = matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some("mod.rs" | "lib.rs" | "main.rs")
    );
    let mod_dir = if is_mod_rs {
        dir.to_path_buf()
    } else {
        dir.join(path.file_stem().unwrap_or_default())
    };
    let test_only = test_only_lines(path, &src.code);
    let mut path_attr: Option<String> = None;
    let mut out = Vec::new();
    for (line_no, (raw, code)) in src.raw.lines().zip(src.code.lines()).enumerate() {
        if test_gated_only && !test_only.contains(&line_no) {
            path_attr = None;
            continue;
        }
        let trimmed = code.trim();
        if trimmed.starts_with("#[path") {
            // The literal is blanked in `code`; read it from the raw line.
            path_attr = raw.split('"').nth(1).map(str::to_owned);
            continue;
        }
        let Some((vis, name)) = trimmed
            .strip_suffix(';')
            .and_then(|decl| decl.rsplit_once("mod "))
        else {
            if !trimmed.starts_with("#[") {
                path_attr = None;
            }
            continue;
        };
        let vis = vis.trim();
        if !(vis.is_empty() || vis.starts_with("pub"))
            || name.is_empty()
            || !name.chars().all(|c| c.is_alphanumeric() || c == '_')
        {
            path_attr = None;
            continue;
        }
        // Rust reference: a non-inline `#[path]` is relative to the
        // declaring file's directory; otherwise `<mod dir>/x.rs` or
        // `<mod dir>/x/mod.rs`.
        let file = match path_attr.take() {
            Some(p) => dir.join(p),
            None => {
                let flat = mod_dir.join(format!("{name}.rs"));
                if flat.is_file() {
                    flat
                } else {
                    mod_dir.join(name).join("mod.rs")
                }
            }
        };
        out.push(file.canonicalize().unwrap_or(file));
    }
    out
}

// ─── F5 helper self-tests ────────────────────────────────────────────────────

#[test]
fn blanking_spans_multi_line_literals_and_block_comments() {
    let src = "let a = \"{\n}\";\n/* x {\n /* y */ } */ let b = r#\"\n{\"#;\nUdpSocket::bind(x)\n";
    let code = blank_literals_and_comments(src);
    assert_eq!(
        code.lines().count(),
        src.lines().count(),
        "line layout kept"
    );
    assert!(!code.contains('{') && !code.contains('}'), "{code:?}");
    assert!(
        code.contains("let b ="),
        "code after a nested block comment survives"
    );
    assert_eq!(code.lines().last(), Some("UdpSocket::bind(x)"));
}

#[test]
fn raw_primitive_match_respects_identifier_boundaries() {
    let hits = |code: &str| find_path_calls(code, "Socket::new(").count();
    assert_eq!(hits("let s = socket2::Socket::new(d, t, p)?;"), 1);
    assert_eq!(hits("let s = Socket::new(d, t, p)?;"), 1);
    assert_eq!(hits("Box::new(PacketConnSocket::new(conn, remote))"), 0);
    assert_eq!(hits("let s = TcpSocket::new(d)?;"), 0);
}

#[test]
fn test_gated_mod_declarations_resolve_to_files() {
    let dir = std::path::Path::new("/ws/crates/x/src/proto");
    let src = "\
mod live;
#[cfg(test)]
#[path = \"driver_tests.rs\"]
mod tests;
#[cfg(test)]
pub(crate) mod support;
";
    let source = |file: &str| Source {
        path: dir.join(file),
        raw: src.to_owned(),
        code: blank_literals_and_comments(src),
    };
    let gated = mod_decl_files(&source("driver.rs"), true);
    assert_eq!(
        gated,
        vec![
            dir.join("driver_tests.rs"),
            dir.join("driver").join("support").join("mod.rs"),
        ]
    );
    let all = mod_decl_files(&source("mod.rs"), false);
    assert_eq!(all.len(), 3);
    assert_eq!(all[0], dir.join("live").join("mod.rs"));
}
