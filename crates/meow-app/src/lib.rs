//! CLI and service helpers for the meow-rs proxy kernel.
//!
//! Library surface used by the `meow` binary: systemd unit generation,
//! geodata fetch, health checks, and subscription refresh. The binary wires
//! configuration, the tunnel, listeners, DNS, and the REST API together.

pub mod geodata_fetch;
pub mod subscription_refresh;

/// Generate a systemd unit file for the meow service.
///
/// Returns the unit file content as a string.
///
/// # Arguments
/// * `exe_path` - Absolute path to the meow binary
/// * `config_path` - Absolute path to the configuration file
pub fn generate_systemd_unit(exe_path: &str, config_path: &str) -> String {
    let work_dir = std::path::Path::new(config_path)
        .parent()
        .unwrap_or(std::path::Path::new("/"))
        .to_string_lossy()
        .to_string();

    format!(
        r#"[Unit]
Description=meow-rs proxy service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe_path} -f {config_path}
WorkingDirectory={work_dir}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={work_dir}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"#,
    )
}
