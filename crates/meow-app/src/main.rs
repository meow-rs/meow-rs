// dhat heap profiling — only active when compiled with --features dhat-heap.
// The profiler writes dh_out.json on process exit; parse with dhat-viewer.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use dashmap::DashMap;
#[cfg(feature = "listener-tun")]
use meow_api::tun_config_to_listener_config;
use meow_api::ApiServer;
use meow_config::load_config;
use meow_config::proxy_provider::ProxyProvider;
use meow_dns::DnsServer;
#[cfg(feature = "listener-mixed")]
use meow_listener::MixedListener;
#[cfg(feature = "listener-shadowsocks")]
use meow_listener::ShadowsocksListener;
use meow_listener::SnifferRuntime;
#[cfg(feature = "listener-tproxy")]
use meow_listener::TProxyListener;
#[cfg(feature = "listener-tun")]
use meow_listener::TunListener;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{error, info, warn};

#[cfg(target_os = "windows")]
mod windows_service;

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "meow";

#[derive(Parser)]
#[command(name = "meow", version, about = "A rule-based tunnel in Rust")]
struct Args {
    /// Path to configuration file
    #[arg(short = 'f', long = "config", default_value = "config.yaml")]
    config: String,

    /// Home directory
    #[arg(short = 'd', long = "directory")]
    directory: Option<String>,

    /// Test configuration and exit
    #[arg(short = 't', long = "test")]
    test: bool,

    /// Set geodata mode
    #[arg(short = 'm', long = "geodata-mode")]
    geodata_mode: bool,

    /// Specify base64-encoded configuration string
    #[arg(long = "config-string")]
    config_string: Option<String>,

    /// Override external UI directory
    #[arg(long = "ext-ui")]
    ext_ui: Option<String>,

    /// Override external controller address
    #[arg(long = "ext-ctl")]
    ext_ctl: Option<String>,

    /// Override external controller TLS address
    #[arg(long = "ext-ctl-tls")]
    ext_ctl_tls: Option<String>,

    /// Override external controller unix address
    #[arg(long = "ext-ctl-unix")]
    ext_ctl_unix: Option<String>,

    /// Override external controller pipe address
    #[arg(long = "ext-ctl-pipe")]
    ext_ctl_pipe: Option<String>,

    /// Override external controller routing mark
    #[arg(long = "ext-ctl-routing-mark")]
    ext_ctl_routing_mark: Option<u32>,

    /// Override secret for RESTful API
    #[arg(long = "secret")]
    secret: Option<String>,

    /// Set post-up script
    #[arg(long = "post-up")]
    post_up: Option<String>,

    /// Set post-down script
    #[arg(long = "post-down")]
    post_down: Option<String>,

    /// Specify age secret key to decrypt configuration
    #[arg(long = "age-secret-key")]
    age_secret_key: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Install as a system service
    Install {
        /// Config file path for the service
        #[arg(short = 'f', long = "config")]
        config: Option<String>,
    },
    /// Uninstall the system service
    Uninstall,
    /// Show service status
    Status,
    /// Internal entry point used by the Windows Service Control Manager
    #[cfg(target_os = "windows")]
    #[command(hide = true)]
    RunService,
}

enum LogTarget {
    Console,
    #[cfg(target_os = "windows")]
    WindowsService(std::path::PathBuf),
}

enum ShutdownSignal {
    Console,
    #[cfg(target_os = "windows")]
    WindowsService(tokio::sync::oneshot::Receiver<()>),
}

impl ShutdownSignal {
    async fn wait(self) -> Result<()> {
        match self {
            Self::Console => {
                #[cfg(unix)]
                {
                    let mut sigterm =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {},
                        _ = sigterm.recv() => {},
                    }
                }
                #[cfg(not(unix))]
                {
                    tokio::signal::ctrl_c().await?;
                }
                Ok(())
            }
            #[cfg(target_os = "windows")]
            Self::WindowsService(receiver) => receiver
                .await
                .map_err(|_| anyhow::anyhow!("Windows service shutdown channel closed")),
        }
    }
}

struct Logging {
    tx: tokio::sync::broadcast::Sender<meow_api::log_stream::LogMessage>,
    #[cfg(target_os = "windows")]
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

type ReadyCallback = Box<dyn FnOnce() -> Result<()> + Send>;

fn main() -> Result<()> {
    // dhat profiler guard — must be the first local, lives for the duration of main().
    // Writes dh_out.json on drop. Active only when compiled with --features dhat-heap.
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    // nyanpasu uses -v to query version (mihomo format)
    if std::env::args().any(|a| a == "-v") {
        println!("Meow Meta {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let args = Args::parse();

    // Hard-error on unsupported flags instead of silently ignoring them.
    if args.post_up.is_some() {
        anyhow::bail!("--post-up is not yet supported");
    }
    if args.post_down.is_some() {
        anyhow::bail!("--post-down is not yet supported");
    }
    if args.age_secret_key.is_some() {
        anyhow::bail!("--age-secret-key is not yet supported");
    }
    if args.ext_ctl_tls.is_some() {
        anyhow::bail!("--ext-ctl-tls is not yet supported");
    }
    if args.ext_ctl_unix.is_some() {
        anyhow::bail!("--ext-ctl-unix is not yet supported");
    }
    if args.ext_ctl_pipe.is_some() {
        anyhow::bail!("--ext-ctl-pipe is not yet supported");
    }

    // Accepted for mihomo CLI compatibility but not implemented. Frontends may
    // pass these blindly, so warn instead of bailing (tracing is not yet
    // initialized here, hence eprintln).
    if args.geodata_mode {
        eprintln!("warning: --geodata-mode is not supported and will be ignored");
    }
    if args.ext_ctl_routing_mark.is_some() {
        eprintln!("warning: --ext-ctl-routing-mark is not supported and will be ignored");
    }

    // Handle subcommands before initializing logging/runtime
    if let Some(cmd) = &args.command {
        return handle_service_command(cmd, &args);
    }

    run_application(args, &LogTarget::Console, ShutdownSignal::Console, None)
}

#[allow(clippy::unnecessary_wraps)] // WindowsService arm uses `?`
fn init_logging(target: &LogTarget) -> Result<Logging> {
    // Initialize logging + log broadcast channel for GET /logs WebSocket.
    // LogBroadcastLayer sits on its own TRACE filter so it receives ALL events
    // (including DEBUG/TRACE) regardless of the fmt layer's EnvFilter. This
    // ensures GET /logs?level=debug works even when the console/file filter is
    // set to info. Per-connection ?level= filtering in the WS handler provides
    // client-visible suppression.
    use meow_api::log_stream::LogBroadcastLayer;
    use tokio::sync::broadcast;
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::prelude::*;

    // mihomo uses "warning"/"silent" but EnvFilter only understands "warn"/"off".
    let normalize_level = |level: &str| -> String {
        match level.to_ascii_lowercase().as_str() {
            "warning" => "warn".to_string(),
            "silent" => "off".to_string(),
            other => other.to_string(),
        }
    };

    let env_filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
    };

    match target {
        LogTarget::Console => {
            let (tx, _) = broadcast::channel(128);
            let log_layer = LogBroadcastLayer { tx: tx.clone() }.with_filter(LevelFilter::TRACE);
            let (filter_layer, reload_handle) =
                tracing_subscriber::reload::Layer::new(env_filter());
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_filter(filter_layer))
                .with(log_layer)
                .init();
            meow_api::log_stream::install_log_reloader(move |level| {
                let normalized = normalize_level(level);
                reload_handle
                    .reload(tracing_subscriber::EnvFilter::new(&normalized))
                    .map_err(|e| e.to_string())
            });
            Ok(Logging {
                tx,
                #[cfg(target_os = "windows")]
                _file_guard: None,
            })
        }
        #[cfg(target_os = "windows")]
        LogTarget::WindowsService(log_dir) => {
            std::fs::create_dir_all(log_dir).map_err(|e| {
                anyhow::anyhow!(
                    "failed to create Windows service log directory {}: {e}",
                    log_dir.display()
                )
            })?;
            let appender = tracing_appender::rolling::RollingFileAppender::builder()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .filename_prefix("meow")
                .filename_suffix("log")
                .max_log_files(7)
                .build(log_dir)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to initialize Windows service log in {}: {e}",
                        log_dir.display()
                    )
                })?;
            let (writer, guard) = tracing_appender::non_blocking(appender);
            let (tx, _) = broadcast::channel(128);
            let log_layer = LogBroadcastLayer { tx: tx.clone() }.with_filter(LevelFilter::TRACE);
            let (filter_layer, reload_handle) =
                tracing_subscriber::reload::Layer::new(env_filter());
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(writer)
                        .with_ansi(false)
                        .with_filter(filter_layer),
                )
                .with(log_layer)
                .init();
            meow_api::log_stream::install_log_reloader(move |level| {
                let normalized = normalize_level(level);
                reload_handle
                    .reload(tracing_subscriber::EnvFilter::new(&normalized))
                    .map_err(|e| e.to_string())
            });
            Ok(Logging {
                tx,
                _file_guard: Some(guard),
            })
        }
    }
}

fn run_application(
    args: Args,
    log_target: &LogTarget,
    shutdown: ShutdownSignal,
    on_ready: Option<ReadyCallback>,
) -> Result<()> {
    let logging = init_logging(log_target)?;
    let log_tx = logging.tx.clone();
    let result = run_application_inner(args, log_tx, shutdown, on_ready);

    // Keep the non-blocking file writer guard alive while recording the
    // terminal error. Dropping it afterwards flushes the queued record before
    // the Windows service host reports Stopped to SCM.
    if let Err(error) = &result {
        error!(error = %format_args!("{error:#}"), "meow-rs stopped with an error");
    }
    drop(logging);
    result
}

fn run_application_inner(
    args: Args,
    log_tx: tokio::sync::broadcast::Sender<meow_api::log_stream::LogMessage>,
    shutdown: ShutdownSignal,
    on_ready: Option<ReadyCallback>,
) -> Result<()> {
    info!("meow-rs starting...");

    // Propagate -d to the process-wide home directory so all resource-path
    // helpers (default_geoip_path, default_asn_path, default_geosite_path, …)
    // resolve under that directory instead of $XDG_CONFIG_HOME/meow.
    if let Some(dir) = &args.directory {
        meow_common::set_home_dir(std::path::PathBuf::from(dir));
    }

    // Load config
    let config_path = if let Some(dir) = &args.directory {
        let config = std::path::Path::new(&args.config);
        if config.is_absolute() {
            args.config.clone()
        } else {
            std::path::Path::new(dir)
                .join(config)
                .to_string_lossy()
                .to_string()
        }
    } else {
        args.config.clone()
    };

    if args.test {
        // Validate config only — spin up a minimal runtime for the async load.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            load_config(&config_path).await?;
            info!("Configuration test passed");
            Ok::<(), anyhow::Error>(())
        })?;
        return Ok(());
    }

    // Run the async runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        // --config-string replaces the config file as the source (mihomo
        // behavior); the flag overrides below apply on top of either source.
        let mut config = if let Some(ref cs) = args.config_string {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(cs)
                .map_err(|e| anyhow::anyhow!("--config-string: invalid base64: {e}"))?;
            let yaml = String::from_utf8(bytes)
                .map_err(|e| anyhow::anyhow!("--config-string: invalid UTF-8: {e}"))?;
            let config = meow_config::load_config_from_str(&yaml)
                .await
                .map_err(|e| anyhow::anyhow!("--config-string: {e}"))?;
            info!("Config loaded from --config-string");
            config
        } else {
            let config = load_config(&config_path).await?;
            info!("Config loaded from {}", config_path);
            config
        };

        // Apply CLI overrides to the loaded config.
        if let Some(ref s) = args.secret {
            config.api.secret = Some(s.clone());
            info!("API secret overridden by --secret");
        }
        if let Some(ref ctl) = args.ext_ctl {
            let addr: std::net::SocketAddr = ctl
                .parse()
                .map_err(|e| anyhow::anyhow!("--ext-ctl: invalid address '{ctl}': {e}"))?;
            config.api.external_controller = Some(addr);
            info!("External controller overridden by --ext-ctl: {addr}");
        }
        if let Some(ref ui) = args.ext_ui {
            config.api.external_ui = Some(std::path::PathBuf::from(ui));
            info!("External UI overridden by --ext-ui");
        }

        run(config, config_path, log_tx, shutdown, on_ready).await
    })
}

fn handle_service_command(cmd: &Command, args: &Args) -> Result<()> {
    match cmd {
        Command::Install { config } => install_service(config.as_deref(), args),
        Command::Uninstall => uninstall_service(),
        Command::Status => service_status(),
        #[cfg(target_os = "windows")]
        Command::RunService => windows_service::dispatch(),
    }
}

#[cfg(target_os = "linux")]
fn install_service(config_override: Option<&str>, args: &Args) -> Result<()> {
    // Determine the binary path
    let exe_path = std::env::current_exe()?;
    let exe_path = exe_path
        .canonicalize()
        .unwrap_or(exe_path)
        .to_string_lossy()
        .to_string();

    // Determine config path (absolute)
    let config_rel = config_override.unwrap_or(&args.config);
    let config_path = if std::path::Path::new(config_rel).is_absolute() {
        config_rel.to_string()
    } else {
        let cwd = std::env::current_dir()?;
        cwd.join(config_rel).to_string_lossy().to_string()
    };

    let unit = meow_app::generate_systemd_unit(&exe_path, &config_path);

    let service_path = format!("/etc/systemd/system/{SERVICE_NAME}.service");

    // Check if running as root
    if !is_root() {
        eprintln!("Root privileges required. Run with sudo:");
        eprintln!("  sudo {exe_path} install -f {config_path}");
        std::process::exit(1);
    }

    // Write service file
    std::fs::write(&service_path, &unit)?;
    println!("Service file written to {service_path}");

    // Reload systemd and enable
    run_cmd("systemctl", &["daemon-reload"])?;
    run_cmd("systemctl", &["enable", SERVICE_NAME])?;
    run_cmd("systemctl", &["start", SERVICE_NAME])?;

    println!();
    println!("meow service installed and started.");
    println!();
    println!("  Config:  {config_path}");
    println!("  Binary:  {exe_path}");
    println!();
    println!("Commands:");
    println!("  sudo systemctl status {SERVICE_NAME}");
    println!("  sudo systemctl restart {SERVICE_NAME}");
    println!("  sudo systemctl stop {SERVICE_NAME}");
    println!("  sudo journalctl -u {SERVICE_NAME} -f");

    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_service() -> Result<()> {
    if !is_root() {
        let exe = std::env::current_exe().unwrap_or_default();
        eprintln!("Root privileges required. Run with sudo:");
        eprintln!("  sudo {} uninstall", exe.display());
        std::process::exit(1);
    }

    let service_path = format!("/etc/systemd/system/{SERVICE_NAME}.service");

    // Stop and disable
    let _ = run_cmd("systemctl", &["stop", SERVICE_NAME]);
    let _ = run_cmd("systemctl", &["disable", SERVICE_NAME]);

    // Remove service file
    if std::path::Path::new(&service_path).exists() {
        std::fs::remove_file(&service_path)?;
        println!("Removed {service_path}");
    }

    run_cmd("systemctl", &["daemon-reload"])?;
    println!("meow service uninstalled.");

    Ok(())
}

#[cfg(target_os = "linux")]
fn service_status() -> Result<()> {
    let output = std::process::Command::new("systemctl")
        .args(["status", SERVICE_NAME])
        .output()?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}

// --- macOS launchd user agent ---

#[cfg(target_os = "macos")]
const LAUNCHD_LABEL: &str = "com.meow.proxy";

#[cfg(target_os = "macos")]
fn macos_dirs() -> Result<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set"))?;
    let home = std::path::PathBuf::from(home);
    let app_support = home.join("Library/Application Support/meow");
    let log_dir = home.join("Library/Logs/meow");
    let launch_agents = home.join("Library/LaunchAgents");
    Ok((app_support, log_dir, launch_agents))
}

#[cfg(target_os = "macos")]
fn install_service(config_override: Option<&str>, args: &Args) -> Result<()> {
    let exe_path = std::env::current_exe()?;
    let exe_path = exe_path
        .canonicalize()
        .unwrap_or(exe_path)
        .to_string_lossy()
        .to_string();

    // Resolve source config path
    let config_rel = config_override.unwrap_or(&args.config);
    let src_config = if std::path::Path::new(config_rel).is_absolute() {
        std::path::PathBuf::from(config_rel)
    } else {
        std::env::current_dir()?.join(config_rel)
    };

    if !src_config.exists() {
        anyhow::bail!("Config file not found: {}", src_config.display());
    }

    let (app_support, log_dir, launch_agents) = macos_dirs()?;

    // Create directories
    std::fs::create_dir_all(&app_support)?;
    std::fs::create_dir_all(&log_dir)?;
    std::fs::create_dir_all(&launch_agents)?;

    // Copy config to ~/Library/Application Support/meow/config.yaml
    let dest_config = app_support.join("config.yaml");
    std::fs::copy(&src_config, &dest_config)?;
    println!("Config copied to {}", dest_config.display());

    let plist = format!(
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
    <key>StandardOutPath</key>
    <string>{log_dir}/meow.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/meow.err.log</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        exe = exe_path,
        config = dest_config.display(),
        work_dir = app_support.display(),
        log_dir = log_dir.display(),
    );

    let plist_path = launch_agents.join(format!("{LAUNCHD_LABEL}.plist"));

    // Bootout existing service if loaded (ignore errors)
    let uid = unsafe { libc::getuid() };
    let domain_target = format!("gui/{uid}");
    let service_target = format!("gui/{uid}/{LAUNCHD_LABEL}");
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &service_target])
        .output();

    // Write plist
    std::fs::write(&plist_path, &plist)?;
    println!("Plist written to {}", plist_path.display());

    // Bootstrap the service
    run_cmd(
        "launchctl",
        &["bootstrap", &domain_target, &plist_path.to_string_lossy()],
    )?;

    println!();
    println!("meow service installed and started.");
    println!();
    println!("  Config:  {}", dest_config.display());
    println!("  Binary:  {exe_path}");
    println!("  Logs:    {}/meow.log", log_dir.display());
    println!();
    println!("Commands:");
    println!("  {exe_path} status");
    println!("  launchctl kickstart -k {service_target}");
    println!("  tail -f {}/meow.log", log_dir.display());

    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_service() -> Result<()> {
    let (app_support, _log_dir, launch_agents) = macos_dirs()?;
    let plist_path = launch_agents.join(format!("{LAUNCHD_LABEL}.plist"));

    // Bootout the service (ignore errors if not loaded)
    let uid = unsafe { libc::getuid() };
    let service_target = format!("gui/{uid}/{LAUNCHD_LABEL}");
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &service_target])
        .output();

    // Remove plist
    if plist_path.exists() {
        std::fs::remove_file(&plist_path)?;
        println!("Removed {}", plist_path.display());
    }

    // Remove copied config
    let dest_config = app_support.join("config.yaml");
    if dest_config.exists() {
        std::fs::remove_file(&dest_config)?;
        println!("Removed {}", dest_config.display());
    }

    println!("meow service uninstalled.");

    Ok(())
}

#[cfg(target_os = "macos")]
fn service_status() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let service_target = format!("gui/{uid}/{LAUNCHD_LABEL}");
    let output = std::process::Command::new("launchctl")
        .args(["print", &service_target])
        .output()?;

    if output.status.success() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
    } else {
        println!("Service {LAUNCHD_LABEL} is not loaded.");
        if !output.stderr.is_empty() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }
    }
    Ok(())
}

// --- Windows Service Control Manager ---

#[cfg(target_os = "windows")]
fn install_service(config: Option<&str>, args: &Args) -> Result<()> {
    windows_service::install(config, args)
}

#[cfg(target_os = "windows")]
fn uninstall_service() -> Result<()> {
    windows_service::uninstall()
}

#[cfg(target_os = "windows")]
fn service_status() -> Result<()> {
    windows_service::status()
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(cmd).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{} {} failed with {}", cmd, args.join(" "), status);
    }
    Ok(())
}

/// Build a listener bind address from an IP-literal `listen` string and a port.
///
/// Parses `listen` as an `IpAddr` and composes via `SocketAddr::new`, instead
/// of `format!("{listen}:{port}")`. The string form produces an unparseable
/// `:::7890` for an IPv6 listen address like `::`, which silently broke
/// dual-stack binding (`bind-address: '::'`); `SocketAddr::new` handles IPv4
/// and IPv6 uniformly. `listen` is always an IP literal here (`0.0.0.0`, `::`,
/// `127.0.0.1`, or a specific address).
fn bind_socket_addr(listen: &str, port: u16) -> Result<SocketAddr> {
    let ip: IpAddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address '{listen}': {e}"))?;
    Ok(SocketAddr::new(ip, port))
}

async fn run(
    config: meow_config::Config,
    config_path: String,
    log_tx: tokio::sync::broadcast::Sender<meow_api::log_stream::LogMessage>,
    shutdown: ShutdownSignal,
    on_ready: Option<ReadyCallback>,
) -> Result<()> {
    // Keep raw config in shared state for runtime mutations
    let raw_config = Arc::new(RwLock::new(config.raw.clone()));

    // Wrap proxy providers in a DashMap for concurrent access.
    let proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>> = {
        let map = DashMap::new();
        for (name, provider) in config.proxy_providers {
            map.insert(name, provider);
        }
        Arc::new(map)
    };

    // Rule providers in shared state for runtime refresh and API exposure.
    let rule_providers = Arc::new(RwLock::new(config.rule_providers));

    // Install the configured resolver as the global host-resolver hook used
    // by `meow_common::connect_tcp_host` / `resolve_host`, so a proxy node's
    // own server hostname is resolved by the DNS in the config — matching
    // mihomo, and matching what `DirectAdapter` already does for destination
    // hostnames. Without it the proxy adapters fall back to libc's
    // `getaddrinfo`, which ignores `dns:` entirely (wrong nameserver,
    // wrong `hosts:` entries) and, on a VPN-active device, opens DNS sockets
    // that bypass `VpnService.protect(fd)` so the query loops back through
    // our own tunnel. See `meow-common/src/socket_protect.rs` for the full
    // failure mode; the Android `SocketProtector` is installed separately by
    // the JNI bridge.
    //
    // On desktop this is gated on `dns.enable`: with DNS off,
    // `config.dns.resolver` is a stub pointing at a hard-coded upstream, and
    // forcing every proxy dial through it would be worse than the OS resolver
    // the user asked for. Clearing otherwise keeps a config reload from
    // leaving a stale hook installed.
    //
    // The VPN platforms are the exception and install it unconditionally.
    // There the hook is not a DNS-quality choice but a correctness one: it is
    // the only thing keeping proxy-server lookups off libc `getaddrinfo`,
    // whose sockets bypass `VpnService.protect(fd)` / the NE tunnel's
    // exclusion and therefore loop the query back through our own tunnel.
    // Android installed it unconditionally before proxy-server resolution
    // moved cross-platform; gating it on `dns.enable` there would resurrect
    // that loop for `dns.enable: false` configs (the very case
    // `socket_protect::resolve_addrs` warns about). The stub upstream is a
    // worse resolver than the OS one, but a reachable one beats a lookup that
    // deadlocks against the tunnel carrying it.
    const VPN_PLATFORM: bool = cfg!(any(target_os = "android", target_os = "ios"));
    if config.dns.enabled || VPN_PLATFORM {
        meow_common::set_host_resolver(Arc::new(
            meow_dns::ResolverHostHook::new_with_proxy_resolver(
                Arc::clone(&config.dns.resolver),
                config.dns.proxy_resolver.clone(),
            ),
        ));
    } else {
        meow_common::clear_host_resolver();
    }

    // Create the tunnel (core routing engine)
    // Share the DNS config's resolver slot so runtime `set_resolver` swaps
    // reach the map's DIRECT adapters built from this slot (issue #514).
    let tunnel = Tunnel::new_with_slot(Arc::clone(&config.dns.resolver_slot));
    if config.api.external_controller.is_none() {
        // No API can inspect individual connections. Keep cancellation handles
        // for cold reloads without storing their display metadata.
        tunnel.statistics().set_headless();
    }
    // Provider-sourced nodes resolve `dialer-proxy` names against this
    // registry; install before the first `update_routing` so it publishes
    // the initial route map (issue #489).
    tunnel.set_dialer_registry(config.provider_dialer_registry.clone());
    tunnel.set_mode(config.general.mode);
    tunnel.update_routing(config.proxies, config.rules, config.dialer_registry);
    tunnel.spawn_background_tasks();

    // Spawn periodic health checks for fallback / url-test proxy groups.
    // The supervisor lives on the tunnel so config reloads can reconcile
    // the task set (issue #514).
    tunnel.reconcile_health_checks(&meow_config::extract_health_check_specs(
        config.raw.proxy_groups.as_deref().unwrap_or(&[]),
    ));

    // Start DNS server if configured. The handle is shared with the API
    // layer so `PUT /configs` can hot-swap the resolver or rebind on a
    // `dns.listen` change (issue #514).
    let dns_server_handle = Arc::new(parking_lot::RwLock::new(None));
    if let Some(listen_addr) = config.dns.listen_addr {
        let dns_server = DnsServer::new(Arc::clone(&config.dns.resolver), listen_addr);
        let slot = dns_server.resolver_slot();
        let task = tokio::spawn(async move {
            if let Err(e) = dns_server.run().await {
                error!("DNS server error: {}", e);
            }
        });
        *dns_server_handle.write() = Some(meow_api::routes::DnsServerHandle {
            listen: listen_addr,
            task,
            resolver_slot: slot,
        });
    }

    // Interval-refresh loops are owned by a supervisor so commits that
    // swap the registry (PUT /configs, subscription refresh) can spawn or
    // abort tasks — startup reconciles the initial set (issue #543).
    let rule_provider_refresh =
        Arc::new(meow_config::rule_provider_refresh::RefreshSupervisor::default());
    rule_provider_refresh.reconcile(&rule_providers);

    // Same supervision for `proxy-providers` `interval:` — reconciled
    // against the committed declarations on every registry swap
    // (`commit_proxy_providers`), and once here for the startup set
    // (issue #625).
    let proxy_provider_refresh =
        Arc::new(meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor::default());
    proxy_provider_refresh.reconcile(&proxy_providers, config.raw.proxy_providers.as_ref());

    // Providers whose `proxy:` name could not resolve during the
    // pre-publish initial fetch retry once now that `update_routing` has
    // populated the provider dialer registry (issue #625).
    for entry in proxy_providers.iter() {
        if entry.take_deferred_initial() {
            let provider = Arc::clone(entry.value());
            tokio::spawn(async move {
                if let Err(e) = provider.acquire_initial().await {
                    warn!(
                        "proxy-provider '{}': deferred initial fetch failed: {e}",
                        provider.name
                    );
                }
            });
        }
    }

    // Start subscription background refresh task
    {
        let raw_config = Arc::clone(&raw_config);
        let tunnel = tunnel.clone();
        let config_path = config_path.clone();
        let dns_server = Arc::clone(&dns_server_handle);
        let rule_providers = Arc::clone(&rule_providers);
        let proxy_providers = Arc::clone(&proxy_providers);
        let rule_provider_refresh = Arc::clone(&rule_provider_refresh);
        let proxy_provider_refresh = Arc::clone(&proxy_provider_refresh);
        let provider_dialer_registry = config.provider_dialer_registry.clone();
        tokio::spawn(async move {
            meow_app::subscription_refresh::run_loop(
                raw_config,
                tunnel,
                config_path,
                dns_server,
                rule_providers,
                proxy_providers,
                provider_dialer_registry,
                rule_provider_refresh,
                proxy_provider_refresh,
            )
            .await;
        });
    }

    // Fetch any missing geodata DBs on startup (unconditional — independent of
    // geodata.auto-update). Runs in the background so listener startup is not
    // blocked; rules are rebuilt and the DNS resolver republished afterward
    // if anything was downloaded.
    {
        let geodata = config.geodata.clone();
        let tunnel = tunnel.clone();
        let raw_config = Arc::clone(&raw_config);
        let rule_providers = Arc::clone(&rule_providers);
        let proxy_providers = Arc::clone(&proxy_providers);
        let dns_server = Arc::clone(&dns_server_handle);
        let cache_dir = meow_config::resource_cache_dir_for_config_path(&config_path);
        tokio::spawn(async move {
            meow_app::geodata_fetch::run_on_startup(
                geodata,
                tunnel,
                raw_config,
                rule_providers,
                proxy_providers,
                dns_server,
                cache_dir,
            )
            .await;
        });
    }

    // Spawn geodata auto-update task if enabled.
    if config.geodata.auto_update {
        let geodata = config.geodata.clone();
        let tunnel = tunnel.clone();
        let raw_config = Arc::clone(&raw_config);
        let rule_providers = Arc::clone(&rule_providers);
        let proxy_providers = Arc::clone(&proxy_providers);
        let dns_server = Arc::clone(&dns_server_handle);
        let cache_dir = meow_config::resource_cache_dir_for_config_path(&config_path);
        tokio::spawn(async move {
            meow_app::geodata_fetch::auto_update_loop(
                geodata,
                tunnel,
                raw_config,
                rule_providers,
                proxy_providers,
                dns_server,
                cache_dir,
            )
            .await;
        });
    }

    // Build shared SnifferRuntime from config (once per startup).
    let sniffer_runtime = Arc::new(SnifferRuntime::new(config.sniffer));
    let auth = config.auth;
    // Suppress unused-variable warnings: sniffer_runtime and auth are
    // consumed only inside feature-gated listener blocks below.
    let _ = (&sniffer_runtime, &auth);

    // Start listeners. Bind before spawning the accept loops so a `port: 0`
    // (ephemeral) listener resolves to its OS-assigned port up front; the
    // resolved ports are patched into `named_listeners`, which feeds the
    // startup logs and the API snapshot (`GET /listeners`) below.
    use meow_config::ListenerSpec;

    let mut named_listeners = config.listeners.named.clone();
    for nl in &mut named_listeners {
        let addr = bind_socket_addr(&nl.listen, nl.port)
            .map_err(|e| anyhow::anyhow!("listener '{}': {e}", nl.name))?;
        // Suppress unused-variable warning: addr is consumed only inside
        // feature-gated match arms below.
        let _ = addr;
        match &nl.spec {
            ListenerSpec::Mixed | ListenerSpec::Http | ListenerSpec::Socks5 => {
                #[cfg(feature = "listener-mixed")]
                {
                    let socket = match tokio::net::TcpListener::bind(addr).await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("listener '{}': bind {} failed: {}", nl.name, addr, e);
                            continue;
                        }
                    };
                    let bound = socket.local_addr().unwrap_or(addr);
                    nl.port = bound.port();
                    let listener = MixedListener::new(tunnel.clone(), bound, nl.name.clone())
                        .with_sniffer(Arc::clone(&sniffer_runtime))
                        .with_auth(Arc::clone(&auth))
                        .with_max_connections(nl.max_connections);
                    tokio::spawn(async move {
                        if let Err(e) = listener.run_on(socket).await {
                            error!("Listener error: {}", e);
                        }
                    });
                }
                #[cfg(not(feature = "listener-mixed"))]
                tracing::warn!(
                    "listener '{}': type {:?} requires feature 'listener-mixed'",
                    nl.name,
                    nl.spec
                );
            }
            ListenerSpec::TProxy {
                sni,
                firewall,
                udp,
                udp_timeout,
            } => {
                #[cfg(feature = "listener-tproxy")]
                {
                    let socket = match tokio::net::TcpListener::bind(addr).await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("listener '{}': bind {} failed: {}", nl.name, addr, e);
                            continue;
                        }
                    };
                    let bound = socket.local_addr().unwrap_or(addr);
                    nl.port = bound.port();
                    let listener = TProxyListener::new(
                        tunnel.clone(),
                        bound,
                        *sni,
                        config.listeners.routing_mark,
                        nl.name.clone(),
                    )
                    .with_sniffer(Arc::clone(&sniffer_runtime))
                    .with_max_connections(nl.max_connections)
                    .with_firewall(*firewall)
                    .with_udp(*udp, std::time::Duration::from_secs(*udp_timeout));
                    tokio::spawn(async move {
                        if let Err(e) = listener.run_on(socket).await {
                            error!("TProxy listener error: {}", e);
                        }
                    });
                }
                #[cfg(not(feature = "listener-tproxy"))]
                {
                    // `sni`/`firewall`/`udp`/`udp_timeout` are only consumed by
                    // the `listener-tproxy` build above; mark them used so the
                    // bindings don't trip `-D warnings` on tproxy-less feature
                    // sets.
                    let _ = (sni, firewall, udp, udp_timeout);
                    tracing::warn!(
                        "listener '{}': TProxy requires feature 'listener-tproxy'",
                        nl.name
                    );
                }
            }
            ListenerSpec::Shadowsocks(cfg) => {
                #[cfg(feature = "listener-shadowsocks")]
                {
                    use meow_config::ObfsMode as CfgObfsMode;
                    use meow_listener::SsObfsMode;

                    let socket = match tokio::net::TcpListener::bind(addr).await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("listener '{}': bind {} failed: {}", nl.name, addr, e);
                            continue;
                        }
                    };
                    let bound = socket.local_addr().unwrap_or(addr);
                    nl.port = bound.port();
                    let obfs = cfg.simple_obfs.as_ref().map(|o| match o.mode {
                        CfgObfsMode::Http => SsObfsMode::Http,
                        CfgObfsMode::Tls => SsObfsMode::Tls,
                    });
                    let listener = match ShadowsocksListener::new(
                        tunnel.clone(),
                        bound,
                        nl.name.clone(),
                        &cfg.cipher,
                        &cfg.password,
                        cfg.udp,
                        obfs,
                    ) {
                        Ok(l) => l.with_max_connections(nl.max_connections),
                        Err(e) => {
                            error!("listener '{}': invalid shadowsocks config: {}", nl.name, e);
                            continue;
                        }
                    };
                    tokio::spawn(async move {
                        if let Err(e) = listener.run_on(socket).await {
                            error!("Shadowsocks listener error: {}", e);
                        }
                    });
                }
                #[cfg(not(feature = "listener-shadowsocks"))]
                {
                    let _ = cfg;
                    tracing::warn!(
                        "listener '{}': shadowsocks requires feature 'listener-shadowsocks'",
                        nl.name
                    );
                }
            }
        }
    }

    // Start REST API if configured. Runs after the listener bind phase so the
    // `GET /listeners` snapshot reports OS-assigned ports for `port: 0`
    // (ephemeral) listeners rather than the configured `0`.
    if let Some(api_addr) = config.api.external_controller {
        // `external-ui-url` auto-download is gated behind the optional
        // `external-ui-download` feature (it pulls in the `zip` crate, against
        // the ADR-0007 size caps). Without the feature we just hint the user to
        // populate the directory manually. See issue #223.
        if let (Some(url), Some(dir)) = (&config.api.external_ui_url, &config.api.external_ui) {
            if !dir.is_dir() {
                // Auto-download is gated behind `external-ui-download` AND is
                // force-disabled on iOS/Android (mobile ships its own UI).
                #[cfg(all(
                    feature = "external-ui-download",
                    not(any(target_os = "ios", target_os = "android"))
                ))]
                {
                    if let Err(e) = meow_config::external_ui::download_external_ui(url, dir).await {
                        warn!("failed to download external-ui from {url}: {e:#}");
                    }
                }
                #[cfg(not(all(
                    feature = "external-ui-download",
                    not(any(target_os = "ios", target_os = "android"))
                )))]
                {
                    warn!(
                        "external-ui-url ({url}) is set but auto-download is unavailable in this \
                         build; download and extract the UI into {} manually",
                        dir.display()
                    );
                }
            }
        }
        let api_server = ApiServer::new(
            tunnel.clone(),
            api_addr,
            config.api.secret.clone(),
            config_path.clone(),
            Arc::clone(&raw_config),
            log_tx.clone(),
            Arc::clone(&proxy_providers),
            Arc::clone(&rule_providers),
            Arc::clone(&rule_provider_refresh),
            Arc::clone(&proxy_provider_refresh),
            named_listeners.clone(),
            config.api.external_ui.clone(),
            Arc::clone(&dns_server_handle),
            config.provider_dialer_registry.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = api_server.run().await {
                error!("API server error: {}", e);
            }
        });
    }

    // TUN inbound (issue #326) — spawned from the top-level `tun:` section,
    // not the `listeners:` array (mihomo layout).
    if config.tun.enable {
        #[cfg(feature = "listener-tun")]
        {
            // Snapshot the TunConfig this generation is built from — the
            // Ready arm re-validates against the *committed* config.
            let startup_tun = config.tun.clone();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let listener = TunListener::new(
                tunnel.clone(),
                tun_config_to_listener_config(&config.tun),
                "meow-tun".to_string(),
            )
            .with_readiness_signal(ready_tx);

            let handle = tokio::spawn(async move {
                if let Err(e) = listener.run().await {
                    error!("TUN listener error: {}", e);
                }
            });

            // Await device readiness before treating TUN as "running".
            // If device creation fails (permission denied, etc.) the
            // notifier sends `TunReady::Failed` immediately — no timeout
            // wait.  Only a genuinely stuck setup hits the timeout.
            match tokio::time::timeout(meow_api::TUN_STARTUP_TIMEOUT, ready_rx).await {
                Ok(Ok(meow_listener::TunReady::Ready {
                    core_done,
                    udp_flows,
                })) => {
                    publish_tun_if_committed(
                        &tunnel,
                        &raw_config,
                        &startup_tun,
                        meow_tunnel::TunHandle {
                            task: handle,
                            core_done: Some(core_done),
                            udp_flows,
                        },
                    )
                    .await;
                }
                Ok(Ok(meow_listener::TunReady::Failed(msg))) => {
                    if msg.contains("wintun.dll") {
                        error!("TUN listener failed to start: {msg}");
                    } else {
                        error!(
                            "TUN listener failed to start: {msg} — \
                             check permissions / admin / CAP_NET_ADMIN"
                        );
                    }
                    handle.abort();
                    rollback_tun_enable(&tunnel, &raw_config).await;
                }
                Ok(Err(_)) => {
                    error!("TUN listener readiness signal dropped unexpectedly");
                    handle.abort();
                    rollback_tun_enable(&tunnel, &raw_config).await;
                }
                Err(_) => {
                    error!(
                        "TUN listener startup timed out after {} s",
                        meow_api::TUN_STARTUP_TIMEOUT.as_secs()
                    );
                    handle.abort();
                    rollback_tun_enable(&tunnel, &raw_config).await;
                }
            }
        }
        #[cfg(not(feature = "listener-tun"))]
        warn!("tun.enable is set but this build lacks the 'listener-tun' feature");
    }

    if let Some(on_ready) = on_ready {
        on_ready()?;
    }
    info!("meow-rs is running");

    // Wait for shutdown signal
    shutdown.wait().await?;
    info!("Shutting down...");

    Ok(())
}

/// #625: roll the committed `tun.enable` back to false after an initial
/// startup failure — mirrors the PUT-path rollback in
/// `swap_config_and_reconcile_tun` so the stored config never claims TUN
/// is up when nothing runs, and a later same-config PUT retries off→on
/// instead of early-returning on an unchanged diff.
///
/// Skips the write when a listener is already stored+running: while the
/// lane is held no sibling spawn can be in flight, so a live handle can
/// only belong to a `PUT /configs` that committed its own `tun:` section
/// during our bring-up — that mutation owns the outcome, and clobbering
/// its `enable` would re-create the very divergence this fix removes
/// (a live device the committed config claims is off).
#[cfg(feature = "listener-tun")]
async fn rollback_tun_enable(tunnel: &Tunnel, raw_config: &RwLock<meow_config::raw::RawConfig>) {
    let _mutation = meow_api::routes::CONFIG_MUTATION.lock().await;
    rollback_committed_enable(tunnel, raw_config);
}

/// The lane-held core of [`rollback_tun_enable`], shared with
/// [`publish_tun_if_committed`]'s died-before-publish arm (the lane is
/// already held there — re-locking would deadlock).
#[cfg(feature = "listener-tun")]
fn rollback_committed_enable(tunnel: &Tunnel, raw_config: &RwLock<meow_config::raw::RawConfig>) {
    if tunnel.has_tun() {
        return;
    }
    if let Some(ref mut tun) = raw_config.write().tun {
        tun.enable = false;
        warn!("tun.enable rolled back to false (startup failed)");
    }
}

/// #625: publish a freshly-ready TUN handle only when the *committed*
/// config still asks for exactly the TunConfig this generation was built
/// from. A `PUT /configs` during bring-up commits before this runs — its
/// `stop_tun` no-ops on the empty slot, and a committed `enable: false`
/// (or a different `tun:` section whose own reconcile already spawned a
/// replacement) would end up shadowed by this stale generation. The
/// re-check runs inside the CONFIG_MUTATION lane; on mismatch the stale
/// handle is torn down without touching the stored slot. A listener that
/// sent `Ready` but already exited is likewise torn down and rolled back
/// rather than stored dead. The `TunConfig` compare is section-only, but
/// that is sufficient: a same-config PUT restart (e.g. fake-IP change)
/// serializes through this lane and the listener's single-core gate, so
/// a survivor here can't silently embed different resolver-era inputs.
#[cfg(feature = "listener-tun")]
async fn publish_tun_if_committed(
    tunnel: &Tunnel,
    raw_config: &RwLock<meow_config::raw::RawConfig>,
    startup_tun: &meow_config::TunConfig,
    tun_handle: meow_tunnel::TunHandle,
) {
    let _mutation = meow_api::routes::CONFIG_MUTATION.lock().await;
    let still_current = {
        let committed = raw_config.read();
        committed.tun.as_ref().is_some_and(|t| t.enable)
            && meow_config::parse_tun_config(committed.tun.as_ref(), committed.max_connections)
                .is_ok_and(|c| c == *startup_tun)
    };
    if !still_current {
        warn!(
            "TUN startup finished after the committed config \
             moved on — tearing down the stale device"
        );
        tunnel.teardown_tun_handle(tun_handle).await;
        return;
    }
    if tun_handle.task.is_finished() {
        // The listener sent `Ready` then died before we could publish it
        // (pump/device failure post-ready, or a long lane wait). Storing
        // it would commit `enable: true` over a dead handle and the next
        // same-config PUT would early-return on the unchanged diff —
        // treat it exactly like a startup failure.
        warn!("TUN listener reported ready then exited before its handle was stored");
        tunnel.teardown_tun_handle(tun_handle).await;
        rollback_committed_enable(tunnel, raw_config);
        return;
    }
    tunnel.set_tun_handle(tun_handle).await;
}

#[cfg(test)]
mod tests {
    use super::bind_socket_addr;
    #[cfg(target_os = "windows")]
    use super::{run_application, Args, LogTarget, ShutdownSignal};
    #[cfg(target_os = "windows")]
    use clap::Parser;

    #[test]
    fn ipv4_bind_address() {
        let a = bind_socket_addr("0.0.0.0", 7890).unwrap();
        assert_eq!(a.to_string(), "0.0.0.0:7890");
        assert!(a.is_ipv4());
    }

    #[test]
    fn ipv6_unspecified_bind_address_is_dual_stack() {
        // Regression: format!("{}:{}", "::", port) yields the unparseable
        // ":::7890". SocketAddr::new must bracket it correctly so that
        // `bind-address: '::'` actually binds (and on Linux accepts both
        // IPv4 and IPv6 LAN clients).
        let a = bind_socket_addr("::", 7890).unwrap();
        assert_eq!(a.to_string(), "[::]:7890");
        assert!(a.is_ipv6());
    }

    #[test]
    fn specific_ipv6_bind_address() {
        let a = bind_socket_addr("2408:820c:8f4b:9b41::1001", 9090).unwrap();
        assert_eq!(a.to_string(), "[2408:820c:8f4b:9b41::1001]:9090");
    }

    #[test]
    fn invalid_bind_address_errors() {
        assert!(bind_socket_addr("not-an-ip", 80).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn service_startup_error_is_flushed_before_ready() {
        use std::ffi::OsString;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("meow");
        let log_dir = temp.path().join("logs");
        let mmdb_path = temp.path().join("Country.mmdb");
        let config_path = temp.path().join("test.yaml");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(&mmdb_path, b"not a maxmind database").unwrap();
        let yaml_mmdb_path = mmdb_path.to_string_lossy().replace('\\', "/");
        std::fs::write(
            &config_path,
            format!(
                "mixed-port: 17890\nmode: rule\ngeodata:\n  mmdb-path: '{yaml_mmdb_path}'\nrules:\n  - GEOIP,CN,DIRECT\n"
            ),
        )
        .unwrap();

        let args = Args::try_parse_from(vec![
            OsString::from("meow"),
            OsString::from("-f"),
            config_path.as_os_str().to_os_string(),
            OsString::from("-d"),
            home.as_os_str().to_os_string(),
        ])
        .unwrap();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let ready = Arc::new(AtomicBool::new(false));
        let ready_flag = Arc::clone(&ready);

        let result = run_application(
            args,
            &LogTarget::WindowsService(log_dir.clone()),
            ShutdownSignal::WindowsService(shutdown_rx),
            Some(Box::new(move || {
                ready_flag.store(true, Ordering::Release);
                Ok(())
            })),
        );
        assert!(result.is_err());
        assert!(!ready.load(Ordering::Acquire));

        let log_path = std::fs::read_dir(&log_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|ext| ext == "log"))
            .expect("service log file");
        let log = std::fs::read_to_string(log_path).unwrap();
        assert!(log.contains("meow-rs stopped with an error"), "{log}");
        assert!(log.contains("Failed to load GeoIP database"), "{log}");
        assert!(log.contains("GEOIP,CN,DIRECT"), "{log}");
    }

    /// #625: initial TUN startup vs. `PUT /configs` — the Ready arm must
    /// only publish while the committed config still wants this exact
    /// generation, and startup failures must roll back committed
    /// `tun.enable`.
    #[cfg(feature = "listener-tun")]
    mod tun_startup {
        use crate::{publish_tun_if_committed, rollback_tun_enable};
        use meow_common::DnsMode;
        use meow_config::raw::RawConfig;
        use meow_dns::Resolver;
        use meow_trie::DomainTrie;
        use meow_tunnel::{TunHandle, Tunnel};
        use parking_lot::RwLock;
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;

        fn test_tunnel() -> Tunnel {
            Tunnel::new(Arc::new(Resolver::new(
                vec!["8.8.8.8:53".parse().unwrap()],
                vec![],
                DnsMode::Normal,
                DomainTrie::new(),
                true,
                true,
            )))
        }

        fn raw_with_tun(yaml: &str) -> Arc<RwLock<RawConfig>> {
            let raw: RawConfig = serde_yaml::from_str(yaml).unwrap();
            Arc::new(RwLock::new(raw))
        }

        fn startup_tun(raw: &RwLock<RawConfig>) -> meow_config::TunConfig {
            let guard = raw.read();
            meow_config::parse_tun_config(guard.tun.as_ref(), guard.max_connections).unwrap()
        }

        /// A pending listener task plus a drop signal proving teardown.
        fn pending_handle() -> (TunHandle, tokio::sync::oneshot::Receiver<()>) {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let handle = TunHandle {
                task: tokio::spawn(async move {
                    let _tx = tx;
                    std::future::pending::<()>().await;
                }),
                core_done: None,
                udp_flows: Arc::new(AtomicUsize::new(0)),
            };
            (handle, rx)
        }

        #[tokio::test]
        async fn publishes_when_committed_config_is_unchanged() {
            let tunnel = test_tunnel();
            let raw = raw_with_tun("tun:\n  enable: true\n  mtu: 1500\n");
            let startup = startup_tun(&raw);
            let (handle, _drop_rx) = pending_handle();

            publish_tun_if_committed(&tunnel, &raw, &startup, handle).await;
            assert!(tunnel.has_tun(), "matching committed config → stored");

            tunnel.stop_tun().await;
        }

        #[tokio::test]
        async fn tears_down_when_committed_disabled_tun() {
            let tunnel = test_tunnel();
            // The PUT committed `enable: false` while startup was pending.
            let raw = raw_with_tun("tun:\n  enable: false\n");
            let startup = meow_config::TunConfig {
                enable: true,
                ..meow_config::TunConfig::default()
            };
            let (handle, mut drop_rx) = pending_handle();

            publish_tun_if_committed(&tunnel, &raw, &startup, handle).await;
            // Assert !has_tun first — under a regression to unconditional
            // store this fails instead of hanging on the channel.
            assert!(!tunnel.has_tun(), "stale generation must not publish");
            // Teardown awaited the task → its drop guard already fired.
            assert!(
                matches!(
                    drop_rx.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Closed)
                ),
                "stale task was aborted"
            );
        }

        #[tokio::test]
        async fn tears_down_when_committed_tun_changed() {
            let tunnel = test_tunnel();
            // The PUT committed a different `tun:` section and installed
            // its own generation — the stale startup handle must die
            // without evicting the stored successor.
            let raw = raw_with_tun("tun:\n  enable: true\n  mtu: 9000\n");
            let (successor, mut keep_rx) = pending_handle();
            tunnel.set_tun_handle(successor).await;

            let startup = meow_config::TunConfig {
                enable: true,
                mtu: 1500,
                ..meow_config::TunConfig::default()
            };
            let (stale, _stale_rx) = pending_handle();

            publish_tun_if_committed(&tunnel, &raw, &startup, stale).await;
            assert!(
                tunnel.has_tun(),
                "successor installed by the PUT must survive"
            );
            // The successor's task must still own its drop guard —
            // `Empty` (alive, unsent) proves it wasn't aborted; under the
            // old unconditional-store path the stale handle would have
            // replaced and killed it (`Closed`).
            assert!(
                matches!(
                    keep_rx.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                ),
                "stored successor must not be torn down"
            );

            tunnel.stop_tun().await;
        }

        #[tokio::test]
        async fn tears_down_when_tun_section_removed() {
            let tunnel = test_tunnel();
            // Committed config dropped the `tun:` key entirely.
            let raw = raw_with_tun("mixed-port: 7890\n");
            let startup = meow_config::TunConfig::default();
            let (handle, _rx) = pending_handle();

            publish_tun_if_committed(&tunnel, &raw, &startup, handle).await;
            assert!(!tunnel.has_tun());
        }

        #[tokio::test]
        async fn startup_failure_rolls_back_committed_enable() {
            let tunnel = test_tunnel();
            let raw = raw_with_tun("tun:\n  enable: true\n  mtu: 1500\n");
            rollback_tun_enable(&tunnel, &raw).await;
            assert!(!raw.read().tun.as_ref().unwrap().enable);
        }

        #[tokio::test]
        async fn rollback_is_noop_without_tun_section() {
            let tunnel = test_tunnel();
            let raw = raw_with_tun("mixed-port: 7890\n");
            rollback_tun_enable(&tunnel, &raw).await;
            assert!(raw.read().tun.is_none());
        }

        /// #625 mirror: a sibling PUT that installed its own listener
        /// during our bring-up owns the committed config — our startup
        /// failure must not flip its `enable` off under a live device.
        #[tokio::test]
        async fn rollback_skipped_while_sibling_listener_is_live() {
            let tunnel = test_tunnel();
            let raw = raw_with_tun("tun:\n  enable: true\n  mtu: 9000\n");
            let (successor, _keep) = pending_handle();
            tunnel.set_tun_handle(successor).await;

            rollback_tun_enable(&tunnel, &raw).await;
            assert!(
                raw.read().tun.as_ref().unwrap().enable,
                "sibling-owned committed config must not be clobbered"
            );
            assert!(tunnel.has_tun());

            tunnel.stop_tun().await;
        }

        /// A handle whose task already exited — the listener sent Ready
        /// then died before publish could store it.
        fn finished_handle() -> TunHandle {
            TunHandle {
                task: tokio::spawn(async {}),
                core_done: None,
                udp_flows: Arc::new(AtomicUsize::new(0)),
            }
        }

        /// Storing a dead handle would commit `enable: true` over nothing
        /// running and stick (a same-config PUT early-returns) — treat it
        /// as a startup failure instead.
        #[tokio::test]
        async fn dead_ready_handle_rolls_back_instead_of_storing() {
            let tunnel = test_tunnel();
            let raw = raw_with_tun("tun:\n  enable: true\n  mtu: 1500\n");
            let startup = startup_tun(&raw);

            // Let the task actually reap before publish observes it.
            let handle = finished_handle();
            for _ in 0..100 {
                if handle.task.is_finished() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert!(handle.task.is_finished());

            publish_tun_if_committed(&tunnel, &raw, &startup, handle).await;
            assert!(!tunnel.has_tun(), "dead handle must not be stored");
            assert!(
                !raw.read().tun.as_ref().unwrap().enable,
                "dead-before-publish is a startup failure → rolled back"
            );
        }

        /// Dead gen-A + live sibling B (a same-config PUT that respawned):
        /// A must not evict B, and rollback must skip B's committed
        /// enable.
        #[tokio::test]
        async fn dead_ready_handle_preserves_live_sibling() {
            let tunnel = test_tunnel();
            let raw = raw_with_tun("tun:\n  enable: true\n  mtu: 1500\n");
            let startup = startup_tun(&raw);
            let (successor, mut keep_rx) = pending_handle();
            tunnel.set_tun_handle(successor).await;

            let stale = finished_handle();
            for _ in 0..100 {
                if stale.task.is_finished() {
                    break;
                }
                tokio::task::yield_now().await;
            }

            publish_tun_if_committed(&tunnel, &raw, &startup, stale).await;
            assert!(tunnel.has_tun(), "live sibling must survive");
            assert!(
                matches!(
                    keep_rx.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                ),
                "sibling task still owns its guard"
            );
            assert!(
                raw.read().tun.as_ref().unwrap().enable,
                "sibling's committed enable stays true"
            );

            tunnel.stop_tun().await;
        }
    }
}
