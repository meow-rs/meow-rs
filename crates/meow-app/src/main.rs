// dhat heap profiling — only active when compiled with --features dhat-heap.
// The profiler writes dh_out.json on process exit; parse with dhat-viewer.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// mimalloc global allocator — always on for musl targets (where the stock
// allocator retains freed pages under periodic churn — health probes,
// provider rebuilds — and RSS ratchets upward over long uptimes); opt-in
// elsewhere via --features alloc-mimalloc. The cfg mirrors the split
// target-gated deps in Cargo.toml: musl carries the dep unconditionally,
// other linux/android targets only under the feature (RFC 2957 — the
// feature alone never activates an inactive platform dep).
#[cfg(all(
    not(feature = "dhat-heap"),
    any(target_os = "linux", target_os = "android"),
    any(feature = "alloc-mimalloc", target_env = "musl")
))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::Context as _;
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
#[cfg(feature = "listener-wireguard")]
use meow_listener::WireGuardListener;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};

mod ntp;
#[cfg(target_os = "windows")]
mod windows_service;

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "meow";

#[derive(Parser)]
#[command(name = "meow", version = env!("MEOW_VERSION"), about = "A rule-based tunnel in Rust")]
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

    /// Read the REST API secret from a single-line file
    #[arg(long = "secret-file", conflicts_with = "secret")]
    secret_file: Option<PathBuf>,

    /// Set post-up script
    #[arg(long = "post-up")]
    post_up: Option<String>,

    /// Set post-down script
    #[arg(long = "post-down")]
    post_down: Option<String>,

    /// Specify age secret key to decrypt configuration
    #[arg(long = "age-secret-key")]
    age_secret_key: Option<String>,

    /// Disable executable SIP003 plugins (built-in plugins remain available)
    #[arg(long)]
    no_external_plugins: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Send one unicast ARP reply to a selected LAN client (Linux only)
    #[cfg(target_os = "linux")]
    ArpReply {
        interface: String,
        sender: std::net::Ipv4Addr,
        target_mac: String,
        target_ip: std::net::Ipv4Addr,
    },
    /// Install as a system service
    Install {
        /// Config file path for the service
        #[arg(short = 'f', long = "config")]
        config: Option<String>,
    },
    /// Convert a rule-set file, as mihomo's `convert-ruleset`: an upstream
    /// `.mrs` (`domain` or `ipcidr`) to text, one entry per line — e.g. for
    /// inspecting the `.mrs` rule-providers OpenWrt frontends ship.
    ConvertRuleset {
        /// `domain` or `ipcidr`
        behavior: String,
        /// Source format; only `mrs` is read
        format: String,
        source: std::path::PathBuf,
        /// Output file (default: the source path with `.txt`)
        target: Option<std::path::PathBuf>,
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
    /// Wait for the stop request; names what asked.
    async fn wait(self) -> Result<&'static str> {
        match self {
            Self::Console => {
                #[cfg(unix)]
                {
                    let mut sigterm =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => Ok("SIGINT"),
                        _ = sigterm.recv() => Ok("SIGTERM"),
                    }
                }
                #[cfg(not(unix))]
                {
                    tokio::signal::ctrl_c().await?;
                    Ok("Ctrl-C")
                }
            }
            #[cfg(target_os = "windows")]
            Self::WindowsService(receiver) => receiver
                .await
                .map(|()| "service stop")
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
    if std::env::args_os().any(|a| a == "-v") {
        println!("Meow Meta {}", env!("MEOW_VERSION"));
        return Ok(());
    }

    let args = Args::parse();
    meow_config::set_external_plugins_allowed(!args.no_external_plugins);

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
    // `--ext-ctl-{tls,unix,pipe}` map onto the `external-controller-*`
    // overrides applied after config load (issue #974).

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
        return handle_subcommand(cmd, &args);
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
            let filter = env_filter();
            let log_level = log_max_level(&filter);
            let (filter_layer, reload_handle) = tracing_subscriber::reload::Layer::new(filter);
            tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_filter(filter_layer))
                .with(log_layer)
                .init();
            log::set_max_level(log_level);
            meow_api::log_stream::install_log_reloader(move |level| {
                let filter = tracing_subscriber::EnvFilter::new(normalize_level(level));
                let log_level = log_max_level(&filter);
                reload_handle.reload(filter).map_err(|e| e.to_string())?;
                log::set_max_level(log_level);
                Ok(())
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
            let filter = env_filter();
            let log_level = log_max_level(&filter);
            let (filter_layer, reload_handle) = tracing_subscriber::reload::Layer::new(filter);
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(writer)
                        .with_ansi(false)
                        .with_filter(filter_layer),
                )
                .with(log_layer)
                .init();
            log::set_max_level(log_level);
            meow_api::log_stream::install_log_reloader(move |level| {
                let filter = tracing_subscriber::EnvFilter::new(normalize_level(level));
                let log_level = log_max_level(&filter);
                reload_handle.reload(filter).map_err(|e| e.to_string())?;
                log::set_max_level(log_level);
                Ok(())
            });
            Ok(Logging {
                tx,
                _file_guard: Some(guard),
            })
        }
    }
}

/// The `log` facade's max level under a console filter: DEBUG, or TRACE when
/// the filter asks for it (RUST_LOG). `init()` leaves it at the subscriber's
/// max level, which the broadcast layer's TRACE filter pins at TRACE, so every
/// `log` record crossed into tracing only to be dropped there. quiche writes
/// one per QUIC packet and frame, an eighth of a hysteria2 download's CPU. The
/// DEBUG floor keeps `log` debug records for GET /logs?level=debug.
fn log_max_level(filter: &tracing_subscriber::EnvFilter) -> log::LevelFilter {
    use tracing_subscriber::filter::LevelFilter;
    if filter
        .max_level_hint()
        .is_none_or(|level| level == LevelFilter::TRACE)
    {
        log::LevelFilter::Trace
    } else {
        log::LevelFilter::Debug
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
        meow_common::logbook::engine_stopped(meow_common::logbook::Stop::Failed(&format!(
            "{error:#}"
        )));
        // The ledger opened at startup; a run that failed later still
        // writes out what it counted and lets the directory go.
        meow_common::traffic_ledger::uninstall();
    }
    drop(logging);
    result
}

// The "remedy" tail shared by the failure warnings below.
#[cfg(unix)]
const NOFILE_REMEDY: &str =
    "raise via ulimit -n / launchd SoftResourceLimits / systemd LimitNOFILE";

/// Raise this process's `RLIMIT_NOFILE` soft limit toward the hard
/// limit. Deployment vectors that already ship a large limit (systemd
/// `LimitNOFILE`, OpenWrt procd, meow-bench's own raise) make the bare
/// launchd/shell default of 256 the odd one out — do it in-process so
/// every launch path benefits. Never fatal: a denied or clamped raise
/// only warns.
#[cfg(unix)]
fn raise_nofile_limit() {
    // Deliberately conservative vs. the 1M shipped in the systemd/procd
    // vectors: 64K covers ~32K proxied conns (128× the default listener
    // cap) while keeping fd-leak runway bounded in bare shell/launchd
    // runs — and matches the plist + meow-bench values.
    const TARGET: libc::rlim_t = 65_536;
    /// Final limits below this warn no matter which branch produced
    /// them — a low *hard* ceiling is as real as a kernel clamp.
    const COMFORTABLE: libc::rlim_t = 4096;
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            warn!(
                "getrlimit(RLIMIT_NOFILE) failed ({}) — conn-heavy traffic may hit the inherited cap; {NOFILE_REMEDY}",
                std::io::Error::last_os_error()
            );
            return;
        }
        let target = lim.rlim_max.min(TARGET);
        if lim.rlim_cur >= target {
            if lim.rlim_cur < COMFORTABLE {
                warn!(
                    "RLIMIT_NOFILE capped at {} by the hard limit — conn-heavy traffic may hit the cap; {NOFILE_REMEDY}",
                    lim.rlim_cur
                );
            } else {
                tracing::debug!(
                    soft = lim.rlim_cur,
                    "RLIMIT_NOFILE soft limit already sufficient"
                );
            }
            return;
        }
        let previous = lim.rlim_cur;
        lim.rlim_cur = target;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
            warn!(
                "setrlimit(RLIMIT_NOFILE, {target}) failed ({}) — conn-heavy traffic may hit the low cap; {NOFILE_REMEDY}",
                std::io::Error::last_os_error()
            );
            return;
        }
        // XNU can *silently clamp* rlim_cur to kern.maxfilesperproc and
        // still return success — re-read to confirm the raise landed.
        let mut after = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut after) != 0 {
            tracing::debug!(
                "getrlimit(RLIMIT_NOFILE) re-check failed ({})",
                std::io::Error::last_os_error()
            );
        } else if after.rlim_cur < COMFORTABLE {
            warn!(
                "RLIMIT_NOFILE only reached {} (wanted {target}, hard {}) — conn-heavy traffic may hit the low cap; {NOFILE_REMEDY}",
                after.rlim_cur, lim.rlim_max
            );
        } else if after.rlim_cur < target {
            info!(
                "RLIMIT_NOFILE clamped to {} by the OS ceiling (wanted {target}) — still comfortably above the default 256",
                after.rlim_cur
            );
        } else {
            info!(
                "raised RLIMIT_NOFILE soft limit {previous} → {}",
                after.rlim_cur
            );
        }
    }
}

fn run_application_inner(
    args: Args,
    log_tx: tokio::sync::broadcast::Sender<meow_api::log_stream::LogMessage>,
    shutdown: ShutdownSignal,
    on_ready: Option<ReadyCallback>,
) -> Result<()> {
    info!("meow-rs starting...");

    let file_secret = args
        .secret_file
        .as_deref()
        .map(read_api_secret)
        .transpose()?;

    // Raise RLIMIT_NOFILE before the runtime and any listener come up —
    // every proxied conn costs two fds (inbound + outbound), and the
    // macOS/launchd default of 256 EMFILEs at ~120 live conns while the
    // default 256-conn listener cap never binds (issue #670).
    #[cfg(unix)]
    raise_nofile_limit();

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
        // Offline: a config *test* checks structure, so it must not block on a
        // slow or unreachable subscription fetch (which also lets LuCI's
        // pre-save `meow -t` finish inside rpcd's exec timeout).
        meow_config::set_offline_validate(true);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            // Same source as the run path: `-t --config-string` must
            // validate the string, not the file (issue #711).
            let config = if let Some(ref cs) = args.config_string {
                let raw = parse_config_string(cs)?;
                meow_config::build_config(raw, None)
                    .await
                    .map_err(|e| anyhow::anyhow!("--config-string: {e}"))?
            } else {
                load_config(&config_path).await?
            };
            // An inbound this build did not compile would be
            // warn-skipped at startup — that must not pass a config test.
            ensure_inbounds_supported(&config)?;
            #[cfg(feature = "listener-vless")]
            ensure_vless_security_valid(&config)?;
            if args.config_string.is_some() {
                info!("Configuration test passed (--config-string)");
            } else {
                info!("Configuration test passed");
            }
            Ok::<(), anyhow::Error>(())
        })?;
        return Ok(());
    }

    // Run the async runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let early_binding: EarlyOutboundBinding;
        // --config-string replaces the config file as the source (mihomo
        // behavior); the flag overrides below apply on top of either source.
        //
        // Parse first and build second: the build is where startup network
        // I/O begins (ECH pre-resolution, provider / geodata fetches), and a
        // `tun.auto-route: global` config needs its outbound-interface
        // binding in place before the first of those sockets exists
        // (issue #695) — see `preinstall_global_route_binding`.
        let raw = if let Some(ref cs) = args.config_string {
            parse_config_string(cs)?
        } else {
            meow_config::load_raw_config(&config_path).await?
        };

        // `log-level:` is the deployment's stated level — apply it to the
        // reloadable filter before build_config so parse/provider warnings
        // are already at the configured level, matching mihomo's
        // parseGeneral → SetLogLevel ordering (issue #729: the field was
        // parsed but never applied, so a configured `debug` silently ran
        // at `info` until a PATCH). An explicit `RUST_LOG` wins: env is
        // the operator override, config is the baseline.
        if std::env::var_os("RUST_LOG").is_none() {
            let level = raw.log_level.as_deref().unwrap_or("info");
            // Whitelist before reload: an invalid string would reach
            // EnvFilter as a `target=TRACE` directive and silence all
            // logging instead of erroring (same set PATCH enforces).
            if meow_api::log_stream::is_valid_log_level(level) {
                if let Err(e) = meow_api::log_stream::reload_log_level(level) {
                    warn!("failed to apply log-level '{level}': {e}");
                }
            } else {
                warn!(
                    "unknown log-level '{level}' — keeping current filter \
                     (expected one of: debug, info, warning, warn, error, silent)"
                );
            }
        }

        // The logbook opens once the config says whether it is wanted, so
        // the startup's own events (a provider that fails to load) are
        // recorded; the run is marked started once it is up.
        meow_common::logbook::apply(meow_config::raw::RawLogbook::enabled(raw.logbook.as_ref()));
        meow_common::traffic_ledger::apply(
            meow_config::raw::RawTrafficLedger::enabled(raw.traffic_ledger.as_ref()),
            meow_config::raw::RawTrafficLedger::options(raw.traffic_ledger.as_ref()),
        );

        // mihomo's `routing-mark` marks every outbound socket, from the first
        // provider fetch on (the deployer's rules exempt it).
        meow_common::set_routing_mark(raw.routing_mark);
        // mihomo's `interface-name` (issue #974) binds every outbound
        // socket likewise — installed before the build so the first
        // provider fetch already takes it. A node's own `interface-name`
        // and the loopback exemption outrank it inside the dial scope;
        // `None`/empty clears.
        meow_common::set_global_interface_name(raw.interface_name.as_deref());
        // `global-ua` (issue #974) — same process-wide shape as
        // `interface-name`/`routing-mark`: validate and install before the
        // build's first provider/geodata fetch emits a `User-Agent`.
        // `build_config` re-asserts it ahead of those fetches.
        meow_common::set_global_ua(meow_config::validate_global_ua(raw.global_ua.as_deref())?);
        // `tcp-concurrent` — live dial policy on the same process-global
        // lane: installed before the build's first provider fetch dials,
        // so those candidates already honor it. `-t` validation never
        // reaches here; PUT/PATCH re-assert at their commit points.
        meow_common::dial::set_tcp_concurrent(meow_config::effective_tcp_concurrent(
            raw.tcp_concurrent,
        ));
        // `keep-alive-*` — the outbound-dial keepalive policy, same
        // lane and same ordering rationale: `connect_tcp` snapshots it
        // per dial, so it must be installed before the build's first
        // provider/geodata fetch opens a socket. `-t` never reaches here;
        // PUT/PATCH re-assert at their commit points.
        meow_common::set_outbound_tcp_keepalive(meow_config::resolve_outbound_tcp_keepalive(&raw)?);

        let mut config = if args.config_string.is_some() {
            early_binding = preinstall_global_route_binding(&raw);
            let config = meow_config::build_config(raw, None)
                .await
                .map_err(|e| anyhow::anyhow!("--config-string: {e}"))?;
            info!("Config loaded from --config-string");
            config
        } else {
            early_binding = preinstall_global_route_binding(&raw);
            let cache_dir = meow_config::resource_cache_dir_for_config_path(&config_path);
            let config = meow_config::build_config(raw, Some(cache_dir.as_path())).await?;
            info!("Config loaded from {}", config_path);
            config
        };

        // Global like mihomo's: every delay probe (API, groups, providers).
        // Set once the config built; PUT /configs re-applies it on commit.
        meow_proxy::health::set_unified_delay(config.raw.unified_delay.unwrap_or(false));

        // Apply CLI overrides to the loaded config.
        if let Some(secret) = file_secret {
            config.api.secret = Some(secret);
            info!("API secret overridden by --secret-file");
        } else if let Some(secret) = args.secret {
            config.api.secret = Some(secret);
            info!("API secret overridden by --secret");
        }
        if let Some(ref ctl) = args.ext_ctl {
            let addr: std::net::SocketAddr = ctl
                .parse()
                .map_err(|e| anyhow::anyhow!("--ext-ctl: invalid address '{ctl}': {e}"))?;
            config.api.external_controller = Some(addr);
            info!("External controller overridden by --ext-ctl: {addr}");
        }
        apply_ext_controller_overrides(
            args.ext_ctl_tls.as_deref(),
            args.ext_ctl_unix.as_deref(),
            args.ext_ctl_pipe.as_deref(),
            &mut config.api,
        );
        if let Some(ref ui) = args.ext_ui {
            config.api.external_ui = Some(std::path::PathBuf::from(ui));
            info!("External UI overridden by --ext-ui");
        }

        // A declared inbound this build cannot serve must fail startup,
        // not warn-and-skip: the port would never listen (silent inbound
        // outage). Unknown type names are already fatal at parse.
        ensure_inbounds_supported(&config)?;
        // The `PUT /configs` persistence gate checks the same feature set.
        meow_api::set_listener_gate(listener_feature_gate);

        run(
            config,
            // A --config-string run has no backing file: persist paths
            // (PUT/save, subscription write-back) must not invent one
            // (issue #717).
            args.config_string.is_none().then_some(config_path),
            log_tx,
            shutdown,
            on_ready,
            early_binding,
        )
        .await
    })
}

fn read_api_secret(path: &Path) -> Result<String> {
    let mut secret = std::fs::read_to_string(path)
        .with_context(|| format!("--secret-file: could not read {}", path.display()))?;
    let line = secret
        .strip_suffix("\r\n")
        .or_else(|| secret.strip_suffix('\n'))
        .unwrap_or(&secret);
    if line.is_empty() || line.ends_with(' ') || !line.bytes().all(|b| matches!(b, b' '..=b'~')) {
        anyhow::bail!(
            "--secret-file: expected a nonempty line of printable ASCII without trailing spaces"
        );
    }
    secret.truncate(line.len());
    Ok(secret)
}

/// The extended controller flags (`--ext-ctl-tls` / `-unix` / `-pipe`)
/// override the matching raw keys verbatim (issue #974): strings,
/// resolved at endpoint bind like the config values they replace. Like
/// upstream, an *empty* override is not applied — `--ext-ctl-tls ''`
/// must not erase a YAML endpoint.
fn apply_ext_controller_overrides(
    ext_ctl_tls: Option<&str>,
    ext_ctl_unix: Option<&str>,
    ext_ctl_pipe: Option<&str>,
    api: &mut meow_config::ApiConfig,
) {
    if let Some(ctl) = ext_ctl_tls.filter(|s| !s.is_empty()) {
        api.external_controller_tls = Some(ctl.to_owned());
        info!("External controller TLS overridden by --ext-ctl-tls: {ctl}");
    }
    if let Some(ctl) = ext_ctl_unix.filter(|s| !s.is_empty()) {
        api.external_controller_unix = Some(ctl.to_owned());
        info!("External controller unix socket overridden by --ext-ctl-unix: {ctl}");
    }
    if let Some(ctl) = ext_ctl_pipe.filter(|s| !s.is_empty()) {
        api.external_controller_pipe = Some(ctl.to_owned());
        info!("External controller pipe overridden by --ext-ctl-pipe: {ctl}");
    }
}

/// Whether this binary can actually serve one of the configured
/// controller endpoints. `ApiConfig::has_servable_endpoint` reports the
/// *configured* set; `external-controller-tls` additionally needs the
/// `api-tls` build feature (`minimal` compiles the endpoint out,
/// ADR-0007), so a TLS-only config on a TLS-less build is headless and
/// must not spawn an API server that binds nothing (issue #974).
fn api_endpoint_servable(api: &meow_config::ApiConfig) -> bool {
    api.external_controller.is_some()
        || (cfg!(feature = "api-tls") && api.external_controller_tls.is_some())
        || (cfg!(unix) && api.external_controller_unix.is_some())
        || (cfg!(windows) && api.external_controller_pipe.is_some())
}

/// Owner of the outbound-interface binding installed ahead of the config
/// build (see [`preinstall_global_route_binding`]); handed to the TUN
/// listener, which keeps it for as long as its routes exist.
#[cfg(feature = "listener-tun")]
type EarlyOutboundBinding = Option<meow_listener::OutboundBinding>;
#[cfg(not(feature = "listener-tun"))]
type EarlyOutboundBinding = Option<std::convert::Infallible>;

/// Install the `tun.auto-route: global` outbound-interface binding before
/// anything dials (issue #695).
///
/// The binding is per-socket and applied at creation, so any socket opened
/// before it exists stays unbound for life: the config build's provider /
/// geodata / ECH fetches, provider and subscription refreshes, health-check
/// probes and DNS upstreams all run before the TUN listener comes up, and a
/// session they leave open (QUIC, mux, pooled DNS TCP) re-enters the TUN as
/// soon as the split default routes go in — looping until it times out.
/// Installing here, between parsing the raw document and building it,
/// precedes every one of those sockets; the TUN listener then adopts the
/// binding instead of installing its own (`TunListener::with_outbound_binding`).
///
/// Shares [`meow_api::preinstall_global_route_binding`] with the config
/// reload paths, so startup and reload agree on when a binding is due: a
/// no-op (`None`) unless the raw config selects an enabled TUN in global
/// route scope — TUN-off and fake-IP-scope startups are untouched.
/// An install failure is not fatal here: the listener retries before it
/// touches any route and fails closed with the same error, exactly as
/// before, and until then no global route exists for a socket to loop on.
#[cfg(feature = "listener-tun")]
fn preinstall_global_route_binding(raw: &meow_config::raw::RawConfig) -> EarlyOutboundBinding {
    meow_api::preinstall_global_route_binding(raw, meow_api::PreinstallScope::Startup)
        .into_binding()
}

#[cfg(not(feature = "listener-tun"))]
fn preinstall_global_route_binding(_raw: &meow_config::raw::RawConfig) -> EarlyOutboundBinding {
    None
}

/// The cargo feature a `listeners:` entry needs when this binary did not
/// compile it — `None` when the entry can run. Mirrors the
/// `#[cfg(feature = …)]` arms in the listener spawn loop below: `mixed`,
/// `http` and `socks5` are all served by `MixedListener` under
/// `listener-mixed`; `listener-http`/`listener-socks5` do not gate named
/// listeners. Installed into [`meow_api::set_listener_gate`] so the
/// `PUT /configs` persistence gate enforces the same contract.
fn listener_feature_gate(spec: &meow_config::ListenerSpec) -> Option<&'static str> {
    use meow_config::ListenerSpec as S;
    // Exhaustive on purpose — no `_` arm: a future ListenerSpec variant
    // must fail compile here, not silently map to "supported".
    match spec {
        S::Mixed | S::Http | S::Socks5 => {
            (!cfg!(feature = "listener-mixed")).then_some("listener-mixed")
        }
        S::TProxy { .. } => (!cfg!(feature = "listener-tproxy")).then_some("listener-tproxy"),
        S::Shadowsocks(_) => {
            (!cfg!(feature = "listener-shadowsocks")).then_some("listener-shadowsocks")
        }
        S::WireGuard(_) => (!cfg!(feature = "listener-wireguard")).then_some("listener-wireguard"),
        S::Tun(_) => (!cfg!(feature = "listener-tun")).then_some("listener-tun"),
        S::Anytls(_) => (!cfg!(feature = "listener-anytls")).then_some("listener-anytls"),
        S::Vless(_) => (!cfg!(feature = "listener-vless")).then_some("listener-vless"),
    }
}

/// All declared inbounds (`listeners:` and the top-level `tun:` section)
/// must be servable by this build — `meow -t` and startup share the check
/// so a config that can never listen fails identically on both paths.
fn ensure_inbounds_supported(config: &meow_config::Config) -> anyhow::Result<()> {
    meow_api::ensure_listeners_supported(&config.listeners.named, listener_feature_gate)?;
    if let Some(feature) = tun_feature_gate(config.tun.enable) {
        anyhow::bail!(
            "tun.enable is set but this build lacks the '{feature}' feature — \
             rebuild with it or set tun.enable: false"
        );
    }
    Ok(())
}

#[cfg(feature = "listener-vless")]
fn vless_security_spec(security: &meow_config::VlessSecurity) -> meow_listener::VlessSecuritySpec {
    match security {
        meow_config::VlessSecurity::StandardTls {
            certificate,
            private_key,
            alpn,
        } => meow_listener::VlessSecuritySpec::StandardTls {
            certificate: certificate.clone(),
            private_key: private_key.clone(),
            alpn: alpn.clone(),
        },
        meow_config::VlessSecurity::Reality(reality) => {
            meow_listener::VlessSecuritySpec::Reality(meow_listener::VlessRealitySpec {
                dest_host: reality.dest_host.clone(),
                dest_port: reality.dest_port,
                private_key: reality.private_key,
                short_ids: reality.short_ids.clone(),
                server_names: reality.server_names.clone(),
                max_time_difference_us: reality.max_time_difference_us,
                limit_fallback_upload: meow_listener::VlessFallbackLimit {
                    after_bytes: reality.limit_fallback_upload.after_bytes,
                    bytes_per_sec: reality.limit_fallback_upload.bytes_per_sec,
                    burst_bytes_per_sec: reality.limit_fallback_upload.burst_bytes_per_sec,
                },
                limit_fallback_download: meow_listener::VlessFallbackLimit {
                    after_bytes: reality.limit_fallback_download.after_bytes,
                    bytes_per_sec: reality.limit_fallback_download.bytes_per_sec,
                    burst_bytes_per_sec: reality.limit_fallback_download.burst_bytes_per_sec,
                },
                mimic: reality.mimic,
            })
        }
    }
}

/// `meow -t` shares startup's eager VLESS security validation. Unlike the
/// rest of config validation this deliberately reads referenced PEM files:
/// a certificate pair is runtime material whose syntax and key match cannot
/// be checked from the YAML shape alone. It still binds nothing, resolves no
/// cover target, and makes no network connection.
#[cfg(feature = "listener-vless")]
fn ensure_vless_security_valid(config: &meow_config::Config) -> anyhow::Result<()> {
    for nl in &config.listeners.named {
        if let meow_config::ListenerSpec::Vless(cfg) = &nl.spec {
            meow_listener::validate_vless_security_spec(vless_security_spec(&cfg.security))
                .map_err(|e| {
                    anyhow::anyhow!("listener '{}': invalid vless security: {e}", nl.name)
                })?;
        }
    }
    Ok(())
}

/// Decode a `--config-string` argument (base64-encoded YAML — mihomo
/// compat) into the raw config document. Shared by `-t` and the run path
/// so both validate/run the same source (issue #711 — `-t` used to ignore
/// the string and test the file).
fn parse_config_string(cs: &str) -> anyhow::Result<meow_config::raw::RawConfig> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(cs)
        .map_err(|e| anyhow::anyhow!("--config-string: invalid base64: {e}"))?;
    let yaml = String::from_utf8(bytes)
        .map_err(|e| anyhow::anyhow!("--config-string: invalid UTF-8: {e}"))?;
    // Parity with `load_raw_config`: a UTF-8 BOM must not break parsing —
    // libyaml otherwise reports a misleading "more than one document".
    let yaml = yaml.strip_prefix('\u{feff}').unwrap_or(&yaml);
    meow_config::parse_raw_yaml(yaml).map_err(|e| anyhow::anyhow!("--config-string: {e}"))
}

/// `tun:` isn't a `listeners:` entry so [`listener_feature_gate`] can't
/// see it — same contract separately: enabled on a build without the
/// feature is unservable.
fn tun_feature_gate(enable: bool) -> Option<&'static str> {
    (enable && !cfg!(feature = "listener-tun")).then_some("listener-tun")
}

fn handle_subcommand(cmd: &Command, args: &Args) -> Result<()> {
    match cmd {
        #[cfg(target_os = "linux")]
        Command::ArpReply {
            interface,
            sender,
            target_mac,
            target_ip,
        } => meow_app::arp::send(interface, *sender, target_mac, *target_ip),
        Command::Install { config } => {
            if args.config_string.is_some() {
                anyhow::bail!(
                    "--config-string is not supported for `meow install` — a service \
                     unit must point at a file; write the config to a file and pass -f"
                );
            }
            install_service(config.as_deref(), args)
        }
        Command::ConvertRuleset {
            behavior,
            format,
            source,
            target,
        } => convert_ruleset(behavior, format, source, target.as_deref()),
        Command::Uninstall => uninstall_service(),
        Command::Status => service_status(),
        #[cfg(target_os = "windows")]
        Command::RunService => windows_service::dispatch(),
    }
}

/// `meow convert-ruleset <behavior> mrs <source> [<target>]`.
fn convert_ruleset(
    behavior: &str,
    format: &str,
    source: &std::path::Path,
    target: Option<&std::path::Path>,
) -> Result<()> {
    use meow_rules::mrs_parser::{UpstreamRuleSetReader, TYPE_DOMAIN, TYPE_IPCIDR};

    if !format.eq_ignore_ascii_case("mrs") {
        anyhow::bail!("convert-ruleset: only the mrs format is read (got `{format}`)");
    }
    let want = match behavior.to_ascii_lowercase().as_str() {
        "domain" => TYPE_DOMAIN,
        "ipcidr" => TYPE_IPCIDR,
        other => {
            anyhow::bail!("convert-ruleset: behavior must be domain or ipcidr (got `{other}`)")
        }
    };
    let target = target.map_or_else(
        || source.with_extension("txt"),
        std::path::Path::to_path_buf,
    );
    // `Path` equality is lexical: `dir/sub/../set.mrs` or a symlink names the
    // source without comparing equal to it, and the final rename would
    // happily replace it (issue #877 review). Where the spelling exists on
    // disk, dev+ino is checked too — a hard link or a case-insensitive
    // (APFS/NTFS) spelling of the source aliases it without sharing a
    // resolved path.
    let source_resolved = resolved_path(source);
    if resolved_path(&target) == source_resolved || same_file_on_disk(source, &target) {
        anyhow::bail!(
            "convert-ruleset: output {} would overwrite the source; name a target",
            target.display()
        );
    }
    let bytes = std::fs::read(source)
        .with_context(|| format!("convert-ruleset: read {}", source.display()))?;
    let reader = UpstreamRuleSetReader::open(&bytes)
        .with_context(|| format!("convert-ruleset: decode {}", source.display()))?;
    // `reader` owns the decompressed body; the wire bytes are dead weight.
    drop(bytes);
    if reader.behavior() != want {
        anyhow::bail!(
            "convert-ruleset: {} is not a {behavior} rule-set",
            source.display()
        );
    }
    // Decode fully into a sibling scratch and rename over the target, so a
    // corrupt body never leaves a truncated output (or clobbers an old one).
    meow_common::fs_util::sweep_scratch_siblings_excluding(
        &target,
        meow_common::fs_util::SCRATCH_STALE_AGE,
        source,
    );
    // `create_new` refuses to follow or truncate a pre-planted file or
    // symlink at the scratch name — bump the counter and take the next
    // one instead of writing through it.
    let (part, file) = loop {
        let part = convert_scratch_path(&target);
        if resolved_path(&part) == source_resolved || same_file_on_disk(source, &part) {
            anyhow::bail!(
                "convert-ruleset: scratch path {} would overwrite the source; name a different target",
                part.display()
            );
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)
        {
            Ok(file) => break (part, file),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("convert-ruleset: create {}", part.display()));
            }
        }
    };
    let written =
        write_rule_set_text(reader, want == TYPE_DOMAIN, source, file, &part).and_then(|skipped| {
            std::fs::rename(&part, &target)
                .with_context(|| format!("convert-ruleset: rename to {}", target.display()))
                .map(|()| skipped)
        });
    let skipped = match written {
        Ok(skipped) => skipped,
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
    };
    if skipped > 0 {
        eprintln!(
            "warning: convert-ruleset: {}: {skipped} entr{} skipped (stored keys are not valid UTF-8)",
            source.display(),
            if skipped == 1 { "y" } else { "ies" },
        );
    }
    Ok(())
}

/// The path `path` resolves to, for clobber-guard comparisons: `Path`
/// equality is lexical, so `./x`, `d/sub/../x` and symlinked parents all
/// alias the same file. Canonicalize the deepest ancestor that exists
/// (handles `.`/`..` and symlinks) and re-append the not-yet-existing tail;
/// when nothing on the path exists at all, fold `.`/`..` lexically over the
/// absolute path. An over-eager result only trips the guard — the safe
/// direction. Existing-path-only callers can use the lib crate's
/// `meow_app::same_resolved_path` instead (canonicalize-and-compare).
fn resolved_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor = path;
    loop {
        if let Ok(canon) = cursor.canonicalize() {
            let mut resolved = canon;
            for comp in tail.iter().rev() {
                resolved.push(comp);
            }
            return resolved;
        }
        let (Some(parent), Some(name)) = (cursor.parent(), cursor.file_name()) else {
            break;
        };
        tail.push(name.to_os_string());
        cursor = parent;
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
    };
    let mut folded = std::path::PathBuf::new();
    for comp in absolute.components() {
        match comp {
            std::path::Component::CurDir => {}
            // `..` at the root pops nothing — correct for an absolute path.
            std::path::Component::ParentDir => {
                folded.pop();
            }
            _ => folded.push(comp.as_os_str()),
        }
    }
    folded
}

/// Whether two on-disk paths are the same file — catches hard links and
/// case-insensitive (APFS/NTFS) spellings that a canonical-path comparison
/// reports distinct. `false` when either side can't be stat'ed (e.g. a
/// not-yet-created target or scratch), where `resolved_path` still stands.
/// `same-file` owns the dev+ino vs `GetFileInformationByHandle` split —
/// `MetadataExt::{volume_serial_number,file_index}` is still
/// `windows_by_handle`-gated nightly, not stable.
fn same_file_on_disk(a: &std::path::Path, b: &std::path::Path) -> bool {
    same_file::is_same_file(a, b).unwrap_or(false)
}

/// Unique scratch sibling of `target` — the same `{path}.{pid}.{n}.tmp`
/// scheme as `meow_config::unique_scratch_path` (pub(crate), unreachable
/// from this crate) so `meow_common::fs_util::sweep_scratch_siblings`
/// recognises leftovers of a killed run, and a fixed `.part` name can
/// neither alias the source nor be spliced by a concurrent convert.
fn convert_scratch_path(target: &std::path::Path) -> std::path::PathBuf {
    static COUNTER: meow_common::atomic::AtomicU = meow_common::atomic::AtomicU::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut name = target.as_os_str().to_os_string();
    name.push(format!(".{}.{}.tmp", std::process::id(), n));
    std::path::PathBuf::from(name)
}

/// Writes the decoded set, one entry per line. `file` is the scratch
/// already opened `create_new` at `path`; `source` only names decode
/// errors and write errors carry `path`. `reader` is consumed so its
/// decoded body can drop as soon as the (collecting) domain walk
/// finishes. Returns the number of stored domain keys skipped as
/// invalid UTF-8 (0 for `ipcidr`).
fn write_rule_set_text(
    reader: meow_rules::mrs_parser::UpstreamRuleSetReader,
    domains: bool,
    source: &std::path::Path,
    file: std::fs::File,
    path: &std::path::Path,
) -> Result<usize> {
    use std::io::Write;
    let mut out = std::io::BufWriter::new(file);
    let mut io_err = None;
    let mut emit = |s: &dyn std::fmt::Display| {
        if io_err.is_none() {
            if let Err(e) = writeln!(out, "{s}") {
                io_err = Some(e);
            }
        }
    };
    let mut skipped = 0usize;
    if domains {
        // Upstream `domainStrategy.DumpMrs` compacts an exact entry and its
        // suffix-only twin (`x.com` + `.x.com`) into one `+.x.com` line and
        // emits the list sorted — mirror it so the text matches `mihomo
        // convert-ruleset` output. The merge needs every key up front, so
        // unlike the ipcidr walk below this collects first; the io_err
        // side-channel is unneeded until the writes begin.
        let mut keys = Vec::new();
        skipped = reader
            .for_each_domain(|d| keys.push(d.to_string()))
            .with_context(|| format!("convert-ruleset: decode {}", source.display()))?;
        // The decoded body is dead once the keys are collected.
        drop(reader);
        for line in dump_domain_lines(keys) {
            emit(&line);
        }
    } else {
        let walked = reader.for_each_net(|n| emit(&n));
        // The walk drained the decoded body; flush can run without it.
        drop(reader);
        // A failed write is the actionable failure even when the walk then
        // also trips a decode error — the decode keeps draining into emit
        // no-ops meanwhile, so report io_err first.
        if let Some(e) = io_err {
            return Err(e).with_context(|| format!("convert-ruleset: write {}", path.display()));
        }
        walked.with_context(|| format!("convert-ruleset: decode {}", source.display()))?;
    }
    if let Some(e) = io_err {
        return Err(e).with_context(|| format!("convert-ruleset: write {}", path.display()));
    }
    out.flush()
        .with_context(|| format!("convert-ruleset: write {}", path.display()))?;
    Ok(skipped)
}

/// Upstream `domainStrategy.DumpMrs` (`rules/provider/domain_strategy.go`)
/// compaction, tightened to the canonical twin forms: an exact entry `x`
/// and its suffix-only twin `.x` collapse into `+.x`. Upstream merges any
/// pair equal after `TrimPrefix(".")` — which also folds `x`+`x` or
/// `.x`+`.x` (distinct internal keys CAN decode to the same form, e.g.
/// `moc.x.` and `moc.x.+` both yield `.x`) into coverage the set never
/// had — so only `x` followed by `.x` merges, and the merge sort keys on
/// (trimmed, has-dot) for a deterministic bare-first order.
fn dump_domain_lines(mut keys: Vec<String>) -> Vec<String> {
    keys.sort_unstable_by(|a, b| {
        a.strip_prefix('.')
            .unwrap_or(a)
            .cmp(b.strip_prefix('.').unwrap_or(b))
            .then(a.starts_with('.').cmp(&b.starts_with('.')))
    });
    let mut merged = Vec::with_capacity(keys.len());
    let mut i = 0;
    while i < keys.len() {
        if !keys[i].starts_with('.')
            && keys
                .get(i + 1)
                .is_some_and(|next| next.strip_prefix('.') == Some(keys[i].as_str()))
        {
            merged.push(format!("+.{}", keys[i]));
            i += 2;
        } else {
            merged.push(std::mem::take(&mut keys[i]));
            i += 1;
        }
    }
    merged.sort_unstable();
    merged
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

    let unit = meow_app::generate_systemd_unit(&exe_path, &config_path)
        .context("failed to generate systemd unit")?;

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
use meow_app::LAUNCHD_LABEL;

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
    // The agent installs into the calling user's gui/<uid> launchd domain
    // and ~/Library. macOS sudo preserves HOME by default, so a sudo'd
    // install would drop root-owned files into the user's ~/Library
    // (/var/root under `sudo -i`/`-H`) and fail to bootstrap gui/0
    // either way (issue #678).
    if unsafe { libc::geteuid() } == 0 {
        anyhow::bail!(
            "do not run `meow install` via sudo on macOS: the LaunchAgent targets \
             your per-user gui/<uid> domain — run it as your own user"
        );
    }
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

    // Validate + generate the plist before any fs mutation so a rejected
    // path leaves nothing behind (issue #677).
    let dest_config = app_support.join("config.yaml");
    let plist = meow_app::generate_launchd_plist(
        &exe_path,
        &dest_config.display().to_string(),
        &app_support.display().to_string(),
        &log_dir.display().to_string(),
    )
    .context("failed to generate launchd plist")?;

    // Create directories
    std::fs::create_dir_all(&app_support)?;
    std::fs::create_dir_all(&log_dir)?;
    std::fs::create_dir_all(&launch_agents)?;

    // Copy config to ~/Library/Application Support/meow/config.yaml
    std::fs::copy(&src_config, &dest_config)?;
    println!("Config copied to {}", dest_config.display());

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
    // Under `sudo -i`/`-H` HOME resolves to /var/root, where the only files
    // this can touch are debris from a pre-fix `sudo meow install` — allow
    // that cleanup. With HOME preserved (`sudo`, `sudo -E`) the paths would
    // resolve into the real user's ~/Library while `bootout gui/0` no-ops,
    // deleting the plist+config and orphaning the loaded agent. The HOME
    // comparison is canonicalized: a crafted "/var/root/../Users/x" must not
    // pass as root's home (issue #678).
    if unsafe { libc::geteuid() } == 0
        && !std::env::var("HOME").is_ok_and(|home| {
            meow_app::same_resolved_path(
                std::path::Path::new(&home),
                std::path::Path::new("/var/root"),
            )
        })
    {
        anyhow::bail!(
            "do not run `meow uninstall` via sudo on macOS: it targets the \
             calling user's gui/<uid> agent — run it as that user. Root-owned \
             debris left by a previous `sudo meow install` can be removed with \
             `sudo rm` under the affected ~/Library or /var/root/Library"
        );
    }
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
    // gui/0 never hosts the agent, so under sudo this would falsely report
    // "not loaded" (issue #678).
    if unsafe { libc::geteuid() } == 0 {
        anyhow::bail!(
            "do not run `meow status` via sudo on macOS: it queries the calling \
             user's gui/<uid> domain — run it as your own user"
        );
    }
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

/// Bind ALL of one multi-address TCP listener's addresses, then apply its
/// `routing-mark` — atomically: any failure returns the error and the
/// already-bound sockets drop with the `Vec`, so a half-bound group is
/// never left holding ports. `listeners[].routing-mark` applies to every
/// socket this listener binds; a mark failure is a startup failure, not a
/// skip: the group must not half-publish.
#[cfg(any(feature = "listener-anytls", feature = "listener-vless"))]
async fn bind_multi_tcp_sockets(
    name: &str,
    addrs: &[meow_config::ListenerBind],
    routing_mark: Option<u32>,
) -> Result<Vec<tokio::net::TcpListener>> {
    let mut sockets = Vec::with_capacity(addrs.len());
    for a in addrs {
        let addr = bind_socket_addr(&a.listen, a.port).map_err(|e| {
            listener_failed(name, &format!("invalid listen address '{}': {e}", a.listen));
            anyhow::anyhow!(
                "listener '{name}': invalid listen address '{}': {e}",
                a.listen
            )
        })?;
        match tokio::net::TcpListener::bind(addr).await {
            Ok(s) => sockets.push(s),
            Err(e) => {
                listener_failed(name, &format!("bind {addr} failed: {e}"));
                return Err(anyhow::anyhow!(
                    "listener '{name}': bind {addr} failed: {e}"
                ));
            }
        }
    }
    for s in &sockets {
        if !apply_listener_mark(name, s, routing_mark) {
            return Err(anyhow::anyhow!(
                "listener '{name}': routing-mark setup failed"
            ));
        }
    }
    Ok(sockets)
}

async fn run(
    config: meow_config::Config,
    config_path: Option<String>,
    log_tx: tokio::sync::broadcast::Sender<meow_api::log_stream::LogMessage>,
    shutdown: ShutdownSignal,
    on_ready: Option<ReadyCallback>,
    early_binding: EarlyOutboundBinding,
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
    // The config-scoped `profile.store-selected` persistence owner — every
    // rebuild lane (API PUT, subscription/geodata republish) attaches
    // through it so groups share the startup store and enable epoch.
    tunnel.set_selection_backing(Arc::clone(&config.selection));
    // The `ntp:` supervisor holds only a Weak at the tunnel so shutdown's
    // drop order can't strand it; the worker starts after TUN binding
    // settles below, and PUT reconciles it through the API lane
    // (issue #974).
    let ntp_supervisor = Arc::new(ntp::NtpSupervisor::new(&tunnel));
    meow_tunnel::nftset::install(
        &tunnel,
        config
            .raw
            .dns
            .as_ref()
            .and_then(|d| d.nftset.as_ref())
            .and_then(|n| n.parse().ok().flatten()),
    );
    if !api_endpoint_servable(&config.api) {
        // No API can inspect individual connections. Keep cancellation handles
        // for cold reloads without storing their display metadata.
        tunnel.statistics().set_headless();
    }
    // Provider-sourced nodes resolve `dialer-proxy` names against this
    // registry; install before the first `update_routing` so it publishes
    // the initial route map (issue #489).
    tunnel.set_dialer_registry(config.provider_dialer_registry.clone());
    // `type: dns` leaves — static and provider-sourced alike — resolve the
    // live resolver through this cell; `install_resolver_everywhere`
    // republishes the tunnel's slot into it on every DNS install
    // (issue #974).
    tunnel.set_dns_outbound_cell(Arc::clone(&config.provider_dns_cell));
    tunnel.set_mode(config.general.mode);
    tunnel.set_connection_notes(config.general.connection_notes);
    tunnel.set_tcp_idle_timeout(config.general.tcp_idle_timeout);
    // `find-process-mode` — install before dispatch starts: the cell is
    // shared with the traffic ledger's app lookup (issue #974). `-t`
    // validation never reaches here; PUT/PATCH re-assert at commit.
    tunnel.set_process_lookup_mode(config.general.find_process_mode);
    tunnel.update_routing(
        config.proxies,
        config.rules,
        config.sub_rules,
        config.dialer_registry,
    );
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
        // Bind eagerly: a `dns.listen` failure (EADDRINUSE, sandbox deny)
        // is a hard startup error — there is no prior listener to fall
        // back to, and a detached `run()` would leave the process
        // "running" with a dead DNS endpoint (issue #641).
        let bound = dns_server
            .bind()
            .await
            .map_err(|e| anyhow::anyhow!("dns.listen {listen_addr}: {e}"))?;
        let socket = bound.socket_weak();
        let task = tokio::spawn(async move {
            if let Err(e) = bound.run().await {
                error!("DNS server error: {}", e);
            }
        });
        *dns_server_handle.write() = Some(meow_api::routes::DnsServerHandle {
            listen: listen_addr,
            task,
            resolver_slot: slot,
            socket: Some(socket),
        });
    }

    // Interval-refresh loops are owned by a supervisor so commits that
    // swap the registry (PUT /configs, subscription refresh) can spawn or
    // abort tasks — startup reconciles the initial set (issue #543).
    let rule_provider_refresh =
        Arc::new(meow_config::rule_provider_refresh::RefreshSupervisor::default());
    rule_provider_refresh.reconcile(&rule_providers);
    // The providers the startup build left out, recorded once now that it
    // runs (startup builds its providers more than once).
    config.dropped_providers.record();

    // Same supervision for `proxy-providers` `interval:` — reconciled
    // against the committed declarations on every registry swap
    // (`commit_proxy_providers`), and once here for the startup set
    // (issue #625).
    let proxy_provider_refresh =
        Arc::new(meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor::default());
    proxy_provider_refresh.reconcile(&proxy_providers, config.raw.proxy_providers.as_ref());

    // Providers the startup load left owing a remote fetch — served from
    // their on-disk cache, failed, or with a `proxy:` name that could not
    // resolve before `update_routing` populated the provider dialer
    // registry (issue #625) — fetch now, retrying with backoff.
    //
    // Detached, and after the listeners are up: a provider reached through
    // a proxy front is the flakiest thing at cold start, and awaiting it
    // here would leave the box with no listener, no DNS and no API for as
    // long as the fetch takes — or, if it is treated as fatal, refuse to
    // start at all over a third-party feed being down.
    meow_config::proxy_provider::spawn_deferred_initial_fetches(&proxy_providers);

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
        // Refresh never rebinds listeners, so the startup snapshot is the
        // right dependency set for the prospective-route sweep.
        let running_listeners = config.listeners.named.clone();
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
                running_listeners,
            )
            .await;
        });
    }

    // Rebuild context mirrors startup: a `--config-string` run had no
    // backing file, so provider `path:`/fakeip resolution must see the
    // same `cache_dir: None` here (issue #717). Geodata download targets
    // resolve under the `-d`/XDG home independently.
    let geodata_cache_dir = config_path
        .as_deref()
        .filter(|p| !p.is_empty())
        .map(meow_config::resource_cache_dir_for_config_path);

    // A referenced geosite DB that `build_config` failed to download is
    // tolerated absent (its rules no-match); keep retrying it in the
    // background so a transient CDN error does not last until restart.
    if config.geo_needs.geosite && !meow_config::geosite_db_present(&config.geodata) {
        let geodata = config.geodata.clone();
        let tunnel = tunnel.clone();
        let raw_config = Arc::clone(&raw_config);
        let rule_providers = Arc::clone(&rule_providers);
        let proxy_providers = Arc::clone(&proxy_providers);
        let dns_server = Arc::clone(&dns_server_handle);
        let cache_dir = geodata_cache_dir.clone();
        // Refreshes never rebind listeners — the startup snapshot is the
        // republish sweep's dependency set, as subscription_refresh's.
        let running_listeners = config.listeners.named.clone();
        tokio::spawn(async move {
            meow_app::geodata_fetch::missing_geosite_retry_loop(
                geodata,
                tunnel,
                raw_config,
                rule_providers,
                proxy_providers,
                running_listeners,
                dns_server,
                cache_dir,
            )
            .await;
        });
    }

    // Spawn geodata auto-update task if enabled. `geo_needs` is the
    // startup snapshot of which DBs the config references — the tick
    // refreshes only those.
    if config.geodata.auto_update {
        let geodata = config.geodata.clone();
        let geo_needs = config.geo_needs;
        let tunnel = tunnel.clone();
        let raw_config = Arc::clone(&raw_config);
        let rule_providers = Arc::clone(&rule_providers);
        let proxy_providers = Arc::clone(&proxy_providers);
        let dns_server = Arc::clone(&dns_server_handle);
        let cache_dir = geodata_cache_dir;
        let running_listeners = config.listeners.named.clone();
        tokio::spawn(async move {
            meow_app::geodata_fetch::auto_update_loop(
                geodata,
                geo_needs,
                tunnel,
                raw_config,
                rule_providers,
                proxy_providers,
                running_listeners,
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
    // `take()`d by the TUN spawn paths below, which exist only under
    // `listener-tun`; the not-feature build moves it once at the end.
    #[cfg(feature = "listener-tun")]
    let mut early_binding = early_binding;

    // Start listeners. Bind before spawning the accept loops so a `port: 0`
    // (ephemeral) listener resolves to its OS-assigned port up front; the
    // resolved ports are patched into `named_listeners`, which feeds the
    // startup logs and the API snapshot (`GET /listeners`) below.
    use meow_config::ListenerSpec;

    let mut named_listeners = config.listeners.named.clone();
    for nl in &mut named_listeners {
        // A named `type: tun` owns no socket — skip the bind entirely
        // (`""` is not a bindable address). It spawns here like every
        // named inbound, but its startup failures are fatal: the sole
        // effective TUN cannot be left half-started behind a "running"
        // banner, and no PUT-path rollback exists for it.
        if let ListenerSpec::Tun(cfg) = &nl.spec {
            #[cfg(feature = "listener-tun")]
            {
                if let Err(msg) = spawn_named_tun(
                    &tunnel,
                    cfg,
                    &nl.name,
                    nl.route_override.clone(),
                    Arc::clone(&sniffer_runtime),
                    early_binding.take(),
                )
                .await
                {
                    listener_failed(&nl.name, &format!("TUN failed to start: {msg}"));
                    return Err(anyhow::anyhow!(
                        "listener '{}': TUN failed to start: {msg}",
                        nl.name
                    ));
                }
            }
            #[cfg(not(feature = "listener-tun"))]
            {
                let _ = cfg;
                tracing::warn!(
                    "listener '{}': type tun requires feature 'listener-tun'",
                    nl.name
                );
            }
            continue;
        }
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
                            listener_failed(&nl.name, &format!("bind {addr} failed: {e}"));
                            continue;
                        }
                    };
                    // `listeners[].routing-mark` — ingress SO_MARK on the
                    // listen socket; accepted sockets inherit it.
                    if !apply_listener_mark(&nl.name, &socket, nl.routing_mark) {
                        continue;
                    }
                    let bound = socket.local_addr().unwrap_or(addr);
                    nl.port = bound.port();
                    let listener = MixedListener::new(tunnel.clone(), bound, nl.name.clone())
                        .with_sniffer(Arc::clone(&sniffer_runtime))
                        .with_auth(Arc::clone(&auth))
                        .with_lan_acl(Arc::clone(&config.listeners.lan_acl))
                        .with_max_connections(nl.max_connections)
                        .with_tcp_keepalive(config.listeners.tcp_keepalive)
                        .with_route_override(nl.route_override.clone())
                        // The SOCKS5 UDP-associate relay socket binds per
                        // association inside the listener — its mark cannot
                        // come from the listen socket's inheritance.
                        .with_routing_mark(nl.routing_mark);
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
                transparent,
            } => {
                #[cfg(feature = "listener-tproxy")]
                {
                    let socket = match meow_listener::tproxy::bind_tcp(addr, *transparent) {
                        Ok(s) => s,
                        Err(e) => {
                            listener_failed(&nl.name, &format!("bind {addr} failed: {e}"));
                            continue;
                        }
                    };
                    // No `routing-mark` here: the parser already warns and
                    // drops it on `type: tproxy` — marking the transparent
                    // socket would mark the reply packets the policy rules
                    // must route back.
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
                    .with_udp(*udp, std::time::Duration::from_secs(*udp_timeout))
                    .with_tcp_keepalive(config.listeners.tcp_keepalive)
                    .with_transparent(*transparent)
                    .with_route_override(nl.route_override.clone());
                    // Firewall rules and the UDP TPROXY socket are fallible
                    // setup — run them eagerly so a failure can't drop the
                    // bound TCP socket inside a detached task (issue #641).
                    let listener = match listener.prepare(bound).await {
                        Ok(l) => l,
                        Err(e) => {
                            listener_failed(&nl.name, &format!("setup failed: {e}"));
                            continue;
                        }
                    };
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
                    let _ = (sni, firewall, udp, udp_timeout, transparent);
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
                            listener_failed(&nl.name, &format!("bind {addr} failed: {e}"));
                            continue;
                        }
                    };
                    if !apply_listener_mark(&nl.name, &socket, nl.routing_mark) {
                        continue;
                    }
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
                        Ok(l) => l
                            .with_max_connections(nl.max_connections)
                            .with_tcp_keepalive(config.listeners.tcp_keepalive)
                            .with_route_override(nl.route_override.clone())
                            // The UDP relay socket binds inside the
                            // listener — the TCP listen socket's mark
                            // can't reach it.
                            .with_routing_mark(nl.routing_mark),
                        Err(e) => {
                            listener_failed(&nl.name, &format!("invalid shadowsocks config: {e}"));
                            continue;
                        }
                    };
                    // The UDP relay socket binds eagerly — otherwise a UDP
                    // bind failure would drop the already-bound TCP socket
                    // when the detached task exits (issue #641).
                    let udp_sock = match listener.bind_udp(bound).await {
                        Ok(s) => s,
                        Err(e) => {
                            listener_failed(&nl.name, &e.to_string());
                            continue;
                        }
                    };
                    tokio::spawn(async move {
                        if let Err(e) = listener.run_on_udp(socket, udp_sock).await {
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
            ListenerSpec::WireGuard(cfg) => {
                #[cfg(feature = "listener-wireguard")]
                {
                    // UDP bind here (not inside the listener) so a
                    // `port: 0` resolves to the real port for the
                    // `/listeners` snapshot — the same bind-before-spawn
                    // contract the TCP listeners follow.
                    let socket = match WireGuardListener::bind(addr) {
                        Ok(s) => s,
                        Err(e) => {
                            listener_failed(&nl.name, &format!("bind {addr} failed: {e}"));
                            continue;
                        }
                    };
                    // No `routing-mark` here either — the parser warns and
                    // drops it on `type: wireguard`; marking the responder
                    // socket would mark handshake replies the policy rules
                    // must route back.
                    let bound = socket.local_addr().unwrap_or(addr);
                    nl.port = bound.port();
                    // meow-listener takes plain ctor args, never a
                    // meow-config type — map the validated config onto
                    // the listener-facing spec.
                    let spec = meow_listener::WgListenerSpec {
                        private_key: cfg.private_key,
                        peers: cfg
                            .peers
                            .iter()
                            .map(|p| meow_listener::WgPeerSpec {
                                public_key: p.public_key,
                                preshared_key: p.preshared_key,
                                allowed_ips: p.allowed_ips.clone(),
                                name: p.name.clone(),
                                reserved: p.reserved,
                            })
                            .collect(),
                        mtu: cfg.mtu,
                        udp: cfg.udp,
                        udp_timeout: cfg.udp_timeout,
                    };
                    let listener = WireGuardListener::new(tunnel.clone(), spec, nl.name.clone())
                        .with_max_connections(nl.max_connections)
                        .with_sniffer(Arc::clone(&sniffer_runtime))
                        .with_route_override(nl.route_override.clone());
                    match listener.spawn(socket) {
                        Ok(guard) => {
                            tokio::spawn(async move {
                                if let Err(e) = guard.wait().await {
                                    error!("WireGuard listener error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            listener_failed(&nl.name, &format!("spawn failed: {e}"));
                        }
                    }
                }
                #[cfg(not(feature = "listener-wireguard"))]
                {
                    let _ = cfg;
                    tracing::warn!(
                        "listener '{}': wireguard requires feature 'listener-wireguard'",
                        nl.name
                    );
                }
            }
            ListenerSpec::Anytls(cfg) => {
                #[cfg(feature = "listener-anytls")]
                {
                    // TLS material + padding resolve BEFORE any socket is
                    // bound: a bad PEM, mixed cert/key form, or broken
                    // scheme fails the listener outright — never leaves
                    // bound sockets behind on a "skipped" entry.
                    let spec = meow_listener::AnytlsListenerSpec {
                        users: cfg
                            .users
                            .iter()
                            .map(|u| (u.name.clone(), u.password_sha256))
                            .collect(),
                        certificate: cfg.certificate.clone(),
                        private_key: cfg.private_key.clone(),
                        allow_insecure: cfg.allow_insecure,
                        padding_scheme: cfg.padding_scheme.clone(),
                    };
                    let listener = match meow_listener::AnytlsListener::new(
                        tunnel.clone(),
                        nl.name.clone(),
                        spec,
                    ) {
                        Ok(l) => std::sync::Arc::new(
                            l.with_max_connections(nl.max_connections)
                                .with_tcp_keepalive(config.listeners.tcp_keepalive)
                                .with_route_override(nl.route_override.clone()),
                        ),
                        Err(e) => {
                            listener_failed(&nl.name, &format!("invalid anytls config: {e}"));
                            return Err(anyhow::anyhow!(
                                "listener '{}': invalid anytls config: {e}",
                                nl.name
                            ));
                        }
                    };
                    // Bind every configured address eagerly and
                    // atomically: any bind/mark failure fails the whole
                    // listener and the already-bound sockets drop with
                    // the returned Vec (upstream iterates all listen
                    // addresses; partial binds release on drop here).
                    let sockets =
                        bind_multi_tcp_sockets(&nl.name, &cfg.addresses, nl.routing_mark).await?;
                    // Publish the REAL bound endpoints: `local_addr()`
                    // from EVERY socket, collected atomically — a single
                    // failure used to drop that entry and `zip`-misalign
                    // the rest. Snapshot top-level `listen`/`port` and
                    // the `addresses` array from this ONE complete list
                    // so they can never diverge (F11).
                    let bound_addrs: Vec<(String, u16)> = sockets
                        .iter()
                        .map(|s| {
                            s.local_addr()
                                .map(|b| (b.ip().to_string(), b.port()))
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "listener '{}': bound address read failed: {e}",
                                        nl.name
                                    )
                                })
                        })
                        .collect::<Result<_, _>>()?;
                    if let ListenerSpec::Anytls(cfg) = &mut nl.spec {
                        for (a, (ip, port)) in cfg.addresses.iter_mut().zip(&bound_addrs) {
                            a.listen = ip.clone();
                            a.port = *port;
                        }
                    }
                    if let Some((ip, port)) = bound_addrs.first() {
                        nl.listen = ip.clone();
                        nl.port = *port;
                    }
                    for socket in sockets {
                        let listener = std::sync::Arc::clone(&listener);
                        tokio::spawn(async move {
                            if let Err(e) = listener.run_on(socket).await {
                                error!("AnyTLS listener error: {}", e);
                            }
                        });
                    }
                }
                #[cfg(not(feature = "listener-anytls"))]
                {
                    let _ = cfg;
                    // Same contract as the feature-on arm: a listener that
                    // cannot start fails startup — a silent skip would
                    // still publish it in the /listeners snapshot (F09).
                    listener_failed(&nl.name, "anytls requires feature 'listener-anytls'");
                    return Err(anyhow::anyhow!(
                        "listener '{}': anytls requires feature 'listener-anytls'",
                        nl.name
                    ));
                }
            }
            ListenerSpec::Vless(cfg) => {
                #[cfg(feature = "listener-vless")]
                {
                    let security = vless_security_spec(&cfg.security);
                    let spec = meow_listener::VlessListenerSpec {
                        users: cfg
                            .users
                            .iter()
                            .map(|u| meow_listener::VlessUserSpec {
                                username: u.username.clone(),
                                uuid: u.uuid,
                            })
                            .collect(),
                        security,
                        udp: cfg.udp,
                    };
                    let listener = match meow_listener::VlessListener::new(
                        tunnel.clone(),
                        nl.name.clone(),
                        spec,
                    ) {
                        Ok(l) => std::sync::Arc::new(
                            l.with_max_connections(nl.max_connections)
                                .with_tcp_keepalive(config.listeners.tcp_keepalive)
                                .with_route_override(nl.route_override.clone()),
                        ),
                        Err(e) => {
                            listener_failed(&nl.name, &format!("invalid vless config: {e}"));
                            return Err(anyhow::anyhow!(
                                "listener '{}': invalid vless config: {e}",
                                nl.name
                            ));
                        }
                    };
                    // Same atomic multi-bind contract as AnyTLS. REALITY
                    // self-loop protection learns the real endpoints before
                    // any accept task can classify a probe — important when
                    // `port: 0` resolves to ephemeral ports.
                    let sockets =
                        bind_multi_tcp_sockets(&nl.name, &cfg.addresses, nl.routing_mark).await?;
                    let bound_addrs: Vec<(String, u16)> = sockets
                        .iter()
                        .map(|s| {
                            s.local_addr()
                                .map(|b| {
                                    listener.note_bound_endpoint(s, b);
                                    (b.ip().to_string(), b.port())
                                })
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "listener '{}': bound address read failed: {e}",
                                        nl.name
                                    )
                                })
                        })
                        .collect::<Result<_, _>>()?;
                    if let ListenerSpec::Vless(cfg) = &mut nl.spec {
                        for (a, (ip, port)) in cfg.addresses.iter_mut().zip(&bound_addrs) {
                            a.listen = ip.clone();
                            a.port = *port;
                        }
                    }
                    if let Some((ip, port)) = bound_addrs.first() {
                        nl.listen = ip.clone();
                        nl.port = *port;
                    }
                    for socket in sockets {
                        let listener = std::sync::Arc::clone(&listener);
                        tokio::spawn(async move {
                            if let Err(e) = listener.run_on(socket).await {
                                error!("VLESS listener error: {}", e);
                            }
                        });
                    }
                }
                #[cfg(not(feature = "listener-vless"))]
                {
                    let _ = cfg;
                    listener_failed(&nl.name, "vless requires feature 'listener-vless'");
                    return Err(anyhow::anyhow!(
                        "listener '{}': vless requires feature 'listener-vless'",
                        nl.name
                    ));
                }
            }
            // Spawned above the bind (a TUN owns no socket) — this arm
            // is unreachable, kept only for exhaustiveness.
            ListenerSpec::Tun(_) => {}
        }
    }

    // Start REST API if configured. Runs after the listener bind phase so the
    // `GET /listeners` snapshot reports OS-assigned ports for `port: 0`
    // (ephemeral) listeners rather than the configured `0`.
    let mut controller_file = None;
    // Owns the `external-controller-unix` socket-path cleanup for the
    // daemon's lifetime — declared out here so the guard drops at shutdown,
    // not when the endpoint block ends (issue #974).
    #[cfg(unix)]
    let mut _unix_socket_guard: Option<meow_api::endpoint::UnixSocketGuard> = None;
    // Non-native transports configured by config key or CLI override warn
    // here too — `api_endpoint_servable` already excludes them, so an
    // unsupported-only config would otherwise go silent (issue #974).
    #[cfg(not(unix))]
    if let Some(ref unix_path) = config.api.external_controller_unix {
        warn!("external-controller-unix '{unix_path}' ignored — Unix sockets are unsupported on this platform");
    }
    #[cfg(not(windows))]
    if let Some(ref pipe_name) = config.api.external_controller_pipe {
        warn!("external-controller-pipe '{pipe_name}' ignored — named pipes are Windows-only");
    }
    // The HTTPS endpoint is a build feature, not just a platform gate:
    // `minimal` leaves it out (ADR-0007) and parses the key as dead
    // config — loud like the plugin placeholders, never silently dropped
    // (issue #974).
    #[cfg(not(feature = "api-tls"))]
    if let Some(ref tls_addr) = config.api.external_controller_tls {
        warn!("external-controller-tls '{tls_addr}' ignored — the HTTPS controller is not compiled into this build (feature 'api-tls')");
    }
    if api_endpoint_servable(&config.api) {
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
        let api_server = std::sync::Arc::new(ApiServer::new(
            tunnel.clone(),
            config.api.external_controller,
            config.api.secret.clone(),
            config.api.cors.clone(),
            config_path.clone(),
            Arc::clone(&raw_config),
            log_tx.clone(),
            Arc::clone(&proxy_providers),
            Arc::clone(&rule_providers),
            Arc::clone(&rule_provider_refresh),
            Arc::clone(&proxy_provider_refresh),
            named_listeners.clone(),
            config.api.external_ui.as_deref(),
            Arc::clone(&dns_server_handle),
            config.provider_dialer_registry.clone(),
            Some({
                let supervisor = Arc::clone(&ntp_supervisor);
                Arc::new(move |cfg| supervisor.reconcile(cfg)) as meow_api::routes::NtpReconcile
            }),
        ));
        // Every configured endpoint attempts its own bind: the plain TCP
        // controller stays startup-fatal (issue #641), while the TLS/unix/
        // pipe listeners are best-effort — a bad one is logged and skipped
        // so the rest still serve (issue #974).
        let mut bound_any = false;
        if let Some(api_addr) = config.api.external_controller {
            let socket = tokio::net::TcpListener::bind(api_addr)
                .await
                .map_err(|e| anyhow::anyhow!("external-controller {api_addr}: {e}"))?;
            controller_file = publish_controller(
                &socket,
                config.api.secret.as_deref(),
                config_path.as_deref(),
            );
            bound_any = true;
            let server = std::sync::Arc::clone(&api_server);
            tokio::spawn(async move {
                if let Err(e) = server.run_on(socket).await {
                    error!("API server error: {}", e);
                }
            });
        }
        // On builds without `api-tls` the field is dead config — the warn
        // above already named it; this arm is what the feature compiles.
        #[cfg(feature = "api-tls")]
        if let Some(ref tls_addr) = config.api.external_controller_tls {
            match meow_api::endpoint::bind_tls(
                tls_addr,
                config.api.tls_certificate.as_deref(),
                config.api.tls_private_key.as_deref(),
            )
            .await
            {
                Ok(endpoint) => {
                    bound_any = true;
                    info!("REST API (TLS) listening on https://{}", endpoint.addr());
                    let server = std::sync::Arc::clone(&api_server);
                    tokio::spawn(async move {
                        if let Err(e) = server.serve_tls_on(endpoint).await {
                            error!("API TLS server error: {e}");
                        }
                    });
                }
                Err(e) => {
                    error!("external-controller-tls {tls_addr}: {e:#} — endpoint skipped");
                }
            }
        }
        #[cfg(unix)]
        if let Some(ref unix_path) = config.api.external_controller_unix {
            match meow_api::endpoint::bind_unix(unix_path).await {
                Ok((endpoint, guard)) => {
                    bound_any = true;
                    info!("REST API listening on unix://{}", guard.path().display());
                    _unix_socket_guard = Some(guard);
                    let server = std::sync::Arc::clone(&api_server);
                    tokio::spawn(async move {
                        if let Err(e) = server.serve_on(endpoint).await {
                            error!("API unix server error: {e}");
                        }
                    });
                }
                Err(e) => {
                    error!("external-controller-unix {unix_path}: {e:#} — endpoint skipped");
                }
            }
        }

        #[cfg(windows)]
        if let Some(ref pipe_name) = config.api.external_controller_pipe {
            match meow_api::endpoint::bind_pipe(pipe_name) {
                Ok(endpoint) => {
                    bound_any = true;
                    info!("REST API listening on named pipe {pipe_name}");
                    let server = std::sync::Arc::clone(&api_server);
                    tokio::spawn(async move {
                        if let Err(e) = server.serve_on(endpoint).await {
                            error!("API pipe server error: {e}");
                        }
                    });
                }
                Err(e) => {
                    error!("external-controller-pipe '{pipe_name}': {e:#} — endpoint skipped");
                }
            }
        }
        if !bound_any {
            error!("external-controller endpoints are configured but no controller is available");
        }
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
            let mut listener = TunListener::new(
                tunnel.clone(),
                tun_config_to_listener_config(&config.tun),
                "meow-tun".to_string(),
            )
            .with_readiness_signal(ready_tx)
            .with_sniffer(Arc::clone(&sniffer_runtime))
            .with_tcp_dns_hijack(config.tun.dns_hijack);
            // The global-route binding installed before the config build
            // moves into the listener, which clears it with its routes —
            // or right away if startup fails (issue #695).
            if let Some(binding) = early_binding.take() {
                listener = listener.with_outbound_binding(binding);
            }

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
                            owner: meow_tunnel::TunOwner::TopLevel,
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
                    meow_api::routes::tun_failed(format!(
                        "TUN failed to start and was turned off: {msg}"
                    ));
                    handle.abort();
                    rollback_tun_enable(&tunnel, &raw_config).await;
                }
                Ok(Err(_)) => {
                    error!("TUN listener readiness signal dropped unexpectedly");
                    meow_api::routes::tun_failed(
                        "TUN failed to start and was turned off: the listener exited".into(),
                    );
                    handle.abort();
                    rollback_tun_enable(&tunnel, &raw_config).await;
                }
                Err(_) => {
                    let timeout = meow_api::TUN_STARTUP_TIMEOUT.as_secs();
                    error!("TUN listener startup timed out after {timeout} s");
                    meow_api::routes::tun_failed(format!(
                        "TUN failed to start and was turned off: timed out after {timeout} s"
                    ));
                    handle.abort();
                    rollback_tun_enable(&tunnel, &raw_config).await;
                }
            }
        }
        #[cfg(not(feature = "listener-tun"))]
        {
            let _ = early_binding;
            warn!("tun.enable is set but this build lacks the 'listener-tun' feature");
        }
    }

    // Start the NTP worker now that routing, the resolver hook, and any
    // TUN binding are settled — its own dial may ride the tunnel.
    // Reconcile from the COMMITTED document rather than the boot
    // `config.ntp` snapshot: the API lane has been serving since before
    // the TUN wait, and a PUT committed in that window already swapped
    // `raw_config` and fired its own reconcile — firing the stale boot
    // target now would resurrect a worker the operator just disabled
    // (issue #974 review). The resolve+reconcile pair runs inside the
    // `CONFIG_MUTATION` lane so it cannot split a PUT's commit (publish
    // seen, its reconcile still pending) — either this fires before the
    // PUT's own reconcile or it already sees the fully committed
    // document. A committed document always resolves (PUT admission
    // gates `resolve_ntp`); on a defect leave the worker stopped and
    // say so.
    {
        let _mutation = meow_api::routes::CONFIG_MUTATION.lock().await;
        // Arm the supervisor only now that readiness settled: a PUT
        // committed while the TUN wait was open already fired its own
        // reconcile — stored, never spawned — and its stored config
        // starts below (issue #974 review).
        ntp_supervisor.settle();
        match meow_config::resolve_ntp(&raw_config.read()) {
            Ok(ntp) => ntp_supervisor.reconcile(ntp),
            Err(e) => warn!("startup ntp resolution failed; worker left stopped: {e}"),
        }
    }

    // Only now: a signal before `shutdown.wait()` installs its handler
    // kills the process, which must not read as an unclean exit.
    meow_common::logbook::engine_started(config_path.as_deref().unwrap_or("--config-string"));
    if let Some(on_ready) = on_ready {
        on_ready()?;
    }
    info!("meow-rs is running");

    // Wait for shutdown signal
    let by = shutdown.wait().await?;
    info!("Shutting down ({by})...");
    ntp_supervisor.shutdown().await;
    meow_common::logbook::engine_stopped(meow_common::logbook::Stop::Requested(by));
    meow_common::traffic_ledger::uninstall();
    drop(controller_file);

    Ok(())
}

/// Tell `meow-cli` where this meow's API is, in a file only this user can
/// read (`meow_common::controller_file`); it stays until the returned
/// guard drops. Failing costs meow-cli only its lookup without options.
fn publish_controller(
    socket: &tokio::net::TcpListener,
    secret: Option<&str>,
    config_path: Option<&str>,
) -> Option<meow_common::controller_file::Published> {
    let published = socket.local_addr().and_then(|addr| {
        meow_common::controller_file::publish(addr, secret, config_path.map(std::path::Path::new))
    });
    match published {
        Ok(published) => published,
        Err(e) => {
            warn!("cannot publish the external-controller for meow-cli: {e}");
            None
        }
    }
}

/// A listener that did not start: logged, recorded in the logbook, and
/// skipped — the rest of the engine runs without it.
#[allow(
    dead_code,
    reason = "needed whenever ANY listener feature or the linux mark \
              path compiles — --no-default-features makes every call site \
              cfg'd out"
)]
fn listener_failed(name: &str, message: &str) {
    error!("listener '{name}': {message}");
    meow_common::logbook::event(
        meow_common::logbook::kind::LISTENER_START,
        meow_common::logbook::Level::Error,
        format!("Listener '{name}' did not start: {message}"),
    )
    .subject(name)
    .record();
}

/// `listeners[].routing-mark` — `SO_MARK` on the listener's own socket
/// (ingress; upstream `InboundOption.RoutingMark`). Linux only — the
/// config layer already warned and ignored the key elsewhere, so the
/// non-Linux arm is a silent no-op. A failed `setsockopt` (missing
/// `CAP_NET_ADMIN`) is a listener startup failure like a bind error: a
/// silently unmarked socket would evade the policy routing the mark was
/// declared for. Returns `false` when the listener must be skipped.
#[cfg(unix)]
#[allow(
    dead_code,
    reason = "every call site sits inside a `listener-*`-gated arm — \
              --no-default-features compiles them all out"
)]
fn apply_listener_mark<F: std::os::fd::AsRawFd>(name: &str, sock: &F, mark: Option<u32>) -> bool {
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    if let Some(mark) = mark {
        if let Err(e) = meow_common::set_listener_socket_mark(sock.as_raw_fd(), mark) {
            listener_failed(
                name,
                &format!("routing-mark {mark}: {e} (SO_MARK needs CAP_NET_ADMIN)"),
            );
            return false;
        }
    }
    #[cfg(not(all(target_os = "linux", not(target_env = "ohos"))))]
    let _ = (name, sock, mark);
    true
}

/// Windows has no `AsRawFd` (its socket handle type differs); the
/// `routing-mark` key is Linux-only anyway and already warned off at
/// parse time.
#[cfg(not(unix))]
#[allow(
    dead_code,
    reason = "every call site sits inside a `listener-*`-gated arm — \
              --no-default-features compiles them all out"
)]
fn apply_listener_mark<F>(_name: &str, _sock: &F, _mark: Option<u32>) -> bool {
    true
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
            && meow_config::parse_tun_config(
                committed.tun.as_ref(),
                committed.max_connections,
                committed.fake_ip_range(),
            )
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

/// Spawn a named `listeners: type: tun` device and publish it as the
/// effective TUN ([`meow_tunnel::TunOwner::Named`]). Unlike the top-level
/// section's spawn there is no committed-config re-validation and no
/// `tun.enable` rollback — a named device is a startup-snapshot object no
/// PUT can restart or roll back, so any failure here is returned to the
/// caller, which fails startup instead of logging-and-continuing.
/// `binding` is the early global-route binding installed before the
/// config build ([`preinstall_global_route_binding`], issue #695) —
/// adopted by this listener or given up with it on failure.
#[cfg(feature = "listener-tun")]
async fn spawn_named_tun(
    tunnel: &Tunnel,
    cfg: &meow_config::TunConfig,
    name: &str,
    route_override: Option<meow_common::InboundRouteOverride>,
    sniffer: Arc<SnifferRuntime>,
    binding: Option<meow_listener::OutboundBinding>,
) -> Result<(), String> {
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let mut listener = TunListener::new(
        tunnel.clone(),
        tun_config_to_listener_config(cfg),
        name.to_string(),
    )
    .with_readiness_signal(ready_tx)
    .with_sniffer(sniffer)
    .with_route_override(route_override);
    if let Some(binding) = binding {
        listener = listener.with_outbound_binding(binding);
    }
    let task_name = name.to_string();
    let handle = tokio::spawn(async move {
        if let Err(e) = listener.run().await {
            error!("TUN listener '{task_name}' error: {e}");
        }
    });

    let (core_done, udp_flows) =
        match tokio::time::timeout(meow_api::TUN_STARTUP_TIMEOUT, ready_rx).await {
            Ok(Ok(meow_listener::TunReady::Ready {
                core_done,
                udp_flows,
            })) => (core_done, udp_flows),
            Ok(Ok(meow_listener::TunReady::Failed(msg))) => {
                handle.abort();
                let _ = handle.await;
                return Err(msg);
            }
            Ok(Err(_)) => {
                handle.abort();
                let _ = handle.await;
                return Err("TUN readiness signal dropped unexpectedly".into());
            }
            Err(_) => {
                handle.abort();
                let _ = handle.await;
                return Err(format!(
                    "TUN startup timed out after {} s",
                    meow_api::TUN_STARTUP_TIMEOUT.as_secs()
                ));
            }
        };

    let tun_handle = meow_tunnel::TunHandle {
        task: handle,
        owner: meow_tunnel::TunOwner::Named(name.to_string()),
        core_done: Some(core_done),
        udp_flows,
    };
    if tun_handle.task.is_finished() {
        // Reported ready, then exited before the handle could publish —
        // the same dead-handle refusal the top-level publish applies.
        tunnel.teardown_tun_handle(tun_handle).await;
        return Err("TUN listener exited after reporting ready".into());
    }
    tunnel.set_tun_handle(tun_handle).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F09/F11: a multi-address AnyTLS listener is all-or-nothing — a
    /// bind failure on a LATER address must return the error AND release
    /// the sockets already bound (the returned `Vec` drops them), never
    /// leaving a half-bound group holding ports.
    #[cfg(feature = "listener-anytls")]
    #[tokio::test]
    async fn anytls_partial_bind_failure_releases_the_whole_group() {
        let blocked = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let blocked_port = blocked.local_addr().unwrap().port();
        // A port verified free, then released for the listener to take.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let free_port = probe.local_addr().unwrap().port();
        drop(probe);

        let addrs = [
            meow_config::ListenerBind {
                listen: "127.0.0.1".into(),
                port: free_port,
            },
            meow_config::ListenerBind {
                listen: "127.0.0.1".into(),
                port: blocked_port,
            },
        ];
        let err = bind_multi_tcp_sockets("t", &addrs, None)
            .await
            .expect_err("second address is occupied");
        assert!(err.to_string().contains(&blocked_port.to_string()), "{err}");
        // The first bind was rolled back: its port binds again.
        tokio::net::TcpListener::bind(("127.0.0.1", free_port))
            .await
            .expect("first address stayed bound — group not released");
    }

    #[test]
    fn api_secret_file_requires_a_valid_single_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("controller-secret");
        assert!(read_api_secret(&path).is_err());

        for contents in [
            "synthetic token",
            "synthetic token\n",
            "synthetic token\r\n",
        ] {
            std::fs::write(&path, contents).unwrap();
            assert_eq!(read_api_secret(&path).unwrap(), "synthetic token");
        }

        for contents in [
            b"".as_slice(),
            b"\n",
            b"synthetic token \n",
            b"synthetic token\n\n",
            b"synthetic\r token",
            b"synthetic\ttoken",
            b"synthetic token\0",
            b"synthetic token\xff",
        ] {
            std::fs::write(&path, contents).unwrap();
            assert!(read_api_secret(&path).is_err());
        }
    }

    #[test]
    fn api_secret_file_conflicts_with_inline_secret() {
        let result = Args::try_parse_from([
            "meow",
            "--secret",
            "synthetic-token",
            "--secret-file",
            "controller-secret",
        ]);
        assert!(matches!(result, Err(e) if e.kind() == clap::error::ErrorKind::ArgumentConflict));
    }

    #[test]
    fn empty_ext_ctl_overrides_keep_yaml_endpoints() {
        // `--ext-ctl-tls ''` is an empty override: applied verbatim it
        // would erase a configured endpoint — upstream skips empties
        // (issue #974).
        let args = Args::try_parse_from([
            "meow",
            "--ext-ctl-tls",
            "",
            "--ext-ctl-unix",
            "",
            "--ext-ctl-pipe",
            "",
        ])
        .unwrap();
        let mut api = meow_config::ApiConfig {
            external_controller: None,
            external_controller_tls: Some("127.0.0.1:9443".into()),
            external_controller_unix: Some("/tmp/meow.sock".into()),
            external_controller_pipe: Some(r"\\.\pipe\meow".into()),
            tls_certificate: None,
            tls_private_key: None,
            cors: Default::default(),
            secret: None,
            external_ui: None,
            external_ui_url: None,
        };
        apply_ext_controller_overrides(
            args.ext_ctl_tls.as_deref(),
            args.ext_ctl_unix.as_deref(),
            args.ext_ctl_pipe.as_deref(),
            &mut api,
        );
        assert_eq!(
            api.external_controller_tls.as_deref(),
            Some("127.0.0.1:9443")
        );
        assert_eq!(
            api.external_controller_unix.as_deref(),
            Some("/tmp/meow.sock")
        );
        assert_eq!(
            api.external_controller_pipe.as_deref(),
            Some(r"\\.\pipe\meow")
        );

        // Nonempty overrides replace — and a mix replaces only its own key.
        let args = Args::try_parse_from(["meow", "--ext-ctl-unix", "/tmp/cli.sock"]).unwrap();
        apply_ext_controller_overrides(
            args.ext_ctl_tls.as_deref(),
            args.ext_ctl_unix.as_deref(),
            args.ext_ctl_pipe.as_deref(),
            &mut api,
        );
        assert_eq!(
            api.external_controller_unix.as_deref(),
            Some("/tmp/cli.sock")
        );
        assert_eq!(
            api.external_controller_tls.as_deref(),
            Some("127.0.0.1:9443")
        );
        assert_eq!(
            api.external_controller_pipe.as_deref(),
            Some(r"\\.\pipe\meow")
        );
    }

    #[test]
    fn servable_gate_applies_the_api_tls_build_flag() {
        // `ApiConfig::has_servable_endpoint` is the *configured* set;
        // the startup predicate adds the compile gate: a TLS-only config
        // is servable exactly when `api-tls` built the endpoint, else the
        // daemon is headless (issue #974).
        let base = meow_config::ApiConfig {
            external_controller: None,
            external_controller_tls: None,
            external_controller_unix: None,
            external_controller_pipe: None,
            tls_certificate: None,
            tls_private_key: None,
            cors: Default::default(),
            secret: None,
            external_ui: None,
            external_ui_url: None,
        };
        let mut api = meow_config::ApiConfig {
            external_controller_tls: Some("127.0.0.1:9443".into()),
            ..base
        };
        assert_eq!(api_endpoint_servable(&api), cfg!(feature = "api-tls"));
        // Dead TLS config never drags a live endpoint down — a TLS+unix
        // config on a TLS-less build still serves the socket.
        api.external_controller = Some("127.0.0.1:9090".parse().unwrap());
        assert!(api_endpoint_servable(&api));
        api.external_controller = None;
        // The platform arms below assert on unix/pipe alone — a
        // lingering TLS endpoint would answer true on an api-tls
        // Windows build before the unix arm is even asked.
        api.external_controller_tls = None;
        api.external_controller_unix = Some("meow.sock".into());
        assert_eq!(api_endpoint_servable(&api), cfg!(unix));
        api.external_controller_pipe = Some(r"\\.\pipe\meow".into());
        assert_eq!(api_endpoint_servable(&api), cfg!(any(unix, windows)));
    }

    // Upstream `MRS\x01` fixture writers — the same shapes the
    // `meow_rules::mrs_parser` tests build (their encoders are
    // `#[cfg(test)]` and unreachable across crates).
    fn i64be(out: &mut Vec<u8>, v: i64) {
        out.extend_from_slice(&v.to_be_bytes());
    }

    fn u64be(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&v.to_be_bytes());
    }

    fn set_bit(bits: &mut Vec<u64>, idx: usize) {
        let word = idx / 64;
        if bits.len() <= word {
            bits.resize(word + 1, 0);
        }
        bits[word] |= 1u64 << (idx % 64);
    }

    fn upstream_mrs(behavior: u8, count: i64, body: &[u8]) -> Vec<u8> {
        let mut inner = b"MRS\x01".to_vec();
        inner.push(behavior);
        i64be(&mut inner, count);
        i64be(&mut inner, 0); // extra_len
        inner.extend_from_slice(body);
        zstd::encode_all(std::io::Cursor::new(inner), 0).unwrap()
    }

    /// Domain-set body: internal keys are each entry reversed byte-wise
    /// (`"+.x.com"` stores the single suffix key `moc.x.+`).
    fn domain_set_body(entries: &[&str]) -> Vec<u8> {
        let mut keys: Vec<Vec<u8>> = entries.iter().map(|e| e.bytes().rev().collect()).collect();
        keys.sort();
        let (mut leaves, mut label_bitmap, mut labels) = (Vec::new(), Vec::new(), Vec::new());
        let mut label_idx = 0usize;
        let mut queue = vec![(0usize, keys.len(), 0usize)];
        let mut idx = 0usize;
        while idx < queue.len() {
            let (mut start, end, col) = queue[idx];
            if col == keys[start].len() {
                start += 1;
                set_bit(&mut leaves, idx);
            }
            let mut j = start;
            while j < end {
                let from = j;
                while j < end && keys[j][col] == keys[from][col] {
                    j += 1;
                }
                queue.push((from, j, col + 1));
                labels.push(keys[from][col]);
                label_idx += 1;
            }
            set_bit(&mut label_bitmap, label_idx);
            label_idx += 1;
            idx += 1;
        }
        let mut out = vec![1u8]; // domain_set version
        i64be(&mut out, leaves.len() as i64);
        for word in leaves {
            u64be(&mut out, word);
        }
        i64be(&mut out, label_bitmap.len() as i64);
        for word in label_bitmap {
            u64be(&mut out, word);
        }
        i64be(&mut out, labels.len() as i64);
        out.extend_from_slice(&labels);
        out
    }

    fn domain_mrs(entries: &[&str]) -> Vec<u8> {
        upstream_mrs(
            meow_rules::mrs_parser::TYPE_DOMAIN,
            entries.len() as i64,
            &domain_set_body(entries),
        )
    }

    fn scratch_siblings(dir: &tempfile::TempDir, base: &str) -> Vec<std::ffi::OsString> {
        std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .filter(|n| {
                n.to_str()
                    .is_some_and(|s| s.starts_with(base) && s.ends_with(".tmp"))
            })
            .collect()
    }

    #[test]
    fn convert_ruleset_refuses_clobbering_and_leaves_no_partial_output() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("set.txt");
        std::fs::write(&src, b"not an mrs").unwrap();
        // Default target of a `.txt` source is the source itself.
        assert!(convert_ruleset("domain", "mrs", &src, None).is_err());
        assert_eq!(std::fs::read(&src).unwrap(), b"not an mrs");
        let out = dir.path().join("out.txt");
        std::fs::write(&out, b"old").unwrap();
        assert!(convert_ruleset("domain", "mrs", &src, Some(&out)).is_err());
        assert_eq!(std::fs::read(&out).unwrap(), b"old", "old output untouched");
        assert!(scratch_siblings(&dir, "out.txt").is_empty());
        assert!(convert_ruleset("classical", "mrs", &src, Some(&out)).is_err());
        assert!(convert_ruleset("domain", "yaml", &src, Some(&out)).is_err());
    }

    #[test]
    fn convert_ruleset_domain_dumps_upstream_compacted_text() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("set.mrs");
        // `+.a.com` byte-reverses into the single suffix key `moc.a.+`;
        // decoded next to `a.com`'s `moc.a` the pair is upstream's `+.a.com`
        // entry — DumpMrs collapses it back to one `+.a.com` line, while a
        // lone suffix key (`.only.com`) stays suffix-only, and the dump is
        // sorted over the merged list.
        std::fs::write(
            &src,
            domain_mrs(&["b.com", "a.com", "+.a.com", "+.only.com"]),
        )
        .unwrap();
        convert_ruleset("domain", "mrs", &src, None).unwrap();
        let out = dir.path().join("set.txt");
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            "+.a.com\n.only.com\nb.com\n"
        );
        assert!(scratch_siblings(&dir, "set.txt").is_empty());
    }

    /// Distinct internal keys can decode to the same form — `moc.a.` and
    /// `moc.a.+` both yield `.a.com` — and upstream's loose trimmed-equal
    /// merge would fold that duplicate (or `x`+`x`) into coverage the set
    /// never had. Only the canonical `x` + `.x` twin may collapse.
    #[test]
    fn convert_ruleset_domain_dump_merges_only_canonical_twins() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("set.mrs");
        std::fs::write(
            &src,
            domain_mrs(&["a.com", "+.a.com", ".a.com", "+.x.com", ".x.com"]),
        )
        .unwrap();
        let out = dir.path().join("set.txt");
        convert_ruleset("domain", "mrs", &src, Some(&out)).unwrap();
        // `a.com` + one `.a.com` merge; the second `.a.com` and the
        // `.x.com` + `.x.com` pair stay unfolded.
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            "+.a.com\n.a.com\n.x.com\n.x.com\n"
        );
        assert!(scratch_siblings(&dir, "set.txt").is_empty());
    }

    /// A `domain` .mrs fed to the `ipcidr` convert is refused on the
    /// behavior guard before anything is written.
    #[test]
    fn convert_ruleset_refuses_behavior_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("set.mrs");
        std::fs::write(&src, domain_mrs(&["a.com"])).unwrap();
        let out = dir.path().join("out.txt");
        assert!(convert_ruleset("ipcidr", "mrs", &src, Some(&out)).is_err());
        assert!(!out.exists());
        assert!(scratch_siblings(&dir, "out.txt").is_empty());
    }

    #[test]
    fn convert_ruleset_ipcidr_dumps_cidrs() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("ip.mrs");
        let mut body = vec![1u8]; // ipcidr_set version
        i64be(&mut body, 1);
        body.extend_from_slice(
            &std::net::Ipv4Addr::new(192, 168, 0, 0)
                .to_ipv6_mapped()
                .octets(),
        );
        body.extend_from_slice(
            &std::net::Ipv4Addr::new(192, 168, 0, 255)
                .to_ipv6_mapped()
                .octets(),
        );
        std::fs::write(
            &src,
            upstream_mrs(meow_rules::mrs_parser::TYPE_IPCIDR, 1, &body),
        )
        .unwrap();
        let out = dir.path().join("ip.txt");
        convert_ruleset("ipcidr", "mrs", &src, Some(&out)).unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "192.168.0.0/24\n");
        assert!(scratch_siblings(&dir, "ip.txt").is_empty());
    }

    #[test]
    fn convert_ruleset_refuses_dotdot_target_naming_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("set.mrs");
        let bytes = domain_mrs(&["a.com"]);
        std::fs::write(&src, &bytes).unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        // Lexically different from the source yet names the same file —
        // the old `target == source` guard let it through and the rename
        // replaced the source.
        let tricky = dir.path().join("sub/../set.mrs");
        assert!(convert_ruleset("domain", "mrs", &src, Some(&tricky)).is_err());
        assert_eq!(std::fs::read(&src).unwrap(), bytes, "source untouched");
        assert!(scratch_siblings(&dir, "set.mrs").is_empty());
    }

    /// A hard link has its own resolved path — only the dev+ino check
    /// sees that it *is* the source. `std::fs::hard_link` needs no
    /// privilege on NTFS either, so this runs on every platform
    /// (unlike the symlink test below).
    #[test]
    fn convert_ruleset_refuses_target_hardlink_to_source() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("real.mrs");
        let bytes = domain_mrs(&["a.com"]);
        std::fs::write(&src, &bytes).unwrap();
        let link = dir.path().join("out.txt");
        std::fs::hard_link(&src, &link).unwrap();
        assert!(convert_ruleset("domain", "mrs", &src, Some(&link)).is_err());
        assert_eq!(std::fs::read(&src).unwrap(), bytes, "source untouched");
    }

    #[cfg(unix)]
    #[test]
    fn convert_ruleset_refuses_target_symlink_to_source() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("real.mrs");
        let bytes = domain_mrs(&["a.com"]);
        std::fs::write(&src, &bytes).unwrap();
        let link = dir.path().join("out.txt");
        std::os::unix::fs::symlink(&src, &link).unwrap();
        assert!(convert_ruleset("domain", "mrs", &src, Some(&link)).is_err());
        assert!(link.is_symlink(), "symlink itself left alone");
        assert_eq!(std::fs::read(&src).unwrap(), bytes, "source untouched");
    }

    /// The scratch must be removed even when the rename itself fails —
    /// here because the target is a directory, which a file rename cannot
    /// replace on any platform.
    #[test]
    fn convert_ruleset_failed_rename_removes_the_scratch() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("set.mrs");
        std::fs::write(&src, domain_mrs(&["a.com"])).unwrap();
        let out = dir.path().join("out.txt");
        std::fs::create_dir(&out).unwrap();
        assert!(convert_ruleset("domain", "mrs", &src, Some(&out)).is_err());
        assert!(scratch_siblings(&dir, "out.txt").is_empty());
    }

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

    #[test]
    fn log_facade_stops_at_debug_unless_the_filter_traces() {
        use tracing_subscriber::EnvFilter;
        for directives in ["off", "warn", "info", "debug", "info,meow_proxy=debug"] {
            let level = super::log_max_level(&EnvFilter::new(directives));
            assert_eq!(level, log::LevelFilter::Debug, "{directives}");
        }
        for directives in ["trace", "info,quiche=trace"] {
            let level = super::log_max_level(&EnvFilter::new(directives));
            assert_eq!(level, log::LevelFilter::Trace, "{directives}");
        }
    }

    fn ss_spec() -> meow_config::ListenerSpec {
        meow_config::ListenerSpec::Shadowsocks(meow_config::SsListenerConfig {
            cipher: "aes-128-gcm".into(),
            password: "p".into(),
            udp: true,
            simple_obfs: None,
        })
    }

    fn anytls_spec() -> meow_config::ListenerSpec {
        meow_config::ListenerSpec::Anytls(meow_config::AnytlsListenerConfig {
            allow_insecure: true,
            addresses: vec![meow_config::ListenerBind {
                listen: "0.0.0.0".into(),
                port: 23301,
            }],
            ..Default::default()
        })
    }

    /// The spawn-loop feature mapping is `listener-mixed` for
    /// mixed/http/socks5, `listener-tproxy` for tproxy, and
    /// `listener-shadowsocks` for shadowsocks (in `full`, not `minimal`).
    /// Asserting the exact feature *name* (not just polarity) catches a
    /// typo'd or drifted mapping.
    #[test]
    fn listener_gate_matches_spawn_arms() {
        use meow_config::ListenerSpec as S;
        let gate = super::listener_feature_gate;
        assert_eq!(
            gate(&S::Mixed),
            (!cfg!(feature = "listener-mixed")).then_some("listener-mixed")
        );
        assert_eq!(
            gate(&S::Http),
            (!cfg!(feature = "listener-mixed")).then_some("listener-mixed"),
            "http rides the mixed-listener feature, not listener-http"
        );
        assert_eq!(
            gate(&S::Socks5),
            (!cfg!(feature = "listener-mixed")).then_some("listener-mixed")
        );
        assert_eq!(
            gate(&S::TProxy {
                sni: true,
                firewall: true,
                udp: false,
                udp_timeout: 60,
                transparent: false,
            }),
            (!cfg!(feature = "listener-tproxy")).then_some("listener-tproxy")
        );
        assert_eq!(
            gate(&ss_spec()),
            (!cfg!(feature = "listener-shadowsocks")).then_some("listener-shadowsocks")
        );
        assert_eq!(
            gate(&S::WireGuard(meow_config::WgListenerConfig {
                private_key: [0u8; 32],
                peers: vec![],
                mtu: 1420,
                udp: true,
                udp_timeout: std::time::Duration::from_secs(60),
            })),
            (!cfg!(feature = "listener-wireguard")).then_some("listener-wireguard")
        );
        assert_eq!(
            gate(&anytls_spec()),
            (!cfg!(feature = "listener-anytls")).then_some("listener-anytls")
        );
    }

    /// `tun:` rides its own gate — disabled is always servable, enabled
    /// demands `listener-tun`.
    #[test]
    fn tun_gate() {
        assert_eq!(super::tun_feature_gate(false), None);
        assert_eq!(
            super::tun_feature_gate(true),
            (!cfg!(feature = "listener-tun")).then_some("listener-tun")
        );
    }

    /// `listener-shadowsocks` is the regression case behind this gate: a
    /// `type: shadowsocks` listener used to warn-and-skip, leaving the
    /// port dead while `-t` still passed. `full` now compiles the listener,
    /// so the uncompiled case is played by a gate that reports it missing;
    /// `listener_gate_matches_spawn_arms` pins the real gate's mapping.
    #[test]
    fn ensure_rejects_uncompiled_shadowsocks_listener() {
        fn without_shadowsocks(spec: &meow_config::ListenerSpec) -> Option<&'static str> {
            matches!(spec, meow_config::ListenerSpec::Shadowsocks(_))
                .then_some("listener-shadowsocks")
        }
        let named = [meow_config::NamedListener {
            name: "ss-in".into(),
            spec: ss_spec(),
            port: 23300,
            listen: "0.0.0.0".into(),
            max_connections: 256,
            route_override: None,
            routing_mark: None,
        }];
        let err = meow_api::ensure_listeners_supported(&named, without_shadowsocks)
            .expect_err("ss listener must fail on a feature-less build");
        assert!(err.to_string().contains("listener-shadowsocks"), "{err}");
        assert_eq!(
            meow_api::ensure_listeners_supported(&named, super::listener_feature_gate).is_ok(),
            cfg!(feature = "listener-shadowsocks")
        );
    }

    /// Same contract for `type: anytls`: on a build without
    /// `listener-anytls` the config must fail `ensure_inbounds_supported`
    /// (and therefore `-t`), not warn-and-skip into a dead port.
    #[test]
    fn ensure_rejects_uncompiled_anytls_listener() {
        fn without_anytls(spec: &meow_config::ListenerSpec) -> Option<&'static str> {
            matches!(spec, meow_config::ListenerSpec::Anytls(_)).then_some("listener-anytls")
        }
        let named = [meow_config::NamedListener {
            name: "anytls-in".into(),
            spec: anytls_spec(),
            port: 23301,
            listen: "0.0.0.0".into(),
            max_connections: 256,
            route_override: None,
            routing_mark: None,
        }];
        let err = meow_api::ensure_listeners_supported(&named, without_anytls)
            .expect_err("anytls listener must fail on a feature-less build");
        assert!(err.to_string().contains("listener-anytls"), "{err}");
        assert_eq!(
            meow_api::ensure_listeners_supported(&named, super::listener_feature_gate).is_ok(),
            cfg!(feature = "listener-anytls")
        );
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
            let raw: RawConfig = serde_saphyr::from_str(yaml).unwrap();
            Arc::new(RwLock::new(raw))
        }

        fn startup_tun(raw: &RwLock<RawConfig>) -> meow_config::TunConfig {
            let guard = raw.read();
            meow_config::parse_tun_config(
                guard.tun.as_ref(),
                guard.max_connections,
                guard.fake_ip_range(),
            )
            .unwrap()
        }

        /// A pending listener task plus a drop signal proving teardown.
        fn pending_handle() -> (TunHandle, tokio::sync::oneshot::Receiver<()>) {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let handle = TunHandle {
                task: tokio::spawn(async move {
                    let _tx = tx;
                    std::future::pending::<()>().await;
                }),
                owner: meow_tunnel::TunOwner::TopLevel,
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
                owner: meow_tunnel::TunOwner::TopLevel,
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

    /// #695: the global-route binding is installed from the raw config,
    /// ahead of the build's first dial, only for an enabled TUN in global
    /// route scope (`auto-route` unset, `true` or `global`) — TUN-off and
    /// fake-IP startups never touch the process-global registry.
    #[cfg(all(
        feature = "listener-tun",
        any(target_os = "linux", target_os = "macos")
    ))]
    mod early_outbound_binding {
        use crate::preinstall_global_route_binding;
        use meow_config::raw::RawConfig;

        /// Loopback exists on every host.
        const LO: &str = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };

        /// Parse `yaml` with `LO` standing in for the loopback interface.
        fn raw(yaml: &str) -> RawConfig {
            meow_config::parse_raw_yaml(&yaml.replace("LO", LO)).unwrap()
        }

        /// One test drives every case because the registry is
        /// process-global; separate `#[test]` fns would race each other.
        #[test]
        fn preinstalls_only_for_global_route_scope() {
            assert!(meow_common::outbound_interface().is_none());

            for yaml in [
                "port: 7890\n",
                "tun:\n  enable: false\n  auto-route: global\n  outbound-interface: LO\n",
                "tun:\n  enable: true\n  auto-route: fake-ip\n  outbound-interface: LO\n",
                "tun:\n  enable: true\n  auto-route: false\n",
                // Rejected later by `build_config`; never pre-installs.
                "tun:\n  enable: true\n  auto-route: bogus\n  outbound-interface: LO\n",
            ] {
                assert!(
                    preinstall_global_route_binding(&raw(yaml)).is_none(),
                    "{yaml}"
                );
                assert!(meow_common::outbound_interface().is_none(), "{yaml}");
            }

            // A failed early install is not fatal (the listener retries and
            // fails closed) and leaves nothing installed.
            let missing = "tun:\n  enable: true\n  auto-route: global\n  \
                           outbound-interface: no-such-iface-zz9\n";
            assert!(preinstall_global_route_binding(&raw(missing)).is_none());
            assert!(meow_common::outbound_interface().is_none());

            for global in [
                "tun:\n  enable: true\n  outbound-interface: LO\n",
                "tun:\n  enable: true\n  auto-route: true\n  outbound-interface: LO\n",
                "tun:\n  enable: true\n  auto-route: global\n  outbound-interface: LO\n",
            ] {
                let binding = preinstall_global_route_binding(&raw(global))
                    .expect("global route scope pre-installs the binding");
                assert_eq!(
                    meow_common::outbound_interface().as_deref(),
                    Some(LO),
                    "{global}"
                );
                drop(binding);
                assert!(meow_common::outbound_interface().is_none(), "{global}");
            }
        }
    }

    #[cfg(feature = "listener-vless")]
    mod vless_test_security {
        use super::*;

        const TEST_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQCb2SWxd4NvsjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjYxMTI2MTgyMDEyWhcNMzYxMTIzMTgyMDEyWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDM
mkGQMyS/oSU0JO8ETadgzYUmVXB0lPNkwdhRS0nLqrNSW09G/+PhG7Ex0xLAIRH1
HSLJPKs0oL/iVzuPx+L85/cHTISnw7loGVCcgHN/he8G9fWzs8VlJCwxKYOn6A3b
NgZNCFCLS4aNVnFGauWS1MkvNzFqtz2eoLEgHherr5jtV1WlcdpxNl0xHuCesCHI
BF041RO+0DhNTg4tahgVk3IZmSrR8kMCzx1EizBJlqBMJPHqTheFKjenelI3jolB
YFFxR86U8d7iVceAzqBSnJOKPvx+2Y//87COT6TcJzsUg4ALZBp5Ym3yy9IzRlEd
z+Tv3Sd8Y/w9a6bo3ZunAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEonlDigkFLY
39hLj9jWvUmHpCRXpri+FKf8IEJvHxbn/ImWTdSXCGD0gyYndB3CI3piYU4nKiWz
6puCyLWBw7RVNK/y0s6cAnieNkAJcFWfqXsskt8jqY3Nq2bWtKjJ0gyNG21yZEZg
fQ+/5d2QpD4+fGkrtum8jYZR4gMSV+s5RGs2ayByiMzCisk+VHbjKAVygdqc3Jtq
vQ4fzC+KxHuL0eCq/Bc1AJQ1lcoIEPYYlX5IMI/Kgx7OIgAneG2rswEc9YV0mpH8
iRc/qmfkS4j+cho90gY3guK6sZTvJJzGpNIrN7qeYb+90UZ7vMJ2SOqKE6WRNWaD
+O+0KabQ2oo=
-----END CERTIFICATE-----
"#;
        const TEST_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDMmkGQMyS/oSU0
JO8ETadgzYUmVXB0lPNkwdhRS0nLqrNSW09G/+PhG7Ex0xLAIRH1HSLJPKs0oL/i
VzuPx+L85/cHTISnw7loGVCcgHN/he8G9fWzs8VlJCwxKYOn6A3bNgZNCFCLS4aN
VnFGauWS1MkvNzFqtz2eoLEgHherr5jtV1WlcdpxNl0xHuCesCHIBF041RO+0DhN
Tg4tahgVk3IZmSrR8kMCzx1EizBJlqBMJPHqTheFKjenelI3jolBYFFxR86U8d7i
VceAzqBSnJOKPvx+2Y//87COT6TcJzsUg4ALZBp5Ym3yy9IzRlEdz+Tv3Sd8Y/w9
a6bo3ZunAgMBAAECggEBAMTfZVjwrVqrH5ZWN5tHcVgnSgjBy6ySKsV39ML8k+yi
u1vyuozR6x8PO2h69p7i81mNCIzkkMTaLOkJESnfp529QqjGSxr2rS/qs/Nzci9x
27cx8pNQ1w7kSJWhoapuEu8sw9FZv87ZBIZ5eBPPBkpL7648CJPr8CHz85u4+QPc
AVtPs+cG1nScngnyewoImsv2JEZsqnDzPBejs+qFaUyTspNgaqwhZ2pi/GYRBoV5
buT8PrpjK4ckStlSXBRbgafIYPN+AJaEvU7HCfu66a91w3HbpJdl54/JTCIjm5CW
MPJiMuGUVWQkaQxOrBbk+cMeHY+tp8z+urFPu6UoepECgYEA8SPbZ2rHcS0bKg+P
4KbCWY4WWPyGIo7rqimg576GqfE/PHMgBIC5cxcH38adnEiVqMxZ0JuPKq774j6D
MZhnN+tlnc9hX8MofiK2HxE9G4VVM7bWY/3yR5MNQLoXmpy4uy1QEXzQJw3oo2Qe
bfW6JG6dL0WdzH8KgoM0guhfQdkCgYEA2TX+9c4u3VbZVKkoc4vQ6DvPQJIPCHMu
bD8gwY1ZmtRhRMBlyyIcQ10VRA5WS9OzAnErnWfkIaFGAUXrFcvGHp1RXcTn6g/E
RY40iQQH9GwL4snu5oIBcWEnABurEaOzIejmubI+jt/u5YnPn83XIKv3mHk7QNn/
J9RjxH9D2X8CgYB1CiNWqaQN0YfKvWzm6+mO0AEWxdJQ+a92kufvMzFnUJmRvIsA
xH2+V6JRwbQEA9Ln7+9z6dzuKapF4HOK4d7PbGiQ1PP9J9sChdSBdbuEHQ4CoK6k
L8ClbsFS9j+4onKjHtYq9rqNChotG84NLuRfBHU0WYTCmbK/L/GPzDtX2QKBgQCM
Acz0ndEBZJCzjFGBoPaoKp0dbsf3115t8Ybom3bNYOXNjgJPHA6BsUca1e7z82Ho
ShAl5qhasPxRp8KvCukKJLckrN4btcv6VX4xbwK9nsNOjIDL3bKWZVvhKvRqa0z0
p43I1kaSi28OT3Uf+WsYKSBwDHyQAbQA9VrVdn7CewKBgG9FIFNdD+2RCVknVNXb
0NOIduRdx69nUwfUrm9iE7GMeK02+zhbpiOEOlm40RZbxH3dL98naMNo6HgdoQdw
RcBjFNmTQsDAu5vjXtOw8Yu3NxWfzeLwwaVvVCko8aXUTHqUaPQOfm9HiDXE36cH
1KwIXpEoToqHaITDAs6F5ySk
-----END PRIVATE KEY-----
"#;
        const MISMATCHED_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDUwa45RDHDbXgk
zwtca4bB4kKb+i1gN0DtNCoAAR0udopvL29pbjrn2saThBE+brnC1LNzKV8Pku31
HUHx/xYZCc06Q8s6mPyUb59CDeysErac9ZFRU4CajwkQKQwLjEdAGVizBAbStylA
wdV/gzofthvG4+GGoHqs+HY9fpIUk2YeiQKezSumppVJ2NFuJY1lN+AWh3Tfla0u
R/Br/icsU09qTrwhFVHql1PhNB7yX2ABMhNPDHvfkqIOAhochSF298Gyph1GhM+2
POEJobR/7/kHl1GyRdrQN7gi1jTR+tRIra+egDH9in1QQ/zAg6zX4oUxNxW4Ary6
BPuuT+ZhAgMBAAECggEARMIDSEadvobWWS8AgPHPL0GsPTRxDbNNrFs7Z5z0jVuK
CbzOyMfzCZNOscXwvLiUGD8db45jRmk5tgmqkkbaIWVlifr25w0iM+aPFY3iewnh
MoC6YgoWedzYFPzvA5xmOnT2kYQvoFHJZ0A9e2QxmKYF/BURgazDeLsjm2QYWcVi
Hp59aBQ0sMISkYhRqRtMs9EVLnEOtJVA2w3TIW4q55BtCZ/JeBTDQBbzb+K0FDdr
7+gV44jJqBhRCUswdp3MbCO7Uy1SqBwRWKahVzqtC/EjJXFlEiiTtYbJ0aptRmKU
nvCPJ6+KGK5XC2w5crhYOLBb2iLv75Gm162RQcoVQQKBgQD2RlAr0qYcDUssD4Xv
4/8HqQ8NTGNAbghznRjj58TCcaEndlRv6AKkCNaH1S/q2OFNTC4p3TC9wxFq8IBW
qW4mliZF/roTp/UKaLhqvFt4d+OOt6aMxN5/1btzYn+A6nsgvfvXK/NL6IIz1UdL
ViB9eSoBL43P8/1o+WMMPZBpJQKBgQDdKIUVLtvSq2fYMKruesOtoeKcWygnzhba
UZ9uL/y2m+gaxxntj2UF6Y8NnsYHcIYlLxeqENdHvvoSA2WB3lh0QV3LS8YQCEPA
N7aGq09ebFfZMLOUS5CSvvzhfQk26ovlnIVKyU00HMNACAaLnt8ECcRnEIS+v8ue
lA0cRC35jQKBgQC7noWlXS2/YUFLp+faAlBgfaNB9lgG1c0KhzxXJFL576decP+S
4aZhYXpOsVN4DxJV2RuyORjQ+LNkTST44MtSCkHOQWlxYBuGepFEf4sQFAYAzFjO
FY2Mxj+wf/GzPO/g2dvq6UjJI7FN28Yc1tiZvp0JmjjnnHIKbzPON3i1IQKBgDj2
ZtC98QCiBW05m80w8ZWXTLbZA8681kYFH/tRgNXH8lBzV8pIVMzhC2eGrZrc8LBD
IOU80TY5ik95cHuyuTW4YGAsdCdM+aZYszqchSTc4wOd96MKk4I4jwnFGsp6Pu41
El/g2XHCtseXSZhMo0R2/49MQeSfoeKGX5oYNX9BAoGAG2DQq8VDDoaVy/QCwZXN
jRMlyTkbj09s3i2Q2JPa8CRfrv6QXcNWSTzqED7HSA/wpBS/3lxdSjBSgrP2Mi2Q
aR7y+yjHyFyl4TjohXNY2MEKAUK50TAcxkI02AVD5kLv0NkcrxCELt8ILHA2/o1R
ebe3y+ZRTVQVKhyaC1jbQ5c=
-----END PRIVATE KEY-----
"#;

        fn pem_block(pem: &str) -> String {
            pem.lines().map(|line| format!("      {line}\n")).collect()
        }

        fn tls_listener_yaml(cert: &str, key: &str) -> String {
            format!(
                "listeners:\n  - name: vision-in\n    type: vless\n    port: 0\n    certificate: |\n{}    private-key: |\n{}    users:\n      - username: alice\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-vision\n",
                pem_block(cert),
                pem_block(key)
            )
        }

        async fn config_from_yaml(yaml: &str) -> meow_config::Config {
            let raw = meow_config::parse_raw_yaml(yaml).unwrap();
            meow_config::build_config(raw, None).await.unwrap()
        }

        #[tokio::test]
        async fn test_mode_vless_validation_accepts_a_matching_cert_pair() {
            let config = config_from_yaml(&tls_listener_yaml(TEST_CERT, TEST_KEY)).await;
            ensure_vless_security_valid(&config).unwrap();
        }

        #[tokio::test]
        async fn test_mode_vless_validation_rejects_a_mismatched_key() {
            let config = config_from_yaml(&tls_listener_yaml(TEST_CERT, MISMATCHED_KEY)).await;
            let err = ensure_vless_security_valid(&config).unwrap_err();
            assert!(err.to_string().contains("invalid vless security"), "{err}");
        }

        #[tokio::test]
        async fn test_mode_vless_validation_rejects_missing_cert_files() {
            let yaml = "listeners:\n  - name: vision-in\n    type: vless\n    port: 0\n    certificate: missing-vless-cert.pem\n    private-key: missing-vless-key.pem\n    users:\n      - username: alice\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-vision\n";
            let config = config_from_yaml(yaml).await;
            assert!(ensure_vless_security_valid(&config).is_err());
        }

        #[tokio::test]
        async fn test_mode_vless_validation_accepts_reality_and_rejects_short_id_overflow() {
            let valid = "listeners:\n  - name: vision-in\n    type: vless\n    port: 0\n    reality-config:\n      dest: \"localhost:443\"\n      private-key: \"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo\"\n      short-id: [\"0123456789abcdef\"]\n      server-names: [\"localhost\"]\n    users:\n      - username: alice\n        uuid: \"71884bd4-d6a0-4e19-9895-3e1d8b469317\"\n        flow: xtls-rprx-vision\n";
            let config = config_from_yaml(valid).await;
            ensure_vless_security_valid(&config).unwrap();

            let ids = (0..65)
                .map(|i| format!("\"{i:015x}1\""))
                .collect::<Vec<_>>()
                .join(", ");
            let overflow = valid.replace(
                "\"0123456789abcdef\"",
                &format!("\"0123456789abcdef\", {ids}"),
            );
            // Config parsing itself rejects the overflow, so the runtime
            // validation layer can never observe it through the load path.
            let raw = meow_config::parse_raw_yaml(&overflow).unwrap();
            let Err(err) = meow_config::build_config(raw, None).await else {
                panic!("65 short ids must be rejected at config build time");
            };
            assert!(err.to_string().contains("at most 64 entries"), "{err}");
        }
    }
}
