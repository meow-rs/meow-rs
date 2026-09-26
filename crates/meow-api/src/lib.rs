//! REST API server (Axum) for the meow-rs proxy kernel.
//!
//! Runtime control of proxies, rules, connections, config, traffic, and DNS,
//! plus the built-in web dashboard.

pub mod log_stream;
pub mod routes;
pub mod ui;

use dashmap::DashMap;
use log_stream::LogMessage;
use meow_config::{
    proxy_provider::ProxyProvider, raw::RawConfig, rule_provider::RuleProvider, NamedListener,
};
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};

/// How long to wait for the TUN readiness signal (device creation + stack
/// init + child-task setup) before treating the listener as failed to
/// start. Shared between the startup path (`meow-app/src/main.rs`) and the
/// config-reload path (`routes.rs::spawn_tun_from_raw`) so the two don't
/// drift.
///
/// Setup *failures* return immediately via `TunReady::Failed` — this bound
/// only covers genuine hangs and legitimately slow startups: wintun adapter
/// creation, first-time driver install, and the PowerShell DNS backup/set
/// can together take minutes on slow Windows machines (5 s and 30 s both
/// proved too aggressive there; 300 s measured comfortable in practice).
/// Trade-off to be aware of: the config-reload path awaits this inside the
/// `CONFIG_MUTATION` lane, so a hung startup blocks every config-mutation
/// API call for the full duration — including `POST /api/config/save`,
/// which queues behind the same lane (issue #543). The stop/restart side
/// adds its own lane-held wait: `DnsGuard::drop` runs the Windows
/// PowerShell DNS restore synchronously on the listener task before
/// `stop_tun`'s 10 s reap bound even applies.
pub const TUN_STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Map a parsed `TunConfig` onto a `TunListenerConfig`. Shared between the
/// startup path (`meow-app/src/main.rs`) and the config-reload path
/// (`routes.rs::spawn_tun_from_raw`) so the two don't drift.
#[cfg(feature = "listener-tun")]
pub fn tun_config_to_listener_config(
    tun: &meow_config::TunConfig,
) -> meow_listener::TunListenerConfig {
    meow_listener::TunListenerConfig {
        device: tun.device.clone(),
        mtu: tun.mtu,
        inet4_address: tun.inet4_address,
        auto_route: tun.auto_route,
        route_scope: match tun.route_mode {
            meow_config::TunRouteMode::FakeIp => meow_listener::TunRouteScope::FakeIp,
            meow_config::TunRouteMode::Global => meow_listener::TunRouteScope::Global,
        },
        outbound_interface: tun.outbound_interface.clone(),
        dns_hijack: tun.dns_hijack,
        udp_timeout: tun.udp_timeout,
        max_connections: tun.max_connections,
    }
}

pub struct ApiServer {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    secret: Option<String>,
    config_path: String,
    raw_config: Arc<RwLock<RawConfig>>,
    log_tx: broadcast::Sender<LogMessage>,
    proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>>,
    rule_providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
    /// Shared supervisor the API commit paths reconcile after every
    /// registry swap (issue #543).
    rule_provider_refresh: Arc<meow_config::rule_provider_refresh::RefreshSupervisor>,
    /// Shared supervisor the commit paths reconcile so `proxy-providers`
    /// `interval:` declarations gain/lose their refresh task (issue #625).
    proxy_provider_refresh:
        Arc<meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor>,
    listeners: Vec<NamedListener>,
    external_ui: Option<PathBuf>,
    /// Shared handle the embedder fills once the standalone DNS server is
    /// spawned; `PUT /configs` rebinds or hot-swaps it (issue #514).
    dns_server: Arc<RwLock<Option<routes::DnsServerHandle>>>,
    /// Provider-dialer cell `PUT /configs` rebuilds hand to newly declared
    /// providers (issue #489).
    provider_dialer_registry: meow_proxy::dialer::ProxyRegistry,
}

impl ApiServer {
    #[allow(
        clippy::too_many_arguments,
        reason = "startup wiring funnel: every arg is an independently owned \
                  runtime handle assembled in main; bundling them into a \
                  params struct would only rename the same arity"
    )]
    pub fn new(
        tunnel: Tunnel,
        listen_addr: SocketAddr,
        secret: Option<String>,
        config_path: String,
        raw_config: Arc<RwLock<RawConfig>>,
        log_tx: broadcast::Sender<LogMessage>,
        proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>>,
        rule_providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
        rule_provider_refresh: Arc<meow_config::rule_provider_refresh::RefreshSupervisor>,
        proxy_provider_refresh: Arc<
            meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor,
        >,
        listeners: Vec<NamedListener>,
        external_ui: Option<PathBuf>,
        dns_server: Arc<RwLock<Option<routes::DnsServerHandle>>>,
        provider_dialer_registry: meow_proxy::dialer::ProxyRegistry,
    ) -> Self {
        Self {
            tunnel,
            listen_addr,
            secret,
            config_path,
            raw_config,
            log_tx,
            proxy_providers,
            rule_providers,
            rule_provider_refresh,
            proxy_provider_refresh,
            listeners,
            external_ui,
            dns_server,
            provider_dialer_registry,
        }
    }

    /// Bind and serve in one call. Kept for callers that await `run()`
    /// directly and can observe its error; embedders that spawn the serve
    /// loop should bind themselves and use [`Self::run_on`] so bind
    /// failures surface at startup instead of inside a detached task.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = tokio::net::TcpListener::bind(self.listen_addr).await?;
        self.run_on(listener).await
    }

    /// Serve on a pre-bound listener (issue #641 — the startup path binds
    /// eagerly so `EADDRINUSE` is a hard error, not a dead spawned task).
    pub async fn run_on(
        &self,
        listener: tokio::net::TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = Arc::new(routes::AppState {
            tunnel: self.tunnel.clone(),
            secret: self.secret.clone(),
            config_path: self.config_path.clone(),
            raw_config: Arc::clone(&self.raw_config),
            log_tx: self.log_tx.clone(),
            proxy_providers: Arc::clone(&self.proxy_providers),
            rule_providers: Arc::clone(&self.rule_providers),
            rule_provider_refresh: Arc::clone(&self.rule_provider_refresh),
            proxy_provider_refresh: Arc::clone(&self.proxy_provider_refresh),
            listeners: self.listeners.clone(),
            external_ui: self.resolve_external_ui(),
            traffic_feed: Default::default(),
            dns_server: Arc::clone(&self.dns_server),
            provider_dialer_registry: self.provider_dialer_registry.clone(),
        });

        let app = routes::create_router(state);

        let bound = listener.local_addr().unwrap_or(self.listen_addr);
        info!("REST API listening on {bound}");
        info!("Web UI available at http://{bound}/ui");
        axum::serve(listener, app).await?;
        Ok(())
    }

    /// Validate the configured external-UI directory. Returns the path only when
    /// it exists as a directory; otherwise logs a warning and falls back to the
    /// built-in panel (issue #223).
    fn resolve_external_ui(&self) -> Option<PathBuf> {
        let dir = self.external_ui.as_ref()?;
        if dir.is_dir() {
            info!("Serving external Web UI from {}", dir.display());
            Some(dir.clone())
        } else {
            warn!(
                "external-ui directory {} not found; serving the built-in panel instead",
                dir.display()
            );
            None
        }
    }
}
