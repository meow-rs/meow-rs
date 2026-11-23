//! REST API server (Axum) for the meow-rs proxy kernel.
//!
//! Runtime control of proxies, rules, connections, config, traffic, and DNS,
//! plus the built-in web dashboard.

pub mod cors;
pub mod endpoint;
pub mod log_stream;
mod logbook;
pub mod routes;
mod storage;
pub use storage::{UiStorage, UiStorageSlot};
mod traffic_ledger;
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
        inet6_address: tun.inet6_address,
        auto_route: tun.auto_route,
        route_scope: match tun.route_mode {
            meow_config::TunRouteMode::FakeIp => meow_listener::TunRouteScope::FakeIp,
            meow_config::TunRouteMode::Global => meow_listener::TunRouteScope::Global,
        },
        outbound_interface: tun.outbound_interface.clone(),
        dns_hijack: tun.dns_hijack,
        udp_timeout: tun.udp_timeout,
        max_connections: tun.max_connections,
        stack: match tun.stack {
            meow_config::TunStack::Lwip => meow_listener::TunStack::Lwip,
            meow_config::TunStack::System => meow_listener::TunStack::System,
        },
    }
}

/// The TUN listener's outbound-interface binding — or an uninhabited
/// stand-in in builds without the `listener-tun` feature, where no TUN
/// (and so no global route scope) can run.
#[cfg(feature = "listener-tun")]
pub(crate) type OutboundBinding = meow_listener::OutboundBinding;
#[cfg(not(feature = "listener-tun"))]
pub(crate) type OutboundBinding = std::convert::Infallible;

/// A `tun.auto-route: global` outbound-interface binding installed for a
/// configuration *before* its first dial (issue #695), as returned by
/// [`preinstall_global_route_binding`]. Holding it keeps the binding in
/// effect; handing it to the TUN listener the configuration spawns keeps it
/// in effect for as long as the listener's routes exist; dropping it gives
/// it up, which restores the binding of a still-running older owner (the
/// previous configuration's listener) or clears it when there is none.
#[must_use = "dropping it gives the pre-installed binding up immediately"]
#[derive(Debug, Default)]
pub struct PreinstalledBinding {
    binding: Option<OutboundBinding>,
    interface_changed: bool,
}

impl PreinstalledBinding {
    /// Whether a binding was installed: the configuration selects an
    /// enabled TUN with `auto-route: global` and the install succeeded.
    pub fn is_installed(&self) -> bool {
        self.binding.is_some()
    }

    /// Whether installing the binding changed the interface in effect —
    /// none was bound (`None → Some(Y)`) or another one was
    /// (`Some(X) → Some(Y ≠ X)`). Sockets and pooled sessions created
    /// before such a transition are not bound to `Y`: they stay unbound
    /// (or bound to `X`) for life, and once global routes steer through
    /// the TUN their traffic can loop into it. `false` when nothing was
    /// installed. Read before installing, so a mutation must evaluate it
    /// under the `CONFIG_MUTATION` lane it installed in.
    pub fn interface_changed(&self) -> bool {
        self.interface_changed
    }

    /// The binding, for `TunListener::with_outbound_binding`.
    #[cfg(feature = "listener-tun")]
    pub fn into_binding(self) -> Option<meow_listener::OutboundBinding> {
        self.binding
    }

    /// Move the binding out (into a TUN listener) while keeping
    /// [`Self::interface_changed`] readable.
    pub(crate) fn take_binding(&mut self) -> Option<OutboundBinding> {
        self.binding.take()
    }
}

/// When [`preinstall_global_route_binding`] runs — which arm of `raw` may
/// select the binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreinstallScope {
    /// Process startup: the sole effective TUN may come from the `tun:`
    /// section or a named `listeners: type: tun` entry — both are
    /// consulted, `tun:` first
    /// ([`meow_config::named_tun_global_route_interface`]).
    Startup,
    /// A live-config mutation (PUT/PATCH and every candidate commit): only
    /// the `tun:` section may install. A staged named entry takes effect on
    /// the next boot — installing its interface now would retarget live
    /// egress for a device that does not run (and may never run). And
    /// while a named TUN owns the running slot, no mutation may displace
    /// its binding at all.
    Mutation { named_tun_running: bool },
}

/// Install the `tun.auto-route: global` outbound-interface binding for `raw`
/// before anything dials on its behalf (issue #695).
///
/// The binding is per-socket and applied at creation, so a socket opened
/// before it exists stays unbound for life and loops into the TUN once the
/// split default routes go in. Every dial a configuration triggers before
/// its TUN listener comes up must therefore see the binding already: at
/// startup the config build's ECH / provider / geodata fetches and
/// everything `run()` starts ahead of the listener; on a config reload
/// (`PUT /configs` and every other mutation that commits a candidate) the
/// candidate's ECH pre-resolution, the rebuild's provider fetches with the
/// new adapters, the DNS rebuild, and any dial routed through the new
/// adapters once the route swap publishes them. The (re)spawned listener
/// adopts the returned binding (`TunListener::with_outbound_binding`)
/// instead of installing its own, so the binding stays in effect without
/// a gap across a listener restart.
///
/// The registry is owner-aware (`meow_common::OutboundIfaceGuard`): this
/// install supersedes a running listener's binding without invalidating it.
/// If the mutation is rejected the returned value is dropped and the
/// listener's binding is back in effect; if it commits a restart, the old
/// listener's teardown does not disturb this one.
///
/// A no-op (default value) unless `raw` and `scope` select an enabled TUN
/// in global route scope (`auto-route` unset, `true` or `global`) —
/// TUN-off, fake-IP-scope and `auto-route: false` configs are untouched.
/// An install failure is not fatal here: the listener retries before it
/// touches any route and fails closed with the same error, exactly as
/// before, and until then no global route exists for a socket to loop on.
/// API callers must hold the `CONFIG_MUTATION` lane (the registry's
/// before/after comparison and the install must not interleave with a
/// sibling mutation's).
#[cfg(feature = "listener-tun")]
pub fn preinstall_global_route_binding(
    raw: &RawConfig,
    scope: PreinstallScope,
) -> PreinstalledBinding {
    let iface = match scope {
        PreinstallScope::Startup => meow_config::global_route_outbound_interface(raw.tun.as_ref())
            .or_else(|| meow_config::named_tun_global_route_interface(raw)),
        PreinstallScope::Mutation {
            named_tun_running: false,
        } => meow_config::global_route_outbound_interface(raw.tun.as_ref()),
        // A running named TUN owns its binding until restart.
        PreinstallScope::Mutation {
            named_tun_running: true,
        } => None,
    };
    let Some(iface) = iface else {
        return PreinstalledBinding::default();
    };
    let previous = meow_common::outbound_interface();
    match meow_listener::OutboundBinding::install(iface.as_deref()) {
        Ok(binding) => PreinstalledBinding {
            interface_changed: previous.as_deref() != Some(binding.interface()),
            binding: Some(binding),
        },
        Err(e) => {
            tracing::debug!(
                "early outbound-interface binding failed ({e}); the TUN listener retries \
                 before installing routes"
            );
            PreinstalledBinding::default()
        }
    }
}

/// Without the `listener-tun` feature no TUN can run, so there is never a
/// global-route binding to install.
#[cfg(not(feature = "listener-tun"))]
pub fn preinstall_global_route_binding(
    _raw: &RawConfig,
    _scope: PreinstallScope,
) -> PreinstalledBinding {
    PreinstalledBinding::default()
}

/// Which cargo feature a listener type needs, when the running binary did
/// not compile it. The gate is injected by the embedder (`meow-app` knows
/// its own feature set); the API alone cannot observe the binary's cargo
/// features.
pub type ListenerGate = fn(&meow_config::ListenerSpec) -> Option<&'static str>;

/// Default gate before [`set_listener_gate`] runs, and permanently for
/// tests/embedders that never install one: report every listener type
/// supported, preserving the pre-gate behaviour.
pub fn permissive_listener_gate(_spec: &meow_config::ListenerSpec) -> Option<&'static str> {
    None
}

/// The feature set is a property of the compiled binary, not of an
/// `ApiServer` instance — a process-global cell is the honest shape.
static LISTENER_GATE: std::sync::OnceLock<ListenerGate> = std::sync::OnceLock::new();

/// Install the binary's real listener-feature set (meow-app calls this at
/// startup). A second install keeps the first — the binary's features do
/// not change at runtime. Tests must not install a gate: `OnceLock` makes
/// it process-global, so one test's install would leak into every
/// sibling.
pub fn set_listener_gate(gate: ListenerGate) {
    let _ = LISTENER_GATE.set(gate);
}

/// The installed gate, or [`permissive_listener_gate`] when none was.
pub fn listener_gate() -> ListenerGate {
    LISTENER_GATE
        .get()
        .copied()
        .unwrap_or(permissive_listener_gate)
}

/// Fail when `named` declares a listener type the running binary cannot
/// serve, per `gate`.
///
/// Listener implementations are cargo-feature-gated (ADR-0007 size caps).
/// Before this check a missing feature only produced a startup `warn!`
/// and the declared port simply never listened — `-t` reported
/// "Configuration test passed" on a config whose inbound was dead on
/// arrival. Unknown *type names* already hard-error at parse; a
/// known-but-uncompiled type is the same severity (the listener cannot
/// exist), so it errors too.
///
/// Called by `meow -t` and the startup path after `load_config`, and by
/// the `PUT /configs` gate (on `resolve_named_listeners`' output) so a
/// persisted `listeners:` section cannot wedge the next boot — unless
/// `force` is set, which logs-and-commits by design.
pub fn ensure_listeners_supported(
    named: &[NamedListener],
    gate: ListenerGate,
) -> Result<(), anyhow::Error> {
    let missing: Vec<String> = named
        .iter()
        .filter_map(|l| {
            gate(&l.spec).map(|feature| {
                format!(
                    "'{}' (type {}, needs feature '{feature}')",
                    l.name,
                    l.spec.type_name()
                )
            })
        })
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "listener(s) require cargo features this build lacks: {} — \
         rebuild with the named feature(s) or remove the listener entries",
        missing.join(", ")
    )
}

pub struct ApiServer {
    /// The plain `external-controller` TCP address, when configured — the
    /// only endpoint whose bind is startup-fatal (issue #974).
    listen_addr: Option<SocketAddr>,
    /// The shared router state built once in [`Self::new`]: every
    /// configured transport — plain TCP, `external-controller-tls`,
    /// `external-controller-unix`, `external-controller-pipe` — serves a
    /// clone of the router over this one `AppState` (issue #974).
    state: Arc<routes::AppState>,
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
        listen_addr: Option<SocketAddr>,
        secret: Option<String>,
        cors: meow_config::ApiCorsConfig,
        config_path: Option<String>,
        raw_config: Arc<RwLock<RawConfig>>,
        log_tx: broadcast::Sender<LogMessage>,
        proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>>,
        rule_providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
        rule_provider_refresh: Arc<meow_config::rule_provider_refresh::RefreshSupervisor>,
        proxy_provider_refresh: Arc<
            meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor,
        >,
        listeners: Vec<NamedListener>,
        external_ui: Option<&std::path::Path>,
        dns_server: Arc<RwLock<Option<routes::DnsServerHandle>>>,
        provider_dialer_registry: meow_proxy::dialer::ProxyRegistry,
        ntp_reconcile: Option<routes::NtpReconcile>,
    ) -> Self {
        Self {
            listen_addr,
            state: Arc::new(routes::AppState {
                tunnel,
                secret,
                config_path,
                raw_config,
                log_tx,
                proxy_providers,
                rule_providers,
                rule_provider_refresh,
                proxy_provider_refresh,
                listeners,
                external_ui: resolve_external_ui(external_ui),
                traffic_feed: Default::default(),
                dns_server,
                ui_storage: Default::default(),
                provider_dialer_registry,
                ntp_reconcile,
                cors,
            }),
        }
    }

    /// A fresh router over the shared state — one per configured endpoint
    /// transport (issue #974). Routes, auth and the CORS middleware are
    /// identical on all of them.
    pub fn router(&self) -> axum::Router {
        routes::create_router(Arc::clone(&self.state))
    }

    /// Bind and serve the plain `external-controller` TCP listener in one
    /// call. Kept for callers that await `run()` directly and can observe
    /// its error; embedders that spawn the serve loop should bind
    /// themselves and use [`Self::run_on`] so bind failures surface at
    /// startup instead of inside a detached task.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = self
            .listen_addr
            .ok_or("external-controller is not configured")?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        self.run_on(listener).await
    }

    /// Serve one already-bound endpoint — TLS, Unix socket or named pipe —
    /// over the shared router (issue #974). Keeps `axum` out of the
    /// embedder's hands.
    pub async fn serve_on<L>(&self, listener: L) -> std::io::Result<()>
    where
        L: axum::serve::Listener,
        L::Addr: std::fmt::Debug,
    {
        axum::serve(listener, self.router()).await
    }

    /// `serve_on` for `external-controller-tls`: the router clone carries
    /// the [`routes::TlsTransport`] marker so the no-secret origin guard
    /// sees the `https` scheme the decrypted bytes can't express
    /// (issue #974).
    pub async fn serve_tls_on<L>(&self, listener: L) -> std::io::Result<()>
    where
        L: axum::serve::Listener,
        L::Addr: std::fmt::Debug,
    {
        let app = self
            .router()
            .layer(axum::middleware::from_fn(routes::mark_tls_transport));
        axum::serve(listener, app).await
    }

    /// Serve on a pre-bound listener (issue #641 — the startup path binds
    /// eagerly so `EADDRINUSE` is a hard error, not a dead spawned task).
    pub async fn run_on(
        &self,
        listener: tokio::net::TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app = self.router();

        let bound = listener
            .local_addr()
            .ok()
            .or(self.listen_addr)
            .map_or_else(|| "<unknown>".to_string(), |a| a.to_string());
        info!("REST API listening on {bound}");
        info!("Web UI available at http://{bound}/ui");
        axum::serve(listener, app).await?;
        Ok(())
    }
}

/// Validate the configured external-UI directory. Returns the path only when
/// it exists as a directory; otherwise logs a warning and falls back to the
/// built-in panel (issue #223).
fn resolve_external_ui(dir: Option<&std::path::Path>) -> Option<PathBuf> {
    let dir = dir?;
    if dir.is_dir() {
        info!("Serving external Web UI from {}", dir.display());
        Some(dir.to_path_buf())
    } else {
        warn!(
            "external-ui directory {} not found; serving the built-in panel instead",
            dir.display()
        );
        None
    }
}
