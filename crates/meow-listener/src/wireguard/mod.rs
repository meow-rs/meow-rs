//! WireGuard inbound listener (`listeners:` entry `type: wireguard`).
//!
//! meow is the WireGuard *responder* here: it binds one UDP socket and
//! serves a static peer table. Each peer owns a vendored-boringtun
//! [`meow_wireguard::Tunn`]; a handshake initiation is dispatched by the
//! peer public key it decrypts to, every other packet by the
//! `receiver_idx >> 8` slot namespace (see `demux.rs`). Decrypted inner
//! IPv4/IPv6 packets are terminated in userspace — TCP by a smoltcp
//! `Interface` behind a lazy per-(peer, dport) listen pool, UDP by a
//! per-flow `dial_udp` task — and routed through the normal tunnel, so
//! the listener is semantically a TUN inbound carried over WireGuard
//! (the sing-box `wireguard` inbound's shape).
//!
//! Everything smoltcp and every `Tunn` lives on one dedicated actor
//! thread running a current-thread Tokio runtime — the same actor
//! pattern as the outbound pump (`meow-proxy/src/wireguard/pump.rs`).
//! Only the `Send` pieces cross: the bound std socket, the typed config,
//! the tunnel handle, and mpsc channels for conn/flow payload. Routing
//! tasks (TCP `route_inbound_tcp`, UDP flow loops) are spawned back onto
//! the main runtime through the `Handle` captured at [`spawn`](WireGuardListener::spawn).

mod actor;
mod demux;
mod inner_udp;
mod peer;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use meow_tunnel::Tunnel;
use smol_str::SmolStr;
use tracing::debug;

use crate::sniffer::SnifferRuntime;

/// Listener-facing spec for one `type: wireguard` listener, mapped
/// from `meow_config::WgListenerConfig` by the app layer — the same
/// ctor-args boundary `TunListenerConfig` keeps between meow-config
/// and meow-listener (this crate never takes a meow-config type).
///
/// `Debug` is hand-rolled so `private_key`/`preshared_key` stay
/// out of logs.
#[derive(Clone)]
pub struct WgListenerSpec {
    /// Listener static private key, 32 bytes. Never logged.
    pub private_key: [u8; 32],
    /// Static peer table — at least one entry (config validation
    /// guarantees it; the demux rejects an overflowing table).
    pub peers: Vec<WgPeerSpec>,
    /// Outer (wire) MTU; `inner_mtu = mtu - 64` floors at 576.
    pub mtu: u16,
    /// `false` silently drops inner UDP datagrams.
    pub udp: bool,
    /// Inner UDP flow idle timeout.
    pub udp_timeout: Duration,
}

/// One static peer of the listener — the app-mapped copy of
/// `meow_config::WgPeerConfig`.
#[derive(Clone)]
pub struct WgPeerSpec {
    /// Peer static public key — the handshake demux key; must be unique
    /// inside the table (config validation guarantees it).
    pub public_key: [u8; 32],
    /// Optional pre-shared symmetric key (Noise psk mixing). Never logged.
    pub preshared_key: Option<[u8; 32]>,
    /// Inbound inner-source-IP ACL — non-empty after validation.
    pub allowed_ips: Vec<ipnet::IpNet>,
    /// Log/diagnostic label only (`peer-<index>` when unnamed).
    pub name: SmolStr,
    /// WARP-style 3-byte `reserved` field stamped onto wire datagrams
    /// headed to this peer; inbound reserved bytes are cleared
    /// regardless.
    pub reserved: Option<[u8; 3]>,
}

impl std::fmt::Debug for WgListenerSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgListenerSpec")
            .field("private_key", &"[REDACTED]")
            .field("peers", &self.peers)
            .field("mtu", &self.mtu)
            .field("udp", &self.udp)
            .field("udp_timeout", &self.udp_timeout)
            .finish()
    }
}

impl std::fmt::Debug for WgPeerSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgPeerSpec")
            .field("public_key", &self.public_key)
            .field("preshared_key", &self.preshared_key.map(|_| "[REDACTED]"))
            .field("allowed_ips", &self.allowed_ips)
            .field("name", &self.name)
            .field("reserved", &self.reserved)
            .finish()
    }
}

/// `type: wireguard` named listener — see the module docs for the shape.
///
/// Constructed on the app (multi-threaded) runtime; [`Self::spawn`]
/// hands the bound UDP socket to the actor thread the returned
/// [`WireGuardListenerGuard`] owns.
pub struct WireGuardListener {
    tunnel: Tunnel,
    cfg: WgListenerSpec,
    name: String,
    max_connections: usize,
    sniffer: Option<Arc<SnifferRuntime>>,
}

/// Owning handle for a running WG listener. `shutdown()` (or drop)
/// stops the actor; [`Self::wait`] joins the thread and reports a
/// listener-level failure.
pub struct WireGuardListenerGuard {
    shutdown: tokio::sync::mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WireGuardListener {
    /// `tunnel` is the shared routing engine — the actor clones its
    /// `Arc<TunnelInner>` into every spawned TCP route task and UDP flow.
    pub fn new(tunnel: Tunnel, cfg: WgListenerSpec, name: String) -> Self {
        Self {
            tunnel,
            cfg,
            name,
            max_connections: 0,
            sniffer: None,
        }
    }

    /// Single cap over inner TCP connections + UDP flows combined
    /// (`max-connections`; `0` = unlimited) — the shadowsocks/TProxy
    /// listener precedent.
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// The global sniffer: a ClientHello/`Host` first payload names the
    /// flow before rule matching, same as the TUN inbound's TCP tail.
    pub fn with_sniffer(mut self, rt: Arc<SnifferRuntime>) -> Self {
        self.sniffer = Some(rt);
        self
    }

    /// Bind the listener's endpoint UDP socket. The app does this before
    /// spawning so a `port: 0` resolves to its real port for the
    /// `GET /listeners` snapshot — the same bind-before-spawn contract
    /// the TCP listeners follow. Nonblocking is set here; the actor
    /// wraps the socket in tokio and enlarges its receive buffer.
    pub fn bind(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    }

    /// Spawn the dedicated actor thread. Everything smoltcp or `Tunn`
    /// touches is built inside the thread (the `spawn_pump` precedent);
    /// only the connected std socket and plain data cross.
    pub fn spawn(self, std_sock: std::net::UdpSocket) -> std::io::Result<WireGuardListenerGuard> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
        // `Handle::current` is the app runtime: routing and DNS work
        // spawned by the actor lands on the multi-thread pool rather
        // than serializing behind the single-threaded wire loop.
        let main_rt = tokio::runtime::Handle::current();
        let thread_name = format!("wg-listener-{}", self.name);
        let name = self.name.clone();
        let thread = std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::warn!(
                            "wireguard listener '{name}': tokio runtime build failed: {e}"
                        );
                        return;
                    }
                };
                rt.block_on(async move {
                    match actor::WgActor::new(self, std_sock, shutdown_rx, main_rt) {
                        Ok(actor) => actor.run().await,
                        Err(e) => {
                            tracing::warn!("wireguard listener '{name}': init failed: {e}");
                        }
                    }
                });
            })?;
        Ok(WireGuardListenerGuard {
            shutdown: shutdown_tx,
            thread: Some(thread),
        })
    }
}

impl WireGuardListenerGuard {
    /// Ask the actor to stop — nonblocking and idempotent. The actor's
    /// own `Drop` closes every conn channel and UDP flow with it.
    pub fn shutdown(&self) {
        let _ = self.shutdown.try_send(());
    }

    /// Wait for the actor thread to exit. The join runs on a blocking
    /// thread so a long-lived runtime worker is not parked on it.
    pub async fn wait(mut self) -> std::io::Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        match tokio::task::spawn_blocking(move || thread.join()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(std::io::Error::other("wireguard listener actor panicked")),
            Err(e) => Err(std::io::Error::other(format!(
                "wireguard listener join failed: {e}"
            ))),
        }
    }
}

impl Drop for WireGuardListenerGuard {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(thread) = self.thread.take() {
            // A blocking join inside a tokio worker would stall it — the
            // pump reaps its thread on a throwaway thread instead.
            std::thread::spawn(move || {
                if let Err(e) = thread.join() {
                    debug!("wireguard listener actor join failed: {e:?}");
                }
            });
        }
    }
}
