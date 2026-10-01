//! Single-owner lwIP core.
//!
//! Every call into the lwIP C library happens inside [`LwipCore`], which is
//! driven by exactly one tokio task (spawned in `NetStack::with_buffer_size`).
//! Handles (`NetStack`, `TcpStream`, `TcpListener`, `UdpSocket`) never touch C
//! state — they exchange data and commands with the core over channels. This
//! replaces the old global `LWIP_MUTEX` design, which took a spin-then-yield
//! lock on every entry point from arbitrary threads and produced an entire
//! family of production wedges: spin-livelock on small worker pools, a guard
//! legally held across `Pending` (parking the lock forever if the holder's
//! waker was lost), QoS priority inversion between runtimes, and use-after-free
//! when a handle's `Drop` raced a callback. With single ownership there is no
//! lock, so none of those failure modes exist.
//!
//! Threading model: lwIP is built `NO_SYS=1` (no OS integration, no TLS), so
//! its only requirement is that calls are serialized. The core task provides
//! that: tokio polls a task on one thread at a time and provides happens-before
//! between polls, so the C globals may migrate between worker threads but are
//! never touched concurrently. C-side callbacks (accept/recv/sent/err/poll,
//! udp recv, netif output) only ever fire inside the core's own C calls —
//! i.e. on the core task — so they may safely push into channels and the
//! command queue.
//!
//! Consumer contract (unchanged from the mutex design, now enforced in one
//! place): at most ONE live stack generation per process. `lwip_init` runs
//! once per process and pcb lists/netif are process globals, so a new
//! generation must not be constructed until the previous core task has
//! finished tearing down — await [`NetStack::core_done`] after dropping the
//! stack handles.

use std::{collections::HashMap, net::SocketAddr, os::raw, time::Duration};

use log::*;
use tokio::sync::{
    mpsc::{error::TryRecvError, Receiver, Sender, UnboundedReceiver, UnboundedSender},
    watch,
};

use super::lwip::*;
use super::tcp_stream::TcpStream;
use super::util;

pub(crate) type StreamId = u64;

/// Max bytes handed to `tcp_write` per chunk travelling the per-stream write
/// channel. Together with [`WRITE_CHAN_CAP`] this bounds per-stream buffering
/// ahead of lwIP's own `TCP_SND_BUF`.
pub(crate) const WRITE_CHUNK: usize = 4096;
/// Per-stream write channel capacity, in chunks.
pub(crate) const WRITE_CHAN_CAP: usize = 8;

/// Ordered per-stream commands. Travelling a dedicated bounded channel gives
/// the write path real backpressure (a full channel parks the writer via
/// `PollSender`'s waker) while keeping writes and half-close strictly ordered.
/// The channel closing (all handle-side senders dropped) is itself the
/// "handle gone — close the pcb" signal, so teardown cannot be lost to a full
/// queue.
pub(crate) enum StreamCmd {
    Write(Vec<u8>),
    /// Half-close TX (`tcp_shutdown(rx=0, tx=1)`), ordered after all writes.
    Shutdown,
}

/// Unordered control-plane commands, on one shared unbounded channel. All
/// variants are O(1) small and their volume is bounded by traffic or by
/// handle lifecycle events, so unbounded is safe — and it must be unbounded
/// because handles send from `poll_*` and `Drop`, where blocking or dropping
/// a command is not an option.
pub(crate) enum Cmd {
    /// Handle-side bookkeeping for a freshly accepted stream (created inside
    /// `tcp_accept_cb`); FIFO order guarantees the core sees this before any
    /// other command for the same id.
    NewStream {
        id: StreamId,
        pcb: usize,
        write_rx: Receiver<StreamCmd>,
        cbctx: usize,
        dead: std::sync::Arc<std::sync::atomic::AtomicBool>,
    },
    /// The handle pulled `n` bytes off its read channel — open the receive
    /// window. (Deferred `tcp_recved`: the window opens one core-loop
    /// iteration later than the old under-lock call, which lwIP is fine
    /// with.)
    Recved(StreamId, usize),
    /// The per-stream write channel has new data / was closed — drain it.
    Kick(StreamId),
    /// `tcp_sent_cb` fired — retry a parked chunk, then drain more.
    Sent(StreamId),
    /// `tcp_poll_cb` coarse tick — same retry opportunity as `Sent`.
    PollTick(StreamId),
    /// The pcb is no longer ours: `tcp_err_cb` fired (lwIP already freed
    /// it), or `tcp_recv_cb` handed a fully closed pcb back to lwIP with
    /// all callbacks detached. Either way, reap our side without touching
    /// the pcb.
    PcbErr(StreamId),
    /// The UDP out channel has new datagrams — drain it.
    UdpKick,
    /// `UdpSocket` handle dropped.
    RemoveUdp,
    /// `TcpListener` handle dropped.
    CloseListener,
}

/// Per-pcb callback context. `tcp_arg` points at a `Box`-stable instance;
/// callbacks (which only run on the core task, inside the core's C calls)
/// are the sole readers/writers, so plain mutation through the raw pointer is
/// race-free. Freed by the core when the pcb's callbacks are detached (or the
/// pcb died via `tcp_err_cb`).
pub(crate) struct CbCtx {
    id: StreamId,
    /// `None` after EOF-follow-up or error — mirrors the old design where
    /// dropping the sender closes the handle's read channel.
    read_tx: Option<UnboundedSender<Vec<u8>>>,
    cmd_tx: UnboundedSender<Cmd>,
    local_addr: SocketAddr,
    /// Set SYNCHRONOUSLY by `tcp_err_cb` (and by `tcp_recv_cb` when it hands
    /// a fully closed pcb back to lwIP), shared with the core's
    /// `StreamState`. When the err callback fires, lwIP has ALREADY freed the
    /// pcb — but Recved/Kick commands the handle queued before the resulting
    /// `PcbErr` are still ahead of it in the command FIFO. The core checks
    /// this flag before every C call on the pcb so those stale commands
    /// can't dereference a dangling pointer. (The old global-lock design got
    /// the same guarantee from checking `ctx.errored` under the mutex.)
    dead: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Context for the listener pcb: everything `tcp_accept_cb` needs to mint a
/// stream — id allocation, channel plumbing, and the accept queue.
pub(crate) struct ListenerCtx {
    next_id: StreamId,
    cmd_tx: UnboundedSender<Cmd>,
    accept_tx: UnboundedSender<(TcpStream, SocketAddr, SocketAddr)>,
}

/// Context the netif output hook pushes egress frames through. The old code
/// paired the try_send with a hand-rolled waker; the channel's own receiver
/// waker makes that redundant.
pub(crate) struct OutputCtx {
    egress_tx: Sender<Vec<u8>>,
}

/// `OUTPUT_CB_PTR`-style hook target. Only touched from the constructor
/// thread (before the core task exists) and the core task (teardown), under
/// the one-live-stack consumer contract.
pub(crate) static mut OUTPUT_PTR: usize = 0;

fn output(p: *mut pbuf) -> err_t {
    unsafe {
        if OUTPUT_PTR == 0 {
            return err_enum_t_ERR_ABRT as err_t;
        }
        let pbuflen = std::ptr::read_unaligned(p).tot_len;
        let mut buf = Vec::with_capacity(pbuflen as usize);
        pbuf_copy_partial(p, buf.as_mut_ptr() as *mut _, pbuflen, 0);
        buf.set_len(pbuflen as usize);
        let ctx = &*(OUTPUT_PTR as *const OutputCtx);
        // Egress saturation drops the frame (IP is allowed to; TCP
        // retransmits) — blocking here would wedge the whole core.
        let _ = ctx.egress_tx.try_send(buf);
        err_enum_t_ERR_OK as err_t
    }
}

#[allow(unused_variables)]
pub extern "C" fn output_ip4(netif: *mut netif, p: *mut pbuf, ipaddr: *const ip4_addr_t) -> err_t {
    output(p)
}

#[allow(unused_variables)]
pub extern "C" fn output_ip6(netif: *mut netif, p: *mut pbuf, ipaddr: *const ip6_addr_t) -> err_t {
    output(p)
}

// ---------------------------------------------------------------------------
// lwIP C callbacks — all run on the core task, inside the core's C calls.
// ---------------------------------------------------------------------------

#[allow(unused_variables)]
pub unsafe extern "C" fn tcp_recv_cb(
    arg: *mut raw::c_void,
    tpcb: *mut tcp_pcb,
    p: *mut pbuf,
    err: err_t,
) -> err_t {
    if arg.is_null() {
        warn!("tcp connection has been closed");
        return err_enum_t_ERR_CONN as err_t;
    }
    let ctx = &mut *(arg as *mut CbCtx);

    if p.is_null() {
        trace!("netstack tcp eof {}", ctx.local_addr);
        // Empty Vec is the EOF marker, queued behind any undrained data so a
        // handle mid-read sees that data first.
        if let Some(tx) = ctx.read_tx.as_ref() {
            let _ = tx.send(Vec::new());
        }
        // If our FIN already went out (`Cmd::Shutdown`), this peer FIN put
        // the pcb in TIME_WAIT, or in CLOSING on its way there (lwIP moves
        // the state before delivering EOF; FIN_WAIT_1/2 are listed only
        // defensively). lwIP frees a TIME_WAIT pcb WITHOUT calling `errf`:
        // `tcp_kill_timewait()` when `tcp_alloc` runs out of pcbs, and
        // `tcp_slowtmr()` after 2*TCP_MSL. `dead` would never be set, and a
        // later drop of the handle would run `tcp_arg`/`tcp_close` on a memp
        // slot that may already belong to an unrelated connection. Both
        // directions are finished, so hand the pcb to lwIP now: detach every
        // callback, mark it dead and have the core forget it. What remains
        // (retransmitting unacked data and our FIN, then TIME_WAIT) is
        // driven by lwIP's own input and timers and needs no calls from us.
        // Dropping `read_tx` is safe: the receiver yields the queued data
        // and EOF marker before it reports the closed channel.
        let state = std::ptr::read_unaligned(std::ptr::addr_of!((*tpcb).state));
        if state == tcp_state_FIN_WAIT_1
            || state == tcp_state_FIN_WAIT_2
            || state == tcp_state_CLOSING
            || state == tcp_state_TIME_WAIT
        {
            tcp_arg(tpcb, std::ptr::null_mut());
            tcp_recv(tpcb, None);
            tcp_sent(tpcb, None);
            tcp_err(tpcb, None);
            tcp_poll(tpcb, None, 0);
            ctx.dead.store(true, std::sync::atomic::Ordering::Release);
            let _ = ctx.read_tx.take();
            let _ = ctx.cmd_tx.send(Cmd::PcbErr(ctx.id));
        }
        return err_enum_t_ERR_OK as err_t;
    }

    let pbuflen = std::ptr::read_unaligned(p).tot_len;
    let mut buf = Vec::with_capacity(pbuflen as usize);
    pbuf_copy_partial(p, buf.as_mut_ptr() as _, pbuflen, 0);
    buf.set_len(pbuflen as usize);

    if !buf.is_empty() {
        if let Some(tx) = ctx.read_tx.as_ref() {
            let _ = tx.send(buf);
        }
    }

    pbuf_free(p);
    err_enum_t_ERR_OK as err_t
}

#[allow(unused_variables)]
pub extern "C" fn tcp_sent_cb(arg: *mut raw::c_void, tpcb: *mut tcp_pcb, len: u16_t) -> err_t {
    if arg.is_null() {
        return err_enum_t_ERR_OK as err_t;
    }
    let ctx = unsafe { &*(arg as *const CbCtx) };
    let _ = ctx.cmd_tx.send(Cmd::Sent(ctx.id));
    err_enum_t_ERR_OK as err_t
}

#[allow(unused_variables)]
pub extern "C" fn tcp_err_cb(arg: *mut raw::c_void, err: err_t) {
    if arg.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(arg as *mut CbCtx) };
    trace!("netstack tcp err {} {}", err, ctx.local_addr);
    // Order matters: mark the pcb dead FIRST, synchronously, so any
    // Recved/Kick commands already queued ahead of our PcbErr can't reach a
    // C call on the freed pcb. Then close the read channel (surfaces
    // BrokenPipe to a parked reader) and let the core reap its side.
    ctx.dead.store(true, std::sync::atomic::Ordering::Release);
    let _ = ctx.read_tx.take();
    let _ = ctx.cmd_tx.send(Cmd::PcbErr(ctx.id));
}

#[allow(unused_variables)]
pub extern "C" fn tcp_poll_cb(arg: *mut raw::c_void, tpcb: *mut tcp_pcb) -> err_t {
    if arg.is_null() {
        return err_enum_t_ERR_OK as err_t;
    }
    let ctx = unsafe { &*(arg as *const CbCtx) };
    let _ = ctx.cmd_tx.send(Cmd::PollTick(ctx.id));
    err_enum_t_ERR_OK as err_t
}

#[allow(unused_variables)]
pub extern "C" fn tcp_accept_cb(arg: *mut raw::c_void, newpcb: *mut tcp_pcb, err: err_t) -> err_t {
    if arg.is_null() {
        warn!("tcp listener has been closed");
        return err_enum_t_ERR_CONN as err_t;
    }
    if newpcb.is_null() {
        warn!("tcp full");
        return err_enum_t_ERR_OK as err_t;
    }
    if err != err_enum_t_ERR_OK as err_t {
        warn!("accept tcp failed: {}", err);
        return err_enum_t_ERR_OK as err_t;
    }
    let listener = unsafe { &mut *(arg as *mut ListenerCtx) };
    listener.next_id += 1;
    let id = listener.next_id;

    let (read_tx, read_rx) = tokio::sync::mpsc::unbounded_channel();
    let (write_tx, write_rx) = tokio::sync::mpsc::channel(WRITE_CHAN_CAP);
    let dead = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let (src_addr, dest_addr) = unsafe {
        let pcb_v = std::ptr::read_unaligned(newpcb);
        (
            util::to_socket_addr(&pcb_v.remote_ip, pcb_v.remote_port),
            util::to_socket_addr(&pcb_v.local_ip, pcb_v.local_port),
        )
    };

    let cbctx = Box::into_raw(Box::new(CbCtx {
        id,
        read_tx: Some(read_tx),
        cmd_tx: listener.cmd_tx.clone(),
        local_addr: src_addr,
        dead: dead.clone(),
    }));

    unsafe {
        tcp_arg(newpcb, cbctx as *mut raw::c_void);
        tcp_recv(newpcb, Some(tcp_recv_cb));
        tcp_sent(newpcb, Some(tcp_sent_cb));
        tcp_err(newpcb, Some(tcp_err_cb));
        tcp_poll(newpcb, Some(tcp_poll_cb), 8 as _);
        apply_pcb_opts(newpcb);
    }
    trace!("netstack tcp new {}", src_addr);

    // FIFO on cmd_tx guarantees the core registers the stream before any
    // Recved/Kick the new handle can produce.
    let _ = listener.cmd_tx.send(Cmd::NewStream {
        id,
        pcb: newpcb as usize,
        write_rx,
        cbctx: cbctx as usize,
        dead,
    });
    let stream = TcpStream::new(
        id,
        src_addr,
        dest_addr,
        read_rx,
        write_tx,
        listener.cmd_tx.clone(),
    );
    let _ = listener.accept_tx.send((stream, src_addr, dest_addr));

    err_enum_t_ERR_OK as err_t
}

pub unsafe extern "C" fn udp_recv_cb(
    arg: *mut raw::c_void,
    _pcb: *mut udp_pcb,
    p: *mut pbuf,
    addr: *const ip_addr_t,
    port: u16_t,
    dst_addr: *const ip_addr_t,
    dst_port: u16_t,
) {
    if arg.is_null() {
        warn!("udp socket has been closed");
        return;
    }
    let tx = &*(arg as *const Sender<super::udp::UdpPkt>);
    let src_addr = util::to_socket_addr(&*addr, port);
    let dst_addr = util::to_socket_addr(&*dst_addr, dst_port);
    let tot_len = std::ptr::read_unaligned(p).tot_len;
    let mut buf = Vec::with_capacity(tot_len as usize);
    pbuf_copy_partial(p, buf.as_mut_ptr() as *mut _, tot_len, 0);
    buf.set_len(tot_len as usize);
    pbuf_free(p);
    // Inbound UDP saturation drops the datagram, as before.
    let _ = tx.try_send((buf, src_addr, dst_addr));
}

unsafe fn apply_pcb_opts(pcb: *mut tcp_pcb) {
    let mut pcb_v = std::ptr::read_unaligned(pcb);
    #[cfg(target_os = "ios")]
    {
        pcb_v.so_options |= SOF_KEEPALIVE as u8;
    }
    pcb_v.flags |= TF_NODELAY as u16;
    std::ptr::write_unaligned(pcb, pcb_v);
}

// ---------------------------------------------------------------------------
// Core state
// ---------------------------------------------------------------------------

struct StreamState {
    /// Raw pcb as usize so the core future stays `Send`; only dereferenced
    /// synchronously inside core methods. 0 after the pcb is gone.
    pcb: usize,
    write_rx: Receiver<StreamCmd>,
    /// Chunk lwIP refused (`snd_buf` full / `ERR_MEM`) plus the offset
    /// already accepted; retried on `Sent`/`PollTick`. Replaces the old
    /// cross-thread `write_waker`.
    parked: Option<(Vec<u8>, usize)>,
    /// `Shutdown` processed — `tcp_shutdown(tx)` done. Governs whether close
    /// is graceful (`tcp_close`, enabling the FIN_WAIT_2 reap) or an abort.
    tx_shut: bool,
    /// Raw `CbCtx` to free once callbacks are detached.
    cbctx: usize,
    /// Set by `tcp_err_cb` the instant lwIP frees the pcb, or by
    /// `tcp_recv_cb` when it gives a fully closed pcb back to lwIP (which may
    /// then free it silently). MUST be checked before every C call on `pcb`:
    /// commands queued before the matching `PcbErr` would otherwise
    /// dereference a dangling pointer.
    dead: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl StreamState {
    fn pcb_alive(&self) -> bool {
        self.pcb != 0 && !self.dead.load(std::sync::atomic::Ordering::Acquire)
    }
}

pub(crate) struct UdpOut {
    pub data: Vec<u8>,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

pub(crate) struct LwipCore {
    streams: HashMap<StreamId, StreamState>,
    listener_pcb: usize,
    listener_ctx: usize,
    udp_pcb: usize,
    /// Box'd `Sender<UdpPkt>` handed to `udp_recv` as arg.
    udp_arg: usize,
    udp_out_rx: Receiver<UdpOut>,
    output_ctx: usize,
    cmd_rx: UnboundedReceiver<Cmd>,
    /// Core keeps one sender so `cmd_rx` never reports closed while alive.
    _cmd_tx: UnboundedSender<Cmd>,
    ingress_rx: Receiver<Vec<u8>>,
    done_tx: watch::Sender<bool>,
}

/// Bundle handed back to `NetStack::with_buffer_size` alongside the handles.
pub(crate) struct CoreParts {
    pub core: LwipCore,
    pub accept_rx: UnboundedReceiver<(TcpStream, SocketAddr, SocketAddr)>,
    pub egress_rx: Receiver<Vec<u8>>,
    pub udp_in_rx: Receiver<super::udp::UdpPkt>,
    pub udp_out_tx: Sender<UdpOut>,
    pub udp_local_addr: SocketAddr,
    pub cmd_tx: UnboundedSender<Cmd>,
    pub ingress_tx: Sender<Vec<u8>>,
    pub done_rx: watch::Receiver<bool>,
}

impl LwipCore {
    /// One-time C-side construction: init, netif hooks, listener + udp pcbs.
    /// Runs on the constructor's thread; the single-generation contract means
    /// no other thread can be touching lwIP, and the spawn of the core task
    /// provides the happens-before edge for the ownership handoff.
    pub(crate) fn build(
        stack_buffer_size: usize,
        udp_buffer_size: usize,
    ) -> Result<CoreParts, crate::Error> {
        use std::sync::Once;
        static LWIP_INIT: Once = Once::new();
        LWIP_INIT.call_once(|| unsafe { lwip_init() });

        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ingress_tx, ingress_rx) = tokio::sync::mpsc::channel(stack_buffer_size);
        let (egress_tx, egress_rx) = tokio::sync::mpsc::channel(stack_buffer_size);
        let (accept_tx, accept_rx) = tokio::sync::mpsc::unbounded_channel();
        let (udp_in_tx, udp_in_rx) = tokio::sync::mpsc::channel(udp_buffer_size);
        let (udp_out_tx, udp_out_rx) = tokio::sync::mpsc::channel(udp_buffer_size);
        let (done_tx, done_rx) = watch::channel(false);

        let output_ctx = Box::into_raw(Box::new(OutputCtx { egress_tx })) as usize;
        unsafe {
            (*netif_list).output = Some(output_ip4);
            (*netif_list).output_ip6 = Some(output_ip6);
            (*netif_list).mtu = 1500;
            OUTPUT_PTR = output_ctx;
        }

        // TCP listener pcb.
        let (listener_pcb, listener_ctx) = unsafe {
            let mut tpcb = tcp_new();
            let err = tcp_bind(tpcb, &ip_addr_any_type, 0);
            if err != err_enum_t_ERR_OK as err_t {
                error!("bind TCP failed: {}", err);
                return Err(crate::Error::LwIP(err));
            }
            let mut reason: err_t = 0;
            tpcb = tcp_listen_with_backlog_and_err(
                tpcb,
                TCP_DEFAULT_LISTEN_BACKLOG as u8,
                &mut reason,
            );
            if tpcb.is_null() {
                error!("listen TCP failed: {}", reason);
                return Err(crate::Error::LwIP(reason));
            }
            let ctx = Box::into_raw(Box::new(ListenerCtx {
                next_id: 0,
                cmd_tx: cmd_tx.clone(),
                accept_tx,
            }));
            tcp_arg(tpcb, ctx as *mut raw::c_void);
            tcp_accept(tpcb, Some(tcp_accept_cb));
            (tpcb as usize, ctx as usize)
        };

        // UDP pcb.
        let (udp_pcb, udp_arg, udp_local_addr) = unsafe {
            let pcb = udp_new();
            let err = udp_bind(pcb, &ip_addr_any_type, 0);
            if err != err_enum_t_ERR_OK as err_t {
                error!("bind UDP failed: {}", err);
                return Err(crate::Error::LwIP(err));
            }
            let arg = Box::into_raw(Box::new(udp_in_tx));
            udp_recv(pcb, Some(udp_recv_cb), arg as *mut raw::c_void);
            let local = util::to_socket_addr(&(*pcb).local_ip, (*pcb).local_port);
            (pcb as usize, arg as usize, local)
        };

        let core = LwipCore {
            streams: HashMap::new(),
            listener_pcb,
            listener_ctx,
            udp_pcb,
            udp_arg,
            udp_out_rx,
            output_ctx,
            cmd_rx,
            _cmd_tx: cmd_tx.clone(),
            ingress_rx,
            done_tx,
        };

        Ok(CoreParts {
            core,
            accept_rx,
            egress_rx,
            udp_in_rx,
            udp_out_tx,
            udp_local_addr,
            cmd_tx,
            ingress_tx,
            done_rx,
        })
    }

    /// The single driver loop. Exits when the `NetStack` handle drops (its
    /// ingress sender closes), then tears everything down deterministically.
    pub(crate) async fn run(mut self) {
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                frame = self.ingress_rx.recv() => match frame {
                    Some(f) => self.input(f),
                    None => break,
                },
                cmd = self.cmd_rx.recv() => {
                    // Never None: we hold `_cmd_tx`.
                    if let Some(cmd) = cmd {
                        self.handle_cmd(cmd);
                    }
                },
                _ = tick.tick() => unsafe { sys_check_timeouts() },
            }
        }
        self.teardown();
    }

    fn input(&mut self, frame: Vec<u8>) {
        if frame.is_empty() {
            return;
        }
        unsafe {
            let pbuf = pbuf_alloc(
                pbuf_layer_PBUF_RAW,
                frame.len() as u16_t,
                pbuf_type_PBUF_RAM,
            );
            if pbuf.is_null() {
                // lwIP heap exhaustion. An IP device is allowed to drop
                // frames under memory pressure — the sender retransmits.
                warn!(
                    "pbuf_alloc failed (heap exhausted), dropping {} byte frame",
                    frame.len()
                );
                return;
            }
            pbuf_take(
                pbuf,
                frame.as_ptr() as *const raw::c_void,
                frame.len() as u16_t,
            );
            if let Some(input_fn) = (*netif_list).input {
                let err = input_fn(pbuf, netif_list);
                if err != err_enum_t_ERR_OK as err_t {
                    // Per-packet event (e.g. ERR_MEM mid-burst), not stack-fatal.
                    pbuf_free(pbuf);
                    warn!("netif input rejected frame: {}", err);
                }
            } else {
                pbuf_free(pbuf);
            }
        }
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::NewStream {
                id,
                pcb,
                write_rx,
                cbctx,
                dead,
            } => {
                self.streams.insert(
                    id,
                    StreamState {
                        pcb,
                        write_rx,
                        parked: None,
                        tx_shut: false,
                        cbctx,
                        dead,
                    },
                );
            }
            Cmd::Recved(id, mut n) => {
                if let Some(st) = self.streams.get(&id) {
                    if st.pcb_alive() {
                        while n > 0 {
                            let step = n.min(u16::MAX as usize);
                            unsafe { tcp_recved(st.pcb as *mut tcp_pcb, step as u16_t) };
                            n -= step;
                        }
                    }
                }
            }
            Cmd::Kick(id) | Cmd::Sent(id) | Cmd::PollTick(id) => self.drain_writes(id),
            Cmd::PcbErr(id) => {
                // lwIP freed the pcb before tcp_err_cb fired, or owns it
                // outright after tcp_recv_cb detached it; just reap our
                // side. Dropping the state drops write_rx, which surfaces
                // BrokenPipe to a parked writer.
                if let Some(st) = self.streams.remove(&id) {
                    unsafe { drop(Box::from_raw(st.cbctx as *mut CbCtx)) };
                }
            }
            Cmd::UdpKick => self.drain_udp(),
            Cmd::RemoveUdp => self.remove_udp(),
            Cmd::CloseListener => self.close_listener(),
        }
    }

    /// Drain the per-stream ordered channel: writes until lwIP pushes back,
    /// then park; Shutdown in order; channel EOS (handle dropped) closes the
    /// pcb once all queued data has been handed to lwIP.
    fn drain_writes(&mut self, id: StreamId) {
        enum After {
            Stay,
            Finish,
            Abort(err_t),
        }
        let after = {
            let Some(st) = self.streams.get_mut(&id) else {
                return;
            };
            // Dead pcb: no C calls allowed; the queued PcbErr will reap the
            // state (and with it write_rx, surfacing BrokenPipe upstream).
            if !st.pcb_alive() {
                return;
            }
            'drain: loop {
                // Parked chunk first — ordering.
                if let Some((buf, off)) = st.parked.take() {
                    match write_chunk(st.pcb, &buf, off) {
                        WriteOutcome::Done => {}
                        WriteOutcome::Parked(new_off) => {
                            st.parked = Some((buf, new_off));
                            flush_output(st.pcb);
                            break 'drain After::Stay;
                        }
                        WriteOutcome::Fatal(err) => break 'drain After::Abort(err),
                    }
                }
                match st.write_rx.try_recv() {
                    Ok(StreamCmd::Write(buf)) => match write_chunk(st.pcb, &buf, 0) {
                        WriteOutcome::Done => continue,
                        WriteOutcome::Parked(off) => {
                            st.parked = Some((buf, off));
                            flush_output(st.pcb);
                            break 'drain After::Stay;
                        }
                        WriteOutcome::Fatal(err) => break 'drain After::Abort(err),
                    },
                    Ok(StreamCmd::Shutdown) => {
                        trace!("netstack tcp shutdown (id {})", id);
                        let err = unsafe { tcp_shutdown(st.pcb as *mut tcp_pcb, 0, 1) };
                        if err == err_enum_t_ERR_OK as err_t {
                            st.tx_shut = true;
                        } else {
                            warn!("netstack tcp_shutdown tx error {}", err);
                        }
                    }
                    Err(TryRecvError::Empty) => {
                        flush_output(st.pcb);
                        break 'drain After::Stay;
                    }
                    Err(TryRecvError::Disconnected) => {
                        // Handle dropped and every queued write has been
                        // handed to lwIP (parked is empty here) — close.
                        flush_output(st.pcb);
                        break 'drain After::Finish;
                    }
                }
            }
        };
        match after {
            After::Stay => {}
            After::Finish => self.finish_stream(id),
            After::Abort(err) => {
                warn!("netstack tcp_write/tcp_output fatal error {}", err);
                self.abort_stream(id);
            }
        }
    }

    /// Graceful close path for a dropped handle. Mirrors the old
    /// `TcpStreamImpl::drop`: detach callbacks, then either abort (no
    /// half-close seen) or `tcp_close`. The close-after-shutdown sets
    /// TF_RXCLOSED so lwIP's slowtmr can reap a FIN_WAIT_2 pcb whose peer
    /// vanished without FINing (suspended iOS app, dead link) — without it
    /// the pcb plus its unacked segments leak forever. Fall back to abort if
    /// tcp_close errors.
    fn finish_stream(&mut self, id: StreamId) {
        let Some(st) = self.streams.remove(&id) else {
            return;
        };
        if st.pcb_alive() {
            unsafe {
                let pcb = st.pcb as *mut tcp_pcb;
                // Callbacks are detached before abort/close, so tcp_abort's
                // synchronous err-callback cannot fire into freed context.
                tcp_arg(pcb, std::ptr::null_mut());
                tcp_recv(pcb, None);
                tcp_sent(pcb, None);
                tcp_err(pcb, None);
                tcp_poll(pcb, None, 0);
                let closed_gracefully = st.tx_shut && tcp_close(pcb) == err_enum_t_ERR_OK as err_t;
                if !closed_gracefully {
                    tcp_abort(pcb);
                }
            }
        }
        unsafe { drop(Box::from_raw(st.cbctx as *mut CbCtx)) };
    }

    /// Hard-kill path for fatal write errors: detach + abort, and drop the
    /// state so both handle-side channels error out.
    fn abort_stream(&mut self, id: StreamId) {
        let Some(st) = self.streams.remove(&id) else {
            return;
        };
        if st.pcb_alive() {
            unsafe {
                let pcb = st.pcb as *mut tcp_pcb;
                tcp_arg(pcb, std::ptr::null_mut());
                tcp_recv(pcb, None);
                tcp_sent(pcb, None);
                tcp_err(pcb, None);
                tcp_poll(pcb, None, 0);
                tcp_abort(pcb);
            }
        }
        unsafe { drop(Box::from_raw(st.cbctx as *mut CbCtx)) };
    }

    fn drain_udp(&mut self) {
        loop {
            match self.udp_out_rx.try_recv() {
                Ok(pkt) => {
                    if self.udp_pcb == 0 {
                        continue;
                    }
                    unsafe {
                        let pbuf = pbuf_alloc_reference(
                            pkt.data.as_ptr() as *mut _,
                            pkt.data.len() as _,
                            pbuf_type_PBUF_REF,
                        );
                        let src_ip = util::to_ip_addr_t(pkt.src.ip());
                        let dst_ip = util::to_ip_addr_t(pkt.dst.ip());
                        let err = udp_sendto(
                            self.udp_pcb as *mut udp_pcb,
                            pbuf,
                            &dst_ip as *const _,
                            pkt.dst.port(),
                            &src_ip as *const _,
                            pkt.src.port(),
                        );
                        pbuf_free(pbuf);
                        if err != err_enum_t_ERR_OK as err_t {
                            warn!("udp_sendto error: {}", err);
                        }
                    }
                }
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => return,
            }
        }
    }

    fn remove_udp(&mut self) {
        if self.udp_pcb != 0 {
            unsafe {
                udp_recv(self.udp_pcb as *mut udp_pcb, None, std::ptr::null_mut());
                udp_remove(self.udp_pcb as *mut udp_pcb);
                drop(Box::from_raw(
                    self.udp_arg as *mut Sender<super::udp::UdpPkt>,
                ));
            }
            self.udp_pcb = 0;
            self.udp_arg = 0;
        }
    }

    fn close_listener(&mut self) {
        if self.listener_pcb != 0 {
            unsafe {
                let pcb = self.listener_pcb as *mut tcp_pcb;
                tcp_arg(pcb, std::ptr::null_mut());
                tcp_accept(pcb, None);
                tcp_close(pcb);
                drop(Box::from_raw(self.listener_ctx as *mut ListenerCtx));
            }
            self.listener_pcb = 0;
            self.listener_ctx = 0;
        }
    }

    /// Deterministic full teardown, replacing the old scattered `Drop` impls
    /// (which each took the global lock from whatever thread ran them).
    fn teardown(&mut self) {
        trace!("netstack core teardown");
        let ids: Vec<StreamId> = self.streams.keys().copied().collect();
        for id in ids {
            self.finish_stream(id);
        }
        self.close_listener();
        self.remove_udp();
        unsafe {
            if OUTPUT_PTR == self.output_ctx {
                OUTPUT_PTR = 0;
            }
            drop(Box::from_raw(self.output_ctx as *mut OutputCtx));
        }
        self.output_ctx = 0;
        let _ = self.done_tx.send(true);
    }
}

enum WriteOutcome {
    Done,
    /// lwIP accepted `offset` bytes; retry the rest on Sent/PollTick.
    Parked(usize),
    Fatal(err_t),
}

fn write_chunk(pcb: usize, buf: &[u8], mut off: usize) -> WriteOutcome {
    let pcb = pcb as *mut tcp_pcb;
    while off < buf.len() {
        let snd_buf = unsafe { std::ptr::read_unaligned(pcb).snd_buf as usize };
        let n = (buf.len() - off).min(snd_buf);
        if n == 0 {
            return WriteOutcome::Parked(off);
        }
        let err = unsafe {
            tcp_write(
                pcb,
                buf[off..].as_ptr() as *const raw::c_void,
                n as u16_t,
                TCP_WRITE_FLAG_COPY as u8,
            )
        };
        if err == err_enum_t_ERR_OK as err_t {
            off += n;
        } else if err == err_enum_t_ERR_MEM as err_t {
            return WriteOutcome::Parked(off);
        } else {
            return WriteOutcome::Fatal(err);
        }
    }
    WriteOutcome::Done
}

fn flush_output(pcb: usize) {
    let err = unsafe { tcp_output(pcb as *mut tcp_pcb) };
    if err != err_enum_t_ERR_OK as err_t {
        // Best-effort: a failed tcp_output is retried by lwIP's own timers.
        trace!("netstack tcp_output error {}", err);
    }
}

#[cfg(test)]
#[path = "core_tests.rs"]
mod tests;
