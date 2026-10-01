//! Netstack-level regressions for the core's pcb lifecycle.
//!
//! No root and no TUN device: the test plays the TUN peer, writing
//! hand-built IPv4/TCP frames into the `NetStack` sink and parsing the
//! stack's replies off its stream. Zeroed checksums and arbitrary
//! addresses are fine because inbound checksum checks are off
//! (`CHECKSUM_CHECK_*` = 0 in `lwipopts.h`) and this fork's
//! `ip4_input_accept` takes any destination (`TUN2SOCKS`).
//!
//! lwIP state is process-global and only one stack generation may be live
//! at a time (see the `core` module docs), while `cargo test` runs tests on
//! parallel threads. The test therefore tears its stack down and awaits
//! `core_done` before returning; a second stack-building test must also
//! serialize with this one.

use std::net::Ipv4Addr;
use std::time::Duration;

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, timeout_at, Instant};

use crate::lwip::MEMP_NUM_TCP_PCB;
use crate::NetStack;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 5);
const SERVER_PORT: u16 = 80;
/// Client ISN for every connection; nothing here comes near wrapping it.
const CLIENT_ISN: u32 = 1000;
/// Bound on each wait for the stack. Every awaited reply is sent
/// synchronously from `tcp_input` or a core command, never from an lwIP
/// timer, so this only trips when the expected segment never comes.
const STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// A segment the stack emitted, reduced to the fields the test checks.
#[derive(Debug, Clone, Copy)]
struct Seg {
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    /// TCP payload length.
    len: usize,
}

/// IPv4 + TCP frame from `CLIENT:sport` to `SERVER:SERVER_PORT`, without
/// options, with zeroed checksums.
fn tcp_frame(sport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let total = u16::try_from(40 + payload.len()).expect("test payload fits one frame");
    let mut f = Vec::with_capacity(usize::from(total));
    f.extend_from_slice(&[0x45, 0]); // IPv4, IHL 5; TOS
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]); // id; flags / fragment offset
    f.extend_from_slice(&[64, 6, 0, 0]); // TTL; protocol TCP; header checksum
    f.extend_from_slice(&CLIENT.octets());
    f.extend_from_slice(&SERVER.octets());
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&SERVER_PORT.to_be_bytes());
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&ack.to_be_bytes());
    f.extend_from_slice(&[0x50, flags]); // data offset 5; flags
    f.extend_from_slice(&u16::MAX.to_be_bytes()); // window
    f.extend_from_slice(&[0, 0, 0, 0]); // checksum; urgent pointer
    f.extend_from_slice(payload);
    f
}

fn parse(frame: &[u8]) -> Option<Seg> {
    if frame.len() < 40 || frame[0] >> 4 != 4 || frame[9] != 6 {
        return None;
    }
    let ihl = usize::from(frame[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([frame[2], frame[3]]));
    let tcp = frame.get(ihl..total)?;
    let doff = usize::from(tcp.get(12)? >> 4) * 4;
    Some(Seg {
        dport: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: tcp[13],
        len: tcp.len().checked_sub(doff)?,
    })
}

/// The TUN side of the netstack.
struct Peer {
    sink: SplitSink<NetStack, Vec<u8>>,
    egress: SplitStream<NetStack>,
}

impl Peer {
    async fn send(&mut self, sport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) {
        self.sink
            .send(tcp_frame(sport, seq, ack, flags, payload))
            .await
            .expect("netstack ingress closed");
    }

    /// Reads egress until a segment satisfies `pred`. Returns every
    /// segment read on the way, the match last.
    async fn read_until(&mut self, what: &str, pred: impl Fn(&Seg) -> bool) -> Vec<Seg> {
        let deadline = Instant::now() + STEP_TIMEOUT;
        let mut seen = Vec::new();
        loop {
            let frame = timeout_at(deadline, self.egress.next())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for {what}; saw {seen:?}"))
                .unwrap_or_else(|| panic!("egress closed while waiting for {what}"))
                .expect("egress error");
            if let Some(seg) = parse(&frame) {
                seen.push(seg);
                if pred(&seg) {
                    return seen;
                }
            }
        }
    }

    async fn expect(&mut self, what: &str, pred: impl Fn(&Seg) -> bool) -> Seg {
        let seen = self.read_until(what, pred).await;
        *seen.last().expect("read_until returns the match")
    }

    /// Client half of a three-way handshake from `sport`.
    async fn handshake(&mut self, sport: u16) {
        self.send(sport, CLIENT_ISN, 0, SYN, &[]).await;
        let syn_ack = self
            .expect("SYN-ACK", |s| {
                s.dport == sport && s.flags & (SYN | ACK) == SYN | ACK
            })
            .await;
        self.send(sport, CLIENT_ISN + 1, syn_ack.seq.wrapping_add(1), ACK, &[])
            .await;
    }
}

/// Issue #695 item 1. After we half-close a stream and the peer's FIN
/// moves its pcb to TIME_WAIT, lwIP may free that pcb WITHOUT calling
/// `errf` — `tcp_kill_timewait()` when the pcb pool runs dry, or
/// `tcp_slowtmr()` at 2*TCP_MSL. The core used to keep the pointer as
/// live, so dropping the handle later ran `tcp_arg(NULL)` + `tcp_close` on
/// a memp slot that (free lists are LIFO) already belonged to a new
/// connection: FIN/RST on an unrelated live flow, plus use-after-free.
///
/// Drives the pool-pressure leg: connection A reaches TIME_WAIT with its
/// handle still held, `MEMP_NUM_TCP_PCB` filler connections force lwIP to
/// recycle A's pcb, then A's handle is dropped. Nothing may close any
/// filler, and A must still read the bytes that preceded its EOF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timewait_pcb_recycled_by_lwip_is_not_closed_on_drop() {
    const A_PORT: u16 = 40000;
    const FILLER_BASE: u16 = 20000;

    let (stack, mut listener, _udp) = NetStack::new().unwrap();
    let mut core_done = stack.core_done();
    let (sink, egress) = stack.split();
    let mut peer = Peer { sink, egress };

    // A: accept, then close our side first, as the relay does when the
    // upstream finishes before the client.
    peer.handshake(A_PORT).await;
    let (mut a, _, _) = timeout(STEP_TIMEOUT, listener.next())
        .await
        .expect("A: accept timed out")
        .expect("A: listener closed");
    a.shutdown().await.unwrap();
    let our_fin = peer
        .expect("A: our FIN", |s| s.dport == A_PORT && s.flags & FIN != 0)
        .await;

    // The client ACKs our FIN (FIN_WAIT_2), then sends its last bytes with
    // its own FIN: the pcb enters TIME_WAIT and tcp_recv_cb sees the EOF.
    // lwIP ACKing that FIN marks the transition.
    let our_fin_acked = our_fin.seq.wrapping_add(1);
    let client_seq = CLIENT_ISN + 1;
    peer.send(A_PORT, client_seq, our_fin_acked, ACK, &[]).await;
    peer.send(A_PORT, client_seq, our_fin_acked, FIN | PSH | ACK, b"bye")
        .await;
    let client_fin_acked = client_seq + 3 + 1;
    peer.expect("A: ACK of the client FIN (TIME_WAIT)", |s| {
        s.dport == A_PORT && s.flags & ACK != 0 && s.ack == client_fin_acked
    })
    .await;

    // Fill the pcb pool. A still holds a slot, so the last filler's SYN can
    // only get a pcb by tcp_alloc evicting A through tcp_kill_timewait, and
    // the LIFO free list hands it A's slot. Every filler being accepted
    // therefore proves A's pcb was recycled.
    let pool = usize::try_from(MEMP_NUM_TCP_PCB).unwrap();
    let mut fillers = Vec::with_capacity(pool);
    for i in 0..pool {
        let port = FILLER_BASE + u16::try_from(i).unwrap();
        peer.handshake(port).await;
        let (stream, _, _) = timeout(STEP_TIMEOUT, listener.next())
            .await
            .unwrap_or_else(|_| panic!("filler {i}/{pool}: accept timed out"))
            .expect("listener closed");
        fillers.push(stream);
    }

    // A's handle outlived its pcb but must still drain what preceded EOF.
    let mut tail = Vec::new();
    timeout(STEP_TIMEOUT, a.read_to_end(&mut tail))
        .await
        .expect("A: read timed out")
        .expect("A: read failed");
    assert_eq!(tail, b"bye");

    // Drop A, then write one byte on the first filler. Both commands travel
    // the core's FIFO command channel, so by the time that byte reaches
    // egress the core has fully handled A's drop; any FIN/RST it caused
    // was emitted ahead of the byte.
    drop(a);
    fillers[0].write_all(b"x").await.unwrap();
    let window = peer
        .read_until("the first filler's byte", |s| {
            s.dport == FILLER_BASE && s.len == 1
        })
        .await;
    let stray: Vec<&Seg> = window
        .iter()
        .filter(|s| s.flags & (FIN | RST) != 0)
        .collect();
    assert!(
        stray.is_empty(),
        "dropping A's handle closed a connection it no longer owns \
         (filler ports start at {FILLER_BASE}): {stray:?}"
    );

    // Orderly teardown, so no later stack in this process inherits a
    // half-live generation: closing ingress stops the core.
    peer.sink.close().await.unwrap();
    timeout(STEP_TIMEOUT, core_done.wait_for(|done| *done))
        .await
        .expect("core teardown timed out")
        .expect("core dropped its done signal");
}
