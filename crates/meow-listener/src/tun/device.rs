//! Packet pumps between a [`tun_rs::AsyncDevice`] and the lwIP netstack.
//!
//! [`lwip::NetStack`] is a `Stream`/`Sink` of raw IP packets (`Vec<u8>`),
//! while `tun-rs` exposes a packet-oriented `recv`/`send` pair. Two tasks
//! shuttle packets in each direction; either task exiting means the device
//! or the stack is gone, which `run()` treats as fatal for the listener.

use std::io;
use std::sync::Arc;

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use lwip::NetStack;
use tokio::task::JoinHandle;

use tokio::sync::mpsc;

use super::direct_udp;
use super::system::{Nat, Verdict};
use super::udp::{ReplyMsg, UdpPkt};
use super::vnet;
use super::TunDevice;

/// One IP packet. UDP/TCP over IPv4/v6 tops out below 64 KiB regardless of
/// the device MTU, and a fixed buffer sidesteps MTU-change races.
const PACKET_BUF: usize = 65535;

/// What one pump task owns: its handle on the device and its half of the
/// netstack.
///
/// **Field order is load-bearing** (fields drop in declaration order): the
/// device handle must go before the stack half. Listener teardown aborts
/// the pumps and then waits for the lwIP core's `core_done`, which fires
/// once both stack halves are gone; a config reload builds the successor
/// listener right after. The last `Arc<TunDevice>` — whose drop deletes the
/// routes and closes the device — therefore has to be released *before*
/// the half that lets `core_done` fire. The other way round the old device
/// outlived `core_done` for as long as its route deletes took and the
/// successor's device create raced it: `EBUSY` on the configured name, a
/// 500 ms retry and a device renamed `meow-tun-1` (6 of 10 global-scope
/// restarts with four `/1` routes to delete, #375).
struct PumpEnd<D, H> {
    device: D,
    half: H,
}

/// UDP carried between the pumps and the flow table without lwIP
/// (`tun.stack: system`).
pub(super) struct DirectUdp {
    pub(super) incoming: mpsc::Sender<UdpPkt>,
    pub(super) replies: mpsc::Receiver<ReplyMsg>,
}

/// `nat` (`tun.stack: system`) translates TCP in place and writes it back
/// to the device; with `udp` UDP goes straight to the flow table and its
/// replies straight to the device. Everything else goes to lwIP as before.
pub(super) fn spawn_pumps(
    device: Arc<TunDevice>,
    stack: NetStack,
    nat: Option<Arc<Nat>>,
    udp: Option<DirectUdp>,
) -> (JoinHandle<io::Result<()>>, JoinHandle<io::Result<()>>) {
    let vnet = vnet_framing(&device);
    let (stack_sink, stack_stream) = stack.split();
    let (udp_in, udp_replies) = udp.map_or((None, None), |u| (Some(u.incoming), Some(u.replies)));
    let inbound = tokio::spawn(device_to_stack(
        PumpEnd {
            device: Arc::clone(&device),
            half: stack_sink,
        },
        nat,
        udp_in,
        vnet,
    ));
    let outbound = tokio::spawn(stack_to_device(
        PumpEnd {
            device,
            half: stack_stream,
        },
        udp_replies,
        vnet,
    ));
    (inbound, outbound)
}

/// Whether the device frames every packet with a virtio-net header
/// (`IFF_VNET_HDR`, opened with offload for the system stack).
fn vnet_framing(device: &TunDevice) -> bool {
    #[cfg(target_os = "linux")]
    {
        device.device.tcp_gso()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = device;
        false
    }
}

/// device → stack. The per-packet `to_vec` is imposed by the netstack's
/// `Sink<Vec<u8>>` API; this path is not covered by the zero-alloc relay
/// invariant (ADR-0008), which starts at the terminated TCP stream.
///
/// With `nat` (`tun.stack: system`) TCP is translated in place and written
/// straight back to the device. With `vnet` every read carries a
/// virtio-net header: a translated packet goes back with its header as is
/// — a TSO/GRO aggregate stays one write — while lwIP gets plain packets,
/// segmented and checksummed ([`vnet::to_plain`]).
///
/// `end` is only ever borrowed: moving its fields out into locals would
/// give them the locals' drop order (reverse of declaration) and undo
/// [`PumpEnd`]'s ordering.
async fn device_to_stack(
    mut end: PumpEnd<Arc<TunDevice>, SplitSink<NetStack, Vec<u8>>>,
    nat: Option<Arc<Nat>>,
    udp: Option<mpsc::Sender<UdpPkt>>,
    vnet: bool,
) -> io::Result<()> {
    let hdr_len = if vnet { vnet::HDR_LEN } else { 0 };
    // A virtio frame is the header plus up to 64 KiB.
    let mut buf = vec![0u8; hdr_len + PACKET_BUF + usize::from(vnet)];
    loop {
        let n = end.device.device.recv(&mut buf).await?;
        if n <= hdr_len {
            continue;
        }
        let partial = vnet && vnet::needs_csum(&buf[..hdr_len]);
        if let Some(nat) = &nat {
            match nat.translate(&mut buf[hdr_len..n], partial) {
                Verdict::Write => {
                    // A full device queue drops the packet, as a NIC would;
                    // TCP retransmits it.
                    if let Err(e) = end.device.device.send(&buf[..n]).await {
                        tracing::debug!("tun system stack: device write failed: {e}");
                    }
                    continue;
                }
                Verdict::Drop => continue,
                Verdict::Stack => {}
            }
        }
        if let Some(udp) = &udp {
            if direct_udp::is_udp(&buf[hdr_len..n]) {
                if !vnet || vnet::is_single(&buf[..hdr_len]) {
                    deliver_udp(udp, &buf[hdr_len..n]);
                } else {
                    for pkt in vnet::to_plain(&mut buf[..n]) {
                        deliver_udp(udp, &pkt);
                    }
                }
                continue;
            }
        }
        if vnet {
            for pkt in vnet::to_plain(&mut buf[..n]) {
                end.half
                    .send(pkt)
                    .await
                    .map_err(|e| io::Error::other(format!("netstack ingress closed: {e}")))?;
            }
            continue;
        }
        end.half
            .send(buf[..n].to_vec())
            .await
            .map_err(|e| io::Error::other(format!("netstack ingress closed: {e}")))?;
    }
}

/// Hand one plain UDP packet to the flow table; a full queue drops it, as
/// a socket buffer would.
fn deliver_udp(udp: &mpsc::Sender<UdpPkt>, pkt: &[u8]) {
    if let direct_udp::Parsed::Udp(d) = direct_udp::parse(pkt) {
        let _ = udp.try_send(d);
    }
}

/// stack → device. Borrows `end` for the same reason as [`device_to_stack`].
/// With `vnet` each packet goes out behind a virtio-net header (no GSO;
/// lwIP's checksums complete, direct UDP's left to the kernel). `udp`
/// carries the flow table's replies (system stack), built into packets
/// here.
async fn stack_to_device(
    mut end: PumpEnd<Arc<TunDevice>, SplitStream<NetStack>>,
    mut udp: Option<mpsc::Receiver<ReplyMsg>>,
    vnet: bool,
) -> io::Result<()> {
    let mut framed = Vec::new();
    let mut ip_id = 0u16;
    loop {
        let reply = async {
            match udp.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            pkt = end.half.next() => {
                let Some(pkt) = pkt else { break };
                let pkt = pkt?;
                if vnet {
                    framed.clear();
                    framed.resize(vnet::HDR_LEN, 0);
                    framed.extend_from_slice(&pkt);
                    end.device.device.send(&framed).await?;
                } else {
                    end.device.device.send(&pkt).await?;
                }
            }
            reply = reply => {
                // `(payload, src, dst)`: appear as `src`, deliver to `dst`.
                let Some((data, src, dst)) = reply else {
                    udp = None;
                    continue;
                };
                if direct_udp::build(&mut framed, vnet, &data, src, dst, &mut ip_id) {
                    // A full device queue drops the datagram (UDP semantics).
                    if let Err(e) = end.device.device.send(&framed).await {
                        tracing::debug!("tun UDP: device write failed: {e}");
                    }
                }
            }
        }
    }
    Err(io::Error::other("netstack egress closed"))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::PumpEnd;

    struct Recorder(&'static str, Arc<Mutex<Vec<&'static str>>>);

    impl Drop for Recorder {
        fn drop(&mut self) {
            self.1.lock().unwrap().push(self.0);
        }
    }

    /// The pump shape: an async fn that owns a `PumpEnd`, borrows its
    /// fields and is dropped (aborted) while suspended.
    async fn parked(mut end: PumpEnd<Recorder, Recorder>) {
        let _borrows = (&end.device, &mut end.half);
        std::future::pending::<()>().await;
    }

    /// Teardown ordering behind global-scope restarts (#375): an aborted
    /// pump must release the device before its stack half, so the device
    /// is closed by the time `core_done` lets a successor be built.
    #[tokio::test]
    async fn aborted_pump_releases_the_device_before_its_stack_half() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn(parked(PumpEnd {
            device: Recorder("device", Arc::clone(&order)),
            half: Recorder("stack half", Arc::clone(&order)),
        }));
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(*order.lock().unwrap(), ["device", "stack half"]);
    }
}
