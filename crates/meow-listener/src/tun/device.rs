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

pub(super) fn spawn_pumps(
    device: Arc<TunDevice>,
    stack: NetStack,
) -> (JoinHandle<io::Result<()>>, JoinHandle<io::Result<()>>) {
    let (stack_sink, stack_stream) = stack.split();
    let inbound = tokio::spawn(device_to_stack(PumpEnd {
        device: Arc::clone(&device),
        half: stack_sink,
    }));
    let outbound = tokio::spawn(stack_to_device(PumpEnd {
        device,
        half: stack_stream,
    }));
    (inbound, outbound)
}

/// device → stack. The per-packet `to_vec` is imposed by the netstack's
/// `Sink<Vec<u8>>` API; this path is not covered by the zero-alloc relay
/// invariant (ADR-0008), which starts at the terminated TCP stream.
///
/// `end` is only ever borrowed: moving its fields out into locals would
/// give them the locals' drop order (reverse of declaration) and undo
/// [`PumpEnd`]'s ordering.
async fn device_to_stack(
    mut end: PumpEnd<Arc<TunDevice>, SplitSink<NetStack, Vec<u8>>>,
) -> io::Result<()> {
    let mut buf = vec![0u8; PACKET_BUF];
    loop {
        let n = end.device.device.recv(&mut buf).await?;
        if n == 0 {
            continue;
        }
        end.half
            .send(buf[..n].to_vec())
            .await
            .map_err(|e| io::Error::other(format!("netstack ingress closed: {e}")))?;
    }
}

/// stack → device. Borrows `end` for the same reason as [`device_to_stack`].
async fn stack_to_device(
    mut end: PumpEnd<Arc<TunDevice>, SplitStream<NetStack>>,
) -> io::Result<()> {
    while let Some(pkt) = end.half.next().await {
        end.device.device.send(&pkt?).await?;
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
