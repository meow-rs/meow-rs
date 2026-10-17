use super::{lock, TunnelStream};
use bytes::{BufMut, Bytes, BytesMut};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU16, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore},
};
use tokio_util::sync::CancellationToken;

// v1.1.0 uses different decoder and encoder bounds. With an empty App
// Name, its decoder accepts at most 65434 payload bytes; its encoder can
// reply with 65508 bytes received from an IPv6 socket.
const MAX_SEND_PAYLOAD: usize = 65434;
const MAX_RECV_PAYLOAD: usize = 65508;
const HEADER: usize = 36;
struct Packet {
    data: Bytes,
    source: SocketAddr,
    _budget: OwnedSemaphorePermit,
}

pub(crate) struct Mux {
    cancel: CancellationToken,
    retiring: CancellationToken,
    send: mpsc::Sender<Bytes>,
    peers: Mutex<HashMap<SocketAddr, mpsc::Sender<Packet>>>,
    next_port: AtomicU16,
    pub(super) budget: Arc<Semaphore>,
    pub(super) dropped_budget: AtomicUsize,
    pub(super) dropped_unmatched: AtomicUsize,
    pub(super) dropped_oversized: AtomicUsize,
}

impl Mux {
    pub(crate) fn new(
        stream: TunnelStream,
        parent: &CancellationToken,
        retiring: &CancellationToken,
    ) -> Arc<Self> {
        let (send, mut queue) = mpsc::channel::<Bytes>(32);
        let mux = Arc::new(Self {
            cancel: parent.child_token(),
            retiring: retiring.clone(),
            send,
            peers: Mutex::new(HashMap::new()),
            next_port: AtomicU16::new(1024),
            budget: Arc::new(Semaphore::new(4 * 1024 * 1024)),
            dropped_budget: AtomicUsize::new(0),
            dropped_unmatched: AtomicUsize::new(0),
            dropped_oversized: AtomicUsize::new(0),
        });
        let (mut reader, mut writer) = tokio::io::split(stream);
        let cancel = mux.cancel.clone();
        let retiring = retiring.clone();
        let weak = Arc::downgrade(&mux);
        super::spawn_scoped(async move {
            let mut retirement_seen = false;
            loop {
                let frame = tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = retiring.cancelled(), if !retirement_seen => {
                        // The signal stays ready after retirement: observe
                        // it once, then let the last association stop us.
                        retirement_seen = true;
                        if let Some(mux) = weak.upgrade() {
                            mux.stop_if_retired_and_idle();
                        }
                        continue;
                    }
                    frame = queue.recv() => frame,
                };
                let Some(frame) = frame else {
                    break;
                };
                let result = tokio::select! { _ = cancel.cancelled() => break, result = writer.write_all(&frame) => result };
                if let Err(error) = result {
                    tracing::warn!(%error, "TrustTunnel UDP writer stopped");
                    break;
                }
            }
            cancel.cancel();
        });
        let weak = Arc::downgrade(&mux);
        let cancel = mux.cancel.clone();
        super::spawn_scoped(async move {
            // One reusable frame buffer for the whole mux. `split_to().freeze()`
            // hands the payload to the consumer without a second copy, and
            // `reserve()` reclaims the detached head once that consumer drops
            // it — so a forwarded datagram costs no allocation at steady state
            // (the old `vec![0; length]` + `Bytes::copy_from_slice` pair cost
            // two per datagram, on the hot path of every UDP flow).
            let mut frame = BytesMut::with_capacity(8 * (HEADER + 1500));
            loop {
                let result = tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = async {
                        let length = reader.read_u32().await? as usize;
                        if !(HEADER..=HEADER + MAX_RECV_PAYLOAD).contains(&length) { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid TrustTunnel UDP frame length")); }
                        frame.clear();
                        frame.reserve(length);
                        // `resize` only zeroes the bytes `read_exact` is about
                        // to overwrite; no uninitialised memory is exposed.
                        frame.resize(length, 0);
                        reader.read_exact(&mut frame[..]).await?;
                        Ok::<_, io::Error>(frame.split_to(length).freeze())
                    } => result,
                };
                let body = match result {
                    Ok(body) => body,
                    Err(error) => {
                        tracing::warn!(%error, "TrustTunnel UDP reader stopped");
                        break;
                    }
                };
                let Some(mux) = weak.upgrade() else {
                    break;
                };
                let source = address(&body[..18]);
                let destination = address(&body[18..36]);
                let Some(sender) = lock(&mux.peers).get(&destination).cloned() else {
                    let dropped = mux
                        .dropped_unmatched
                        .fetch_add(1, Ordering::Relaxed)
                        .wrapping_add(1);
                    if dropped.is_power_of_two() {
                        tracing::warn!(
                            dropped,
                            "TrustTunnel UDP reply has no matching association"
                        );
                    }
                    continue;
                };
                let size = body.len() - HEADER;
                // Bound aggregate queued receive payloads. A slow consumer
                // can consume this shared budget and cause cross-association
                // drops; expose pressure with exponentially limited logs.
                let Ok(budget) = Arc::clone(&mux.budget).try_acquire_many_owned(size.max(1) as u32)
                else {
                    let dropped = mux
                        .dropped_budget
                        .fetch_add(1, Ordering::Relaxed)
                        .wrapping_add(1);
                    if dropped.is_power_of_two() {
                        tracing::warn!(dropped, "TrustTunnel shared UDP receive budget exhausted");
                    }
                    continue;
                };
                let _ = sender.try_send(Packet {
                    data: body.slice(HEADER..),
                    source,
                    _budget: budget,
                });
            }
            cancel.cancel();
            if let Some(mux) = weak.upgrade() {
                lock(&mux.peers).clear();
            }
        });
        mux
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.cancel.is_cancelled()
    }

    fn stop_if_retired_and_idle(&self) {
        if self.retiring.is_cancelled() && lock(&self.peers).is_empty() {
            // The split stream owns a session lease. Stopping both tasks
            // releases that lease, breaking the session -> cached mux ->
            // writer/reader -> session lifetime cycle after retirement.
            self.cancel.cancel();
        }
    }
    /// Open an association, minting its own wire source tuple.
    ///
    /// The source address in an outbound frame is echoed back by the endpoint
    /// as the destination of each reply, and that round trip is the only use
    /// it has: `peers` is keyed on it, nothing else reads it. So it is ours to
    /// choose — and it must be, because putting the *client's* real address
    /// there would hand the endpoint operator the LAN source IP and port
    /// behind every datagram, which no part of the protocol needs in order to
    /// route a reply. The address stays unspecified (matching the
    /// `local_addr()` convention of the other stream-tunnelled UDP adapters);
    /// only the port carries the per-association identity.
    pub(crate) fn associate(self: &Arc<Self>) -> io::Result<UdpAssociation> {
        let mut peers = lock(&self.peers);
        if self.is_closed() || self.retiring.is_cancelled() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if peers.len() >= 128 {
            return Err(meow_common::error::local_resource_limit(
                "TrustTunnel UDP association limit reached",
            ));
        }
        // Independent associations may share the same inbound tuple. Give
        // each one a distinct virtual source port for unambiguous dispatch.
        let mut source = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        while source.port() == 0 || peers.contains_key(&source) {
            let port = self.next_port.fetch_add(1, Ordering::Relaxed);
            if port >= 1024 {
                source.set_port(port);
            }
        }
        let (sender, receiver) = mpsc::channel(16);
        peers.insert(source, sender);
        Ok(UdpAssociation {
            mux: Arc::clone(self),
            source,
            receiver: AsyncMutex::new(receiver),
            cancel: self.cancel.child_token(),
        })
    }
}

impl Drop for Mux {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub struct UdpAssociation {
    mux: Arc<Mux>,
    source: SocketAddr,
    receiver: AsyncMutex<mpsc::Receiver<Packet>>,
    cancel: CancellationToken,
}

impl UdpAssociation {
    pub fn local_addr(&self) -> SocketAddr {
        self.source
    }
    pub async fn send_to(&self, payload: &[u8], destination: SocketAddr) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if payload.len() > MAX_SEND_PAYLOAD {
            // Drop it, do not fail the write. `handle_udp` evicts the NAT
            // entry on *any* `write_packet` error, so reporting this one
            // would let a single jumbo datagram from one application tear
            // down the whole (client, destination) flow and force a redial
            // for the well-behaved traffic sharing it. An endpoint that
            // cannot carry the datagram is indistinguishable from a path
            // that drops it, which is a thing UDP callers already handle.
            let dropped = self
                .mux
                .dropped_oversized
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            if dropped.is_power_of_two() {
                tracing::warn!(
                    dropped,
                    length = payload.len(),
                    "UDP payload exceeds the endpoint's 65434-byte send limit"
                );
            }
            return Ok(payload.len());
        }
        // Reserve a bounded queue slot before allocating/copying a frame.
        // Concurrent callers waiting for capacity retain no packet copy.
        let permit = tokio::select! {
            _ = self.cancel.cancelled() => return Err(io::ErrorKind::BrokenPipe.into()),
            result = self.mux.send.reserve() => result.map_err(|_| io::ErrorKind::BrokenPipe)?,
        };
        let mut frame = BytesMut::with_capacity(4 + HEADER + 1 + payload.len());
        frame.put_u32((HEADER + 1 + payload.len()) as u32);
        put_address(&mut frame, self.source);
        put_address(&mut frame, destination);
        // App Name is structurally empty, so a future call site cannot
        // accidentally disclose the local process name.
        frame.put_u8(0);
        frame.extend_from_slice(payload);
        permit.send(frame.freeze());
        Ok(payload.len())
    }
    pub async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut receiver = self.receiver.lock().await;
        let packet = tokio::select! { _ = self.cancel.cancelled() => None, packet = receiver.recv() => packet };
        let Some(packet) = packet else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        let length = packet.data.len().min(buffer.len());
        buffer[..length].copy_from_slice(&packet.data[..length]);
        Ok((length, packet.source))
    }
    pub fn close(&self) {
        self.cancel.cancel();
        lock(&self.mux.peers).remove(&self.source);
        self.mux.stop_if_retired_and_idle();
    }
}
impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.close();
    }
}

fn put_address(buffer: &mut BytesMut, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            buffer.extend_from_slice(&[0; 12]);
            buffer.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => buffer.extend_from_slice(&ip.octets()),
    }
    buffer.put_u16(address.port());
}
// Caller passes an exact 18-byte address slice from the checked header.
fn address(bytes: &[u8]) -> SocketAddr {
    // The public wire specification explicitly excludes IPv6 loopback
    // from the otherwise zero-padded IPv4 representation (§11.2).
    let ip = if bytes[..12] == [0; 12] && bytes[..16] != Ipv6Addr::LOCALHOST.octets() {
        IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
    } else {
        let mut octets = [0; 16];
        octets.copy_from_slice(&bytes[..16]);
        IpAddr::V6(Ipv6Addr::from(octets))
    };
    SocketAddr::new(ip, u16::from_be_bytes([bytes[16], bytes[17]]))
}
