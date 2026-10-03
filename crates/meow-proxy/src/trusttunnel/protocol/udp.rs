use super::{lock, TunnelStream};
use bytes::{BufMut, Bytes, BytesMut};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Mutex,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore},
};
use tokio_util::sync::CancellationToken;

const MAX_PAYLOAD: usize = 65507;
const HEADER: usize = 36;
struct Packet {
    data: Bytes,
    source: SocketAddr,
    _budget: OwnedSemaphorePermit,
}

pub(crate) struct Mux {
    cancel: CancellationToken,
    send: mpsc::Sender<Bytes>,
    peers: Mutex<HashMap<SocketAddr, mpsc::Sender<Packet>>>,
    next_port: AtomicU16,
    budget: Arc<Semaphore>,
}

impl Mux {
    pub(crate) fn new(stream: TunnelStream, parent: &CancellationToken) -> Arc<Self> {
        let (send, mut queue) = mpsc::channel::<Bytes>(32);
        let mux = Arc::new(Self {
            cancel: parent.child_token(),
            send,
            peers: Mutex::new(HashMap::new()),
            next_port: AtomicU16::new(1024),
            budget: Arc::new(Semaphore::new(4 * 1024 * 1024)),
        });
        let (mut reader, mut writer) = tokio::io::split(stream);
        let cancel = mux.cancel.clone();
        super::spawn_scoped(async move {
            loop {
                let frame = tokio::select! { _ = cancel.cancelled() => break, frame = queue.recv() => frame };
                let Some(frame) = frame else {
                    break;
                };
                let result = tokio::select! { _ = cancel.cancelled() => break, result = writer.write_all(&frame) => result };
                if result.is_err() {
                    break;
                }
            }
            cancel.cancel();
        });
        let weak = Arc::downgrade(&mux);
        let cancel = mux.cancel.clone();
        super::spawn_scoped(async move {
            loop {
                let result = tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = async {
                        let length = reader.read_u32().await? as usize;
                        if !(HEADER..=HEADER + MAX_PAYLOAD).contains(&length) { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid TrustTunnel UDP frame length")); }
                        let mut body = vec![0; length];
                        reader.read_exact(&mut body).await?;
                        Ok::<_, io::Error>(body)
                    } => result,
                };
                let Ok(body) = result else {
                    break;
                };
                let Some(mux) = weak.upgrade() else {
                    break;
                };
                let source = address(&body[..18]);
                let destination = address(&body[18..36]);
                let Some(sender) = lock(&mux.peers).get(&destination).cloned() else {
                    continue;
                };
                let size = body.len() - HEADER;
                // A slow association drops its own UDP packets; it cannot
                // exhaust the process or block every other association.
                let Ok(budget) = Arc::clone(&mux.budget).try_acquire_many_owned(size.max(1) as u32)
                else {
                    continue;
                };
                let _ = sender.try_send(Packet {
                    data: Bytes::copy_from_slice(&body[HEADER..]),
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
    pub(crate) fn associate(
        self: &Arc<Self>,
        mut source: SocketAddr,
        app: &str,
    ) -> io::Result<UdpAssociation> {
        if app.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP app name exceeds 255 bytes",
            ));
        }
        let mut peers = lock(&self.peers);
        if self.is_closed() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if peers.len() >= 128 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TrustTunnel UDP association limit reached",
            ));
        }
        // Independent associations may share the same inbound tuple. Give
        // each one a distinct virtual source port for unambiguous dispatch.
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
            app: app.to_owned(),
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
    app: String,
    receiver: AsyncMutex<mpsc::Receiver<Packet>>,
    cancel: CancellationToken,
}

impl UdpAssociation {
    pub fn local_addr(&self) -> SocketAddr {
        self.source
    }
    pub async fn send_to(&self, payload: &[u8], destination: SocketAddr) -> io::Result<usize> {
        if payload.len() > MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP payload exceeds 65507 bytes",
            ));
        }
        if self.cancel.is_cancelled() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        // Reserve a bounded queue slot before allocating/copying a frame.
        // Concurrent callers waiting for capacity retain no packet copy.
        let permit = tokio::select! {
            _ = self.cancel.cancelled() => return Err(io::ErrorKind::BrokenPipe.into()),
            result = self.mux.send.reserve() => result.map_err(|_| io::ErrorKind::BrokenPipe)?,
        };
        let mut frame = BytesMut::with_capacity(4 + HEADER + 1 + self.app.len() + payload.len());
        frame.put_u32((HEADER + 1 + self.app.len() + payload.len()) as u32);
        put_address(&mut frame, self.source);
        put_address(&mut frame, destination);
        frame.put_u8(self.app.len() as u8);
        frame.extend_from_slice(self.app.as_bytes());
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
        if packet.data.len() > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP receive buffer is too small",
            ));
        }
        buffer[..packet.data.len()].copy_from_slice(&packet.data);
        Ok((packet.data.len(), packet.source))
    }
    pub fn close(&self) {
        self.cancel.cancel();
        lock(&self.mux.peers).remove(&self.source);
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
