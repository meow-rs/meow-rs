//! `UdpSession`: proxied UDP over hysteria2 QUIC datagrams, bridged to the
//! driver over channels. Sending forwards `(addr, data)` to the driver, which
//! fragments and encodes; receiving pulls decoded `UdpMessage`s the driver
//! routed here and reassembles fragments.

use super::driver::Cmd;
use super::proto::{UdpMessage, MAX_UDP_SIZE};
use super::{Error, Result};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const FRAGMENT_TTL: Duration = Duration::from_secs(10);

pub struct UdpSession {
    session_id: u32,
    cmd_tx: mpsc::Sender<Cmd>,
    packets: mpsc::Receiver<UdpMessage>,
    defragger: UdpDefragger,
}

impl UdpSession {
    pub(crate) fn new(
        session_id: u32,
        cmd_tx: mpsc::Sender<Cmd>,
        packets: mpsc::Receiver<UdpMessage>,
    ) -> Self {
        Self {
            session_id,
            cmd_tx,
            packets,
            defragger: UdpDefragger::new(),
        }
    }

    pub fn send(&self, data: &[u8], addr: &str) -> Result<()> {
        if data.len() > MAX_UDP_SIZE {
            return Err(Error::protocol("UDP payload is too large"));
        }
        match self.cmd_tx.try_send(Cmd::SendUdp {
            session_id: self.session_id,
            addr: addr.to_string(),
            data: data.to_vec(),
        }) {
            // A full driver queue is congestion, not a dead session: drop
            // the datagram as UDP would (meow-openwrt). Reporting `Closed`
            // made the caller tear the association down and open a new one
            // — a new server-side socket and source port mid-flow, which
            // connected UDP peers (iperf3, QUIC, games) then ignore.
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(Error::Closed),
        }
    }

    pub async fn recv(&mut self) -> Result<(Vec<u8>, String)> {
        loop {
            let message = self.packets.recv().await.ok_or(Error::Closed)?;
            if let Some(message) = self.defragger.feed(message)? {
                return Ok((message.data, message.addr));
            }
        }
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        let _ = self.cmd_tx.try_send(Cmd::UnregisterUdp {
            session_id: self.session_id,
        });
    }
}

struct UdpDefragger {
    packets: HashMap<u16, FragmentPacket>,
}

impl UdpDefragger {
    fn new() -> Self {
        Self {
            packets: HashMap::new(),
        }
    }

    fn feed(&mut self, message: UdpMessage) -> Result<Option<UdpMessage>> {
        self.evict_stale();
        if message.frag_count <= 1 {
            return Ok(Some(message));
        }
        if message.frag_id >= message.frag_count {
            return Ok(None);
        }

        let total = usize::from(message.frag_count);
        let item = self
            .packets
            .entry(message.packet_id)
            .or_insert_with(|| FragmentPacket::new(total));
        if item.fragments.len() != total {
            *item = FragmentPacket::new(total);
        }

        let index = usize::from(message.frag_id);
        if item.fragments[index].is_some() {
            return Ok(None);
        }
        item.fragments[index] = Some(message);
        item.received += 1;

        if item.received != total {
            return Ok(None);
        }

        let packet_id = item.fragments[0]
            .as_ref()
            .expect("complete packet has first fragment")
            .packet_id;
        let item = self
            .packets
            .remove(&packet_id)
            .expect("fragment packet exists");
        reassemble(item).map(Some)
    }

    fn evict_stale(&mut self) {
        let now = Instant::now();
        self.packets
            .retain(|_, item| now.duration_since(item.created) <= FRAGMENT_TTL);
    }
}

struct FragmentPacket {
    created: Instant,
    fragments: Vec<Option<UdpMessage>>,
    received: usize,
}

impl FragmentPacket {
    fn new(total: usize) -> Self {
        Self {
            created: Instant::now(),
            fragments: vec![None; total],
            received: 0,
        }
    }
}

fn reassemble(item: FragmentPacket) -> Result<UdpMessage> {
    let fragments: Vec<UdpMessage> = item
        .fragments
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Error::protocol("incomplete UDP fragments"))?;
    let first = fragments
        .first()
        .ok_or_else(|| Error::protocol("empty UDP fragment set"))?
        .clone();
    let mut data = Vec::new();
    for fragment in &fragments {
        data.extend_from_slice(&fragment.data);
    }
    if data.len() > MAX_UDP_SIZE {
        return Err(Error::protocol("reassembled UDP payload is too large"));
    }
    Ok(UdpMessage {
        session_id: first.session_id,
        packet_id: first.packet_id,
        frag_id: 0,
        frag_count: 1,
        addr: first.addr,
        data,
    })
}

#[cfg(test)]
mod tests {
    /// A full driver queue drops the datagram; only a gone driver fails.
    #[test]
    fn send_drops_on_full_queue_and_fails_only_when_closed() {
        let (tx, rx) = mpsc::channel(1);
        let (_ptx, prx) = mpsc::channel(1);
        let session = super::UdpSession::new(7, tx, prx);
        session.send(b"a", "1.2.3.4:5").expect("queued");
        session
            .send(b"b", "1.2.3.4:5")
            .expect("full queue drops, session stays up");
        drop(rx);
        assert!(session.send(b"c", "1.2.3.4:5").is_err(), "driver gone");
    }

    use super::*;

    #[test]
    fn defragger_reassembles_in_order() {
        let mut defragger = UdpDefragger::new();
        let first = UdpMessage {
            session_id: 1,
            packet_id: 2,
            frag_id: 0,
            frag_count: 2,
            addr: "127.0.0.1:53".into(),
            data: b"he".to_vec(),
        };
        let second = UdpMessage {
            frag_id: 1,
            data: b"llo".to_vec(),
            ..first.clone()
        };
        assert!(defragger.feed(first).unwrap().is_none());
        let complete = defragger.feed(second).unwrap().unwrap();
        assert_eq!(complete.data, b"hello");
    }
}
