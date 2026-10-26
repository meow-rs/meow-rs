//! Salamander / Gecko UDP obfuscation and port-hopping for the hysteria2
//! quiche transport.
//!
//! With quinn the socket was an `AsyncUdpSocket` that rewrote datagrams; the
//! quiche driver owns its UDP socket directly, so these are plain per-datagram
//! transforms it applies on send/recv (see `driver.rs`).

use super::{Error, ObfsConfig, Result};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use rand::{Rng, RngCore};
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const SALAMANDER_SALT_LEN: usize = 8;
const HY2_MIN_HOP_INTERVAL_SECS: u64 = 5;
const HY2_DEFAULT_HOP_INTERVAL_SECS: u64 = 30;

/// First-byte bit of a Gecko fragment frame. It is also the QUIC long-header
/// bit, so the sender fragments exactly the long-header (handshake) packets.
const GECKO_FRAGMENT: u8 = 0x80;
const GECKO_HEADER_LEN: usize = 5;
const GECKO_MIN_CHUNKS: u8 = 2;
const GECKO_MAX_CHUNKS: u8 = 8;
const GECKO_DEFAULT_MIN_PACKET: u16 = 512;
const GECKO_DEFAULT_MAX_PACKET: u16 = 1200;
const GECKO_MAX_PACKET: u16 = 2048;
const GECKO_REASSEMBLY_TTL: Duration = Duration::from_secs(8);
/// Messages one connection reassembles at once. Only handshake packets are
/// fragmented, so a handshake has a few in flight at most.
const GECKO_MAX_PARTIALS: usize = 8;

/// Resolves `obfs-min-packet-size` / `obfs-max-packet-size` to Gecko's
/// wire-datagram size range; `0` selects the default, as in the official
/// client and mihomo.
pub(crate) fn gecko_packet_sizes(min: u16, max: u16) -> std::result::Result<(u16, u16), String> {
    let min = if min == 0 {
        GECKO_DEFAULT_MIN_PACKET
    } else {
        min
    };
    let max = if max == 0 {
        GECKO_DEFAULT_MAX_PACKET
    } else {
        max
    };
    if min > max || max > GECKO_MAX_PACKET {
        return Err(format!(
            "gecko packet sizes must satisfy min <= max <= {GECKO_MAX_PACKET}, got min {min}, max {max}"
        ));
    }
    Ok((min, max))
}

/// The `obfs:` layer of one connection.
#[derive(Debug)]
pub(crate) enum Obfs {
    Salamander(Salamander),
    Gecko(Gecko),
}

impl Obfs {
    pub(crate) fn new(cfg: &ObfsConfig) -> Self {
        match cfg {
            ObfsConfig::Salamander { password } => {
                Self::Salamander(Salamander::new(password.as_bytes()))
            }
            ObfsConfig::Gecko {
                password,
                min_packet_size,
                max_packet_size,
            } => Self::Gecko(Gecko::new(
                password.as_bytes(),
                *min_packet_size,
                *max_packet_size,
            )),
        }
    }

    /// The wire datagrams carrying one QUIC datagram.
    pub(crate) fn encode(&mut self, packet: &[u8]) -> Wire {
        match self {
            Self::Salamander(obfs) => Wire::One(obfs.encode(packet)),
            Self::Gecko(obfs) => obfs.encode(packet),
        }
    }

    /// The QUIC datagram a wire datagram from `from` carries. `None` drops it,
    /// or (Gecko) holds it until the rest of its message arrives.
    pub(crate) fn decode(&mut self, datagram: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
        match self {
            Self::Salamander(obfs) => obfs.decode(datagram),
            Self::Gecko(obfs) => obfs.decode(datagram, from, Instant::now()),
        }
    }
}

/// Output of [`Obfs::encode`]: one datagram, except for a fragmented Gecko
/// handshake packet.
pub(crate) enum Wire {
    One(Vec<u8>),
    Fragments(Vec<Vec<u8>>),
}

impl Wire {
    pub(crate) fn datagrams(&self) -> &[Vec<u8>] {
        match self {
            Self::One(datagram) => std::slice::from_ref(datagram),
            Self::Fragments(datagrams) => datagrams,
        }
    }
}

/// Salamander XOR obfuscation (hysteria2 `obfs: salamander`). Each datagram is
/// prefixed with a random 8-byte salt; the key is `BLAKE2b-256(password||salt)`
/// and the payload is XORed with the repeating key.
#[derive(Debug)]
pub(crate) struct Salamander {
    password: Vec<u8>,
}

impl Salamander {
    pub(crate) fn new(password: &[u8]) -> Self {
        Self {
            password: password.to_vec(),
        }
    }

    pub(crate) fn encode(&self, payload: &[u8]) -> Vec<u8> {
        let salt: [u8; SALAMANDER_SALT_LEN] = rand::random();
        let key = self.key(&salt);
        let mut out = Vec::with_capacity(SALAMANDER_SALT_LEN + payload.len());
        out.extend_from_slice(&salt);
        out.extend(
            payload
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % key.len()]),
        );
        out
    }

    pub(crate) fn decode(&self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() <= SALAMANDER_SALT_LEN {
            return None;
        }
        let (salt, ciphertext) = payload.split_at(SALAMANDER_SALT_LEN);
        let key = self.key(salt);
        Some(
            ciphertext
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % key.len()])
                .collect(),
        )
    }

    fn key(&self, salt: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
        hasher.update(&self.password);
        hasher.update(salt);
        let mut key = [0u8; 32];
        hasher
            .finalize_variable(&mut key)
            .expect("BLAKE2b output buffer has requested length");
        key
    }
}

/// Gecko obfuscation (hysteria2 `obfs: gecko`): Salamander, plus hiding the
/// handshake's packet sizes. Each QUIC long-header packet is split into 2–8
/// chunks sent as separate datagrams, each randomly padded so the datagram
/// lands in `[min_packet, max_packet]` bytes; short-header packets go out as
/// plain Salamander.
///
/// A chunk's frame, before Salamander: the header bytes
/// `[0x80, msg_id, index << 4 | total, pad_len (u16 BE)]`, `pad_len` random
/// bytes, then the chunk.
#[derive(Debug)]
pub(crate) struct Gecko {
    salamander: Salamander,
    min_packet: usize,
    max_packet: usize,
    next_msg_id: u8,
    /// Oldest first.
    partials: Vec<Partial>,
}

/// A fragmented message still missing chunks.
#[derive(Debug)]
struct Partial {
    from: SocketAddr,
    msg_id: u8,
    chunks: Vec<Option<Vec<u8>>>,
    missing: usize,
    expires: Instant,
}

impl Gecko {
    /// `min_packet` / `max_packet` come from [`gecko_packet_sizes`].
    pub(crate) fn new(password: &[u8], min_packet: u16, max_packet: u16) -> Self {
        Self {
            salamander: Salamander::new(password),
            min_packet: usize::from(min_packet),
            max_packet: usize::from(max_packet),
            next_msg_id: 0,
            partials: Vec::new(),
        }
    }

    fn encode(&mut self, packet: &[u8]) -> Wire {
        if packet.first().is_none_or(|b| b & GECKO_FRAGMENT == 0) {
            return Wire::One(self.salamander.encode(packet));
        }
        let mut rng = rand::rng();
        let total = rng.random_range(GECKO_MIN_CHUNKS..=GECKO_MAX_CHUNKS);
        let msg_id = self.next_msg_id;
        self.next_msg_id = msg_id.wrapping_add(1);
        let chunk_len = packet.len() / usize::from(total);
        let datagrams = (0..total)
            .map(|index| {
                let start = usize::from(index) * chunk_len;
                let end = if index + 1 == total {
                    packet.len()
                } else {
                    start + chunk_len
                };
                let chunk = &packet[start..end];
                let pad_len = self.pad_len(&mut rng, chunk.len());
                let mut frame = Vec::with_capacity(GECKO_HEADER_LEN + pad_len + chunk.len());
                frame.extend_from_slice(&[GECKO_FRAGMENT, msg_id, (index << 4) | total]);
                frame.extend_from_slice(&(pad_len as u16).to_be_bytes());
                frame.resize(GECKO_HEADER_LEN + pad_len, 0);
                // Padding must be random: Salamander XORs it with a repeating
                // key, so constant padding would show that key on the wire.
                rng.fill_bytes(&mut frame[GECKO_HEADER_LEN..]);
                frame.extend_from_slice(chunk);
                self.salamander.encode(&frame)
            })
            .collect();
        Wire::Fragments(datagrams)
    }

    /// Padding that puts the datagram (salt + header + padding + chunk) at a
    /// random size in `[min_packet, max_packet]`; none when the chunk alone
    /// already exceeds `max_packet`.
    fn pad_len(&self, rng: &mut impl Rng, chunk_len: usize) -> usize {
        let base = SALAMANDER_SALT_LEN + GECKO_HEADER_LEN + chunk_len;
        let low = self.min_packet.max(base);
        if low > self.max_packet {
            return 0;
        }
        rng.random_range(low..=self.max_packet) - base
    }

    fn decode(&mut self, datagram: &[u8], from: SocketAddr, now: Instant) -> Option<Vec<u8>> {
        let mut frame = self.salamander.decode(datagram)?;
        if frame.first()? & GECKO_FRAGMENT == 0 {
            return Some(frame);
        }
        let header = frame.get(..GECKO_HEADER_LEN)?;
        let msg_id = header[1];
        let (index, total) = (header[2] >> 4, header[2] & 0x0f);
        let start = GECKO_HEADER_LEN + usize::from(u16::from_be_bytes([header[3], header[4]]));
        // The official peer reads fragments into a 2048-byte buffer, so none
        // is larger; the cap bounds what junk datagrams can park here.
        if datagram.len() > usize::from(GECKO_MAX_PACKET)
            || !(GECKO_MIN_CHUNKS..=GECKO_MAX_CHUNKS).contains(&total)
            || index >= total
            || start > frame.len()
        {
            return None;
        }
        frame.drain(..start);
        self.reassemble(
            from,
            msg_id,
            usize::from(index),
            usize::from(total),
            frame,
            now,
        )
    }

    fn reassemble(
        &mut self,
        from: SocketAddr,
        msg_id: u8,
        index: usize,
        total: usize,
        chunk: Vec<u8>,
        now: Instant,
    ) -> Option<Vec<u8>> {
        self.partials.retain(|p| p.expires > now);
        let slot = if let Some(slot) = self
            .partials
            .iter()
            .position(|p| p.from == from && p.msg_id == msg_id)
        {
            slot
        } else {
            if self.partials.len() == GECKO_MAX_PARTIALS {
                // Evict rather than refuse: a message this old has lost a
                // chunk, and QUIC resends its frames in new packets.
                self.partials.remove(0);
            }
            self.partials.push(Partial {
                from,
                msg_id,
                chunks: vec![None; total],
                missing: total,
                expires: now + GECKO_REASSEMBLY_TTL,
            });
            self.partials.len() - 1
        };
        let partial = &mut self.partials[slot];
        if partial.chunks.len() != total || partial.chunks[index].is_some() {
            return None;
        }
        partial.chunks[index] = Some(chunk);
        partial.missing -= 1;
        if partial.missing > 0 {
            return None;
        }
        let chunks = self.partials.remove(slot).chunks;
        let mut packet = Vec::with_capacity(chunks.iter().flatten().map(Vec::len).sum());
        for chunk in chunks.into_iter().flatten() {
            packet.extend_from_slice(&chunk);
        }
        Some(packet)
    }
}

/// Port-hopping state (hysteria2 `ports`/`hop-interval`). The server listens on
/// a set of ports and expects the client to rotate the destination port
/// periodically; replies may arrive from any of them, so the incoming source is
/// normalised back to the canonical server address for quiche.
#[derive(Debug)]
pub(crate) struct HopState {
    server_addr: SocketAddr,
    ports: HopPorts,
    min: Duration,
    max: Duration,
    current: u16,
    next: Instant,
}

impl HopState {
    /// Returns `Ok(None)` when no `ports` are configured (hopping disabled).
    pub(crate) fn new(
        server_addr: SocketAddr,
        raw_ports: &str,
        min_secs: u64,
        max_secs: u64,
    ) -> Result<Option<Self>> {
        let Some(ports) = HopPorts::parse(raw_ports)? else {
            return Ok(None);
        };
        let min_secs = if min_secs == 0 {
            HY2_DEFAULT_HOP_INTERVAL_SECS
        } else {
            min_secs.max(HY2_MIN_HOP_INTERVAL_SECS)
        };
        let max_secs = max_secs.max(min_secs);
        // Backstop for programmatic callers: `Instant + Duration` overflows
        // on absurd intervals and panics (config parse already rejects these
        // — issue #648).
        let min_secs = min_secs.min(meow_common::MAX_DURATION_SECS);
        let max_secs = max_secs.min(meow_common::MAX_DURATION_SECS);
        let mut state = Self {
            server_addr,
            ports,
            min: Duration::from_secs(min_secs),
            max: Duration::from_secs(max_secs),
            current: 0,
            next: Instant::now(),
        };
        state.rotate(Instant::now());
        Ok(Some(state))
    }

    /// Destination address for an outgoing datagram: the current hop port on
    /// the server IP.
    pub(crate) fn outgoing(&mut self) -> SocketAddr {
        let now = Instant::now();
        if now >= self.next {
            self.rotate(now);
        }
        let mut addr = self.server_addr;
        addr.set_port(self.current);
        addr
    }

    /// Normalise an incoming source back to the canonical server address if it
    /// came from one of the hop ports on the server IP.
    pub(crate) fn normalize_source(&self, source: SocketAddr) -> SocketAddr {
        if source.ip() == self.server_addr.ip() && self.ports.contains(source.port()) {
            self.server_addr
        } else {
            source
        }
    }

    fn rotate(&mut self, now: Instant) {
        self.current = self.ports.random_port();
        self.next = now + self.next_interval();
    }

    fn next_interval(&self) -> Duration {
        if self.min >= self.max {
            return self.min;
        }
        let min = self.min.as_secs();
        let span = self.max.as_secs() - min + 1;
        Duration::from_secs(min + rand::random::<u64>() % span)
    }
}

#[derive(Clone)]
enum HopPorts {
    All,
    List(Vec<u16>),
}

impl fmt::Debug for HopPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("All"),
            Self::List(ports) => f.debug_tuple("List").field(ports).finish(),
        }
    }
}

/// Bound on the pre-dedup port expansion in [`HopPorts::parse`] — the u16
/// port space holds at most this many distinct values (issue #648).
const MAX_HOP_PORT_ENTRIES: usize = u16::MAX as usize;

impl HopPorts {
    fn parse(raw: &str) -> Result<Option<Self>> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(None);
        }
        if raw == "*" || raw.eq_ignore_ascii_case("all") {
            return Ok(Some(Self::All));
        }

        let mut ports = Vec::new();
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(Error::config(format!("invalid hop ports '{raw}'")));
            }
            // Bound the pre-dedup expansion: the port space has only
            // u16::MAX values, so anything past that is necessarily a
            // duplicate — a provider-supplied string of repeated
            // "1-65535" ranges would otherwise amplify ~8 bytes of config
            // into 128 KiB of Vec per range (issue #648).
            if let Some((start, end)) = part.split_once('-') {
                let start = parse_port(start)?;
                let end = parse_port(end)?;
                if start > end {
                    return Err(Error::config(format!("invalid hop port range '{part}'")));
                }
                if ports.len() + (end as usize - start as usize + 1) > MAX_HOP_PORT_ENTRIES {
                    return Err(Error::config(format!(
                        "hop ports '{raw}' expand beyond {MAX_HOP_PORT_ENTRIES} entries"
                    )));
                }
                ports.extend(start..=end);
            } else {
                if ports.len() == MAX_HOP_PORT_ENTRIES {
                    return Err(Error::config(format!(
                        "hop ports '{raw}' expand beyond {MAX_HOP_PORT_ENTRIES} entries"
                    )));
                }
                ports.push(parse_port(part)?);
            }
        }
        ports.sort_unstable();
        ports.dedup();
        if ports.is_empty() {
            return Err(Error::config("empty hop port set"));
        }
        Ok(Some(Self::List(ports)))
    }

    fn contains(&self, port: u16) -> bool {
        match self {
            Self::All => port != 0,
            Self::List(ports) => ports.binary_search(&port).is_ok(),
        }
    }

    fn random_port(&self) -> u16 {
        match self {
            Self::All => (1 + rand::random::<u16>() % u16::MAX).max(1),
            Self::List(ports) => ports[rand::random::<u64>() as usize % ports.len()],
        }
    }
}

fn parse_port(raw: &str) -> Result<u16> {
    let port = raw
        .trim()
        .parse::<u16>()
        .map_err(|e| Error::config(format!("invalid hop port '{raw}': {e}")))?;
    if port == 0 {
        return Err(Error::config("hop port must be non-zero"));
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_ports_expansion_bounded() {
        // Repeated full ranges would pre-dedup into a giant Vec — the port
        // space can't hold more than u16::MAX entries anyway (issue #648).
        assert!(HopPorts::parse("1-65535").unwrap().is_some());
        assert!(HopPorts::parse("1-65535,1-65535").is_err());
        assert!(HopPorts::parse("1-65535,80").is_err());
        assert!(HopPorts::parse("80,443,1-65535").is_err());
        // A full range plus duplicates *within* the bound stays fine.
        let p = HopPorts::parse("1-1024,80,443").unwrap().unwrap();
        assert!(p.contains(80));
        assert!(!p.contains(2000));
    }

    #[test]
    fn salamander_round_trip() {
        let obfs = Salamander::new(b"secret");
        let encoded = obfs.encode(b"payload");
        assert_ne!(&encoded[SALAMANDER_SALT_LEN..], b"payload");
        assert_eq!(obfs.decode(&encoded).unwrap(), b"payload");
    }

    const PEER: &str = "192.0.2.1:443";

    fn gecko(min: u16, max: u16) -> Gecko {
        Gecko::new(b"secret", min, max)
    }

    /// A QUIC long-header (handshake) packet: first bit set.
    fn handshake_packet(len: usize) -> Vec<u8> {
        let mut packet: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
        packet[0] = 0xc3;
        packet
    }

    /// A fragment frame as the peer would send it, under Salamander.
    fn fragment(msg_id: u8, index: u8, total: u8, chunk: &[u8]) -> Vec<u8> {
        let mut frame = vec![GECKO_FRAGMENT, msg_id, (index << 4) | total, 0, 0];
        frame.extend_from_slice(chunk);
        Salamander::new(b"secret").encode(&frame)
    }

    fn fragments(wire: Wire) -> Vec<Vec<u8>> {
        match wire {
            Wire::Fragments(datagrams) => datagrams,
            Wire::One(_) => panic!("a handshake packet must be fragmented"),
        }
    }

    #[test]
    fn gecko_packet_sizes_default_and_bound() {
        assert_eq!(gecko_packet_sizes(0, 0), Ok((512, 1200)));
        assert_eq!(gecko_packet_sizes(600, 0), Ok((600, 1200)));
        assert_eq!(gecko_packet_sizes(2048, 2048), Ok((2048, 2048)));
        // A lone max below the default min is an inverted range.
        assert!(gecko_packet_sizes(0, 400).is_err());
        assert!(gecko_packet_sizes(900, 600).is_err());
        assert!(gecko_packet_sizes(0, 2049).is_err());
    }

    #[test]
    fn gecko_sends_short_header_packets_as_plain_salamander() {
        let mut sender = gecko(512, 1200);
        let packet = [0x40, 1, 2, 3];
        let Wire::One(datagram) = sender.encode(&packet) else {
            panic!("a short-header packet must not be fragmented");
        };
        assert_eq!(datagram.len(), SALAMANDER_SALT_LEN + packet.len());
        assert_eq!(
            Salamander::new(b"secret").decode(&datagram).unwrap(),
            packet
        );
        let peer = PEER.parse().unwrap();
        assert_eq!(
            gecko(512, 1200).decode(&datagram, peer, Instant::now()),
            Some(packet.to_vec())
        );
    }

    #[test]
    fn gecko_fragments_handshake_packets_into_padded_chunks() {
        let peer = PEER.parse().unwrap();
        let packet = handshake_packet(1200);
        let mut sender = gecko(600, 900);
        let mut receiver = gecko(512, 1200);
        let mut chunk_counts = std::collections::HashSet::new();
        for msg in 0..200u32 {
            let datagrams = fragments(sender.encode(&packet));
            chunk_counts.insert(datagrams.len());
            assert!((2..=8).contains(&datagrams.len()));
            for (index, datagram) in datagrams.iter().enumerate() {
                assert!(
                    (600..=900).contains(&datagram.len()),
                    "datagram of {} bytes",
                    datagram.len()
                );
                let frame = Salamander::new(b"secret").decode(datagram).unwrap();
                assert_eq!(frame[0], GECKO_FRAGMENT);
                assert_eq!(frame[1], msg as u8);
                assert_eq!(usize::from(frame[2] >> 4), index);
                assert_eq!(usize::from(frame[2] & 0x0f), datagrams.len());
            }
            // Reassembly does not depend on arrival order.
            let (last, rest) = datagrams.split_first().unwrap();
            for datagram in rest.iter().rev() {
                assert_eq!(receiver.decode(datagram, peer, Instant::now()), None);
            }
            assert_eq!(
                receiver.decode(last, peer, Instant::now()),
                Some(packet.clone())
            );
        }
        assert!(receiver.partials.is_empty());
        assert!(chunk_counts.len() > 1, "the chunk count must vary");
    }

    #[test]
    fn gecko_does_not_pad_chunks_above_the_max_size() {
        let mut sender = gecko(100, 100);
        for datagram in fragments(sender.encode(&handshake_packet(1200))) {
            let frame = Salamander::new(b"secret").decode(&datagram).unwrap();
            assert_eq!(&frame[3..5], &[0, 0]);
        }
    }

    #[test]
    fn gecko_drops_malformed_fragments() {
        let peer = PEER.parse().unwrap();
        let salamander = Salamander::new(b"secret");
        let mut receiver = gecko(512, 1200);
        let short = salamander.encode(&[GECKO_FRAGMENT, 0, 0x02]);
        let padding_past_end = salamander.encode(&[GECKO_FRAGMENT, 0, 0x02, 0, 9, 1]);
        for datagram in [
            short,
            padding_past_end,
            fragment(0, 0, 1, b"one chunk"),
            fragment(0, 0, 9, b"nine chunks"),
            fragment(0, 2, 2, b"index past total"),
            fragment(0, 0, 2, &[0; 2048]),
        ] {
            assert_eq!(receiver.decode(&datagram, peer, Instant::now()), None);
        }
        assert!(receiver.partials.is_empty());
    }

    #[test]
    fn gecko_ignores_repeated_and_inconsistent_chunks() {
        let peer = PEER.parse().unwrap();
        let now = Instant::now();
        let mut receiver = gecko(512, 1200);
        assert_eq!(receiver.decode(&fragment(7, 0, 2, b"ab"), peer, now), None);
        assert_eq!(receiver.decode(&fragment(7, 0, 2, b"xx"), peer, now), None);
        assert_eq!(receiver.decode(&fragment(7, 1, 3, b"xx"), peer, now), None);
        assert_eq!(
            receiver.decode(&fragment(7, 1, 2, b"cd"), peer, now),
            Some(b"abcd".to_vec())
        );
    }

    #[test]
    fn gecko_keeps_sources_apart() {
        let peer = PEER.parse().unwrap();
        let other = "198.51.100.1:443".parse().unwrap();
        let now = Instant::now();
        let mut receiver = gecko(512, 1200);
        assert_eq!(receiver.decode(&fragment(1, 0, 2, b"ab"), peer, now), None);
        assert_eq!(receiver.decode(&fragment(1, 1, 2, b"xx"), other, now), None);
        assert_eq!(
            receiver.decode(&fragment(1, 1, 2, b"cd"), peer, now),
            Some(b"abcd".to_vec())
        );
    }

    #[test]
    fn gecko_bounds_and_expires_partial_messages() {
        let peer = PEER.parse().unwrap();
        let now = Instant::now();
        let mut receiver = gecko(512, 1200);
        for msg_id in 0..=GECKO_MAX_PARTIALS as u8 {
            assert_eq!(
                receiver.decode(&fragment(msg_id, 0, 2, b"ab"), peer, now),
                None
            );
        }
        // Message 0 was evicted for the newest one: its second chunk starts
        // over instead of completing it.
        assert_eq!(receiver.partials.len(), GECKO_MAX_PARTIALS);
        assert_eq!(receiver.decode(&fragment(0, 1, 2, b"cd"), peer, now), None);
        assert_eq!(
            receiver.decode(&fragment(2, 1, 2, b"cd"), peer, now),
            Some(b"abcd".to_vec())
        );

        // Past the TTL every partial message is gone.
        let later = now + GECKO_REASSEMBLY_TTL;
        assert_eq!(
            receiver.decode(&fragment(3, 1, 2, b"cd"), peer, later),
            None
        );
        assert_eq!(receiver.partials.len(), 1);
    }

    #[test]
    fn hop_state_clamps_absurd_interval() {
        // Programmatic callers skip the config-parse bound — the backstop
        // keeps `Instant + Duration` from overflowing (issue #648).
        let state = HopState::new("127.0.0.1:443".parse().unwrap(), "80", u64::MAX, u64::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(
            state.min,
            Duration::from_secs(meow_common::MAX_DURATION_SECS)
        );
        assert_eq!(
            state.max,
            Duration::from_secs(meow_common::MAX_DURATION_SECS)
        );
    }

    #[test]
    fn hop_ports_parse_ranges() {
        let ports = HopPorts::parse("443,8443-8445").unwrap().unwrap();
        assert!(ports.contains(443));
        assert!(ports.contains(8443));
        assert!(ports.contains(8445));
        assert!(!ports.contains(8446));
    }
}
