//! Salamander UDP obfuscation and port-hopping for the hysteria2 quiche
//! transport.
//!
//! With quinn the socket was an `AsyncUdpSocket` that rewrote datagrams; the
//! quiche driver owns its UDP socket directly, so these are plain per-datagram
//! transforms it applies on send/recv (see `driver.rs`).

use super::{Error, Result};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const SALAMANDER_SALT_LEN: usize = 8;
const HY2_MIN_HOP_INTERVAL_SECS: u64 = 5;
const HY2_DEFAULT_HOP_INTERVAL_SECS: u64 = 30;

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
