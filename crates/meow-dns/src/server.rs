use crate::resolver::{AddressLookupResult, Resolver};
use futures::FutureExt;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Record, RecordType};
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Weak};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// TTL stamped on regular (non-fake-IP) A/AAAA answers built by this server.
const DEFAULT_ANSWER_TTL_SECS: u32 = 60;

/// Minimal EDNS0 OPT pseudo-record (11 bytes) appended to responses when the
/// query carried one in the additional section.  Windows DNS Client (used by
/// `Resolve-DnsName` and `curl`) sends EDNS0 queries and may reject or time
/// out on responses that strip the OPT record.
///
/// Layout: root name (1) + OPT type 41 (2) + UDP size 512 (2) + TTL 0 (4) +
/// RDLENGTH 0 (2).
const OPT_RECORD: &[u8] = &[
    0x00, // NAME: root
    0x00, 0x29, // TYPE: OPT (41)
    0x02, 0x00, // CLASS: UDP payload size 512
    0x00, 0x00, 0x00, 0x00, // TTL: ext-rcode=0, version=0, DO=0
    0x00, 0x00, // RDLENGTH: 0
];

/// Shared resolver slot behind `RwLock<Arc<..>>` so a config reload can
/// swap the generation every live server reads per query — no socket
/// rebind, no in-flight query disruption (issue #514).
pub type ResolverSlot = Arc<parking_lot::RwLock<Arc<Resolver>>>;

/// Simple DNS server that handles queries by forwarding to our resolver.
pub struct DnsServer {
    resolver: ResolverSlot,
    listen_addr: SocketAddr,
}

impl DnsServer {
    pub fn new(resolver: Arc<Resolver>, listen_addr: SocketAddr) -> Self {
        Self {
            resolver: Arc::new(parking_lot::RwLock::new(resolver)),
            listen_addr,
        }
    }

    /// The slot the bound server reads per query. Store the returned `Arc`
    /// and write the rebuilt resolver into it on config reload (issue #514).
    pub fn resolver_slot(&self) -> ResolverSlot {
        Arc::clone(&self.resolver)
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Bind the listen socket eagerly and return a [`BoundDnsServer`] ready to
    /// [`BoundDnsServer::run`]. Splitting bind from serve lets embedders treat
    /// a bind failure (EADDRINUSE, missing address, sandbox denial) as a hard
    /// startup error instead of discovering it as a silently dead resolver:
    /// with the old `run()`-binds-internally shape, a caller that spawned
    /// `run()` fire-and-forget had no way to distinguish "listening" from
    /// "bind failed, every query will be dropped".
    pub async fn bind(&self) -> std::io::Result<BoundDnsServer> {
        let socket = Arc::new(UdpSocket::bind(self.listen_addr).await?);
        let bound = socket.local_addr().unwrap_or(self.listen_addr);
        info!("DNS server listening on {bound}");
        Ok(BoundDnsServer {
            resolver: Arc::clone(&self.resolver),
            socket,
        })
    }

    /// Bind and serve in one call. Kept for callers that await `run()`
    /// directly and can observe its error; embedders that spawn the serve
    /// loop should use [`DnsServer::bind`] + [`BoundDnsServer::run`] so bind
    /// failures surface at startup.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.bind().await?.run().await
    }

    pub async fn handle_query(
        data: &[u8],
        resolver: &Resolver,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Minimal DNS parsing: extract the query name and type
        if data.len() < 12 {
            return Err("DNS packet too short".into());
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let arcount = u16::from_be_bytes([data[10], data[11]]);

        if qdcount == 0 {
            return Err("No questions in DNS query".into());
        }
        // The hand-rolled response builders answer exactly one question, and
        // multi-question queries are wire-legal but unsupported by essentially
        // every real resolver. Answer FORMERR instead of emitting a response
        // whose header counts don't match its body.
        if qdcount != 1 {
            return Ok(Self::build_formerr(id, flags));
        }

        // Parse the question name
        let (domain, qtype, question_len) = Self::parse_question(&data[12..]).map_err(|e| {
            debug!(
                "DNS query parse_question failed: {e} | bytes: {}",
                hex_prefix(&data[12..], 64)
            );
            e
        })?;
        debug!(
            "DNS query: id={id:#06x} flags={flags:#06x} arcount={arcount} domain={domain} qtype={qtype}"
        );

        // Non-address queries (TXT, MX, SRV, HTTPS, SOA, PTR, …) go through
        // the same nameserver pipeline as A/AAAA — policy → main → fallback —
        // and the typed `Lookup` is re-emitted into a wire-format response.
        // We deliberately stop short of fake-IP synthesis here: only address
        // records ever get a synthetic answer.
        if qtype != 1 && qtype != 28 {
            return Self::handle_generic_forward(
                id,
                data,
                flags,
                question_len,
                &domain,
                qtype,
                resolver,
            )
            .await;
        }

        // Check hosts trie first. If the domain is present in the hosts table
        // but has no IPs of the queried family, return NOERROR with zero answers
        // rather than NXDOMAIN — clients may retry on NXDOMAIN but not on an
        // empty-answer NOERROR response.
        if let Some(all_ips) = resolver.lookup_hosts_all(&domain) {
            // When IPv6 is disabled, an AAAA query for a hosts entry that
            // *does* have a v6 address still returns that address — the
            // hosts file is an explicit user override that takes priority
            // over the global ipv6 toggle. Only fall through to the
            // empty-answer short-circuit below when the hosts table has no
            // matching entry at all.
            let ip = if qtype == 1 {
                all_ips.iter().find(|ip| ip.is_ipv4()).copied()
            } else {
                all_ips.iter().find(|ip| ip.is_ipv6()).copied()
            };
            return Ok(match ip {
                Some(addr) => Self::build_response(
                    id,
                    data,
                    flags,
                    question_len,
                    qtype,
                    addr,
                    DEFAULT_ANSWER_TTL_SECS,
                ),
                None => Self::build_noerror_empty(id, data, flags, question_len),
            });
        }

        // AAAA short-circuit when IPv6 is disabled: return an empty NOERROR
        // so clients don't wait for an upstream response that would be
        // filtered anyway. This comes *after* the hosts check so a hosts
        // override for the disabled family is still honored.
        if qtype == 28 && !resolver.ipv6_enabled() {
            return Ok(Self::build_noerror_empty(id, data, flags, question_len));
        }

        // Resolve using our resolver (cache + upstream + fake-IP synthesis).
        // The resolver reports the TTL each answer should carry: the short
        // fake-IP TTL for synthesised addresses (clients must re-query after
        // pool eviction), and the upstream's real TTL — decayed by time spent
        // in cache — for everything else, so redir-host / normal-mode clients
        // expire their own caches on the upstream's schedule instead of a
        // synthetic constant.
        let lookup = if qtype == 1 {
            resolver.lookup_ipv4_result(&domain).await
        } else {
            resolver.lookup_ipv6_result(&domain).await
        };

        Ok(match lookup {
            AddressLookupResult::Answer(addr, ttl) => {
                // Sub-second remainders round up to 1 — a 0-TTL answer means
                // "never cache", which is stricter than the entry deserves.
                let ttl_secs = ttl.as_secs().clamp(1, u64::from(u32::MAX)) as u32;
                Self::build_response(id, data, flags, question_len, qtype, addr, ttl_secs)
            }
            AddressLookupResult::NoData => Self::build_noerror_empty(id, data, flags, question_len),
            AddressLookupResult::NxDomain => Self::build_nxdomain(id, data, flags, question_len),
            AddressLookupResult::Failed => Self::build_servfail(id, data, flags, question_len),
        })
    }

    /// Forward a non-A/AAAA query through the resolver pipeline and emit the
    /// returned records as a wire-format response. On upstream failure we
    /// return SERVFAIL (not NXDOMAIN) — clients may negative-cache NXDOMAIN
    /// against the bare name, which would poison subsequent A/AAAA lookups.
    async fn handle_generic_forward(
        id: u16,
        query: &[u8],
        flags: u16,
        question_len: usize,
        domain: &str,
        qtype: u16,
        resolver: &Resolver,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let record_type = RecordType::from(qtype);
        debug!("DNS forward (generic): {} type={:?}", domain, record_type);
        let lookup = resolver.forward_generic(domain, record_type).await;

        // Parse the inbound query just to copy its question section verbatim.
        // If parsing fails we fall back to the hand-rolled NXDOMAIN builder
        // rather than dropping the packet.
        let Ok(req) = Message::from_vec(query) else {
            return Ok(Self::build_nxdomain(id, query, flags, question_len));
        };

        let mut resp = Message::new(id, MessageType::Response, OpCode::Query);
        resp.metadata.recursion_desired = req.metadata.recursion_desired;
        resp.metadata.recursion_available = true;
        resp.add_queries(req.queries.iter().cloned());

        match lookup {
            Some(l) => {
                resp.metadata.response_code = ResponseCode::NoError;
                // In fake-IP mode, drop ipv4hint/ipv6hint from HTTPS/SVCB
                // answers for faked hosts so an HTTP/3 client cannot read a
                // real origin IP out of the hint and bypass the fake-IP
                // routing the tunnel depends on.
                let strip_hints = resolver.fake_ip_active_for(domain);
                let strip_ipv6_hint = !resolver.ipv6_enabled();
                for rec in &l.answers {
                    if strip_hints || strip_ipv6_hint {
                        resp.add_answer(strip_svc_ip_hints(
                            rec,
                            strip_hints,
                            strip_hints || strip_ipv6_hint,
                        ));
                    } else {
                        resp.add_answer(rec.clone());
                    }
                }
            }
            None => {
                resp.metadata.response_code = ResponseCode::ServFail;
            }
        }

        Ok(resp
            .to_vec()
            .unwrap_or_else(|_| Self::build_nxdomain(id, query, flags, question_len)))
    }

    fn parse_question(
        data: &[u8],
    ) -> Result<(String, u16, usize), Box<dyn std::error::Error + Send + Sync>> {
        // First pass: validate label framing and find the QNAME wire length,
        // so the domain buffer below is allocated exactly once.
        let mut pos = 0;
        loop {
            if pos >= data.len() {
                return Err("DNS question truncated".into());
            }
            let len = data[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if pos + 1 + len > data.len() {
                return Err("DNS label truncated".into());
            }
            pos += 1 + len;
        }

        // Second pass: append labels separated by '.' into one pre-sized
        // String. `from_utf8_lossy` only allocates on invalid UTF-8, so the
        // lossy semantics are preserved without per-label Strings.
        let mut domain = String::with_capacity(pos.saturating_sub(2));
        let mut lpos = 0;
        loop {
            let len = data[lpos] as usize;
            if len == 0 {
                break;
            }
            if !domain.is_empty() {
                domain.push('.');
            }
            domain.push_str(&String::from_utf8_lossy(&data[lpos + 1..lpos + 1 + len]));
            lpos += 1 + len;
        }

        if pos + 4 > data.len() {
            return Err("DNS question type/class truncated".into());
        }
        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 4; // skip type and class

        Ok((domain, qtype, pos))
    }

    /// Copy the single question (validated by `parse_question`, which
    /// returned its wire length) from `query` into `buf`. `handle_query`
    /// rejects `qdcount != 1` with FORMERR before any builder runs, so the
    /// hardcoded `QDCOUNT=1` in the response headers always matches the body.
    fn copy_question(buf: &mut Vec<u8>, query: &[u8], question_len: usize) {
        let end = (12 + question_len).min(query.len());
        buf.extend_from_slice(&query[12..end]);
    }

    /// Echo the query flags into response header bytes, preserving the
    /// OPCODE, RD, and CD bits while setting QR=1 and RA=1.
    fn response_flags(query_flags: u16) -> [u8; 2] {
        let hi = (query_flags >> 8) as u8;
        let lo = query_flags as u8;
        // Byte 0: QR=1 | OPCODE(echo) | AA=0 | TC=0 | RD(echo)
        let byte0: u8 = 0x80 | (hi & 0x79); // 0x79 = bits 6,5,4,3 (OPCODE) + bit 0 (RD)
                                            // Byte 1: RA=1 | Z=0 | AD=0 | CD(echo) | RCODE=0
        let byte1: u8 = 0x80 | (lo & 0x10); // 0x10 = bit 4 (CD)
        [byte0, byte1]
    }

    /// Append the EDNS0 OPT record when the query had one (ARCOUNT > 0),
    /// bumping the `arcount` field in the previously-written header.
    fn append_opt_record(buf: &mut Vec<u8>, header_pos: usize) {
        // Patch ARCOUNT at header_pos+10..12 from 0 to 1.
        let len = buf.len();
        buf[header_pos + 10] = 0x00;
        buf[header_pos + 11] = 0x01;
        buf.extend_from_slice(OPT_RECORD);
        debug_assert_eq!(buf.len(), len + OPT_RECORD.len());
    }

    fn build_response(
        id: u16,
        query: &[u8],
        flags: u16,
        question_len: usize,
        qtype: u16,
        addr: std::net::IpAddr,
        ttl_secs: u32,
    ) -> Vec<u8> {
        let arcount = u16::from_be_bytes([query[10], query[11]]);
        let mut response = Vec::with_capacity(512);

        let header_pos = response.len();

        // Header
        response.extend_from_slice(&id.to_be_bytes()); // ID
        response.extend_from_slice(&Self::response_flags(flags));
        response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        response.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
        response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0 (patched below)

        // Copy the question
        Self::copy_question(&mut response, query, question_len);

        // Answer: pointer to name in question
        response.extend_from_slice(&[0xc0, 0x0c]); // Name pointer to offset 12
        response.extend_from_slice(&qtype.to_be_bytes()); // TYPE
        response.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        response.extend_from_slice(&ttl_secs.to_be_bytes()); // TTL

        match addr {
            std::net::IpAddr::V4(v4) => {
                response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
                response.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                response.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
                response.extend_from_slice(&v6.octets());
            }
        }

        if arcount > 0 {
            Self::append_opt_record(&mut response, header_pos);
        }

        response
    }

    fn build_nxdomain(id: u16, query: &[u8], flags: u16, question_len: usize) -> Vec<u8> {
        let arcount = u16::from_be_bytes([query[10], query[11]]);
        let mut response = Vec::with_capacity(512);

        let header_pos = response.len();

        // Header: NXDOMAIN (rcode=3), QR=1, RD=echo, RA=1
        let [byte0, byte1] = Self::response_flags(flags);
        let byte1_rcode = (byte1 & 0xF0) | 0x03; // NXDOMAIN

        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&[byte0, byte1_rcode]);
        response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        response.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0 (patched below)

        // Copy the question
        Self::copy_question(&mut response, query, question_len);

        if arcount > 0 {
            Self::append_opt_record(&mut response, header_pos);
        }

        response
    }

    /// Header-only FORMERR (rcode=1) for queries the hand-rolled builders
    /// cannot answer coherently (e.g. `qdcount > 1`). No question section is
    /// echoed — clients match the response on ID.
    fn build_formerr(id: u16, flags: u16) -> Vec<u8> {
        let [byte0, byte1] = Self::response_flags(flags);
        let byte1_rcode = (byte1 & 0xF0) | 0x01; // FORMERR

        let mut response = Vec::with_capacity(12);
        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&[byte0, byte1_rcode]);
        response.extend_from_slice(&[0x00; 8]); // QD/AN/NS/AR = 0
        response
    }

    #[cfg(test)]
    fn question_len_for_test(query: &[u8]) -> usize {
        Self::parse_question(&query[12..])
            .expect("valid test query")
            .2
    }

    #[cfg(test)]
    pub(crate) fn build_response_for_test(
        id: u16,
        query: &[u8],
        qtype: u16,
        addr: std::net::IpAddr,
        ttl_secs: u32,
    ) -> Vec<u8> {
        Self::build_response(
            id,
            query,
            0x0100,
            Self::question_len_for_test(query),
            qtype,
            addr,
            ttl_secs,
        )
    }

    #[cfg(test)]
    pub(crate) fn build_nxdomain_for_test(id: u16, query: &[u8]) -> Vec<u8> {
        Self::build_nxdomain(id, query, 0x0100, Self::question_len_for_test(query))
    }

    #[cfg(test)]
    pub(crate) fn build_noerror_empty_for_test(id: u16, query: &[u8]) -> Vec<u8> {
        Self::build_noerror_empty(id, query, 0x0100, Self::question_len_for_test(query))
    }

    #[cfg(test)]
    pub(crate) fn parse_question_for_test(
        data: &[u8],
    ) -> Result<(String, u16, usize), Box<dyn std::error::Error + Send + Sync>> {
        Self::parse_question(data)
    }

    /// NOERROR with zero answers: hosts entry matched but no IPs of the queried
    /// address family. Clients must not retry on an empty-answer NOERROR.
    fn build_noerror_empty(id: u16, query: &[u8], flags: u16, question_len: usize) -> Vec<u8> {
        let arcount = u16::from_be_bytes([query[10], query[11]]);
        let mut response = Vec::with_capacity(512);

        let header_pos = response.len();

        // Header: NOERROR (rcode=0), QR=1, RD=echo, RA=1
        let flag_bytes = Self::response_flags(flags);

        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&flag_bytes);
        response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        response.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0 (patched below)

        // Copy the question
        Self::copy_question(&mut response, query, question_len);

        if arcount > 0 {
            Self::append_opt_record(&mut response, header_pos);
        }

        response
    }

    fn build_servfail(id: u16, query: &[u8], flags: u16, question_len: usize) -> Vec<u8> {
        let mut response = Self::build_noerror_empty(id, query, flags, question_len);
        response[3] = (response[3] & 0xF0) | 0x02;
        response
    }
}

/// A [`DnsServer`] whose listen socket is already bound. Produced by
/// [`DnsServer::bind`]; consumed by [`Self::run`].
pub struct BoundDnsServer {
    resolver: ResolverSlot,
    socket: Arc<UdpSocket>,
}

impl BoundDnsServer {
    /// Wrap an externally bound socket so embedders reuse this hardened serve
    /// loop (bounded worker pool, backpressure, panic-guarded workers)
    /// instead of hand-rolling their own — e.g. the TUN loopback DNS servers
    /// on Windows, which must bind `127.0.0.1:53`/`[::1]:53` *before* the OS
    /// resolver is repointed at them.
    pub fn from_socket(socket: UdpSocket, resolver: Arc<Resolver>) -> Self {
        Self {
            resolver: Arc::new(parking_lot::RwLock::new(resolver)),
            socket: Arc::new(socket),
        }
    }

    /// Variant taking a shared slot directly, for callers that hot-swap the
    /// resolver across generations (issue #514).
    pub fn from_slot(socket: UdpSocket, resolver: ResolverSlot) -> Self {
        Self {
            resolver,
            socket: Arc::new(socket),
        }
    }

    /// The slot the serve loop reads per query.
    pub fn resolver_slot(&self) -> ResolverSlot {
        Arc::clone(&self.resolver)
    }

    /// Local address of the bound listen socket (useful with a port-0 bind).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Serve queries until the future is dropped.
    ///
    /// Ownership contract: the serve loop holds the ONLY strong `Arc` to the
    /// listen socket — workers hold `Weak` refs and upgrade per reply. When an
    /// embedder aborts the task running this future, the socket drops with the
    /// future's frame and the port is released immediately, even while a worker
    /// is still parked inside `handle_query` awaiting an upstream (previously
    /// the workers' strong clones kept the port bound for up to the ~5 s query
    /// timeout after an abort, so an immediate stop→start rebind of a fixed
    /// port hit EADDRINUSE).
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let BoundDnsServer { resolver, socket } = self;

        // Worker pool: pre-spawn N workers and round-robin packets to them via
        // bounded mpsc channels. Replaces the previous `tokio::spawn`-per-packet
        // pattern (one task allocation per query under W4 load).
        const N_WORKERS: usize = 4;
        const CHANNEL_DEPTH: usize = 256;
        let mut senders: Vec<tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>> =
            Vec::with_capacity(N_WORKERS);
        for worker_id in 0..N_WORKERS {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(CHANNEL_DEPTH);
            let resolver_slot = Arc::clone(&resolver);
            let sock: Weak<UdpSocket> = Arc::downgrade(&socket);
            tokio::spawn(async move {
                while let Some((data, src)) = rx.recv().await {
                    // Snapshot the current resolver generation per query —
                    // a `PUT /configs` DNS reload swaps the slot (issue #514).
                    // The read guard must drop before `.await`: it is !Send.
                    let resolver = Arc::clone(&resolver_slot.read());
                    // Panic guard: a panic inside query handling must not kill
                    // the worker — a dead worker silently blackholes its
                    // round-robin share of ALL queries for the server's
                    // remaining lifetime (try_send to a dropped rx reads as
                    // ordinary backpressure at the accept loop).
                    let outcome = AssertUnwindSafe(DnsServer::handle_query(&data, &resolver))
                        .catch_unwind()
                        .await;
                    match outcome {
                        Ok(Ok(response)) => {
                            // Upgrade per reply; hold the strong ref only across
                            // the send so the serve loop stays the socket owner.
                            let Some(sock) = sock.upgrade() else {
                                // Server dropped — exit so the port stays free.
                                break;
                            };
                            if let Err(e) = sock.send_to(&response, src).await {
                                warn!("DNS send error: {}", e);
                            }
                        }
                        Ok(Err(e)) => {
                            debug!("DNS query handling error: {}", e);
                        }
                        Err(_) => {
                            error!("DNS worker {} survived a query panic", worker_id);
                        }
                    }
                }
            });
            senders.push(tx);
        }

        let mut buf = vec![0u8; 4096];
        let mut rr: usize = 0;
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    error!("DNS recv error: {}", e);
                    continue;
                }
            };

            let data = buf[..len].to_vec();
            // Round-robin to a worker. If the channel is full we drop the
            // query (DNS is best-effort UDP — better to drop one packet
            // than block the recv loop and stall all queries).
            let worker = rr % N_WORKERS;
            rr = rr.wrapping_add(1);
            if senders[worker].try_send((data, src)).is_err() {
                debug!("DNS worker {} backpressure; dropping query", worker);
            }
        }
    }
}

/// Return a copy of `rec` with `ipv4hint` / `ipv6hint` SvcParams removed when
/// it is an HTTPS or SVCB record; any other record type is cloned unchanged.
///
/// In fake-IP mode both address hints are removed. When IPv6 is disabled,
/// only `ipv6hint` is removed so clients can still use `ipv4hint`. All other
/// SvcParams (alpn, port, ech, …) are preserved.
/// See ADR-0013 for the dual-stack correctness analysis.
fn strip_svc_ip_hints(rec: &Record, strip_ipv4: bool, strip_ipv6: bool) -> Record {
    use hickory_proto::rr::rdata::svcb::{Mandatory, SvcParamKey, SvcParamValue, SVCB};
    use hickory_proto::rr::rdata::HTTPS;
    use hickory_proto::rr::RData;

    fn is_hint(k: SvcParamKey, strip_ipv4: bool, strip_ipv6: bool) -> bool {
        (strip_ipv4 && k == SvcParamKey::Ipv4Hint) || (strip_ipv6 && k == SvcParamKey::Ipv6Hint)
    }

    fn strip(svcb: &SVCB, strip_ipv4: bool, strip_ipv6: bool) -> SVCB {
        let mut params = Vec::with_capacity(svcb.svc_params.len());
        for (key, value) in &svcb.svc_params {
            // Drop the address hints themselves.
            if is_hint(*key, strip_ipv4, strip_ipv6) {
                continue;
            }
            // RFC 9460 §8: a key listed in `mandatory` that is absent from the
            // RR makes the whole record malformed, so the client discards it —
            // which would take the `alpn` (HTTP/3) and `ech` params we want to
            // keep with it. Scrub the hint keys out of the mandatory list, and
            // drop `mandatory` entirely if nothing else remains (an empty
            // mandatory list is itself malformed).
            if let (SvcParamKey::Mandatory, SvcParamValue::Mandatory(Mandatory(keys))) =
                (key, value)
            {
                let kept: Vec<SvcParamKey> = keys
                    .iter()
                    .copied()
                    .filter(|k| !is_hint(*k, strip_ipv4, strip_ipv6))
                    .collect();
                if kept.is_empty() {
                    continue;
                }
                params.push((
                    SvcParamKey::Mandatory,
                    SvcParamValue::Mandatory(Mandatory(kept)),
                ));
                continue;
            }
            params.push((*key, value.clone()));
        }
        SVCB::new(svcb.svc_priority, svcb.target_name.clone(), params)
    }

    let new_rdata = match &rec.data {
        RData::HTTPS(https) => RData::HTTPS(HTTPS(strip(&https.0, strip_ipv4, strip_ipv6))),
        RData::SVCB(svcb) => RData::SVCB(strip(svcb, strip_ipv4, strip_ipv6)),
        // Not an HTTPS/SVCB record (e.g. a CNAME in the chain) — leave intact.
        _ => return rec.clone(),
    };
    Record::from_rdata(rec.name.clone(), rec.ttl, new_rdata)
}

/// Hex-dump the first `max` bytes of `data` for diagnostics. Allocates —
/// only call it from inside a `debug!`/`trace!` macro invocation so the cost
/// is paid exclusively when that level is enabled.
pub fn hex_prefix(data: &[u8], max: usize) -> String {
    let n = data.len().min(max);
    data[..n]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use meow_common::DnsMode;
    use std::net::Ipv4Addr;

    /// Build a minimal valid DNS query: header + single QNAME (`example.com`)
    /// + QTYPE A + QCLASS IN.
    fn sample_query(id: u16, qtype: u16) -> Vec<u8> {
        let mut q = Vec::with_capacity(64);
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]); // standard query, RD=1
        q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR = 0
                                                                    // QNAME: 7"example" 3"com" 0
        q.push(7);
        q.extend_from_slice(b"example");
        q.push(3);
        q.extend_from_slice(b"com");
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        q
    }

    fn https_record_with_hints() -> Record {
        use hickory_proto::rr::rdata::svcb::{Alpn, IpHint, SvcParamKey, SvcParamValue, SVCB};
        use hickory_proto::rr::rdata::{A, AAAA, HTTPS};
        use hickory_proto::rr::{Name, RData};
        use std::str::FromStr;

        let params = vec![
            (
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec!["h3".to_string(), "h2".to_string()])),
            ),
            (SvcParamKey::Port, SvcParamValue::Port(443)),
            (
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A::new(1, 2, 3, 4)])),
            ),
            (
                SvcParamKey::Ipv6Hint,
                SvcParamValue::Ipv6Hint(IpHint(vec![AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)])),
            ),
        ];
        let name = Name::from_str("example.com.").unwrap();
        let svcb = SVCB::new(1, name.clone(), params);
        Record::from_rdata(name, 300, RData::HTTPS(HTTPS(svcb)))
    }

    #[test]
    fn strip_hints_drops_ip_hints_keeps_alpn_and_port() {
        use hickory_proto::rr::rdata::svcb::SvcParamKey;
        use hickory_proto::rr::RData;

        let stripped = strip_svc_ip_hints(&https_record_with_hints(), true, true);
        let RData::HTTPS(https) = &stripped.data else {
            panic!("expected HTTPS rdata");
        };
        let keys: Vec<&SvcParamKey> = https.0.svc_params.iter().map(|(k, _)| k).collect();
        assert!(
            !keys.contains(&&SvcParamKey::Ipv4Hint),
            "ipv4hint must be stripped"
        );
        assert!(
            !keys.contains(&&SvcParamKey::Ipv6Hint),
            "ipv6hint must be stripped"
        );
        assert!(keys.contains(&&SvcParamKey::Alpn), "alpn must be preserved");
        assert!(keys.contains(&&SvcParamKey::Port), "port must be preserved");
    }

    #[test]
    fn strip_ipv6_hint_preserves_ipv4_hint() {
        use hickory_proto::rr::rdata::svcb::SvcParamKey;
        use hickory_proto::rr::RData;

        let stripped = strip_svc_ip_hints(&https_record_with_hints(), false, true);
        let RData::HTTPS(https) = &stripped.data else {
            panic!("expected HTTPS rdata");
        };
        let keys: Vec<_> = https.0.svc_params.iter().map(|(key, _)| *key).collect();
        assert!(keys.contains(&SvcParamKey::Ipv4Hint));
        assert!(!keys.contains(&SvcParamKey::Ipv6Hint));
    }

    #[test]
    fn strip_hints_preserves_ech_and_scrubs_mandatory_list() {
        use hickory_proto::rr::rdata::svcb::{
            Alpn, EchConfigList, IpHint, Mandatory, SvcParamKey, SvcParamValue, SVCB,
        };
        use hickory_proto::rr::rdata::{A, AAAA, HTTPS};
        use hickory_proto::rr::{Name, RData};
        use std::str::FromStr;

        // `mandatory` lists ipv4hint, so a naive strip would leave a dangling
        // mandatory key → malformed RR → client discards it, losing ech (which
        // is only ever delivered via the HTTPS record). Verify we scrub it.
        let params = vec![
            (
                SvcParamKey::Mandatory,
                SvcParamValue::Mandatory(Mandatory(vec![SvcParamKey::Alpn, SvcParamKey::Ipv4Hint])),
            ),
            (
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec!["h3".to_string()])),
            ),
            (
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(vec![0xab, 0xcd])),
            ),
            (
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A::new(1, 2, 3, 4)])),
            ),
            (
                SvcParamKey::Ipv6Hint,
                SvcParamValue::Ipv6Hint(IpHint(vec![AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)])),
            ),
        ];
        let name = Name::from_str("example.com.").unwrap();
        let rec = Record::from_rdata(
            name.clone(),
            300,
            RData::HTTPS(HTTPS(SVCB::new(1, name, params))),
        );

        let RData::HTTPS(https) = &strip_svc_ip_hints(&rec, true, true).data else {
            panic!("expected HTTPS rdata");
        };
        let p = &https.0.svc_params;

        // Hints gone.
        assert!(!p.iter().any(|(k, _)| *k == SvcParamKey::Ipv4Hint));
        assert!(!p.iter().any(|(k, _)| *k == SvcParamKey::Ipv6Hint));
        // ECH and ALPN preserved — the whole point of not returning empty.
        assert!(p.iter().any(|(k, _)| *k == SvcParamKey::EchConfigList));
        assert!(p.iter().any(|(k, _)| *k == SvcParamKey::Alpn));
        // `mandatory` survives but with the stripped hint scrubbed out, so the
        // record stays well-formed (mandatory = [alpn] only).
        let mandatory = p
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (SvcParamKey::Mandatory, SvcParamValue::Mandatory(Mandatory(keys))) => Some(keys),
                _ => None,
            })
            .expect("mandatory must remain");
        assert_eq!(mandatory, &vec![SvcParamKey::Alpn]);
    }

    #[test]
    fn strip_hints_drops_mandatory_when_only_hints_were_mandatory() {
        use hickory_proto::rr::rdata::svcb::{IpHint, Mandatory, SvcParamKey, SvcParamValue, SVCB};
        use hickory_proto::rr::rdata::{A, HTTPS};
        use hickory_proto::rr::{Name, RData};
        use std::str::FromStr;

        let params = vec![
            (
                SvcParamKey::Mandatory,
                SvcParamValue::Mandatory(Mandatory(vec![SvcParamKey::Ipv4Hint])),
            ),
            (
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A::new(1, 2, 3, 4)])),
            ),
        ];
        let name = Name::from_str("example.com.").unwrap();
        let rec = Record::from_rdata(
            name.clone(),
            300,
            RData::HTTPS(HTTPS(SVCB::new(1, name, params))),
        );

        let RData::HTTPS(https) = &strip_svc_ip_hints(&rec, true, true).data else {
            panic!("expected HTTPS rdata");
        };
        // An empty mandatory list is itself malformed, so it must be dropped.
        assert!(
            https.0.svc_params.is_empty(),
            "mandatory must be removed when only hint keys were listed"
        );
    }

    #[test]
    fn strip_hints_passes_through_non_svc_records() {
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData};
        use std::str::FromStr;

        let rec = Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            300,
            RData::A(A::new(93, 184, 216, 34)),
        );
        let out = strip_svc_ip_hints(&rec, true, true);
        assert_eq!(out, rec, "non-HTTPS/SVCB records must be unchanged");
    }

    #[test]
    fn parse_question_reads_qname_and_qtype() {
        let q = sample_query(0xbeef, 0x0001);
        let (name, qtype, _) = DnsServer::parse_question_for_test(&q[12..]).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(qtype, 1);
    }

    #[test]
    fn parse_question_rejects_malformed_input_table() {
        // Each row exercises a distinct rejection branch in `parse_question`.
        let cases: &[(&str, &[u8])] = &[
            // Label length byte 5 but only 2 bytes follow -> label-truncated error.
            ("truncated label", &[5u8, b'a', b'b']),
            // Just a name terminator, no type/class.
            ("missing qtype/qclass", &[3u8, b'a', b'b', b'c', 0x00]),
        ];

        // Collect instead of asserting per row so every case still runs and a
        // failure names every row that wrongly parsed.
        let accepted: Vec<&str> = cases
            .iter()
            .filter(|(_, bytes)| DnsServer::parse_question_for_test(bytes).is_ok())
            .map(|(label, _)| *label)
            .collect();

        assert!(
            accepted.is_empty(),
            "malformed questions must be rejected, but these parsed: {accepted:?}"
        );
    }

    #[test]
    fn build_response_a_record_has_correct_header_and_rdata() {
        let q = sample_query(0xabcd, 1);
        let resp = DnsServer::build_response_for_test(
            0xabcd,
            &q,
            1,
            std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            300,
        );
        // ID echoed
        assert_eq!(&resp[0..2], &[0xab, 0xcd]);
        // Flags = response + RA
        assert_eq!(&resp[2..4], &[0x81, 0x80]);
        // QDCOUNT=1, ANCOUNT=1
        assert_eq!(&resp[4..8], &[0x00, 0x01, 0x00, 0x01]);
        // Last 4 bytes of RDATA = the IPv4 octets.
        assert_eq!(&resp[resp.len() - 4..], &[192, 0, 2, 7]);
        // TTL is the four bytes immediately before RDLENGTH(2)+RDATA(4) = -10..-6
        assert_eq!(
            &resp[resp.len() - 10..resp.len() - 6],
            &300u32.to_be_bytes()
        );
    }

    #[test]
    fn build_response_aaaa_record_uses_16_byte_rdlength() {
        let q = sample_query(1, 28);
        let v6 = std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let resp = DnsServer::build_response_for_test(1, &q, 28, v6, 60);
        // The last 16 bytes are the v6 octets.
        if let std::net::IpAddr::V6(v6_addr) = v6 {
            assert_eq!(&resp[resp.len() - 16..], &v6_addr.octets());
        }
        // RDLENGTH at -18..-16 = 16.
        assert_eq!(&resp[resp.len() - 18..resp.len() - 16], &[0x00, 0x10]);
    }

    #[test]
    fn build_nxdomain_sets_rcode_3_and_zero_answers() {
        let q = sample_query(0x4242, 1);
        let resp = DnsServer::build_nxdomain_for_test(0x4242, &q);
        assert_eq!(&resp[0..2], &[0x42, 0x42], "ID echoed");
        // Flags low byte 0x83 → RA=1 + rcode=3 (NXDOMAIN)
        assert_eq!(resp[2], 0x81);
        assert_eq!(resp[3], 0x83);
        // ANCOUNT = 0
        assert_eq!(&resp[6..8], &[0x00, 0x00]);
    }

    #[test]
    fn build_noerror_empty_has_rcode_0_and_zero_answers() {
        let q = sample_query(7, 28);
        let resp = DnsServer::build_noerror_empty_for_test(7, &q);
        assert_eq!(resp[2], 0x81);
        assert_eq!(
            resp[3], 0x80,
            "low flag byte = RA=1, rcode=0 (NoError) — not NXDOMAIN"
        );
        assert_eq!(&resp[6..8], &[0x00, 0x00], "ANCOUNT must be zero");
    }

    fn empty_resolver() -> crate::resolver::Resolver {
        crate::resolver::Resolver::new(
            Vec::new(),
            Vec::new(),
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        )
    }

    async fn resolver_with_upstream_rcode(code: ResponseCode) -> crate::resolver::Resolver {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = upstream.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.metadata.response_code = code;
            response.add_queries(request.queries.iter().cloned());
            upstream
                .send_to(&response.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });
        crate::resolver::Resolver::new(
            vec![addr],
            Vec::new(),
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        )
    }

    #[tokio::test]
    async fn handle_query_rejects_malformed_packets_table() {
        // Malformed inputs must be rejected outright — no response is emitted.
        let short = vec![0u8; 5];
        let zero_questions = {
            // Valid 12-byte header but QDCOUNT (bytes [4..6]) left at zero.
            let mut q = vec![0u8; 12];
            q[0] = 0x12;
            q[1] = 0x34;
            q
        };
        let cases: [(&str, &[u8]); 2] = [
            ("packet shorter than the 12-byte header", &short),
            ("valid header with qdcount=0", &zero_questions),
        ];

        let resolver = empty_resolver();
        // Collect rather than assert per-case, so a failure in one case does
        // not stop the loop and hide the other case's result.
        let mut failures = Vec::new();
        for (label, packet) in cases {
            if DnsServer::handle_query(packet, &resolver).await.is_ok() {
                failures.push(label);
            }
        }
        assert!(
            failures.is_empty(),
            "handle_query must reject these malformed packets: {failures:?}"
        );
    }

    #[tokio::test]
    async fn handle_query_answers_formerr_for_multi_question() {
        // The hand-rolled builders answer exactly one question; a qdcount=2
        // query must get a FORMERR, never a response whose header counts
        // contradict its body.
        let mut q = sample_query(0x77aa, 1);
        q[5] = 2; // QDCOUNT = 2 (only one question actually present)
        let resolver = empty_resolver();
        let resp = DnsServer::handle_query(&q, &resolver)
            .await
            .expect("FORMERR response, not an error");
        assert_eq!(&resp[0..2], &[0x77, 0xaa], "ID echoed");
        assert_eq!(resp[2] & 0x80, 0x80, "QR=1");
        assert_eq!(resp[3] & 0x0F, 1, "RCODE=FORMERR");
        assert!(
            resp[4..12].iter().all(|&b| b == 0),
            "all header counts zero — no body follows"
        );
        assert_eq!(resp.len(), 12, "header-only response");
    }

    #[tokio::test]
    async fn handle_query_distinguishes_nodata_nxdomain_and_failure() {
        for (upstream, expected) in [
            (ResponseCode::NoError, ResponseCode::NoError),
            (ResponseCode::NXDomain, ResponseCode::NXDomain),
            (ResponseCode::ServFail, ResponseCode::ServFail),
        ] {
            let resolver = resolver_with_upstream_rcode(upstream).await;
            let response = DnsServer::handle_query(&sample_query(7, 1), &resolver)
                .await
                .unwrap();
            assert_eq!(response[3] & 0x0f, expected.low());
            assert_eq!(&response[6..8], &[0, 0]);
        }
    }

    #[test]
    fn build_response_echoes_single_question_verbatim() {
        let q = sample_query(9, 1);
        let resp = DnsServer::build_response_for_test(
            9,
            &q,
            1,
            std::net::IpAddr::V4(Ipv4Addr::new(198, 18, 0, 5)),
            60,
        );
        assert_eq!(&resp[4..6], &[0x00, 0x01], "QDCOUNT always 1");
        let qlen = q.len() - 12;
        assert_eq!(
            &resp[12..12 + qlen],
            &q[12..],
            "question section copied byte-for-byte"
        );
    }

    #[tokio::test]
    async fn bind_propagates_addr_in_use() {
        // Occupy a loopback port, then DnsServer::bind on the same address
        // must surface the error instead of deferring it to a spawned run().
        let holder = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = holder.local_addr().unwrap();
        let server = DnsServer::new(Arc::new(empty_resolver()), addr);
        let err = server.bind().await;
        assert!(err.is_err(), "bind on an in-use port must error eagerly");
    }

    /// The embedder contract behind `BoundDnsServer::run`: aborting the serve
    /// task releases the listen port immediately, even while a worker is still
    /// parked in `handle_query` awaiting an unresponsive upstream. Regression
    /// test for the stop→start EADDRINUSE window (workers used to hold strong
    /// socket clones for up to the ~5 s query timeout past an abort).
    #[tokio::test]
    async fn port_released_on_abort_with_inflight_query() {
        // Resolver whose only upstream is TEST-NET-1: handle_query for any
        // uncached name parks in the UDP client until its 5 s timeout.
        let resolver = Arc::new(crate::resolver::Resolver::new(
            vec!["192.0.2.1:53".parse().unwrap()],
            Vec::new(),
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        ));
        let server = DnsServer::new(resolver, "127.0.0.1:0".parse().unwrap());
        let bound = server.bind().await.unwrap();
        let addr = bound.local_addr().unwrap();
        let serve = tokio::spawn(bound.run());

        // Park a worker: send a real A query and give the pipeline a moment
        // to hand it into handle_query.
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&sample_query(7, 1), addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        serve.abort();
        let _ = serve.await;

        // The port must be immediately rebindable — the aborted serve future
        // held the only strong Arc to the socket.
        let rebind = tokio::net::UdpSocket::bind(addr).await;
        assert!(
            rebind.is_ok(),
            "port must be released at abort, got {:?}",
            rebind.err()
        );
    }
}
