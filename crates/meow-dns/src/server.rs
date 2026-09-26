use crate::resolver::{AddressLookupResult, Resolver};
use futures::FutureExt;
use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Weak};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// TTL stamped on regular (non-fake-IP) A/AAAA answers built by this server.
const DEFAULT_ANSWER_TTL_SECS: u32 = 60;

/// Hard bound on concurrent upstream-bound query tasks (issue #515).
/// Queries decidable from local state (hosts, fake-IP, fresh cache) are
/// answered inline and never consume a permit; beyond this cap additional
/// upstream-bound queries are dropped and counted — UDP semantics, the
/// client retries. Tests use a small cap so saturation is exercised
/// deterministically.
#[cfg(not(test))]
const MAX_IN_FLIGHT: usize = 512;
#[cfg(test)]
const MAX_IN_FLIGHT: usize = 8;

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

/// Build a fresh slot holding `resolver`. Every component that should
/// observe resolver hot-swaps (DNS servers, the built-in DIRECT adapter,
/// the TUN loopback DNS) must share the *same* slot — pass clones of the
/// returned `Arc`, not freshly wrapped copies of the resolver.
pub fn new_resolver_slot(resolver: Arc<Resolver>) -> ResolverSlot {
    Arc::new(parking_lot::RwLock::new(resolver))
}

/// Outcome of [`DnsServer::try_answer_local`] — the synchronous probe the
/// receive loop runs before dispatching a query (issue #515).
#[derive(Debug)]
pub enum LocalAnswer {
    /// Fully answered from local state — send these bytes now.
    Answer(Vec<u8>),
    /// Malformed or otherwise unanswerable — drop silently, exactly what
    /// [`DnsServer::handle_query`]'s error path does, but without spending
    /// an in-flight permit or a task spawn on guaranteed-failure packets.
    Drop,
    /// Needs the upstream pipeline (or a full `handle_query` pass) —
    /// dispatch a bounded task.
    Upstream,
}

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
            dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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

        // A packet with QR=1 is a response, not a query — drop it
        // silently like every resolver does on its query socket.
        // Replying at all would ping-pong forever between two forwarding
        // resolvers: each error reply is itself QR=1, and a spoofed
        // source could even point the loop back at this socket.
        if flags & 0x8000 != 0 {
            return Err("response packet received on the query socket".into());
        }
        // A forwarding resolver serves opcode QUERY only. Status, Update,
        // Notify and friends get NOTIMP rather than a lookup result echoed
        // under an opcode it doesn't answer.
        if flags & 0x7800 != 0 {
            return Ok(Self::build_notimp(id, flags, arcount > 0));
        }

        if qdcount == 0 {
            return Err("No questions in DNS query".into());
        }
        // The hand-rolled response builders answer exactly one question, and
        // multi-question queries are wire-legal but unsupported by essentially
        // every real resolver. Answer FORMERR instead of emitting a response
        // whose header counts don't match its body.
        if qdcount != 1 {
            return Ok(Self::build_formerr(id, flags, arcount > 0));
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

        // Only class IN resolves through this pipeline — the forward query
        // hardcodes IN, so a CH/HS question would be answered from the IN
        // class while echoing the original one back: a mixed-class lie.
        // qclass is the last two bytes of the question section.
        let qclass = u16::from_be_bytes([data[12 + question_len - 2], data[12 + question_len - 1]]);
        if qclass != 1 {
            return Ok(Self::build_notimp(id, flags, arcount > 0));
        }

        // Non-address queries (TXT, MX, SRV, HTTPS, SOA, PTR, …) go through
        // the same nameserver pipeline as A/AAAA — domain-gate → policy →
        // main → fallback — and the upstream `Message` is relayed back on
        // the wire with only per-hop identity rewritten. We deliberately
        // stop short of fake-IP synthesis here: only address records ever
        // get a synthetic answer.
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

    /// Answer a query entirely from local resolver state — hosts entries,
    /// fake-IP synthesis, IPv6-disabled AAAA suppression, and fresh cache
    /// hits — without spending an in-flight permit or a task spawn. The
    /// serve loop calls this before dispatching so a warm-cache query never
    /// queues behind a slow upstream (issue #515).
    ///
    /// Mirrors the decidable prefix of [`Self::handle_query`] step for step:
    /// non-query packets (QR=1) classify as [`LocalAnswer::Drop`] — a
    /// response packet gets wire silence on both paths — non-QUERY opcodes,
    /// non-IN classes and multi-question queries get the same header-only
    /// error answers inline, `qdcount == 0` and malformed packets classify
    /// as [`LocalAnswer::Drop`] so garbage under flood never spends a
    /// permit, and the hosts trie is checked BEFORE the IPv6-disable
    /// short-circuit (a hosts entry is an explicit user override that
    /// outranks the global toggle — including for AAAA).
    ///
    /// `pub` for the TUN dns-hijack path (`meow-listener`), which answers
    /// locally-decidable queries inline instead of spending a task spawn.
    pub fn try_answer_local(data: &[u8], resolver: &Resolver) -> LocalAnswer {
        if data.len() < 12 {
            return LocalAnswer::Drop; // handle_query errs — silently dropped
        }
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let arcount = u16::from_be_bytes([data[10], data[11]]);
        // Same rules as handle_query: a response packet is dropped
        // silently (answering it would ping-pong between resolvers),
        // and only opcode QUERY is served.
        if flags & 0x8000 != 0 {
            return LocalAnswer::Drop;
        }
        if flags & 0x7800 != 0 {
            return LocalAnswer::Answer(Self::build_notimp(id, flags, arcount > 0));
        }
        if qdcount == 0 {
            return LocalAnswer::Drop; // handle_query errs — silently dropped
        }
        // Same rule as handle_query: multi-question queries get FORMERR.
        if qdcount != 1 {
            return LocalAnswer::Answer(Self::build_formerr(id, flags, arcount > 0));
        }
        let Ok((domain, qtype, question_len)) = Self::parse_question(&data[12..]) else {
            // Parity with handle_query's per-error debug log — the inline
            // path would otherwise swallow malformed questions silently.
            debug!("DNS query: malformed question section — dropped");
            return LocalAnswer::Drop;
        };
        // Same rule as handle_query: only class IN is served.
        let qclass = u16::from_be_bytes([data[12 + question_len - 2], data[12 + question_len - 1]]);
        if qclass != 1 {
            return LocalAnswer::Answer(Self::build_notimp(id, flags, arcount > 0));
        }
        if qtype != 1 && qtype != 28 {
            // Generic queries escalate to the task path — the remaining
            // gates there (record-count FORMERR, hickory-parse FORMERR,
            // BADVERS) may not even reach upstream, and they are not
            // evaluated on this probe path.
            return LocalAnswer::Upstream;
        }

        let outcome = {
            // Mirror handle_query's ordering exactly: check the hosts trie
            // BEFORE the IPv6-disable short-circuit — an AAAA query for a
            // hosts entry with a v6 address must still be answered under
            // `ipv6: false`. (The resolver-internal `lookup_ipv6_local`
            // suppresses v6 first, which is correct for name resolution but
            // not on the wire.)
            if let Some(all_ips) = resolver.lookup_hosts_all(&domain) {
                let ip = if qtype == 1 {
                    all_ips.iter().find(|ip| ip.is_ipv4()).copied()
                } else {
                    all_ips.iter().find(|ip| ip.is_ipv6()).copied()
                };
                LocalAnswer::Answer(match ip {
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
                })
            } else if qtype == 28 && !resolver.ipv6_enabled() {
                LocalAnswer::Answer(Self::build_noerror_empty(id, data, flags, question_len))
            } else {
                // lookup_*_local covers the remaining local decisions:
                // hosts alias → upstream, fake-IP synthesis, and fresh
                // per-family cache hits.
                let local = if qtype == 1 {
                    resolver.lookup_ipv4_local(&domain)
                } else {
                    resolver.lookup_ipv6_local(&domain)
                };
                match local {
                    crate::resolver::LocalLookup::Decided(lookup) => {
                        LocalAnswer::Answer(match lookup {
                            AddressLookupResult::Answer(addr, ttl) => {
                                let ttl_secs = ttl.as_secs().clamp(1, u64::from(u32::MAX)) as u32;
                                Self::build_response(
                                    id,
                                    data,
                                    flags,
                                    question_len,
                                    qtype,
                                    addr,
                                    ttl_secs,
                                )
                            }
                            AddressLookupResult::NoData => {
                                Self::build_noerror_empty(id, data, flags, question_len)
                            }
                            AddressLookupResult::NxDomain => {
                                Self::build_nxdomain(id, data, flags, question_len)
                            }
                            // Local probes never yield `Failed` today (they
                            // produce `Upstream` instead); kept so a future
                            // `Decided` variant can't silently change wire
                            // semantics.
                            AddressLookupResult::Failed => {
                                Self::build_servfail(id, data, flags, question_len)
                            }
                        })
                    }
                    crate::resolver::LocalLookup::Upstream(_) => LocalAnswer::Upstream,
                }
            }
        };
        // Observability parity with handle_query's per-query debug log —
        // the inline path would otherwise drop the most common query class.
        if let LocalAnswer::Answer(_) = &outcome {
            debug!("DNS query: id={id:#06x} domain={domain} qtype={qtype} answered locally");
        }
        outcome
    }

    /// Forward a non-A/AAAA query through the resolver pipeline and relay the
    /// upstream response verbatim — answer, authority and additional sections
    /// all travel intact so negative-cache SOAs, MX/SRV glue and upstream
    /// flag semantics (AA, and AD for clients that asked) survive the hop
    /// (issue #632). The rewrites are per-hop identity (transaction id,
    /// opcode, question echo, RD/CD echo, EDNS), plus `recursion_available`
    /// forced on, the RFC 6840 AD gate, hop-level TSIG/SIG stripping and
    /// fake-IP SVC hint stripping. Impossible declared record counts are
    /// FORMERR-ed before the hickory decode can reserve memory for them,
    /// requests hickory rejects get FORMERR, EDNS versions newer than 0
    /// get BADVERS, and an upstream extended rcode the client cannot
    /// express (no EDNS) becomes SERVFAIL. Without
    /// an upstream response, return SERVFAIL — clients may negative-cache
    /// NXDOMAIN against the bare name, which would poison subsequent
    /// A/AAAA lookups.
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
        // Sole caller guarantees this — `question_len` comes from a
        // successful `parse_question` over `query[12..]`.
        debug_assert!(12 + question_len <= query.len());

        // The declared record counts feed a `Vec::with_capacity` inside
        // the hickory decode. A datagram cannot physically hold more
        // resource records than `len / 11` (one-byte root name plus the
        // 10-byte record header), so an impossible count is malformed
        // input — FORMERR before the decoder reserves megabytes for it.
        // The wire outcome is identical either way: hickory fails the
        // same packet at record-read EOF.
        let arcount = u16::from_be_bytes([query[10], query[11]]);
        let declared_records = u16::from_be_bytes([query[6], query[7]]) as usize
            + u16::from_be_bytes([query[8], query[9]]) as usize
            + arcount as usize;
        // `query.len() - 12 - question_len` == remaining record-region bytes.
        if declared_records * 11 > query.len() - 12 - question_len {
            return Ok(Self::build_formerr(id, flags, arcount > 0));
        }

        // Parse the inbound query before spending an upstream round-trip:
        // the question echo, RD/CD request bits and EDNS presence all come
        // from it. A query hickory rejects where `parse_question` succeeded
        // (duplicate OPT, OPT outside the additional section, malformed
        // trailing records — RFC 6891 §6.1.1) is malformed input and gets
        // FORMERR, never a forwarded lookup.
        let Ok(req) = Message::from_vec(query) else {
            // The request's EDNS presence is undecodable here — fall back
            // to the raw ARCOUNT heuristic the preamble uses.
            return Ok(Self::build_formerr(id, flags, arcount > 0));
        };

        // Defense in depth: the preamble already drops QR=1, so this arm
        // is unreachable — kept so the private function cannot silently
        // forward a response packet if it ever gains another caller.
        if req.metadata.message_type != MessageType::Query {
            return Err("response packet cannot be forwarded".into());
        }

        // RFC 6891 §6.1.3: an EDNS version newer than implemented (0) gets
        // BADVERS — the extended rcode rides in a version-0 response OPT.
        if req.edns.as_ref().is_some_and(|e| e.version() > 0) {
            let mut resp = Message::new(id, MessageType::Response, req.metadata.op_code);
            resp.metadata.recursion_desired = req.metadata.recursion_desired;
            resp.metadata.checking_disabled = req.metadata.checking_disabled;
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = ResponseCode::BADVERS;
            resp.add_queries(req.queries.iter().cloned());
            resp.edns = req.edns.as_ref().map(Self::response_edns);
            return Ok(resp
                .to_vec()
                .unwrap_or_else(|_| Self::build_servfail(id, query, flags, question_len)));
        }

        // The name sent upstream is the wire-faithful `Name` hickory decoded
        // from the client's question — a label containing a literal '.'
        // byte or non-UTF-8 bytes would be re-split or mangled if the
        // lossy text form in `domain` were re-parsed instead. `domain`
        // still feeds the text-keyed gates (`domain_gated`/`policy.lookup`)
        // inside `forward_generic`, matching the A/AAAA arm.
        let Some(query_name) = req.queries.first().map(|q| q.name.clone()) else {
            return Ok(Self::build_formerr(id, flags, req.edns.is_some()));
        };
        let lookup = resolver
            .forward_generic(domain, &query_name, record_type)
            .await;

        let mut resp = match lookup {
            Some(mut l) => {
                l.metadata.id = id;
                // `validate_response` already guarantees this — pinned
                // anyway since the field drives what we emit.
                l.metadata.message_type = MessageType::Response;
                // RFC 1035: the opcode is copied from the request into the
                // response — `validate_response` guarantees the upstream's
                // is Query, so echo the client's to keep exotic opcodes
                // consistent with the A/AAAA builders.
                l.metadata.op_code = req.metadata.op_code;
                // RD and CD are request bits — the response must echo the
                // client's values, not whatever our own forward query sent.
                l.metadata.recursion_desired = req.metadata.recursion_desired;
                l.metadata.checking_disabled = req.metadata.checking_disabled;
                // This server does recursion for the client regardless of
                // what the upstream asserted about itself.
                l.metadata.recursion_available = true;
                // AD asserts "the data authenticated"; RFC 6840 §5.8 only
                // lets it reach a client that asked for DNSSEC processing
                // (AD or DO bit). Our upstream query never carries DO, so
                // the upstream's bit is an unverifiable assertion besides.
                l.metadata.authentic_data &= req.metadata.authentic_data
                    || req.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
                l.queries = req.queries.clone();
                // Hop signatures cannot verify client-side. TSIG/SIG(0)
                // records arrive inside `additionals` — hickory's
                // `signature` slot only fills under its `__dnssec`
                // feature — so strip them there too; a relayed TSIG would
                // also illegally precede our synthesized OPT.
                l.signature = None;
                l.additionals
                    .retain(|r| !matches!(r.record_type(), RecordType::TSIG | RecordType::SIG));
                // Drop ipv4hint/ipv6hint from HTTPS/SVCB records whose
                // owner is a faked name, so an HTTP/3 client cannot read a
                // real origin IP out of the hint and bypass the fake-IP
                // routing the tunnel depends on. The gate follows the
                // RECORD's owner, not the qname: a faked CNAME target leaks
                // the same way, and unrelated glue keeps its hints. The
                // ipv6 hint additionally drops whenever the client cannot
                // use IPv6 anyway.
                let strip_ipv6_hint = !resolver.ipv6_enabled();
                for rec in l
                    .answers
                    .iter_mut()
                    .chain(&mut l.authorities)
                    .chain(&mut l.additionals)
                {
                    // `strip_svc_ip_hints` rebuilds unconditionally —
                    // gate on rdata so ordinary records pass through
                    // untouched (this runs for every generic response
                    // whenever ipv6 is off, which is the default).
                    if !matches!(&rec.data, RData::HTTPS(_) | RData::SVCB(_)) {
                        continue;
                    }
                    let strip_v4_hint = resolver.fake_ip_active_for(&record_owner_text(&rec.name));
                    let strip_v6_hint = strip_v4_hint || strip_ipv6_hint;
                    if strip_v6_hint {
                        *rec = strip_svc_ip_hints(rec, strip_v4_hint, strip_v6_hint);
                    }
                }
                l
            }
            None => {
                let mut resp = Message::new(id, MessageType::Response, req.metadata.op_code);
                resp.metadata.recursion_desired = req.metadata.recursion_desired;
                resp.metadata.checking_disabled = req.metadata.checking_disabled;
                resp.metadata.recursion_available = true;
                resp.metadata.response_code = ResponseCode::ServFail;
                resp.add_queries(req.queries.iter().cloned());
                resp
            }
        };

        // EDNS is strictly per-hop: the upstream's OPT describes our hop to
        // it, not ours to the client. Replace it with a minimal response
        // OPT, and only when the inbound query carried one (RFC 6891
        // §6.1.1). Upstream options (EDE, COOKIE, …) are hop-bound and
        // dropped; extended-rcode high bits still reach the client —
        // `to_vec` writes `response_code.high()` into this OPT.
        resp.edns = req.edns.as_ref().map(Self::response_edns);

        // Without a response OPT the extended rcode's high bits cannot be
        // expressed and the surviving low nibble lies — BADVERS(16)
        // masquerades as NOERROR, BADCOOKIE(23) as YXRRSet. Answer SERVFAIL
        // instead of an rcode the client cannot interpret.
        if resp.edns.is_none() && resp.metadata.response_code.high() != 0 {
            resp.metadata.response_code = ResponseCode::ServFail;
        }

        Ok(resp
            .to_vec()
            .unwrap_or_else(|_| Self::build_servfail(id, query, flags, question_len)))
    }

    /// Minimal per-hop response OPT synthesized from the client's request
    /// EDNS: version 0, the 2020 DNS-flag-day payload, echoing only DO.
    fn response_edns(req_edns: &Edns) -> Edns {
        let mut edns = Edns::new();
        edns.set_dnssec_ok(req_edns.flags().dnssec_ok);
        edns.set_max_payload(1232);
        edns
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
            // A leading QNAME can never legally carry a compression pointer
            // or an extended label — both take the top two bits of the
            // length byte — and treating them as literal label lengths lets
            // this parser see a different name than hickory does on the
            // same packet.
            if len & 0xC0 != 0 {
                return Err("DNS question label uses pointer/extended encoding".into());
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

    /// Header-only error response (no question echo — clients match on ID).
    /// `request_edns` carries a minimal response OPT when the request had
    /// one (RFC 6891 §6.1.1 — error responses are not exempt, and Windows
    /// stubs reject OPT-less answers).
    fn build_header_error(id: u16, flags: u16, rcode: u8, request_edns: bool) -> Vec<u8> {
        let [byte0, byte1] = Self::response_flags(flags);
        let byte1_rcode = (byte1 & 0xF0) | (rcode & 0x0F);

        let mut response = Vec::with_capacity(12 + OPT_RECORD.len());
        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&[byte0, byte1_rcode]);
        response.extend_from_slice(&[0x00; 8]); // QD/AN/NS/AR = 0
        if request_edns {
            Self::append_opt_record(&mut response, 0);
        }
        response
    }

    /// Header-only FORMERR (rcode=1) for queries this server cannot answer
    /// coherently — `qdcount > 1`, impossible record counts, a packet the
    /// full hickory parse rejects, or a parsed query with zero questions.
    fn build_formerr(id: u16, flags: u16, request_edns: bool) -> Vec<u8> {
        Self::build_header_error(id, flags, 1, request_edns)
    }

    /// Header-only NOTIMP (rcode=4): the question asks for something a
    /// forwarding resolver does not serve — a non-IN class or a non-QUERY
    /// opcode.
    fn build_notimp(id: u16, flags: u16, request_edns: bool) -> Vec<u8> {
        Self::build_header_error(id, flags, 4, request_edns)
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
    /// Queries dropped because `MAX_IN_FLIGHT` upstream-bound tasks were
    /// already running. Exposed for stats/observability (issue #515).
    dropped: Arc<std::sync::atomic::AtomicU64>,
}

impl BoundDnsServer {
    /// Wrap an externally bound socket so embedders reuse this hardened serve
    /// loop (locally-decidable answers inline, upstream-bound queries under a
    /// bounded in-flight semaphore, counted drops) instead of hand-rolling
    /// their own — e.g. the TUN loopback DNS servers
    /// on Windows, which must bind `127.0.0.1:53`/`[::1]:53` *before* the OS
    /// resolver is repointed at them.
    /// The resolver is captured as a fixed `Arc` — it does NOT track a later
    /// `Tunnel::set_resolver` generation swap. Callers that must follow
    /// runtime DNS reloads should use [`BoundDnsServer::from_slot`] instead
    /// (issue #514).
    pub fn from_socket(socket: UdpSocket, resolver: Arc<Resolver>) -> Self {
        Self {
            resolver: Arc::new(parking_lot::RwLock::new(resolver)),
            socket: Arc::new(socket),
            dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Variant taking a shared slot directly, for callers that hot-swap the
    /// resolver across generations (issue #514).
    pub fn from_slot(socket: UdpSocket, resolver: ResolverSlot) -> Self {
        Self {
            resolver,
            socket: Arc::new(socket),
            dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Queries dropped at admission since this server started — for want of
    /// an in-flight slot or a full local-answer send buffer (issue #515 — a
    /// drop was previously invisible). A query lost mid-task (e.g. a panic)
    /// is not counted here.
    pub fn dropped_queries(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Shared handle to the drop counter. [`Self::run`] consumes the
    /// server, so embedders that want live observability must clone this
    /// `Arc` beforehand.
    pub fn dropped_counter(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.dropped)
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
    /// Dispatch model (issue #515): queries the resolver can fully decide
    /// without an upstream round-trip — hosts, fake-IP, fresh cache,
    /// IPv6-disabled AAAA — are answered inline on the receive loop, so a
    /// cache hit never queues behind a slow upstream. Everything else gets
    /// one task per query, bounded by `MAX_IN_FLIGHT` permits; on
    /// exhaustion the query is dropped and counted (UDP semantics: the
    /// client retries). This replaces the 4-worker serial pool whose fixed
    /// concurrency let four slow upstreams stall the whole server.
    ///
    /// Ownership contract: the serve loop holds the ONLY strong `Arc` to the
    /// listen socket — query tasks hold `Weak` refs and upgrade per reply.
    /// When an embedder aborts the task running this future, the socket
    /// drops with the future's frame and the port is released immediately,
    /// even while a task is still parked inside `handle_query` awaiting an
    /// upstream (previously worker-held strong clones kept the port bound
    /// for up to the ~5 s query timeout after an abort, so an immediate
    /// stop→start rebind of a fixed port hit EADDRINUSE).
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let BoundDnsServer {
            resolver,
            socket,
            dropped,
        } = self;

        let in_flight = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));

        let mut buf = vec![0u8; 4096];
        // A persistent recv failure must not spin the loop or flood the log;
        // a transient one must not be delayed meaningfully.
        let mut recv_backoff = meow_common::ErrorBackoff::new();
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => {
                    recv_backoff.succeeded();
                    v
                }
                Err(e) => {
                    // Loud only when the backoff engaged — per-packet
                    // async-ICMP errors stay at debug!.
                    if recv_backoff.failed(&e).await {
                        error!("DNS recv error: {}", e);
                    } else {
                        debug!("DNS recv error: {}", e);
                    }
                    continue;
                }
            };

            // Fast path: answer entirely from local state (hosts, fake-IP,
            // fresh cache) without spending an in-flight permit. The read
            // guard is scoped to the probe so no lock is held across .await.
            let local = {
                let resolver_guard = resolver.read();
                DnsServer::try_answer_local(&buf[..len], &resolver_guard)
            };
            match local {
                LocalAnswer::Answer(response) => {
                    // `try_send_to`, not `send_to().await`: a transient
                    // full send buffer must not head-of-line block every
                    // later query behind one slow reply (UDP semantics —
                    // the stub resolver retries). Counted like the
                    // saturation drops below so `dropped_queries` stays a
                    // truthful "no response was sent" signal.
                    match socket.try_send_to(&response, src) {
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(e) => warn!("DNS send error: {e}"),
                        Ok(_) => {}
                    }
                    continue;
                }
                // Malformed/unanswerable — exactly what the task's
                // handle_query error path does, minus the task.
                LocalAnswer::Drop => continue,
                LocalAnswer::Upstream => {}
            }

            // Acquire the permit BEFORE copying the payload: under
            // saturation a dropped query must not pay the alloc either.
            let Ok(permit) = Arc::clone(&in_flight).try_acquire_owned() else {
                let n = dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                // Power-of-two warn cadence: first drop is loud, sustained
                // saturation stays bounded in the log.
                if n.is_power_of_two() {
                    warn!(
                        "DNS server saturated: {n} queries dropped ({MAX_IN_FLIGHT} in-flight cap)"
                    );
                }
                continue;
            };

            let data = buf[..len].to_vec();
            let resolver_slot = Arc::clone(&resolver);
            let sock: Weak<UdpSocket> = Arc::downgrade(&socket);
            tokio::spawn(async move {
                let _permit = permit;
                // Snapshot the current resolver generation per query —
                // a `PUT /configs` DNS reload swaps the slot (issue #514).
                // The read guard must drop before `.await`: it is !Send.
                let resolver = Arc::clone(&resolver_slot.read());
                // Panic guard: a panicked task would drop the query, so keep
                // the panic scoped to this one request and log it loudly.
                let outcome = AssertUnwindSafe(DnsServer::handle_query(&data, &resolver))
                    .catch_unwind()
                    .await;
                match outcome {
                    Ok(Ok(response)) => {
                        // Upgrade per reply; hold the strong ref only across
                        // the send so the serve loop stays the socket owner.
                        let Some(sock) = sock.upgrade() else {
                            // Server dropped — exit so the port stays free.
                            return;
                        };
                        if let Err(e) = sock.send_to(&response, src).await {
                            warn!("DNS send error: {}", e);
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("DNS query handling error: {}", e);
                    }
                    Err(_) => {
                        error!("DNS query task survived a panic");
                    }
                }
            });
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
    let mut stripped = Record::from_rdata(rec.name.clone(), rec.ttl, new_rdata);
    // `from_rdata` defaults class to IN — preserve the original.
    stripped.dns_class = rec.dns_class;
    stripped
}

/// Text form of a record owner name in the same representation
/// `parse_question` produces: raw label bytes lossy-UTF-8 joined on '.'.
/// This is the form the fake-IP pool, hosts trie and skipper key on —
/// `Name::to_utf8` would IDNA-decode `xn--` labels, so a unicode-form
/// `hosts:` entry could mask the gate for a wire name the A/AAAA path
/// still fakes (ADR-0013).
fn record_owner_text(name: &Name) -> String {
    let mut out = String::new();
    for label in name {
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label));
    }
    out
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
    use hickory_proto::op::OpCode;
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, DecodeError};
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

    fn https_record_with_hints_named(name: &str) -> Record {
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
        let name = Name::from_str(name).unwrap();
        let svcb = SVCB::new(1, name.clone(), params);
        Record::from_rdata(name, 300, RData::HTTPS(HTTPS(svcb)))
    }

    fn https_record_with_hints() -> Record {
        https_record_with_hints_named("example.com.")
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
    fn strip_hints_preserves_record_dns_class() {
        use hickory_proto::rr::DNSClass;

        // The rebuild path (`Record::from_rdata`) defaults the class to IN —
        // a record carrying another class must keep it through the strip.
        let mut rec = https_record_with_hints();
        rec.dns_class = DNSClass::CH;
        let stripped = strip_svc_ip_hints(&rec, true, true);
        assert_eq!(
            stripped.dns_class,
            DNSClass::CH,
            "rebuild must preserve the record's DNS class"
        );
    }

    #[test]
    fn strip_hints_handles_svcb_rdata() {
        use hickory_proto::rr::rdata::svcb::SvcParamKey;
        use hickory_proto::rr::RData;

        // The SVCB arm shares the strip logic with HTTPS but is a distinct
        // rdata variant — pin it so the match arm can't silently pass
        // SVCB records through unstripped.
        let mut rec = https_record_with_hints_named("svc.example.com.");
        let RData::HTTPS(https) = rec.data else {
            panic!("fixture must be HTTPS");
        };
        rec.data = RData::SVCB(https.0);

        let stripped = strip_svc_ip_hints(&rec, true, true);
        let RData::SVCB(svcb) = &stripped.data else {
            panic!("expected SVCB rdata");
        };
        let keys: Vec<&SvcParamKey> = svcb.svc_params.iter().map(|(k, _)| k).collect();
        assert!(!keys.contains(&&SvcParamKey::Ipv4Hint));
        assert!(!keys.contains(&&SvcParamKey::Ipv6Hint));
        assert!(keys.contains(&&SvcParamKey::Alpn));
    }

    #[test]
    fn record_owner_text_keeps_wire_labels_unlike_to_utf8() {
        // `Name::to_utf8` IDNA-decodes `xn--` labels, but the fake-IP
        // pool, hosts trie and skipper all key on the raw wire text that
        // `parse_question` produces — a unicode-form gate key would let
        // an `xn--` owner's hints leak past `fake_ip_active_for`.
        let name = Name::from_utf8("bücher.example").unwrap();
        let wire = record_owner_text(&name);
        assert_eq!(wire, "xn--bcher-kva.example");
        assert_ne!(
            wire,
            name.to_utf8().trim_end_matches('.'),
            "the unicode form must NOT be the gate key"
        );
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
        resolver_with_upstream_response(code, None).await
    }

    async fn resolver_with_upstream_response(
        code: ResponseCode,
        answer: Option<Record>,
    ) -> crate::resolver::Resolver {
        resolver_with_upstream_message(move |response| {
            response.metadata.response_code = code;
            if let Some(answer) = answer {
                response.add_answer(answer);
            }
        })
        .await
    }

    /// Bind a loopback UDP socket that answers the first query it receives
    /// with a response shaped by `build`, and return its address.
    async fn spawn_dns_responder(build: impl FnOnce(&mut Message) + Send + 'static) -> SocketAddr {
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = upstream.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.add_queries(request.queries.iter().cloned());
            build(&mut response);
            upstream
                .send_to(&response.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });
        addr
    }

    /// Spawn a loopback UDP "upstream" that answers the first query it
    /// receives with a response shaped by `build`, then exits.
    async fn resolver_with_upstream_message(
        build: impl FnOnce(&mut Message) + Send + 'static,
    ) -> crate::resolver::Resolver {
        let addr = spawn_dns_responder(build).await;
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

    #[tokio::test]
    async fn handle_query_generic_preserves_upstream_response_code() {
        use hickory_proto::rr::rdata::TXT;
        use hickory_proto::rr::{Name, RData};

        for qtype in [RecordType::TXT, RecordType::MX, RecordType::HTTPS] {
            for code in [
                ResponseCode::NoError,
                ResponseCode::NXDomain,
                ResponseCode::ServFail,
                ResponseCode::Refused,
            ] {
                // A marker record in the upstream additional section proves
                // the response went through the relay — the local
                // SERVFAIL/FORMERR branches emit empty sections, so the
                // ServFail leg cannot pass vacuously.
                let resolver = resolver_with_upstream_message(move |response| {
                    response.metadata.response_code = code;
                    response.add_additional(Record::from_rdata(
                        Name::from_ascii("marker.example.").unwrap(),
                        60,
                        RData::TXT(TXT::new(vec!["upstream-marker".to_string()])),
                    ));
                })
                .await;
                let query = sample_query(7, u16::from(qtype));
                let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
                let response = Message::from_vec(&response).unwrap();
                assert_eq!(
                    response.metadata.response_code, code,
                    "query type {qtype}, upstream response {code}"
                );
                assert_eq!(response.metadata.id, 7);
                assert_eq!(response.queries, Message::from_vec(&query).unwrap().queries);
                assert!(response.answers.is_empty());
                assert_eq!(
                    response.additionals.len(),
                    1,
                    "upstream marker survived the relay for rcode {code}"
                );
            }
        }
    }

    #[tokio::test]
    async fn handle_query_generic_preserves_txt_answer() {
        use hickory_proto::rr::rdata::TXT;
        use hickory_proto::rr::{Name, RData};

        let answer = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            123,
            RData::TXT(TXT::new(vec!["forwarded TXT answer".to_string()])),
        );
        let resolver =
            resolver_with_upstream_response(ResponseCode::NoError, Some(answer.clone())).await;
        let query = sample_query(7, u16::from(RecordType::TXT));
        let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
        let response = Message::from_vec(&response).unwrap();

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0], answer);
        // Record equality ignores TTL.
        assert_eq!(response.answers[0].ttl, answer.ttl);
    }

    #[tokio::test]
    async fn handle_query_generic_without_upstream_returns_servfail() {
        let query = sample_query(7, u16::from(RecordType::TXT));
        let response = DnsServer::handle_query(&query, &empty_resolver())
            .await
            .unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn handle_query_generic_forwards_wire_faithful_name() {
        // A QNAME label containing a literal '.' byte is ONE label on the
        // wire, and a label may carry bytes that are not valid UTF-8.
        // Re-parsing the lossy text form would ask the upstream for a
        // different name than the question echoed back, so the relay
        // forwards the decoded `Name` itself.
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = upstream.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = upstream.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();
            let _ = tx.send(request.queries[0].name.clone());
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.add_queries(request.queries.iter().cloned());
            response.metadata.response_code = ResponseCode::NoError;
            upstream
                .send_to(&response.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });
        let resolver = crate::resolver::Resolver::new(
            vec![addr],
            Vec::new(),
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        );

        // QNAME: 3"a.b" 2<0xFF 0xFE> 7"example" 3"com" 0 — the dot lives
        // INSIDE label 1, and label 2 carries bytes that are not valid
        // UTF-8 at all. The lossy text form `parse_question` produces
        // would render it as "a.b.\u{FFFD}\u{FFFD}.example.com" —
        // re-parsing that would ask the upstream for a different name
        // than the question echoed back. The relay forwards the decoded
        // `Name` instead, so the upstream sees the label boundaries and
        // bytes the client actually sent.
        let mut query = Vec::new();
        query.extend_from_slice(&0xBEEFu16.to_be_bytes());
        query.extend_from_slice(&[0x01, 0x00]); // RD=1
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        query.push(3);
        query.extend_from_slice(b"a.b");
        query.push(2);
        query.extend_from_slice(&[0xFF, 0xFE]);
        query.push(7);
        query.extend_from_slice(b"example");
        query.push(3);
        query.extend_from_slice(b"com");
        query.push(0);
        query.extend_from_slice(&u16::from(RecordType::TXT).to_be_bytes());
        query.extend_from_slice(&[0x00, 0x01]);

        let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NoError,
            "upstream answered — the relay ran"
        );
        // The echoed question must also carry the true wire name.
        let echoed_labels: Vec<&[u8]> = response.queries[0].name.iter().collect();
        assert_eq!(echoed_labels[0], b"a.b");

        let upstream_name = rx.await.expect("upstream saw the query");
        let labels: Vec<&[u8]> = upstream_name.iter().collect();
        assert_eq!(
            labels,
            [b"a.b".as_slice(), &[0xFF, 0xFE], b"example", b"com"],
            "label boundaries and raw bytes must reach upstream byte-for-byte"
        );
    }

    #[tokio::test]
    async fn handle_query_generic_gates_on_text_domain_but_sends_wire_name() {
        use crate::resolver::FallbackFilter;
        use crate::upstream::{HostOrIp, NameServerUrl};

        // `forward_generic`'s central invariant: `domain` — the lossy
        // text form `parse_question` produces — keys the text gates
        // (fallback-filter domain trie, nameserver-policy), while
        // `query_name` is the wire-faithful `Name` sent upstream. A
        // fallback-filter entry matching the TEXT form of a
        // literal-dot-label name must route the query to the fallback
        // pool, and the fallback upstream must still see `a.b` as one
        // label — not two labels re-split from the text.
        let fallback_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fallback_addr = fallback_sock.local_addr().unwrap();
        let main_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let main_addr = main_sock.local_addr().unwrap();

        // Any datagram reaching the main pool means the gate keyed on
        // the wrong form.
        let (hit_tx, mut hit_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if main_sock.recv_from(&mut buf).await.is_ok() {
                let _ = hit_tx.send(());
            }
        });
        let (name_tx, name_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = fallback_sock.recv_from(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf[..len]).unwrap();
            let _ = name_tx.send(request.queries[0].name.clone());
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.add_queries(request.queries.iter().cloned());
            response.metadata.response_code = ResponseCode::NoError;
            fallback_sock
                .send_to(&response.to_bytes().unwrap(), peer)
                .await
                .unwrap();
        });

        let mut ff_domain = meow_trie::DomainTrie::new();
        // Exact match against the TEXT form parse_question yields for
        // the wire name "a.b"."example"."com".
        ff_domain.insert("a.b.example.com", ());
        let resolver = crate::resolver::Resolver::new_with_bootstrap(
            vec![NameServerUrl::Udp {
                addr: HostOrIp::Ip(main_addr.ip()),
                port: main_addr.port(),
            }],
            vec![NameServerUrl::Udp {
                addr: HostOrIp::Ip(fallback_addr.ip()),
                port: fallback_addr.port(),
            }],
            Vec::new(),
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
            None,
            Some(FallbackFilter {
                geoip_enabled: false,
                geoip_code: "CN".to_string(),
                ipcidr: vec![],
                domain: ff_domain,
                geoip_reader: None,
            }),
        )
        .await
        .unwrap();

        // QNAME: 3"a.b" 7"example" 3"com" 0 — one label holding a dot.
        let mut query = Vec::new();
        query.extend_from_slice(&0xCAFEu16.to_be_bytes());
        query.extend_from_slice(&[0x01, 0x00]);
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        query.push(3);
        query.extend_from_slice(b"a.b");
        query.push(7);
        query.extend_from_slice(b"example");
        query.push(3);
        query.extend_from_slice(b"com");
        query.push(0);
        query.extend_from_slice(&u16::from(RecordType::TXT).to_be_bytes());
        query.extend_from_slice(&[0x00, 0x01]);

        let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NoError,
            "the fallback tier answered — the text gate routed correctly"
        );
        let upstream_name = name_rx.await.expect("fallback upstream saw the query");
        let labels: Vec<&[u8]> = upstream_name.iter().collect();
        assert_eq!(
            labels[0], b"a.b",
            "the fallback upstream must receive the wire-faithful name"
        );
        assert!(
            hit_rx.try_recv().is_err(),
            "the domain gate must key on the text form — main pool untouched"
        );
    }

    /// Build a wire-format query with an EDNS OPT record attached.
    fn sample_edns_query(id: u16, qtype: RecordType, dnssec_ok: bool) -> Vec<u8> {
        sample_edns_query_named(id, "example.com.", qtype, dnssec_ok)
    }

    fn sample_edns_query_named(id: u16, name: &str, qtype: RecordType, dnssec_ok: bool) -> Vec<u8> {
        use hickory_proto::op::Query;
        use hickory_proto::rr::Name;

        let mut q = Message::new(id, MessageType::Query, OpCode::Query);
        q.metadata.recursion_desired = true;
        q.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(dnssec_ok);
        edns.set_max_payload(1400);
        q.edns = Some(edns);
        q.to_vec().unwrap()
    }

    #[tokio::test]
    async fn handle_query_generic_relays_authority_and_additionals() {
        use hickory_proto::rr::rdata::{A, MX, SOA};
        use hickory_proto::rr::{Name, RData};

        let mx = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::MX(MX::new(10, Name::from_ascii("mail.example.com.").unwrap())),
        );
        let soa = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.com.").unwrap(),
                Name::from_ascii("hostmaster.example.com.").unwrap(),
                1,
                7200,
                3600,
                1209600,
                300,
            )),
        );
        let glue = Record::from_rdata(
            Name::from_ascii("mail.example.com.").unwrap(),
            300,
            RData::A(A::new(192, 0, 2, 1)),
        );
        let expected_soa = soa.clone();
        let expected_glue = glue.clone();
        let resolver = resolver_with_upstream_message(move |response| {
            response.metadata.response_code = ResponseCode::NoError;
            response.add_answer(mx);
            response.add_authority(soa);
            response.add_additional(glue);
        })
        .await;

        let query = sample_query(7, u16::from(RecordType::MX));
        let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
        let response = Message::from_vec(&response).unwrap();

        // Assert the upstream path actually answered before checking
        // sections — a local SERVFAIL emits empty sections and would make
        // the checks below vacuous.
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(
            response.authorities.len(),
            1,
            "authority section (negative-cache SOA) must be relayed verbatim"
        );
        assert_eq!(
            response.additionals.len(),
            1,
            "additional section (MX/SRV glue) must be relayed verbatim"
        );
        assert_eq!(response.authorities[0], expected_soa);
        assert_eq!(response.additionals[0], expected_glue);
    }

    #[tokio::test]
    async fn handle_query_generic_relays_upstream_flags() {
        // TC is deliberately left out: the DNS client layer retries
        // truncated UDP answers over TCP before `handle_generic_forward`
        // ever sees them (client.rs exchange), so no message with TC set
        // reaches this path over a UDP-only upstream. Whatever TC a
        // post-retry message still carries is relayed verbatim like the
        // rest of the flag word.
        let resolver = resolver_with_upstream_message(|response| {
            response.metadata.response_code = ResponseCode::NoError;
            response.metadata.authoritative = true;
            response.metadata.authentic_data = true;
        })
        .await;

        let query = sample_query(7, u16::from(RecordType::TXT));
        let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
        let response = Message::from_vec(&response).unwrap();

        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NoError,
            "upstream answered — the local SERVFAIL path clears AA anyway"
        );
        assert!(response.metadata.authoritative, "AA relayed");
        assert!(
            !response.metadata.authentic_data,
            "AD is gated on the client asking for DNSSEC (RFC 6840 §5.8)"
        );
        assert!(response.metadata.recursion_available, "RA=1");
    }

    #[tokio::test]
    async fn handle_query_generic_passes_ad_when_client_asked() {
        for (label, query) in [
            (
                "DO bit in request EDNS",
                sample_edns_query(7, RecordType::TXT, true),
            ),
            // AD bit set directly in the request flag word.
            ("AD bit in request flags", {
                let mut q = sample_query(8, u16::from(RecordType::TXT));
                q[3] |= 0x20;
                q
            }),
        ] {
            let resolver = resolver_with_upstream_message(|response| {
                response.metadata.response_code = ResponseCode::NoError;
                response.metadata.authentic_data = true;
            })
            .await;
            let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
            let response = Message::from_vec(&response).unwrap();
            assert!(
                response.metadata.authentic_data,
                "{label}: upstream AD must reach a client that asked"
            );
        }

        // The gate is `&=`, not assignment: an upstream that never asserted
        // AD must not have it fabricated just because the client asked.
        let resolver = resolver_with_upstream_message(|response| {
            response.metadata.response_code = ResponseCode::NoError;
            response.metadata.authentic_data = false;
        })
        .await;
        let query = sample_edns_query(9, RecordType::TXT, true);
        let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(
            !response.metadata.authentic_data,
            "AD must not be fabricated when the upstream never asserted it"
        );
    }

    #[tokio::test]
    async fn handle_query_notimp_for_non_query_opcode() {
        // A forwarding resolver serves opcode QUERY only — a Status packet
        // gets NOTIMP, answered in the preamble without an upstream lookup.
        // The response still echoes the request's opcode (RFC 1035).
        let mut q = sample_query(9, u16::from(RecordType::TXT));
        // 0x87 clears the 4-bit opcode field, preserving QR/AA/TC/RD.
        q[2] = (q[2] & 0x87) | (2 << 3); // opcode=Status(2)
        for resolver in [
            resolver_with_upstream_message(|response| {
                response.metadata.response_code = ResponseCode::NoError;
            })
            .await,
            empty_resolver(),
        ] {
            let response = DnsServer::handle_query(&q, &resolver).await.unwrap();
            let response = Message::from_vec(&response).unwrap();
            assert_eq!(
                response.metadata.response_code,
                ResponseCode::NotImp,
                "non-QUERY opcodes get NOTIMP"
            );
            assert_eq!(
                response.metadata.op_code,
                OpCode::Status,
                "the response echoes the request's opcode"
            );
        }
    }

    #[tokio::test]
    async fn handle_query_generic_echoes_request_rd_and_cd() {
        // Upstream claims RD=0/CD=0 (it echoes whatever our forward query
        // sent); the client asked RD=1, so the response must reflect the
        // client's request bits, not the upstream hop's.
        let resolver = resolver_with_upstream_message(|response| {
            response.metadata.response_code = ResponseCode::NoError;
            response.metadata.recursion_desired = false;
            response.metadata.checking_disabled = false;
        })
        .await;

        // sample_query sets flags 0x0100 → RD=1, CD=0.
        let query = sample_query(7, u16::from(RecordType::TXT));
        let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.metadata.recursion_desired, "RD echoes request");
        assert!(!response.metadata.checking_disabled, "CD echoes request");

        // CD=1 in the request must likewise echo through.
        let mut cd_query = sample_query(8, u16::from(RecordType::TXT));
        cd_query[3] |= 0x10; // CD bit
        let resolver2 = resolver_with_upstream_message(|response| {
            response.metadata.response_code = ResponseCode::NoError;
        })
        .await;
        let response = DnsServer::handle_query(&cd_query, &resolver2)
            .await
            .unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.metadata.checking_disabled, "CD=1 echoes request");
    }

    #[tokio::test]
    async fn handle_query_generic_drops_upstream_edns_when_request_has_none() {
        let resolver = resolver_with_upstream_message(|response| {
            response.metadata.response_code = ResponseCode::NoError;
            let mut edns = Edns::new();
            edns.set_max_payload(4096);
            response.edns = Some(edns);
        })
        .await;

        // sample_query has ARCOUNT=0 — no OPT record.
        let query = sample_query(7, u16::from(RecordType::TXT));
        let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NoError,
            "upstream answer must have arrived — SERVFAIL also yields edns=None here"
        );
        assert!(
            response.edns.is_none(),
            "upstream OPT is hop-bound and must not leak to a non-EDNS client"
        );
    }

    #[tokio::test]
    async fn handle_query_generic_synthesizes_edns_when_request_has_one() {
        let resolver = resolver_with_upstream_message(|response| {
            response.metadata.response_code = ResponseCode::NoError;
            // Upstream OPT advertises a big buffer and DO=0 — none of that
            // describes our hop to the client.
            let mut edns = Edns::new();
            edns.set_max_payload(4096);
            response.edns = Some(edns);
        })
        .await;

        let query = sample_edns_query(7, RecordType::TXT, true);
        let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NoError,
            "upstream answer must have arrived — the SERVFAIL branch synthesizes the same OPT"
        );
        let edns = response
            .edns
            .expect("request had EDNS → response OPT required (RFC 6891)");
        assert!(
            edns.flags().dnssec_ok,
            "response DO echoes the request's DO bit"
        );
        assert_eq!(
            edns.max_payload(),
            1232,
            "synthesized OPT advertises the flag-day payload, not the upstream's hop-bound size"
        );
        assert_eq!(edns.version(), 0, "EDNS version 0");
    }

    #[tokio::test]
    async fn handle_query_generic_badvers_for_newer_edns_version() {
        // RFC 6891 §6.1.3: a request with EDNS version > 0 gets BADVERS
        // (extended rcode 16) with a version-0 OPT — never a lookup.
        use hickory_proto::op::Query;
        use hickory_proto::rr::Name;

        let mut q = Message::new(7, MessageType::Query, OpCode::Query);
        q.metadata.recursion_desired = true;
        q.metadata.checking_disabled = true;
        q.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::TXT,
        ));
        let mut edns = Edns::new();
        edns.set_version(1);
        edns.set_dnssec_ok(true);
        q.edns = Some(edns);
        let query = q.to_vec().unwrap();

        // No upstream configured — the BADVERS path must not even try.
        let response = DnsServer::handle_query(&query, &empty_resolver())
            .await
            .unwrap();
        let response = Message::from_vec(&response).unwrap();
        // BADVERS and BADSIG share wire value 16; hickory decodes it as
        // BADSIG. The wire encoding is what matters.
        assert!(
            matches!(
                response.metadata.response_code,
                ResponseCode::BADVERS | ResponseCode::BADSIG
            ),
            "extended rcode 16 (BADVERS)"
        );
        let edns = response
            .edns
            .expect("BADVERS carries a response OPT for an EDNS request");
        assert_eq!(edns.version(), 0, "BADVERS carries a version-0 OPT");
        assert_eq!(
            edns.max_payload(),
            1232,
            "BADVERS OPT uses the same synthesized shape as the relay path"
        );
        assert!(edns.flags().dnssec_ok, "request DO bit echoes");
        assert_eq!(response.metadata.id, 7);
        assert!(
            response.metadata.recursion_desired
                && response.metadata.checking_disabled
                && response.metadata.recursion_available,
            "request bits echo on the BADVERS path too"
        );
        assert_eq!(response.queries.len(), 1, "question echoed");
    }

    #[tokio::test]
    async fn handle_query_generic_formerr_for_hickory_rejected_request() {
        // `parse_question` only validates the question; a malformed record
        // section makes `Message::from_vec` fail — the answer is FORMERR,
        // and no upstream round-trip is spent on it.
        //
        // Case 1: ARCOUNT=1 with truncated record bytes. Note this
        // particular fixture now trips the impossible-count pre-gate
        // (1 RR cannot fit in 3 trailing bytes) rather than the hickory
        // parse — same FORMERR on the wire; kept to pin the OPT echo.
        let mut q = sample_query(9, u16::from(RecordType::TXT));
        q[11] = 1; // ARCOUNT = 1
        q.extend_from_slice(&[0xC0, 0x0C, 0xFF]); // truncated record
        let response = DnsServer::handle_query(&q, &empty_resolver())
            .await
            .unwrap();
        assert_eq!(response[3] & 0x0F, 1, "RCODE=FORMERR");
        assert_eq!(&response[0..2], &[0x00, 0x09], "ID echoed");
        // The request carried an additional record, so the header-only
        // FORMERR must still carry a minimal response OPT — a 12-byte
        // header plus the 11-byte canned OPT, nothing more.
        assert_eq!(
            response.len(),
            23,
            "FORMERR = 12-byte header + minimal response OPT"
        );
        let parsed = Message::from_vec(&response).unwrap();
        assert!(
            parsed.edns.is_some(),
            "request had an additional section — the error must echo an OPT"
        );

        // Case 2: gate-legal counts (one 11-byte record exactly fits the
        // tail) but malformed CONTENT hickory rejects — an OPT-typed
        // record in the answer section (OPT is legal only in additional).
        // This keeps the `Message::from_vec` FORMERR arm itself covered.
        let mut q = sample_query(10, u16::from(RecordType::TXT));
        q[7] = 1; // ANCOUNT = 1
                  // root name + OPT type + class + ttl + rdlen=0 — 11 bytes, the
                  // record fits the byte budget but fails section validation.
        q.extend_from_slice(&[
            0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        // Both FORMERR producers emit identical bytes, so pin directly
        // that this fixture reaches the hickory arm, not the count gate.
        assert!(matches!(
            Message::from_vec(&q),
            Err(DecodeError::RecordNotInAdditionalSection(RecordType::OPT))
        ));
        let response = DnsServer::handle_query(&q, &empty_resolver())
            .await
            .unwrap();
        assert_eq!(response[3] & 0x0F, 1, "RCODE=FORMERR");
        assert_eq!(&response[0..2], &[0x00, 0x0A], "ID echoed");
        assert_eq!(response.len(), 12, "no additional section → no OPT");
    }

    #[tokio::test]
    async fn handle_query_generic_formerr_for_impossible_record_counts() {
        // AN/NS/AR counts feed a `Vec::with_capacity` inside the hickory
        // decode. A record needs at least 11 wire bytes (one-byte root
        // name + 10-byte record header), so a count that exceeds the
        // datagram's capacity is malformed input — FORMERR before the
        // decoder reserves megabytes. (The wire outcome matches what
        // hickory would produce at record-read EOF; the gate just fails
        // without the allocation.)
        let mut q = sample_query(10, u16::from(RecordType::TXT));
        q[6] = 0xFF;
        q[7] = 0xFF; // ANCOUNT = 65535
        let response = DnsServer::handle_query(&q, &empty_resolver())
            .await
            .unwrap();
        assert_eq!(response[3] & 0x0F, 1, "RCODE=FORMERR");
        assert_eq!(&response[0..2], &[0x00, 0x0A], "ID echoed");
    }

    #[tokio::test]
    async fn handle_query_drops_response_packets_silently() {
        // A stray QR=1 datagram with a well-formed question is a response,
        // not a query — it must not spend an upstream round-trip, and it
        // must not be *answered* either: every reply is itself QR=1, so
        // answering a response would ping-pong forever between two
        // forwarding resolvers (or self-loop via a spoofed source). Wire
        // silence is the correct behavior on both the task path and the
        // inline probe.
        for qtype in [u16::from(RecordType::TXT), 1] {
            let mut q = sample_query(9, qtype);
            q[2] |= 0x80; // QR=1
            let resolver = empty_resolver();
            assert!(
                DnsServer::handle_query(&q, &resolver).await.is_err(),
                "qtype {qtype}: a response packet must be dropped, not answered"
            );
            assert!(
                matches!(
                    DnsServer::try_answer_local(&q, &resolver),
                    LocalAnswer::Drop
                ),
                "qtype {qtype}: the inline probe must drop it identically"
            );
        }
    }

    #[tokio::test]
    async fn handle_query_notimp_for_non_in_class() {
        // A CHAOS-class question (version.bind et al.) cannot be forwarded
        // as IN and echoed back as CH — answer NOTIMP instead of a
        // mixed-class lie.
        for qtype in [u16::from(RecordType::TXT), 1] {
            let mut q = sample_query(11, qtype);
            let n = q.len();
            q[n - 2] = 0x00;
            q[n - 1] = 0x03; // QCLASS CH
            let response = DnsServer::handle_query(&q, &empty_resolver())
                .await
                .unwrap();
            assert_eq!(
                response[3] & 0x0F,
                4,
                "RCODE=NOTIMP for qclass CH (qtype {qtype})"
            );
        }
    }

    #[tokio::test]
    async fn handle_query_drops_compressed_qname() {
        // A leading QNAME cannot legally contain a compression pointer —
        // there is nothing before it to point at. `parse_question` rejects
        // the top-two-bits length bytes so it cannot see a different name
        // than hickory would on the same packet.
        let mut q = sample_query(12, u16::from(RecordType::TXT));
        q[12] = 0xC0; // label-length byte becomes a pointer marker
        assert!(
            DnsServer::handle_query(&q, &empty_resolver())
                .await
                .is_err(),
            "compressed qname is dropped like other malformed questions"
        );
    }

    #[tokio::test]
    async fn handle_query_generic_servfail_for_extended_rcode_without_edns() {
        // The extended rcode's high bits only travel inside an OPT record.
        // A non-EDNS client asking a resolver that answered BADVERS/BADCOOKIE
        // would otherwise read the meaningless low nibble (BADVERS.low()=0
        // → NOERROR). SERVFAIL is honest instead.
        let resolver = resolver_with_upstream_message(|response| {
            response.metadata.response_code = ResponseCode::BADVERS;
            // The upstream needs its own OPT for the high bits to reach us
            // on the wire — without it emit only writes the low nibble.
            response.edns = Some(Edns::new());
        })
        .await;

        // sample_query carries no EDNS → no response OPT can hold rcode_high.
        let query = sample_query(7, u16::from(RecordType::TXT));
        let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert!(response.edns.is_none(), "non-EDNS client gets no OPT");
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::ServFail,
            "an inexpressible extended rcode becomes SERVFAIL, not a lying low nibble"
        );
    }

    #[tokio::test]
    async fn handle_query_generic_drops_tsig_and_sig_records() {
        // Without hickory's `__dnssec` feature an upstream TSIG rides
        // through `additionals` — it must not reach the client (the MAC
        // describes our hop, and a TSIG may not precede the OPT record).
        use hickory_proto::rr::rdata::tsig::{TsigAlgorithm, TSIG};
        use hickory_proto::rr::{Name, RData};

        let tsig = Record::from_rdata(
            Name::from_ascii("key.example.").unwrap(),
            0,
            RData::TSIG(TSIG::new(
                TsigAlgorithm::HmacSha256,
                0,
                300,
                vec![0xAA; 16],
                0,
                None,
                vec![],
            )),
        );
        // A wire SIG(24) decodes as `RData::Unknown` without `__dnssec` —
        // its `record_type()` is still SIG and must hit the same strip.
        let sig = Record::from_rdata(
            Name::from_ascii("sig.example.").unwrap(),
            0,
            RData::Unknown {
                code: RecordType::SIG,
                rdata: hickory_proto::rr::rdata::NULL::with(vec![0x01, 0x02]),
            },
        );
        // Benign glue must survive — only hop signatures get stripped.
        let glue = Record::from_rdata(
            Name::from_ascii("ns.example.com.").unwrap(),
            300,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(192, 0, 2, 53))),
        );
        let resolver = resolver_with_upstream_message(move |response| {
            response.metadata.response_code = ResponseCode::NoError;
            response.add_additional(tsig);
            response.add_additional(sig);
            response.add_additional(glue);
        })
        .await;

        let query = sample_edns_query(7, RecordType::TXT, false);
        let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NoError,
            "upstream answer must have arrived — SERVFAIL shows empty additionals too"
        );
        assert!(
            response
                .additionals
                .iter()
                .all(|r| !matches!(r.record_type(), RecordType::TSIG | RecordType::SIG)),
            "upstream TSIG/SIG records must not be relayed to the client"
        );
        assert!(
            response
                .additionals
                .iter()
                .any(|r| matches!(r.data, RData::A(_))),
            "benign glue records pass the strip untouched"
        );
        assert!(
            response.edns.is_some(),
            "the per-hop OPT is still synthesized after the strip"
        );
    }

    #[tokio::test]
    async fn handle_query_generic_servfail_echoes_request_cd() {
        // The no-upstream SERVFAIL branch echoes CD like the relay branch.
        let mut q = sample_query(8, u16::from(RecordType::TXT));
        q[3] |= 0x10; // CD=1
        let response = DnsServer::handle_query(&q, &empty_resolver())
            .await
            .unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(response.metadata.checking_disabled, "SERVFAIL echoes CD");
        assert_eq!(response.queries, Message::from_vec(&q).unwrap().queries);
    }

    /// Fake-IP mode: HTTPS/SVCB records carrying `ipv4hint`/`ipv6hint`
    /// leak the real origin IP — the strip must reach records in the
    /// authority and additional sections, not just the answer section.
    #[tokio::test]
    async fn handle_query_generic_strips_svc_hints_across_sections() {
        use crate::fakeip::MemoryStore;
        use hickory_proto::rr::rdata::svcb::SvcParamKey;
        use hickory_proto::rr::RData;

        let addr = spawn_dns_responder(|response| {
            response.metadata.response_code = ResponseCode::NoError;
            response.add_answer(https_record_with_hints());
            response.add_authority(https_record_with_hints());
            response.add_additional(https_record_with_hints());
            // An HTTPS record owned by a hosts-mapped (non-faked) name —
            // its hints are legitimate and must survive the strip.
            response.add_additional(https_record_with_hints_named("static.test."));
        })
        .await;
        // A hosts-trie mapping is an explicit override: "static.test" is
        // never faked even in FakeIp mode.
        let mut hosts = meow_trie::DomainTrie::new();
        hosts.insert(
            "static.test",
            vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))].into(),
        );
        let mut resolver = crate::resolver::Resolver::new(
            vec![addr],
            Vec::new(),
            DnsMode::FakeIp,
            hosts,
            true,
            true,
        );
        resolver.set_fakeip_v4(Arc::new(
            crate::fakeip::Pool::new(
                "198.18.0.0/16".parse().unwrap(),
                Arc::new(MemoryStore::new(1024)),
            )
            .unwrap(),
        ));

        let query = sample_query(7, u16::from(RecordType::HTTPS));
        let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
        let response = Message::from_vec(&response).unwrap();

        for (section, records) in [
            ("answers", &response.answers),
            ("authorities", &response.authorities),
        ] {
            assert_eq!(records.len(), 1, "{section}");
            let RData::HTTPS(https) = &records[0].data else {
                panic!("{section}: expected HTTPS rdata");
            };
            let keys: Vec<&SvcParamKey> = https.0.svc_params.iter().map(|(k, _)| k).collect();
            assert!(
                !keys.contains(&&SvcParamKey::Ipv4Hint) && !keys.contains(&&SvcParamKey::Ipv6Hint),
                "{section}: ip hints must be stripped in fake-IP mode"
            );
            assert!(
                keys.contains(&&SvcParamKey::Alpn),
                "{section}: non-hint params are preserved"
            );
        }

        // The additionals carry two records: the faked example.com one is
        // stripped, the hosts-mapped (non-faked) static.test one keeps its
        // hints — the gate follows the record's owner, not the qname.
        assert_eq!(response.additionals.len(), 2);
        for rec in &response.additionals {
            let RData::HTTPS(https) = &rec.data else {
                panic!("expected HTTPS rdata");
            };
            let keys: Vec<&SvcParamKey> = https.0.svc_params.iter().map(|(k, _)| k).collect();
            if rec.name.to_utf8() == "example.com." {
                assert!(
                    !keys.contains(&&SvcParamKey::Ipv4Hint),
                    "faked record's hints stripped"
                );
            } else {
                assert_eq!(rec.name.to_utf8(), "static.test.");
                assert!(
                    keys.contains(&&SvcParamKey::Ipv4Hint),
                    "non-faked record keeps its legitimate hints"
                );
            }
        }
    }

    /// With `ipv6` disabled, only `ipv6hint` is stripped — `ipv4hint`
    /// stays usable (ADR-0013), and only in the sections that need it.
    #[tokio::test]
    async fn handle_query_generic_strips_ipv6_hint_when_ipv6_disabled() {
        use hickory_proto::rr::rdata::svcb::SvcParamKey;
        use hickory_proto::rr::RData;

        let addr = spawn_dns_responder(|response| {
            response.metadata.response_code = ResponseCode::NoError;
            response.add_answer(https_record_with_hints());
            response.add_authority(https_record_with_hints());
            response.add_additional(https_record_with_hints());
        })
        .await;
        let resolver = crate::resolver::Resolver::new(
            vec![addr],
            Vec::new(),
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            false,
        );

        let query = sample_query(7, u16::from(RecordType::HTTPS));
        let response = DnsServer::handle_query(&query, &resolver).await.unwrap();
        let response = Message::from_vec(&response).unwrap();

        for (section, records) in [
            ("answers", &response.answers),
            ("authorities", &response.authorities),
            ("additionals", &response.additionals),
        ] {
            let RData::HTTPS(https) = &records[0].data else {
                panic!("{section}: expected HTTPS rdata");
            };
            let keys: Vec<&SvcParamKey> = https.0.svc_params.iter().map(|(k, _)| k).collect();
            assert!(
                keys.contains(&&SvcParamKey::Ipv4Hint),
                "{section}: ipv4hint survives when only ipv6 is disabled"
            );
            assert!(
                !keys.contains(&&SvcParamKey::Ipv6Hint),
                "{section}: ipv6hint stripped when ipv6 is disabled"
            );
        }
    }

    #[tokio::test]
    async fn handle_query_generic_servfail_echoes_request_edns() {
        // Upstream unreachable → local SERVFAIL; an EDNS-speaking client
        // still gets the minimal response OPT it requires.
        let query = sample_edns_query(7, RecordType::TXT, false);
        let response = DnsServer::handle_query(&query, &empty_resolver())
            .await
            .unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(
            response.edns.is_some(),
            "SERVFAIL still echoes a response OPT to EDNS clients"
        );
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

    /// Wire-format A/AAAA query for an arbitrary name (`sample_query` is
    /// fixed to example.com).
    fn query_named(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::with_capacity(64);
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]); // standard query, RD=1
        q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        q.extend_from_slice(&[0x00; 6]); // AN/NS/AR = 0
        for label in name.split('.') {
            q.push(u8::try_from(label.len()).unwrap());
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        q
    }

    /// Spawn a loopback upstream that swallows every datagram and never
    /// replies — clients park for the full query timeout (a TEST-NET address
    /// would fail fast on ICMP unreachable instead of parking).
    async fn spawn_blackhole_upstream() -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while socket.recv_from(&mut buf).await.is_ok() {}
        });
        addr
    }

    /// Extract the answer bytes from a probe, asserting it was locally
    /// decided.
    fn answered(outcome: super::LocalAnswer) -> Vec<u8> {
        match outcome {
            super::LocalAnswer::Answer(bytes) => bytes,
            other => panic!("expected a local answer, got {other:?}"),
        }
    }

    #[test]
    fn try_answer_local_answers_hosts_entry_without_upstream() {
        let mut hosts = meow_trie::DomainTrie::new();
        hosts.insert(
            "myhost.test",
            crate::resolver::HostEntry::Addresses(vec![std::net::IpAddr::V4(Ipv4Addr::new(
                10, 0, 0, 7,
            ))]),
        );
        let resolver = crate::resolver::Resolver::new(
            vec!["192.0.2.1:53".parse().unwrap()],
            Vec::new(),
            DnsMode::Normal,
            hosts,
            true,
            true,
        );
        let q = query_named(0x1234, "myhost.test", 1);
        let resp = answered(DnsServer::try_answer_local(&q, &resolver));
        assert_eq!(&resp[0..2], &[0x12, 0x34], "ID echoed");
        assert_eq!(&resp[resp.len() - 4..], &[10, 0, 0, 7], "hosts A record");
    }

    #[test]
    fn try_answer_local_answers_fresh_cache_hit() {
        let resolver = empty_resolver();
        resolver.preload_cache(
            "example.com",
            &[std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            std::time::Duration::from_secs(300),
        );
        let q = sample_query(9, 1);
        let resp = answered(DnsServer::try_answer_local(&q, &resolver));
        assert_eq!(&resp[resp.len() - 4..], &[1, 2, 3, 4]);
        // TTL is the remaining cache lifetime, not the fixed default.
        let ttl = u32::from_be_bytes(resp[resp.len() - 10..resp.len() - 6].try_into().unwrap());
        assert!(
            (290..=300).contains(&ttl),
            "cache TTL carried through, got {ttl}"
        );
    }

    #[test]
    fn try_answer_local_returns_upstream_when_upstream_needed() {
        let resolver = empty_resolver();
        assert!(
            matches!(
                DnsServer::try_answer_local(&sample_query(1, 1), &resolver),
                super::LocalAnswer::Upstream
            ),
            "uncached name needs the upstream pipeline"
        );
        assert!(
            matches!(
                DnsServer::try_answer_local(&sample_query(1, 16), &resolver),
                super::LocalAnswer::Upstream
            ),
            "non-A/AAAA types always go through generic forward"
        );
    }

    #[test]
    fn try_answer_local_drops_malformed_without_permit() {
        let resolver = empty_resolver();
        // Every shape where handle_query errs (→ the task logs and drops)
        // classifies as Drop — garbage must not spend a permit (issue #515).
        for (label, q) in [
            ("truncated header", vec![0u8; 8]),
            ("zero questions", {
                let mut q = sample_query(1, 1);
                q[4] = 0;
                q[5] = 0;
                q
            }),
            ("unparseable question", {
                let mut q = sample_query(1, 1);
                q.truncate(13); // question label chopped mid-length
                q
            }),
        ] {
            assert!(
                matches!(
                    DnsServer::try_answer_local(&q, &resolver),
                    super::LocalAnswer::Drop
                ),
                "{label} must classify as Drop"
            );
        }
        // Multi-question is wire-legal and gets FORMERR, not a drop.
        let mut q = sample_query(1, 1);
        q[5] = 2; // qdcount = 2
        let resp = answered(DnsServer::try_answer_local(&q, &resolver));
        assert_eq!(resp[3] & 0x0f, 1, "FORMERR rcode");
    }

    #[test]
    fn try_answer_local_suppresses_aaaa_when_ipv6_disabled() {
        let resolver = crate::resolver::Resolver::new(
            Vec::new(),
            Vec::new(),
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            /* ipv6 = */ false,
        );
        let q = sample_query(2, 28);
        let resp = answered(DnsServer::try_answer_local(&q, &resolver));
        assert_eq!(resp[3] & 0x0f, 0, "NOERROR, not an error rcode");
        assert_eq!(&resp[6..8], &[0, 0], "ANCOUNT = 0");
    }

    /// Regression for the probe-vs-`handle_query` ordering divergence: a
    /// hosts entry is an explicit user override checked BEFORE the IPv6
    /// short-circuit, so an AAAA query for a hosts v6 address must be
    /// answered even under `ipv6: false` (issue #515).
    #[test]
    fn try_answer_local_hosts_v6_outranks_ipv6_disable() {
        let mut hosts = meow_trie::DomainTrie::new();
        hosts.insert(
            "v6host.test",
            crate::resolver::HostEntry::Addresses(vec![
                std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
                "::1".parse().unwrap(),
            ]),
        );
        let resolver = crate::resolver::Resolver::new(
            Vec::new(),
            Vec::new(),
            DnsMode::Normal,
            hosts,
            true,
            /* ipv6 = */ false,
        );
        let q = query_named(0x1234, "v6host.test", 28);
        let resp = answered(DnsServer::try_answer_local(&q, &resolver));
        assert_eq!(resp[3] & 0x0f, 0, "NOERROR");
        assert_eq!(&resp[6..8], &[0, 1], "ANCOUNT = 1 — hosts v6 answered");
        assert_eq!(
            &resp[resp.len() - 16..],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "hosts AAAA ::1"
        );
        // Same query for a non-hosts name still gets the empty NOERROR.
        let resp = answered(DnsServer::try_answer_local(&sample_query(3, 28), &resolver));
        assert_eq!(&resp[6..8], &[0, 0], "non-hosts AAAA: ANCOUNT = 0");
    }

    /// Byte-level parity (issue #515): every locally-decidable query must
    /// produce exactly the response `handle_query` would have produced.
    #[tokio::test]
    async fn try_answer_local_matches_handle_query_bytes() {
        let mut hosts = meow_trie::DomainTrie::new();
        hosts.insert(
            "myhost.test",
            crate::resolver::HostEntry::Addresses(vec![std::net::IpAddr::V4(Ipv4Addr::new(
                10, 0, 0, 7,
            ))]),
        );
        let resolver = crate::resolver::Resolver::new(
            Vec::new(),
            Vec::new(),
            DnsMode::Normal,
            hosts,
            true,
            true,
        );
        resolver.preload_cache(
            "example.com",
            &[std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            std::time::Duration::from_secs(300),
        );

        for (label, q) in [
            ("hosts A", query_named(0x1111, "myhost.test", 1)),
            ("cache hit", sample_query(0x2222, 1)),
            // A hosts entry holding only a v4 address answers AAAA with
            // NOERROR-empty — decided by the hosts arm, not the ipv6 gate.
            (
                "hosts v4-only under AAAA",
                query_named(0x3333, "myhost.test", 28),
            ),
            // An EDNS request answered from the hosts arm exercises the
            // A/AAAA arm's `append_opt_record` path — the OPT echo must
            // be byte-identical between the inline and task paths.
            (
                "hosts A with EDNS",
                sample_edns_query_named(0x8888, "myhost.test.", RecordType::A, false),
            ),
            // The classification gates must answer byte-identically on both
            // paths too — a non-QUERY opcode and a non-IN class get NOTIMP
            // (with the EDNS echo). A QR=1 response packet produces wire
            // silence instead — asserted below since it yields no bytes.
            ("Status opcode", {
                let mut q = sample_edns_query(0x5555, RecordType::TXT, false);
                q[2] = (q[2] & 0x87) | (2 << 3);
                q
            }),
            ("CH qclass", {
                let mut q = sample_edns_query(0x6666, RecordType::TXT, false);
                // QCLASS is the last field of the question; with EDNS
                // attached it is not at the tail — locate it via
                // parse_question's offset instead.
                let qlen = DnsServer::question_len_for_test(&q);
                q[12 + qlen - 2] = 0x00;
                q[12 + qlen - 1] = 0x03;
                q
            }),
        ] {
            let local = answered(DnsServer::try_answer_local(&q, &resolver));
            let full = DnsServer::handle_query(&q, &resolver)
                .await
                .expect("handle_query must succeed");
            assert_eq!(local, full, "{label}: local answer diverged");
        }

        // A QR=1 response packet gets wire silence on both paths — a
        // FORMERR reply would ping-pong forever between two forwarding
        // resolvers, so the packet is dropped like a malformed one.
        let mut q = sample_edns_query(0x7777, RecordType::TXT, false);
        q[2] |= 0x80; // QR=1
        assert!(matches!(
            DnsServer::try_answer_local(&q, &resolver),
            LocalAnswer::Drop
        ));
        assert!(DnsServer::handle_query(&q, &resolver).await.is_err());
    }

    /// The fake-IP synthesis branch — the dominant `Decided` path under
    /// TUN — must produce byte-identical responses to `handle_query`.
    #[tokio::test]
    async fn try_answer_local_matches_handle_query_bytes_fakeip() {
        use crate::fakeip::MemoryStore;

        let mut resolver = crate::resolver::Resolver::new(
            Vec::new(),
            Vec::new(),
            DnsMode::FakeIp,
            meow_trie::DomainTrie::new(),
            true,
            true,
        );
        resolver.set_fakeip_v4(Arc::new(
            crate::fakeip::Pool::new(
                "198.18.0.0/16".parse().unwrap(),
                Arc::new(MemoryStore::new(1024)),
            )
            .unwrap(),
        ));

        for (label, q, want_ancount) in [
            ("fake-IP A synthesis", sample_query(0x4444, 1), 1u8),
            // v4-only pool: AAAA is suppressed to NOERROR-empty so a
            // dual-stack client falls back to the v4 fake.
            ("fake-IP AAAA suppression", sample_query(0x5555, 28), 0u8),
        ] {
            let local = answered(DnsServer::try_answer_local(&q, &resolver));
            let full = DnsServer::handle_query(&q, &resolver)
                .await
                .expect("handle_query must succeed");
            assert_eq!(local, full, "{label}: local answer diverged");
            assert_eq!(local[3] & 0x0f, 0, "{label}: NOERROR");
            assert_eq!(local[7], want_ancount, "{label}: ANCOUNT");
        }
    }

    /// The spawned-task path end-to-end (issue #515): an upstream-bound
    /// query must be answered through the `Weak<UdpSocket>` upgrade +
    /// `send_to`, not just counted.
    #[tokio::test]
    async fn spawned_task_delivers_upstream_answer() {
        // Echo upstream: flips the header to a NOERROR response (QR|RA),
        // returns the query unchanged — an empty-answer response.
        let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = upstream_socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, src)) = upstream_socket.recv_from(&mut buf).await {
                buf[2] = 0x81;
                buf[3] = 0x80;
                let _ = upstream_socket.send_to(&buf[..len], src).await;
            }
        });

        let resolver = Arc::new(crate::resolver::Resolver::new(
            vec![upstream],
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

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&sample_query(0xbeef, 1), addr)
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.recv_from(&mut buf),
        )
        .await
        .expect("upstream-bound query must be answered by the task")
        .unwrap();
        assert_eq!(&buf[0..2], &[0xbe, 0xef], "response id echoed");
        assert!(len >= 12);
        serve.abort();
    }

    /// Saturation contract (issue #515): once `MAX_IN_FLIGHT` queries are
    /// parked on upstream, further upstream-bound queries are dropped and
    /// counted rather than queueing unboundedly.
    #[tokio::test]
    async fn saturated_server_drops_and_counts_upstream_queries() {
        let upstream = spawn_blackhole_upstream().await;
        let resolver = Arc::new(crate::resolver::Resolver::new(
            vec![upstream],
            Vec::new(),
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        ));
        let server = DnsServer::new(resolver, "127.0.0.1:0".parse().unwrap());
        let bound = server.bind().await.unwrap();
        let dropped = Arc::clone(&bound.dropped);
        let addr = bound.local_addr().unwrap();
        let serve = tokio::spawn(bound.run());
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Exact accounting: the receive loop is serial and loopback
        // preserves order, so the first MAX_IN_FLIGHT queries park on
        // permits and the next OVER are each dropped once — no more, no
        // fewer.
        const OVER: u16 = 3;
        for i in 0..MAX_IN_FLIGHT as u16 + OVER {
            client.send_to(&sample_query(i, 1), addr).await.unwrap();
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let n = dropped.load(std::sync::atomic::Ordering::Relaxed);
            if n == u64::from(OVER) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "expected exactly {OVER} drops, got {n}"
            );
            assert!(n < u64::from(OVER), "over-counted drops: {n} > {OVER}");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        serve.abort();
    }

    /// Head-of-line guarantee (issue #515): with the upstream cap fully
    /// parked, a locally-decidable query (hosts) is still answered inline on
    /// the receive loop — it never waits for a permit.
    #[tokio::test]
    async fn local_answer_bypasses_saturated_upstream_cap() {
        let mut hosts = meow_trie::DomainTrie::new();
        hosts.insert(
            "local.test",
            crate::resolver::HostEntry::Addresses(vec![std::net::IpAddr::V4(Ipv4Addr::new(
                10, 9, 9, 9,
            ))]),
        );
        let upstream = spawn_blackhole_upstream().await;
        let resolver = Arc::new(crate::resolver::Resolver::new(
            vec![upstream],
            Vec::new(),
            DnsMode::Normal,
            hosts,
            true,
            true,
        ));
        let server = DnsServer::new(resolver, "127.0.0.1:0".parse().unwrap());
        let bound = server.bind().await.unwrap();
        let dropped = Arc::clone(&bound.dropped);
        let addr = bound.local_addr().unwrap();
        let serve = tokio::spawn(bound.run());
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Park exactly MAX_IN_FLIGHT uncached queries on the blackhole
        // upstream — permits exhausted, nothing dropped yet.
        for i in 0..MAX_IN_FLIGHT as u16 {
            client.send_to(&sample_query(i, 1), addr).await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // The hosts query is answered inline despite zero free permits.
        client
            .send_to(&query_named(0xfeed, "local.test", 1), addr)
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("hosts answer must not wait for a permit")
        .unwrap();
        assert_eq!(&buf[0..2], &[0xfe, 0xed]);
        assert_eq!(&buf[len - 4..len], &[10, 9, 9, 9]);
        // Exactly the cap's worth of queries were sent; none should have
        // been dropped.
        assert_eq!(
            dropped.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the first MAX_IN_FLIGHT queries all got permits"
        );
        serve.abort();
    }
}
