# Proposal for query-type-specific DNS responses

Status: proposed for discussion.

A split DNS gateway may need to return an empty HTTPS answer for one set of
domains, refuse the same query for a second set, and forward it normally for
everyone else. A resolver choice alone cannot express these responses. The
choice also needs a defined relationship with FakeIP and explicit host
records. ADR 0013 already specifies useful default behaviour for HTTPS and
SVCB, including keeping ECH and ALPN when filtering address hints.

## Proposed behaviour

Keep the existing defaults and the existing nameserver-policy matcher. Add
an optional ordered list of DNS response rules. Each rule matches a domain
condition and an optional set of query types; the domain condition
evaluates against the query's name alone — no process, socket or
destination-IP metadata exists on this path for it to see. First match
wins, including a rule explicitly selecting ordinary forwarding. The
absence of a match hands the query to the existing pipeline. Reuse domain
and rule-provider matching, bound to the candidate generation's
rule-provider set on reload — the same commit/reject contract `rule-set:`
nameserver-policy keys already follow.

Apply the selected action identically wherever the query is answered. The
DNS listener is a single UDP receive loop: a synchronous probe answers
locally-decidable queries on the loop itself and hands everything else to
a bounded task running the full query pipeline. A response rule must
produce the same wire answer on either arm.

Allow NODATA (a NOERROR answer with zero records), REFUSED, a typed
static address with TTL, ordinary forwarding, or the existing per-family
FakeIP allocation. A static IPv4 address answers only A — the action
produces a record of one type while the rule's type scope selects the
queries it sees, so the same action scoped to all types returns NODATA
for AAAA, TXT and everything else. The FakeIP action is defined for A
and AAAA alone: the pools are per-family and only the address pipeline
allocates, so on any other query type it degenerates to ordinary
forwarding — and the relayed HTTPS/SVCB answer still passes through ADR
0013 hint-stripping.

A matching rule decides before any upstream fetch. A synthesised answer
therefore never meets `strip_svc_ip_hints` — there is no relayed record
to filter — so an empty HTTPS/SVCB answer forgoes ECH and ALPN by
construction, the same trade mihomo's empty answer makes. Answers that
forward keep today's ADR 0013 filtering.

Preserve the normal opcode, class, EDNS and malformed-query handling
before synthesising an answer. The hand-built A/AAAA responses carry a
fixed OPT record that clears DO and advertises 512 bytes; a synthesised
rule answer should instead echo the client's DO bit and advertise a real
UDP payload, as the forwarded path's response OPT already does. Rules
that choose forwarding must keep the question name's wire encoding.
Proxy-server hostname lookups cannot receive a FakeIP today — the dial
path's `resolve_ips` never allocates from the pools and filters any
answer inside the fake range, and synthesis happens before proxy
selection (ADR 0012). Response rules must not change that.

Keep transport and pool selection in the existing resolver. A proxy
endpoint can need a different bootstrap pool from ordinary client
lookups. Prefer reusing the nameserver-policy map and builder for the
dedicated `proxy-server-nameserver` resolver — the one `ResolverHostHook`
consults for proxy hostnames, not the `direct-nameserver` resolver the
DIRECT outbound uses. Preserve document order on reload. Where a rule
reference could cycle, a new load-time check is needed: the only existing
guard, `circular_proxy_tags`, merely warns on `#PROXY`
`proxy-server-nameserver` entries and covers nothing here. A separate
opt-in proposal covers exclusive pool selection in
[PR #905](https://github.com/meow-rs/meow-rs/pull/905).

## Acceptance examples

All names and addresses below are synthetic. Count packets sent to each
fake upstream as well as checking the reply. Exercise both serve arms —
a query answered locally on the receive loop and one that must reach an
upstream — expecting the same wire result. The DNS listener is UDP-only;
each case is one datagram in, at most one datagram out.

| Configuration or query | Expected result |
| --- | --- |
| No response rules, HTTPS in FakeIP mode | Existing ADR 0013 result, retaining ALPN/ECH |
| First rule returns empty for HTTPS/SVCB under example.test, later rule refuses the same domain | HTTPS and SVCB return NODATA with no upstream traffic. A returns REFUSED |
| Swap those two rules on reload | HTTPS now returns REFUSED |
| A-only NODATA rule followed by a dual-stack FakeIP rule for the same domain | A returns NODATA. AAAA returns a synthetic IPv6 address. HTTPS forwards under the FakeIP action, and `strip_svc_ip_hints` treats the rule-faked owner as faked so no real address hint reaches the answer |
| A-type static-address rule for host.example.test with address 192.0.2.7 and TTL 42 | A contains exactly that address with TTL 42 |
| The same static-address action scoped to all types | A still returns 192.0.2.7; AAAA and TXT return NODATA — the action has no record of those types to emit |
| Earlier forwarding exception, later suffix FakeIP rule | The exception receives a real answer. Its siblings receive synthetic addresses for the enabled families |
| Matching HTTPS question carrying a duplicate OPT | FORMERR — malformed-query handling precedes any rule action |
| Matching HTTPS question with EDNS version > 0 | BADVERS |
| A `rule-set:`-backed condition's provider changes in the candidate configuration | The first query after commit uses the new membership. A rejected reload keeps the previous membership |
| Endpoint-specific bootstrap pool fails under exclusive selection | No query for the endpoint reaches the general pool |

## Interface decision

Should response rules live in a dedicated DNS section, or can an existing
configuration surface express the same decisions without losing order? It
would help to settle that before making a public schema hard to change. In
either design, transport, domain matching, FakeIP allocation and packet
validation stay with their current owners.
