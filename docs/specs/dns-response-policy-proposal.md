# Proposal for query-type-specific DNS responses

Status: response rules implemented; node bootstrap policy is now documented in [proxy-server-dns-policy.md](proxy-server-dns-policy.md).
Owner: engineer
Date: 2026-11-07
Tracking: [PR #906](https://github.com/meow-rs/meow-rs/pull/906)
Upstream reference: `fake-ip-filter-mode: rule`
([MetaCubeX/mihomo#2469](https://github.com/MetaCubeX/mihomo/pull/2469) —
an ordered `fake-ip`/`real-ip` verdict list, the closest shipped relative
of the fake-IP action proposed here), `rcode://` nameserver URLs, and
`proxy-server-nameserver-policy` (now implemented separately; see the transport note below).

A split DNS gateway may need to return an empty HTTPS answer for one set
of domains, refuse the same query for a second set, and forward it
normally for everyone else. A fixed response code is already expressible
at domain granularity: `rcode://success`, `rcode://name_error` and
`rcode://refused` are legal nameserver URLs and valid `nameserver-policy`
values, relayed verbatim on the generic arm — `success` answers
NOERROR-empty (NODATA), `name_error` answers NXDOMAIN, `refused` answers
REFUSED. On the A/AAAA arm the picture splits: `success` and
`name_error` still answer faithfully, but `refused` and its peers
surface as `ClientError::Rcode`, count as upstream failures, and fall
through the tier chain to SERVFAIL rather than reaching the client
intact. What a resolver choice cannot express is the rest of the matrix —
a response scoped to one query type, a faithful NODATA or REFUSED on the
address pipeline, a typed static record with a TTL, an ordered
first-match policy, or an explicit fake-IP decision per name. The choice
also needs a defined relationship with fake-IP and explicit host records.
[ADR-0013](../adr/0013-fakeip-https-svcb-handling.md) already specifies
useful default behaviour for HTTPS and SVCB, including keeping ECH and
ALPN when filtering address hints.

## Proposed behaviour

Keep the existing defaults and the existing nameserver-policy matcher.
Add an optional ordered list of DNS response rules. Each rule matches a
domain condition and an optional set of query types; the domain
condition evaluates against the query's name alone — no process, socket
or destination-IP metadata exists on this path for it to see. First
match wins, including a rule explicitly selecting ordinary forwarding.
The absence of a match hands the query to the existing pipeline. Reuse
domain and rule-provider matching, bound to the candidate generation's
rule-provider set on reload — the same commit/reject contract `rule-set:`
nameserver-policy keys already follow. The reload plumbing must learn
the new surface wherever `rule-set:` conditions may appear:
`dns_needs_rule_providers` scans only `nameserver-policy` keys today,
`dns_uses_runtime_refs` forces a rebuild on that scan alone, and
`dns_inputs_equal` calls a config unchanged without seeing the rule
list — each must learn that the rules exist, that their order is
semantic, and which providers they name.

Apply the selected action identically wherever the query is answered.
The DNS listener is a single UDP receive loop: a synchronous probe
answers locally-decidable queries on the loop itself and hands
everything else to a bounded task running the full query pipeline. A
response rule must produce the same wire answer on either arm, which
bounds what a condition may consult — the domain trie, provider
matchers and the geosite DB must all evaluate synchronously from
already-loaded state, with no I/O, so the probe can run them. Note the
arm split's edge: a non-A/AAAA question always escalates to the task
arm today, so a rule scoped to generic types only ever fires there —
the identical-wire contract binds the arms for A and AAAA alone, and
answering a generic-typed rule on the probe would mean evaluating the
whole rule set on the receive loop. Keep that cost off the probe.

Allow NODATA (a NOERROR answer with zero records), REFUSED, a typed
static address with TTL, ordinary forwarding, or the existing
per-family fake-IP allocation. A static IPv4 address answers only A —
the action produces a record of one type while the rule's type scope
selects the queries it sees, so the same action scoped to all types
returns NODATA for AAAA, TXT and everything else. That is a wider
shadow than a `hosts:` line casts: a hosts mapping answers the family
it holds and leaves every other type to upstream, while an all-types
rule answers for all of them — a user migrating a hosts entry to a
static rule must scope it to the record type it emits, or keep the
hosts entry. The fake-IP action is defined for A and AAAA alone: the
pools are per-family and only the address pipeline allocates, so on
any other query type it degenerates to ordinary forwarding — and the
relayed HTTPS/SVCB answer still passes through ADR-0013
hint-stripping. It also presupposes `enhanced-mode: fake-ip`:
`install_fakeip` builds the pools in that mode alone, so in normal or
redir-host mode there is nothing to allocate from. Reject a fake-IP
action at load when no pool exists rather than silently degrade it to
forwarding — a 'fake' answer that quietly returned real addresses
would serve the config's stated intent worse than the error message
would. And because `strip_svc_ip_hints` keys on `fake_ip_active_for` —
which today consults only the mode, the pools, the hosts trie and the
skipper — a name a rule fakes rather than the global mode must count
as faked there too, or a rule-faked owner's HTTPS answer would keep
the real address hints the strip exists to remove.

A matching rule decides before any upstream fetch. A synthesised answer
therefore never meets `strip_svc_ip_hints` — there is no relayed record
to filter — so an empty HTTPS/SVCB answer forgoes ECH and ALPN by
construction, the same trade mihomo's empty answer makes. Answers that
forward keep today's ADR-0013 filtering.

Pin the rule list's seat in the local decision order, identical on both
serve arms. The hosts trie still answers first — an explicit `hosts:`
mapping is never overridden by a rule, the same priority it already
holds over the IPv6-disable toggle. The rule list runs next, ahead of
the IPv6-disabled AAAA suppression, fake-IP synthesis, fresh cache hits
and the upstream fetch, so a matching rule suppresses all of them and
`forward` resumes the pipeline where a rule-free query would have
continued. A rule's fake-IP action allocates for its name even when
`fake-ip-filter` would bypass it — the ordered list is the more
specific instruction, the relationship mihomo's rule mode gives its
verdicts over the flat blacklist. A `forward` rule, by contrast,
re-enters the ordinary pipeline skipper and all, so a filtered name
stays real under it and a blacklist translates as forwarding rules for
the filtered names; names no rule matches keep today's
mode-plus-skipper behaviour. `GET /dns/query` calls `resolve_ips` for
A/AAAA and `forward_generic` for the rest, bypassing the serve loop's
wire path by design — ADR-0013's hint stripping is already invisible
there — so the hook layer decides which the diagnostics endpoint
reports: hooks inside the resolver's local-decision path let it honour
the rules, hooks at the serve loop keep it a raw-upstream diagnostic.

Preserve the normal opcode, class, EDNS and malformed-query handling
before synthesising an answer. The hand-built A/AAAA responses carry a
fixed OPT record that clears DO and advertises 512 bytes; a synthesised
rule answer should instead echo the client's DO bit and advertise a real
UDP payload, as the forwarded path's response OPT already does. Rules
that choose forwarding must keep the question name's wire encoding.
Proxy-server hostname lookups cannot receive a fake-IP today — the dial
path's `resolve_ips` never allocates from the pools and filters any
answer inside the fake range, and synthesis happens before proxy
selection ([ADR-0012](../adr/0012-dns-via-proxy.md)). Response rules
must not change that.

Keep transport and pool selection in the existing resolver. A proxy
endpoint can need a different bootstrap pool from ordinary client
lookups; upstream gives it a dedicated `proxy-server-nameserver-policy`
field, now implemented by reusing the
nameserver-policy map and builder for the `proxy-server-nameserver`
resolver, the one `ResolverHostHook` consults for proxy hostnames,
rather than growing a second policy surface (the `direct-nameserver`
resolver the DIRECT outbound uses keeps its own follow-policy flag).
The landed `nameserver-policy-exclusive` flag — merged in
[PR #905](https://github.com/meow-rs/meow-rs/pull/905) — already
confines a matched entry to its own nameservers end-to-end, the
ordering the last acceptance row leans on. Preserve document order on
reload. New loop shapes also want a load-time check the existing guards
do not provide: a `?proxy=` entry or a `rule-set:`-backed condition
bound to the proxy-server resolver points back into the chain that
builds it — the provider's fetch, or the proxy's own dial, resolves a
hostname through this resolver, a construction-time self-reference.
`circular_proxy_tags`, the only guard for this loop shape, merely warns
on `proxy-server-nameserver` entries whose `#PROXY`/`?proxy=` tag names
a hostname-reached proxy; the `in_dns_via_proxy_dial` /
`in_host_resolver` fences catch dial-time re-entry and answer from
`resolve_ips_local`, and `reject_proxied_quic_hostname` hard-refuses
proxied QUIC hostnames — none of them sees a cycle formed at build
time.

## Acceptance examples

All names and addresses below are synthetic. Count packets sent to each
fake upstream as well as checking the reply. Exercise both serve arms —
a query answered locally on the receive loop and one that must reach an
upstream — expecting the same wire result. The DNS listener is UDP-only;
each case is one datagram in, at most one datagram out.

| Configuration or query | Expected result |
| --- | --- |
| No response rules, HTTPS in fake-IP mode | Existing ADR-0013 result, retaining ALPN/ECH |
| First rule returns empty for HTTPS/SVCB under example.test, a later all-types rule refuses the same domain | HTTPS and SVCB return NODATA with no upstream traffic. A and every other type return REFUSED |
| Swap those two rules on reload | HTTPS now returns REFUSED |
| A-only NODATA rule followed by a fake-IP rule for the same domain | A returns NODATA. AAAA gets a synthetic address when a v6 pool is configured, NODATA under the default v4-only pool — the enabled families decide. HTTPS forwards under the fake-IP action, and `strip_svc_ip_hints` treats the rule-faked owner as faked so no real address hint reaches the answer |
| `hosts:` entry for a name also matched by a NODATA rule | The hosts mapping answers the address query — an explicit mapping is never overridden; the rule still decides types hosts cannot serve |
| A `fake-ip-filter`-listed name matched by a rule with the fake-IP action | The rule allocates anyway — for matched names the ordered list outranks the flat filter |
| A-type static-address rule for host.example.test with address 192.0.2.7 and TTL 42 | A contains exactly that address with TTL 42 |
| The same static-address action scoped to all types | A still returns 192.0.2.7; AAAA and TXT return NODATA — the action has no record of those types to emit |
| Earlier forwarding exception, later suffix fake-IP rule | The exception receives a real answer. Its siblings receive synthetic addresses for the enabled families |
| Matching HTTPS question carrying a duplicate OPT | FORMERR — malformed-query handling precedes any rule action |
| Matching HTTPS question with EDNS version > 0 | BADVERS |
| A `rule-set:`-backed condition's provider changes in the candidate configuration | The first query after commit uses the new membership. A rejected reload keeps the previous membership |
| Endpoint-specific pool fails under exclusive selection — `nameserver-policy-exclusive` landed in #905 | No query for the endpoint reaches the general pool |

## Interface decision

Should response rules live in a dedicated DNS section, or can an
existing configuration surface express the same decisions without
losing order? The existing surfaces cover only part of the matrix —
`nameserver-policy` with `rcode://` values pins a domain set to a fixed
code on the generic arm, and `fake-ip-filter` chooses fake-vs-real with
no query-type scope — so a new surface is chiefly buying query-type
scope, address-arm fidelity, typed records and ordered composition, not
the responses themselves; folding the rules into either existing
surface would conflate who resolves a name with what is answered for
it. It would help to settle that before making a public schema hard to
change. In either design, transport, domain matching, fake-IP
allocation and packet validation stay with their current owners.

## Implementation choice

The follow-up implementation uses the dedicated ordered
`dns.response-rules` list documented in the [DNS guide](../../website/guide/dns.md#ordered-response-rules).
The schema is a meow extension under review. Rule predicates reuse the
domain trie and loaded geosite/provider matchers. The main resolver owns
the immutable rule list for its generation, and only DNS wire handlers
apply its actions. `GET /dns/query` remains an upstream diagnostic.

The address probe and task path share the same local rule builder.
Generic queries evaluate rules on the task path after packet validation.
Raw rule lists participate in ordered `RawDns` equality, while provider
and geosite discovery include their match conditions. Provider references
force a rebuild on each candidate commit through the existing runtime-ref
gate. Strict validation of this new surface rejects rules that could
otherwise silently forward a query their configuration intended to block
(ADR-0002 Class A).

Endpoint-specific `proxy-server-nameserver-policy` is a separate transport
configuration change. It can reuse the existing nameserver-policy builder
and requires its own construction-cycle and exclusive-pool tests. The
response-rule implementation keeps proxy-server hostname resolution on
the existing non-synthesizing path.
