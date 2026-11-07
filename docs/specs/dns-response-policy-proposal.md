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
condition and an optional set of query types. First match wins, including a
rule explicitly selecting ordinary forwarding. The absence of a match hands
the query to the existing pipeline. Reuse domain and rule-provider matching,
including the candidate provider registry during reload. Reject conditions
that require process, socket or destination-IP metadata at configuration load.

Use a single selected action in both the inline and asynchronous DNS paths.
Allow NOERROR with zero answers, REFUSED, a typed static address with TTL,
ordinary forwarding, or the existing FakeIP allocation for the requested
address family. A fixed IPv4 address answers A. A rule covering other types
with only that address returns NODATA for those types. Preserve the normal
opcode, class, EDNS and malformed-query handling before synthesising an answer.
Rules that choose forwarding must keep the question name's wire encoding.
Real-address lookups for connecting to a proxy must never receive a FakeIP.

Keep transport and pool selection in the existing resolver. A proxy endpoint
can need a different bootstrap pool from ordinary client lookups. Prefer
reusing the nameserver-policy map and builder in the existing dedicated proxy
resolver. Preserve document order on reload and reject circular dependencies.
A separate opt-in proposal covers exclusive pool selection in
[PR #905](https://github.com/meow-rs/meow-rs/pull/905).

## Acceptance examples

All names and addresses below are synthetic. Count packets sent to each fake
upstream as well as checking the reply. Exercise the UDP fast path, the task
path and the stream listener where enabled.

| Configuration or query | Expected result |
| --- | --- |
| No response rules, HTTPS in FakeIP mode | Existing ADR 0013 result, retaining ALPN/ECH |
| First rule returns empty for HTTPS/SVCB under example.test, later rule refuses the same domain | HTTPS and SVCB return NOERROR with no records or upstream traffic. A returns REFUSED |
| A-only NODATA rule followed by a dual-stack FakeIP rule for the same domain | A returns NODATA. AAAA returns a synthetic IPv6 address, and an HTTPS answer cannot expose a real IPv6 hint for that owner |
| Swap those rules on reload | HTTPS now returns REFUSED |
| A override for host.example.test with address 192.0.2.7 and TTL 42 | A contains exactly that address with TTL 42. An all-types override returns NODATA for AAAA and TXT |
| Earlier forwarding exception, later suffix FakeIP rule | The exception receives a real answer. Its siblings receive synthetic addresses for the enabled families |
| Duplicate OPT or unsupported EDNS version in a matching HTTPS question | Normal FORMERR or BADVERS, respectively |
| A nested provider rule changes in the candidate configuration | The first query after commit uses the new membership. A rejected reload keeps the previous membership |
| Endpoint-specific bootstrap pool fails under exclusive selection | No query for the endpoint reaches the general pool |

## Interface decision

Should response rules live in a dedicated DNS section, or can an existing
configuration surface express the same decisions without losing order? It
would help to settle that before making a public schema hard to change. In
either design, transport, domain matching, FakeIP allocation and packet
validation stay with their current owners.
