# TCP on the configured DNS listener

`dns.listen` binds UDP and TCP at the same address, matching mihomo's
[DNS listener](https://github.com/MetaCubeX/mihomo/blob/Meta/dns/server.go).
No new configuration key is introduced. TCP accepts the standard two-byte
length prefix and the full 65535-byte frame range; messages shorter than the
12-byte DNS header are rejected. Requests on one connection are processed in
order, including pipelined requests. The shared resolver slot is read per query,
so existing connections observe reloads without interrupting an active query.

## Resource and lifecycle behavior

- At most 128 accepted TCP client tasks; further connections wait in the OS
  backlog. Each client owns at most one query frame at a time.
- TCP upstream queries share the existing 512-query budget with UDP. TCP waits
  within its exchange deadline while UDP retains its existing drop/retry policy.
  Locally answerable queries require no upstream permit. Deferred answer hooks
  retain their budget until the actual blocking work completes.
- Each exchange has a 30-second deadline covering prefix/body reads, waiting
  for capacity, query execution and response writes. Idle/partial-frame clients
  therefore cannot retain slots indefinitely. These fixed resource bounds are
  an implementation policy, not a new configuration dialect.
- Dropping the listener cancels owned TCP clients and releases both listen
  sockets. Existing UDP task/socket ownership remains unchanged.
- TCP and UDP binding is transactional: if either bind fails, startup returns
  an error and releases the other socket. This deliberately reports incomplete
  dual-transport availability instead of mihomo's independent per-transport
  startup logs (ADR-0002 Class A: fail closed on a partially available listener).
- `BoundDnsServer::from_socket` and `from_slot` remain UDP-only; they do not
  silently bind an additional port supplied by an embedder. TUN TCP DNS hijacking
  is not added by this change.

No transport proxy implementation or new resolver owner is introduced.
