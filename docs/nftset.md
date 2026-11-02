# `dns.nftset` — intercept only what the rules proxy

meow adds the address of every DNS answer whose domain the rules would route
anywhere but `DIRECT` to an nftables set, like dnsmasq's `nftset=`. A
firewall that sends only those destinations (plus your static proxy IP
lists) to meow leaves everything else to kernel forwarding — flowtable and
hardware offload included — and dnsmasq no longer needs the domain lists.

```yaml
dns:
  enable: true
  listen: 127.0.0.1:1053      # clients' DNS must reach meow (e.g. dnsmasq -> meow)
  nftset:
    ipv4: inet#fw4#meow_proxy4   # family#table#set
    ipv6: inet#fw4#meow_proxy6   # optional
    timeout: 86400               # minimum element timeout, s (default 1 day)
```

The sets are the firewall's: create them with `flags timeout` (without it
elements never expire; meow warns once), and as plain address sets (no
`interval`):

```
set meow_proxy4 { type ipv4_addr; flags timeout; }
# in the interception chain, before marking/redirecting:
ip daddr != @meow_proxy4 ip daddr != @proxy_ip_lists return
```

The element is added before the answer leaves meow, so the client cannot
connect ahead of it. An element lives `max(timeout, answer TTL)`; re-adding
refreshes it (Linux 6.x). Keep `timeout` above the longest TTL any cache
between meow and the clients may serve.

## What the verdict sees

A DNS answer has a domain and an address, nothing else. Each rule is judged
on those alone, scanning in order:

| Rule | Judged |
|---|---|
| DOMAIN*, GEOSITE, GEOIP, IP-CIDR, IP-SUFFIX, IP-ASN, RULE-SET (not `src`), MATCH | exactly |
| AND / OR / NOT | from their parts |
| a rule that also needs port, network, source, process… and a destination part matched (`AND,((NETWORK,UDP),(RULE-SET,x))`) | added, if its target is not DIRECT |
| a rule with no destination part (`AND,((NETWORK,UDP),(DST-PORT,443)),REJECT`) | skipped: no address set can express it — apply it by port in the firewall |

The first exact match decides. Groups count as "through meow" even when they
currently select DIRECT, which errs on the safe side. Classical rule-sets are
matched on domain and address only. Fake-IP answers are skipped (intercept
the fake range as a whole).

Caveats: elements stay after a rule change until they expire (flush the set
on reload if that matters), and clients that bypass meow's DNS (DoH, DoT,
hard-coded addresses) are not covered — block them in the firewall.
