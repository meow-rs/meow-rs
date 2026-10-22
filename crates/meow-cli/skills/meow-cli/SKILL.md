---
name: meow-cli
description: Inspect and control a running meow (meow-rs, the Rust mihomo / Clash Meta kernel) from the shell with meow-cli. Use when the user asks why traffic goes where it goes, which node a proxy group uses, to switch a group's node or the routing mode, to look at or close connections, to test node delays, to query or flush DNS, to update providers or subscriptions, to read the logbook or follow the log, or to reload the config.
license: MIT
compatibility: Needs the meow-cli binary on PATH and a running meow with external-controller set.
---

# meow-cli

`meow-cli` talks to a running meow over its REST API (the `external-controller`).
It never starts or stops meow; every command is one or a few HTTP requests.
`meow-cli --help` and `meow-cli <command> --help` list every option.

## Connecting

meow serves the API only when its config sets `external-controller`. Once the
API is up, meow writes its address and secret to a file that only the user
meow runs as can read. On that machine, as that user, meow-cli needs no
options, whoever started meow: a service, a terminal, or a desktop GUI that
passed the secret on meow's command line.

meow-cli finds the controller in this order:

1. `--controller host:port` or `MEOW_CONTROLLER`
2. `external-controller` in the config given with `--config FILE` or `MEOW_CONFIG`
3. the meow running as this user, from its file
4. `127.0.0.1:9090`

The API secret comes from `--secret-stdin`, else `MEOW_SECRET`, else the file
of the meow at that address, else `secret` in the `--config` file.

```bash
meow-cli status                                 # the meow running as this user
meow-cli --config /etc/meow/config.yaml status
meow-cli --controller 192.168.1.1:9090 status   # a meow on another host
printf '%s\n' "$SECRET_FROM_A_VAULT" | meow-cli --secret-stdin status
```

Rules for the secret:

- Never print, echo, log or paste the secret, and never put it on a command
  line: there is no `--secret` flag on purpose.
- Do not open the config file or meow's controller file to show them to the
  user; they hold the secret, and the config holds node passwords. Let
  meow-cli read them.
- A `401` means the secret is missing or wrong. Ask the user how to supply it.

When several meows run as this user, meow-cli lists them and asks for
`--controller`; ask the user which one they mean. A meow running as root (a
system service, or one started with sudo for TUN) or as another user writes
its file for that user only: meow-cli then has to run as that user too, such
as `sudo meow-cli status`. Ask before using sudo.

If meow-cli cannot connect, meow is not running, or it runs without
`external-controller`, or on another address. Say so; do not start meow
yourself unless the user asks.

## Reading state

These commands change nothing; run them freely.

```bash
meow-cli status                      # version, mode, log level, TUN, ports, traffic totals
meow-cli mode                        # without an argument these three only read
meow-cli log-level
meow-cli tun
meow-cli group list                  # every group and the member it routes through
meow-cli group show "Proxy"       # one group's members with their last delay
meow-cli proxy list                  # every proxy, provider members too
meow-cli proxy list --filter HK
meow-cli proxy show "HK 01"          # type, UDP, delay history
meow-cli rule list --filter google   # rules in match order, with their index
meow-cli conn list                   # open connections: rule, destination, route
meow-cli conn list --filter youtube
meow-cli conn show 1a2b3c4d          # one connection with its notes; an id prefix works
meow-cli dns query example.com
meow-cli dns query example.com --type AAAA
meow-cli dns cache --search example --limit 20
meow-cli provider list               # proxy and rule providers, usage and expiry
meow-cli subscription list
meow-cli logbook                     # notable engine events, newest first
meow-cli logbook --level warning --limit 20
meow-cli logbook --kind config       # config.reload, config.change
meow-cli stats                       # bytes each proxy carried since meow started
meow-cli listeners
meow-cli log --level warning --count 50   # follow the log; --count makes it stop
meow-cli traffic --count 5                # one sample per second
```

Add `--json` to any command to get what the API answered, for parsing:

```bash
meow-cli --json group show "Proxy"
meow-cli conn list --json
meow-cli proxy list --json --filter JP
```

Text output puts names last, so names with CJK or emoji do not break the
columns. In `conn list` the route reads from the rule's target to the node that
dials: `Proxy > Auto > HK 01`. `delay` shows `-` before a first successful
test and `down` for a node that failed its last one.

### Answering "why does this go there?"

1. `meow-cli conn list --filter <host>` shows the rule that matched and the
   route each connection took.
2. `meow-cli conn show <id>` adds the connection's notes when the config sets
   `connection-notes: true`: DNS answers, the rule decision, each dial hop.
3. `meow-cli rule list --filter <word>` finds the rule; its index is its place
   in match order.
4. `meow-cli group show <group>` shows which member the group uses now.

### Answering "is something broken?"

`meow-cli logbook` lists notable events, newest first: reloads, provider and
subscription updates, listener starts, network interface changes and
dialer-proxy chain changes, each with how often it repeated. `--level warning`
keeps only the failures. The logbook survives restarts, unlike
`meow-cli log`.

```bash
meow-cli --timeout 5 status          # is meow up and answering at all?
meow-cli logbook --level warning     # what failed, newest first
meow-cli logbook --subject airport   # one provider, group or listener
meow-cli logbook --before 812        # older entries; a full page prints this line
```

## Changing state

These change how meow routes or what it keeps. Tell the user what you are
about to change and get a yes first, unless they asked for exactly that
change.

```bash
meow-cli mode global                 # rule | global | direct
meow-cli group select "Proxy" "HK 01"
meow-cli group unfix Auto            # url-test / fallback back to automatic
meow-cli group test Auto             # delay-test every member
meow-cli group test Auto --url https://cp.cloudflare.com --probe-timeout 3000
meow-cli proxy test "HK 01"
meow-cli proxy test "HK 01" --url https://cp.cloudflare.com --probe-timeout 3000
meow-cli conn close 1a2b3c4d
meow-cli conn close --all
meow-cli dns flush
meow-cli dns flush-fakeip
meow-cli provider update airport
meow-cli provider update reject-list --kind rule
meow-cli provider check airport      # health-check a provider's nodes
meow-cli subscription update airport
meow-cli reload                      # the --config file, else the one meow loaded
meow-cli reload /etc/meow/config.yaml
meow-cli reload --force              # only when the user asks for it, see below
meow-cli log-level debug
meow-cli tun on
meow-cli logbook clear
```

What to know before changing things:

- `group select` on a `select` group switches it and meow remembers the pick
  across restarts. On a `url-test` group it pins that member: the group stops
  choosing on its own until `group unfix`, and a pinned member that goes down
  is routed around but stays pinned. On a `fallback` group the pin holds only
  while the member is up; meow drops it once it sees the member down.
- `group test` on a `url-test` or `fallback` group clears its pin first, as
  mihomo does. To measure without unpinning, test members one by one with
  `proxy test`.
- `select` groups have nothing to unfix; `load-balance` and `relay` groups
  cannot be selected.
- `mode`, `log-level` and `tun` change the running meow, not the config file.
  meow keeps them in its in-memory copy of the config, though, and whatever
  saves that copy writes them into the file: a subscription update (by hand
  or on its timer), or a GUI saving the config. Until then a restart returns
  to the file's values. `reload` returns `log-level` and `tun` to the file's
  values, and `mode` only when the file sets `mode:`.
- `reload` sends the file's text to meow and closes every open connection,
  like `conn close --all`. meow refuses a file that does not parse. Otherwise
  it skips broken proxies, groups and rules with a warning and applies the
  rest, unless the config sets `strict: true`; check
  `meow-cli logbook --kind config` afterwards. `--force` also applies a config
  whose strict checks, TUN, listeners or DNS fail; use it only when the user
  wants that.
- `conn close --all` drops every connection, the user's current calls and
  downloads included. `dns flush-fakeip` breaks open fake-IP flows.
- Provider and subscription updates fetch over the network and can take a
  minute. `provider check` runs the provider's `health-check:`; a provider
  without one (or with it disabled) is refused, so test its nodes with
  `proxy test`.
- `logbook clear` deletes the record for good.
- Subscription URLs carry access tokens: `subscription list` shows only their
  host. Never ask for or print the full URL.

## Errors

meow-cli exits 0 on success and 1 on any failure, with the reason on stderr:

- `cannot reach meow's controller at …`: meow is down, or the address is wrong.
- `meow wants the API secret (401)`: see Connecting.
- `meow answered 400 …` / `404 …`: meow refused the request; the message says
  why (unknown group or member, a member that is not in the group, a config
  that does not parse).
- `proxy test` exits 1 when the node fails the test; `group test` lists
  failed members as `failed` and still exits 0.

## Installing this skill

The desktop release archives (Windows, macOS, and Linux glibc on x86_64 and
aarch64) carry this skill as `skills/meow-cli/`: copy that folder into the
agent's skills directory. `meow-cli skill` prints this file, for a meow-cli
installed another way:

```bash
mkdir -p ~/.claude/skills/meow-cli
meow-cli skill > ~/.claude/skills/meow-cli/SKILL.md
```
