# meow-cli

`meow-cli` controls a running meow from a shell or a script. It talks to the
[REST API](../reference/rest-api) that `external-controller` serves, so it
works with any meow that has the API on: a service, a desktop GUI's core, a
router. It starts and stops nothing.

The desktop release archives (Windows, macOS, and Linux glibc and musl on x86_64
and aarch64) ship it beside `meow`, with its [agent skill](#agent-skill) in
`skills/meow-cli/`. From a checkout:

```bash
cargo build --release -p meow-cli
./target/release/meow-cli --help
```

## Connecting

On the machine meow runs on, as the user it runs as, meow-cli needs no
options:

```bash
meow-cli status
```

Once its `external-controller` is up, meow writes the address a local client
dials, the API secret and its config path to a file only that user can
read, and removes it when it exits. meow-cli reads it, so it also finds a
meow that a desktop GUI started with the secret and the address on meow's
command line, or on a random port (`external-controller: 127.0.0.1:0`).

meow-cli looks for the controller in this order:

1. `--controller host:port` (`-c`), or `MEOW_CONTROLLER`
2. `external-controller` in the config named by `--config` (`-f`), or `MEOW_CONFIG`
3. the meow running as this user, from its file
4. `127.0.0.1:9090`

When several meows run as this user, meow-cli lists them and asks for
`--controller`. The API secret comes from `--secret-stdin` (the first line
of standard input), else `MEOW_SECRET`, else the file of the meow that
bound exactly that address (`localhost:PORT` names one on the loopback),
else `secret` in the `--config` file. There is no `--secret` flag,
so the secret never lands in shell history or the process list.

```bash
meow-cli -f /etc/meow/config.yaml status
meow-cli -c 192.168.1.1:9090 status    # another host: MEOW_SECRET or --secret-stdin
```

`external-controller: :9090` and `0.0.0.0:9090` reach the controller on the
loopback. The controller serves plain HTTP only, so meow-cli refuses an
`https://` address.

### Where the file lives

| meow runs as | Directory |
| --- | --- |
| root (Linux, macOS) | `/var/run/meow/controllers` |
| a user, Linux | `~/.cache/meow/controllers` |
| a user, macOS | `~/Library/Caches/meow/controllers` |
| a user, Windows | `%LOCALAPPDATA%\meow\controllers` |

Each running meow has a `<pid>.json` there, mode 0600 in a 0700 directory.
meow holds a lock on it while it runs; a file left by a meow that was
killed is not locked, and the next meow or meow-cli to look removes it.
`MEOW_RUNTIME_DIR` replaces the directory, for meow and meow-cli alike;
point it only at a directory no other user can write to. On unix meow-cli
skips files another user owns, but on Windows it cannot tell who wrote one.

A meow running as root, or as a Windows service, publishes for that account
only: run `sudo meow-cli`, or pass `--controller` and `MEOW_SECRET`. The
systemd unit `meow install` writes has `RuntimeDirectory=meow`, as its
`ProtectSystem=strict` leaves the rest of `/run` read-only; reinstall an
older unit for meow to publish there.

## Commands

| Command | What it does |
| --- | --- |
| `status` | Version, mode, log level, TUN, ports, connection and traffic totals |
| `mode [rule\|global\|direct]` | Show the routing mode, or switch it |
| `log-level [LEVEL]` | Show the log level, or change it |
| `tun [on\|off]` | Show whether the TUN inbound runs, or turn it on or off |
| `group list` / `show G` | Groups with the member each routes through; one group's members and delays |
| `group select G MEMBER` | Route a group through one member |
| `group unfix G` | Return a url-test or fallback group to its automatic choice |
| `group test G` | Delay-test every member of a group |
| `proxy list` / `show P` / `test P` | Proxies, provider members included; one proxy's delay history; a delay test |
| `rule list` | Rules in match order, with their index |
| `conn list` / `show ID` | Open connections with the rule and route; one connection with its notes |
| `conn close ID…` / `--all` | Close connections by id or unique id prefix, or all of them |
| `dns query NAME [-t TYPE]` | Resolve through meow's resolver |
| `dns cache` / `flush` / `flush-fakeip` | The DNS cache, and the flushes |
| `provider list` / `update NAME` / `check NAME` | Proxy and rule providers, with subscription usage |
| `subscription list` / `update NAME` | Config subscriptions |
| `logbook [clear]` | The logbook, meow's persistent record of notable events: reloads, update failures, listener and network events |
| `log [--level L] [--count N]` | Follow the log |
| `traffic [--count N]` | Follow upload and download rates |
| `stats` | Bytes each proxy carried since meow started |
| `listeners` | Configured named listeners |
| `reload [PATH] [--force]` | Load a config file: by default the `--config` one, else the one meow loaded |
| `skill` | Print the agent skill, see below |

`--filter` narrows `proxy list`, `rule list` and `conn list` to entries that
contain a word, ignoring case. `meow-cli <command> --help` lists every option.

```bash
meow-cli group select "Proxy" "HK 01"
meow-cli conn list --filter youtube
meow-cli logbook --level warning --limit 20
meow-cli log --level warning --count 50
```

What a change does:

- `group select` on a `select` group switches it, and meow keeps the choice
  across restarts. On a `url-test` group it pins the member until
  `group unfix`. On a `fallback` group the pin holds while the member is up:
  meow drops it once it sees the member down. `group test` on either clears
  the pin, as in mihomo.
- `mode`, `log-level` and `tun` change the running meow, not the config
  file. meow keeps them in its in-memory copy of the config, so whatever
  saves that copy writes them into the file: a subscription update, by hand
  or on its timer, or a GUI saving the config. A `reload` returns
  `log-level` and `tun` to the file's values, and `mode` when the file sets
  `mode:`.
- `reload` sends the file's contents, so meow need not be able to read the
  path (another host, another user). It closes every open connection. meow
  refuses a file that does not parse; otherwise it skips broken proxies,
  groups and rules with a warning and applies the rest, unless the config
  sets `strict: true`. `--force` also applies a config whose strict checks,
  TUN, listeners or DNS fail.
- `provider check` runs the provider's `health-check:` and refuses a
  provider without one.
- `subscription list` shows only the scheme and host of each URL: the rest
  usually carries an access token.

## Scripting

`--json` prints what the API answered instead of the text tables, for `jq`
and scripts. `log` and `traffic` print one JSON object per line.

```bash
meow-cli --json group show Auto | jq -r .now
meow-cli traffic --json --count 1 | jq .down
```

meow-cli exits 0 on success and 1 on any failure, with the reason on
standard error. `proxy test` fails when the proxy does, so it works as a
check:

```bash
meow-cli proxy test "HK 01" --probe-timeout 3000 || echo "HK 01 is down"
```

## Agent skill

meow-cli comes with an [Agent Skills](https://agentskills.io) skill that
teaches a coding agent to use it: which commands only read, which change
routing and need the user's yes first, and how to keep the API secret out of
the conversation. The desktop archives carry it as `skills/meow-cli/`; copy
that folder into the agent's skills directory. `meow-cli skill` prints its
`SKILL.md`, for a meow-cli built or installed another way. For Claude Code:

```bash
mkdir -p ~/.claude/skills/meow-cli
meow-cli skill > ~/.claude/skills/meow-cli/SKILL.md
```

The skill matches the meow-cli that printed it, so print it again after an
upgrade.
