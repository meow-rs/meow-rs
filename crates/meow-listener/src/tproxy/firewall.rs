use std::io;
use std::net::IpAddr;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use tracing::{info, warn};

// Needed by `writeln!` in the `build_*` functions which are compiled under
// `#[cfg(test)]` on every platform for unit testing.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use std::fmt::Write as _;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

/// Per-process sequence for managed firewall objects — a listener's
/// nftables table / pf anchor is named `meow_tproxy_{pid}_{seq}` /
/// `com.apple/com.meow.tproxy.{pid}.{seq}`, so two listeners (or two meow
/// processes) never share kernel state, teardown removes only what the
/// instance created, and a dead owner's leftovers are identifiable for
/// the startup sweep (issue #621).
#[cfg(any(target_os = "linux", target_os = "macos"))]
static INSTANCE_SEQ: AtomicU32 = AtomicU32::new(0);

/// Serializes reserve+sweep+create inside `PlatformGuard::setup`.
/// Without it, two listeners starting together can interleave
/// `fetch_add`/`sweep`/`nft -f` so that the earlier reserver's *delayed*
/// sweep sees — and deletes — the later sibling's just-created object:
/// its seq is ≥ the early reserver's, which the stale rule reads as a
/// prior-boot leftover (issue #621 review). Under the lock the
/// lock-holder's seq always exceeds every seq created this boot, so
/// `seq >= reserved` only matches pre-boot debris.
#[cfg(any(target_os = "linux", target_os = "macos"))]
static SETUP_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Live managed firewalls in this process. A second one warns: two
/// output-chain redirects for the same traffic can't both be satisfied —
/// which table/anchor wins is insertion order.
#[cfg(any(target_os = "linux", target_os = "macos"))]
static LIVE_MANAGED: AtomicUsize = AtomicUsize::new(0);

/// Whether `pid` names a live process — `kill(pid, 0)` succeeds, or fails
/// EPERM for a live pid owned by another user; ESRCH means the owner is
/// gone and any firewall state it left is stale.
#[cfg(any(target_os = "linux", target_os = "macos", all(test, unix)))]
fn pid_alive(pid: u32) -> bool {
    // pid 0 is not a real owner: `kill(0, 0)` targets our own process
    // group and always succeeds, so it must not count as "alive".
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    match unsafe { libc::kill(pid as i32, 0) } {
        0 => true,
        _ => io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
    }
}

/// Whether `pid` runs a copy of this binary — the second half of the
/// ownership check. `kill(pid, 0)` alone is fooled by pid reuse: a dead
/// meow's `meow_tproxy_<pid>_<seq>` survives forever if some unrelated
/// process took the pid (its stale redirect keeps black-holing traffic).
/// Comparing `/proc/<pid>/exe` (linux) / `proc_pidpath` (macOS) with our
/// own executable distinguishes "live meow sibling" (keep) from
/// "recycled foreign pid" (stale). Unverifiable → keep: never delete
/// what we can't reason about.
#[cfg(target_os = "linux")]
fn pid_is_meow(pid: u32) -> bool {
    match (
        std::fs::read_link(format!("/proc/{pid}/exe")),
        std::env::current_exe(),
    ) {
        (Ok(exe), Ok(own)) => exe == own,
        _ => true,
    }
}

/// macOS variant of the linux `/proc/<pid>/exe` check above.
#[cfg(target_os = "macos")]
fn pid_is_meow(pid: u32) -> bool {
    let mut buf = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return true;
    }
    use std::os::unix::ffi::OsStrExt;
    let exe = std::ffi::OsStr::from_bytes(&buf[..n as usize]);
    // proc_pidpath and current_exe may differ in symlink resolution —
    // canonicalize both. If EITHER side can't be resolved the identity is
    // unverifiable: keep (never delete what we can't reason about).
    let Ok(own) = std::env::current_exe() else {
        return true;
    };
    let (Ok(e), Ok(o)) = (std::fs::canonicalize(exe), std::fs::canonicalize(&own)) else {
        return true;
    };
    e == o
}

/// Other unixes: no procfs equivalent wired up — test builds only
/// (the classifiers compile under `all(test, unix)`), fall back to
/// "can't verify → keep".
#[cfg(all(test, unix, not(any(target_os = "linux", target_os = "macos"))))]
fn pid_is_meow(_pid: u32) -> bool {
    true
}

/// The owner pid and per-process sequence embedded in a managed name's
/// `<pid><sep><seq>` suffix (`_` for nftables `meow_tproxy_*`, `.` for
/// pf `com.meow.tproxy.*`). Both halves must be all digits — a plain
/// `u32::parse` would accept a leading `+`.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn managed_suffix(rest: &str, sep: char) -> Option<(u32, u32)> {
    let (pid, seq) = rest.split_once(sep)?;
    if pid.is_empty()
        || !pid.bytes().all(|b| b.is_ascii_digit())
        || seq.is_empty()
        || !seq.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some((pid.parse().ok()?, seq.parse().ok()?))
}

/// RAII guard that sets up firewall redirect rules on creation
/// and tears them down on drop.
pub struct FirewallGuard {
    inner: PlatformGuard,
    /// This instance counted itself in `LIVE_MANAGED` at setup.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    managed_live: bool,
}

impl FirewallGuard {
    /// Set up firewall rules to redirect local TCP traffic to the given port.
    ///
    /// Loop avoidance:
    /// - **Linux**: `meta mark` matching — DIRECT adapter sets SO_MARK on outbound sockets,
    ///   nftables skips packets with that mark. Plus IP bypass for upstream proxy servers.
    /// - **macOS**: `user` UID matching (pf has no mark support) + IP bypass.
    ///
    /// Each call manages a table/anchor unique to this listener instance
    /// (`meow_tproxy_{pid}_{seq}` / `com.apple/com.meow.tproxy.{pid}.{seq}`)
    /// and first sweeps leftovers whose owning pid is dead — an uncleaned
    /// output-chain redirect otherwise keeps black-holing traffic after a
    /// crash (issue #621).
    pub fn setup(
        listen_port: u16,
        routing_mark: Option<u32>,
        bypass_ips: &[IpAddr],
    ) -> io::Result<Self> {
        info!(
            "Setting up transparent proxy firewall rules (port={}, mark={:?}, bypass={})",
            listen_port,
            routing_mark,
            bypass_ips.len()
        );
        let inner = PlatformGuard::setup(listen_port, routing_mark, bypass_ips)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if LIVE_MANAGED.fetch_add(1, Ordering::Relaxed) > 0 {
            warn!(
                "multiple managed tproxy firewalls live in this process: each \
                 redirects the host's output chain, so which listener serves \
                 intercepted traffic is kernel insertion order — set \
                 `firewall: false` on all but one (issue #621)"
            );
        }
        Ok(FirewallGuard {
            inner,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            managed_live: true,
        })
    }

    /// Explicitly tear down the firewall rules.
    pub fn teardown(&mut self) -> io::Result<()> {
        let result = self.inner.teardown();
        // Decrement only after the attempt; note `inner.teardown`
        // reports `Ok` on non-zero nft/pfctl exits (it warns instead), so
        // this only keeps counting when the command couldn't even spawn.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if self.managed_live && result.is_ok() {
            self.managed_live = false;
            LIVE_MANAGED.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        if let Err(e) = self.teardown() {
            warn!("Failed to teardown firewall rules: {e}");
        }
    }
}

// ── macOS (pf) ──────────────────────────────────────────────────────────────
// pf has no packet mark support, so we use UID-based bypass.

#[cfg(target_os = "macos")]
struct PlatformGuard {
    anchor: String,
    torn_down: bool,
}

/// Build the pf anchor ruleset that the macOS code path feeds to `pfctl`.
///
/// Order matters, but NOT as first-match-wins: `pfctl` requires rules grouped
/// by category — options, normalization, queueing, **translation** (`rdr`),
/// then **filtering** (`pass`/`block`) — and rejects a file that interleaves
/// them ("Rules must be in order…"). So the `rdr` translation rule must come
/// first, followed by the `pass` filter bypasses. (Translation and filtering
/// are evaluated in separate passes regardless of file order, so the relative
/// position of `rdr` vs `pass` does not change matching — only validity.)
///
/// Extracted as a pure function so the macOS-specific syntax can be unit
/// tested without invoking `pfctl(8)`.
///
/// `ephemeral_first` is the low end of the client ephemeral port range
/// (`net.inet.ip.portrange.first`); see the `no rdr` exemption below.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn build_pf_ruleset(
    uid: u32,
    listen_port: u16,
    ephemeral_first: u16,
    bypass_ips: &[IpAddr],
) -> String {
    // Translation first: redirect lo0 TCP to the local tproxy listener.
    //
    // Every lo0 packet traverses pf twice (out, then in). Without an
    // exemption, the listener's own SYN-ACK — un-translated on the outbound
    // pass — re-enters lo0 inbound, matches the broad `rdr` as a *new*
    // connection, and is rewritten back into the listener: every intercepted
    // handshake wedges in SYN_SENT (issue #354). `rdr` rules cannot match TCP
    // flags, so the discriminator is the destination port: replies go to the
    // client's ephemeral source port, fresh SYNs to service ports. Exempting
    // ephemeral destination ports lets replies through; the trade-off is that
    // destinations listening on ephemeral-range ports bypass the proxy (fail
    // open) instead of wedging. Translation rules are first-match, so the
    // `no rdr` must precede the `rdr`.
    let mut rules =
        format!("no rdr on lo0 proto tcp from any to any port {ephemeral_first}:65535\n");
    let _ = writeln!(
        rules,
        "rdr pass on lo0 proto tcp from any to any -> 127.0.0.1 port {listen_port}"
    );
    // Then filtering bypasses (our own uid, loopback, upstream proxy servers).
    let _ = writeln!(
        rules,
        "pass out quick on lo0 proto tcp from any to any user {uid}"
    );
    rules.push_str("pass out quick on lo0 proto tcp from any to 127.0.0.0/8\n");
    for ip in bypass_ips {
        let _ = writeln!(rules, "pass out quick on lo0 proto tcp from any to {ip}");
    }
    rules
}

/// Low end of the kernel's ephemeral (local) port range, used by `connect()`
/// when picking source ports — replies to intercepted connections always
/// target a port at or above it. Falls back to the macOS default (49152) if
/// the sysctl is unreadable or out of range.
#[cfg(target_os = "macos")]
fn ephemeral_port_first() -> u16 {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    let ret = unsafe {
        libc::sysctlbyname(
            c"net.inet.ip.portrange.first".as_ptr(),
            std::ptr::from_mut(&mut value).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret == 0 && (1..=65535).contains(&value) {
        value as u16
    } else {
        49152
    }
}

/// Anchor path prefix — children of `com.apple/` get evaluated by the
/// default `/etc/pf.conf`'s `rdr-anchor "com.apple/*"`.
#[cfg(any(target_os = "macos", test))]
const PF_ANCHOR_PREFIX: &str = "com.meow.tproxy";

/// Whether `rel` (an anchor name relative to `com.apple/`) is a
/// meow-managed anchor whose owner is gone: the legacy shared anchor
/// `com.meow.tproxy` (pre-#621 naming), `com.meow.tproxy.<pid>.<seq>`
/// whose pid is dead or was recycled by a non-meow process, or an
/// own-pid name with `seq >= reserved_seq` — a table of OUR pid that
/// this boot never created can only be a prior process's leftover under
/// a recycled pid (pid reuse to self would otherwise collide with the
/// upcoming `add`, failing setup outright).
#[cfg(any(target_os = "macos", all(test, unix)))]
fn stale_anchor(rel: &str, own_pid: u32, reserved_seq: u32) -> bool {
    if rel == PF_ANCHOR_PREFIX {
        return true;
    }
    let Some(rest) = rel.strip_prefix("com.meow.tproxy.") else {
        return false;
    };
    match managed_suffix(rest, '.') {
        Some((pid, seq)) if pid == own_pid => seq >= reserved_seq,
        Some((pid, _)) => !pid_alive(pid) || !pid_is_meow(pid),
        None => false,
    }
}

/// Flush pf anchors left behind by dead meow processes — a stale `rdr`
/// under `com.apple/*` keeps redirecting host TCP to a dead listener
/// port. Best-effort: failures warn and continue (issue #621).
#[cfg(target_os = "macos")]
fn sweep_stale_anchors(reserved_seq: u32) {
    let own_pid = std::process::id();
    let Ok(out) = Command::new("pfctl")
        .args(["-a", "com.apple", "-sAnchors"])
        .output()
    else {
        return;
    };
    if !out.status.success() {
        return;
    }
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let name = line.trim();
        if name.is_empty() {
            continue;
        }
        // Output may be relative to `com.apple/` or absolute — normalize.
        let rel = name.strip_prefix("com.apple/").unwrap_or(name);
        if !stale_anchor(rel, own_pid, reserved_seq) {
            continue;
        }
        let full = format!("com.apple/{rel}");
        match Command::new("pfctl")
            .args(["-a", full.as_str(), "-F", "all"])
            .output()
        {
            // warn for the legacy shared anchor: under a rolling restart
            // it may belong to a still-running old-version process — the
            // sweep then interrupts that instance's redirect until it
            // exits (accepted: the alternative is leaking it forever).
            Ok(o) if o.status.success() && rel == PF_ANCHOR_PREFIX => {
                warn!("swept legacy shared pf anchor '{full}'");
            }
            Ok(o) if o.status.success() => info!("swept stale pf anchor '{full}'"),
            Ok(o) => warn!(
                "failed to sweep stale pf anchor '{full}': {}",
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => warn!("failed to sweep stale pf anchor '{full}': {e}"),
        }
    }
}

#[cfg(target_os = "macos")]
impl PlatformGuard {
    fn setup(
        listen_port: u16,
        _routing_mark: Option<u32>,
        bypass_ips: &[IpAddr],
    ) -> io::Result<Self> {
        // Nest under `com.apple/` so the default `/etc/pf.conf`'s
        // `rdr-anchor "com.apple/*"` actually evaluates our rules. A sibling
        // anchor (e.g. `com.meow.tproxy`) loads fine but is never referenced by
        // the active ruleset, so its `rdr` never takes effect (verified: a
        // sibling anchor does not intercept; a `com.apple/*` child does).
        // The `.{pid}.{seq}` suffix keeps every listener instance's anchor
        // distinct — teardown flushes only its own (issue #621).
        let _setup = SETUP_LOCK.lock();
        let seq = INSTANCE_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let anchor = format!("com.apple/{PF_ANCHOR_PREFIX}.{pid}.{seq}");
        let uid = unsafe { libc::getuid() };

        sweep_stale_anchors(seq);

        let rules = build_pf_ruleset(uid, listen_port, ephemeral_port_first(), bypass_ips);

        // `create_new` so a pre-planted symlink in /tmp can't redirect a
        // root-privileged write (the name is predictable). A stale
        // same-name file (dead process that had our pid) is removed first.
        let tmp_path = format!("/tmp/meow_tproxy_{pid}_{seq}.conf");
        let _ = std::fs::remove_file(&tmp_path);
        let wrote = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, rules.as_bytes()));
        if let Err(e) = wrote {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }

        // Collect the spawn result before `?` — a failed spawn must still
        // drop the temp conf rather than leak it in /tmp.
        let output = Command::new("pfctl")
            .args(["-a", &anchor, "-f", &tmp_path])
            .output();

        let _ = std::fs::remove_file(&tmp_path);

        let output = output?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::other(format!(
                "pfctl load anchor failed: {stderr}"
            )));
        }

        let _ = Command::new("pfctl").arg("-e").output();

        info!(
            "pf anchor '{}' loaded (uid={}, {} bypass IPs)",
            anchor,
            uid,
            bypass_ips.len()
        );
        Ok(PlatformGuard {
            anchor,
            torn_down: false,
        })
    }

    fn teardown(&mut self) -> io::Result<()> {
        if self.torn_down {
            return Ok(());
        }

        let output = Command::new("pfctl")
            .args(["-a", &self.anchor, "-F", "all"])
            .output()?;

        if output.status.success() {
            self.torn_down = true;
            info!("pf anchor '{anchor}' flushed", anchor = self.anchor);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("pfctl flush anchor failed: {stderr}");
            // Leave torn_down unset so a later Drop retries the flush —
            // an anchor that survives teardown keeps redirecting the
            // host's traffic for the rest of this process's life.
        }
        Ok(())
    }
}

// ── Linux (nftables) ────────────────────────────────────────────────────────
// Uses SO_MARK matching — DIRECT adapter marks its outbound sockets,
// nftables skips packets carrying that mark.

#[cfg(target_os = "linux")]
struct PlatformGuard {
    table_name: String,
    torn_down: bool,
}

/// nftables table prefix — managed tables are `meow_tproxy_{pid}_{seq}`.
#[cfg(any(target_os = "linux", test))]
const NFT_TABLE_PREFIX: &str = "meow_tproxy";

/// Whether `name` is a meow-managed nft table whose owner is gone: the
/// legacy shared table `meow_tproxy` (pre-#621 naming),
/// `meow_tproxy_<pid>_<seq>` whose pid is dead or was recycled by a
/// non-meow process, or an own-pid name with `seq >= reserved_seq` — a
/// table of OUR pid this boot never created can only be a prior
/// process's leftover under a recycled pid, and would otherwise collide
/// with the upcoming `add` and fail setup outright (issue #621 review).
/// Tables owned by live meow processes — including a sibling listener in
/// this one — are kept.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn stale_table(name: &str, own_pid: u32, reserved_seq: u32) -> bool {
    if name == NFT_TABLE_PREFIX {
        return true;
    }
    let Some(rest) = name.strip_prefix("meow_tproxy_") else {
        return false;
    };
    match managed_suffix(rest, '_') {
        Some((pid, seq)) if pid == own_pid => seq >= reserved_seq,
        Some((pid, _)) => !pid_alive(pid) || !pid_is_meow(pid),
        None => false,
    }
}

/// Delete managed tables left behind by dead meow processes — an
/// uncleaned output-chain redirect keeps black-holing host TCP.
/// `reserved_seq` is the just-allocated sequence of the instance about
/// to be created: own-pid names at or above it predate this boot and
/// are stale by definition. Best-effort: listing/deletion failures warn
/// and continue; setup proceeds regardless (issue #621).
#[cfg(target_os = "linux")]
fn sweep_stale_tables(reserved_seq: u32) {
    let own_pid = std::process::id();
    let Ok(out) = Command::new("nft").args(["list", "tables"]).output() else {
        return;
    };
    if !out.status.success() {
        return;
    }
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some(name) = line.strip_prefix("table inet ").map(str::trim) else {
            continue;
        };
        if !stale_table(name, own_pid, reserved_seq) {
            continue;
        }
        match Command::new("nft")
            .args(["delete", "table", "inet", name])
            .output()
        {
            // warn for the legacy shared table: under a rolling restart
            // it may belong to a still-running old-version process — the
            // sweep interrupts that instance's redirect until it exits
            // (accepted: the alternative is leaking it forever).
            Ok(o) if o.status.success() && name == NFT_TABLE_PREFIX => {
                warn!("swept legacy shared nftables table '{name}'");
            }
            Ok(o) if o.status.success() => {
                // A swept name whose embedded pid is still alive was the
                // reused-pid/replaced-binary case: if that pid actually
                // runs a live meow (different exe path), its redirect is
                // now open — surface it louder than routine debris.
                let swept_live_pid = name
                    .strip_prefix("meow_tproxy_")
                    .and_then(|rest| managed_suffix(rest, '_'))
                    .is_some_and(|(pid, _)| pid_alive(pid));
                if swept_live_pid {
                    warn!(
                        "swept nftables table '{name}' owned by a live pid \
                         (exe mismatch: pid reuse or replaced binary — that \
                         instance's redirect is now open)"
                    );
                } else {
                    info!("swept stale nftables table '{name}'");
                }
            }
            Ok(o) => warn!(
                "failed to sweep stale nftables table '{name}': {}",
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => warn!("failed to sweep stale nftables table '{name}': {e}"),
        }
    }
}

/// Build the nftables ruleset that the Linux code path feeds to `nft -f -`.
///
/// Order of chain rules (top-to-bottom, first match wins):
///   1. Skip marked packets — `meta mark` matches the SO_MARK that
///      `DirectAdapter` puts on its own outbound sockets, breaking the
///      "DIRECT redirects back into the tunnel" loop.
///   2. Loopback bypass (`127.0.0.0/8` and `::1`).
///   3. Per-IP bypass for upstream proxy servers (so meow-rs can reach them).
///   4. Catch-all redirect to `:{listen_port}`.
///
/// Extracted as a pure function so the syntactic shape of the ruleset can be
/// unit tested without invoking `nft(8)` — and a regression that drops, say,
/// the mark-bypass rule (which would silently relay DIRECT traffic through
/// the tunnel) gets caught in CI.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn build_nft_ruleset(
    table: &str,
    listen_port: u16,
    routing_mark: Option<u32>,
    bypass_ips: &[IpAddr],
) -> String {
    let mut bypass_rules = String::new();
    for ip in bypass_ips {
        // In an `inet` table the L3 protocol must be selected explicitly:
        // `ip daddr` only parses IPv4 literals and `ip6 daddr` only IPv6.
        // Emitting `ip daddr <v6>` is a parse error that makes `nft -f -`
        // reject the *entire* ruleset, so the tproxy listener fails to start
        // whenever a proxy host resolves to an IPv6 address.
        match ip {
            IpAddr::V4(v4) => {
                writeln!(bypass_rules, "    ip daddr {v4} accept").expect("write to String");
            }
            IpAddr::V6(v6) => {
                writeln!(bypass_rules, "    ip6 daddr {v6} accept").expect("write to String");
            }
        }
    }
    let mark_rule = match routing_mark {
        Some(mark) => format!("    meta mark 0x{mark:x} accept\n"),
        None => String::new(),
    };
    format!(
        concat!(
            "table inet {table} {{\n",
            "  chain output {{\n",
            "    type nat hook output priority -100; policy accept;\n",
            "{mark_rule}",
            "    ip daddr 127.0.0.0/8 accept\n",
            "    ip6 daddr ::1 accept\n",
            "{bypass}",
            "    tcp dport 1-65535 redirect to :{port}\n",
            "  }}\n",
            "}}\n",
        ),
        table = table,
        mark_rule = mark_rule,
        bypass = bypass_rules,
        port = listen_port,
    )
}

#[cfg(target_os = "linux")]
impl PlatformGuard {
    fn setup(
        listen_port: u16,
        routing_mark: Option<u32>,
        bypass_ips: &[IpAddr],
    ) -> io::Result<Self> {
        // Per-instance table name — two listeners or processes never share
        // kernel state, and teardown deletes only this table (issue #621).
        let _setup = SETUP_LOCK.lock();
        let seq = INSTANCE_SEQ.fetch_add(1, Ordering::Relaxed);
        let table_name = format!("{NFT_TABLE_PREFIX}_{}_{}", std::process::id(), seq);
        sweep_stale_tables(seq);
        let ruleset = build_nft_ruleset(&table_name, listen_port, routing_mark, bypass_ips);

        let output = Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(ruleset.as_bytes())?;
                child.wait_with_output()
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::other(format!("nft load rules failed: {stderr}")));
        }

        info!(
            "nftables table '{}' created (mark={:?}, {} bypass IPs)",
            table_name,
            routing_mark,
            bypass_ips.len()
        );
        Ok(PlatformGuard {
            table_name,
            torn_down: false,
        })
    }

    fn teardown(&mut self) -> io::Result<()> {
        if self.torn_down {
            return Ok(());
        }

        let output = Command::new("nft")
            .args(["delete", "table", "inet", &self.table_name])
            .output()?;

        if output.status.success() {
            self.torn_down = true;
            info!("nftables table '{name}' deleted", name = self.table_name);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("nft delete table failed: {stderr}");
            // Leave torn_down unset so a later Drop retries the delete —
            // an orphaned managed table keeps redirecting host TCP for
            // the rest of this process's life, and the startup sweep
            // won't touch it while its owner (us) is alive.
        }
        Ok(())
    }
}

// ── Unsupported platforms ───────────────────────────────────────────────────

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
struct PlatformGuard;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl PlatformGuard {
    fn setup(
        _listen_port: u16,
        _routing_mark: Option<u32>,
        _bypass_ips: &[IpAddr],
    ) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "transparent proxy firewall not supported on this platform",
        ))
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "matches PlatformGuard API on supported platforms"
    )]
    fn teardown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ─── nftables ───────────────────────────────────────────────────────────

    #[test]
    fn nft_ruleset_contains_expected_skeleton() {
        let rs = build_nft_ruleset("meow_tproxy", 7893, None, &[]);
        assert!(rs.contains("table inet meow_tproxy {"));
        assert!(rs.contains("chain output {"));
        assert!(rs.contains("type nat hook output priority -100; policy accept;"));
        assert!(rs.contains("tcp dport 1-65535 redirect to :7893"));
        // Loopback bypass is non-negotiable — a regression here would
        // recurse the redirect into infinity.
        assert!(rs.contains("ip daddr 127.0.0.0/8 accept"));
        assert!(rs.contains("ip6 daddr ::1 accept"));
    }

    #[test]
    fn nft_routing_mark_emits_meta_mark_rule_in_hex() {
        let rs = build_nft_ruleset("t", 1234, Some(0x42), &[]);
        assert!(
            rs.contains("meta mark 0x42 accept"),
            "mark bypass missing or wrong format:\n{rs}"
        );
    }

    #[test]
    fn nft_no_routing_mark_omits_mark_rule() {
        let rs = build_nft_ruleset("t", 1234, None, &[]);
        assert!(
            !rs.contains("meta mark"),
            "mark rule must not appear when routing_mark is None:\n{rs}"
        );
    }

    #[test]
    fn nft_mark_bypass_appears_before_redirect_catch_all() {
        // pf is first-match-wins; nftables `accept` short-circuits the chain.
        // The mark-bypass must appear ABOVE the catch-all redirect, otherwise
        // every DIRECT-marked packet gets redirected into the tunnel.
        let rs = build_nft_ruleset("t", 7893, Some(0xabcd), &[]);
        let mark_pos = rs.find("meta mark 0xabcd accept").unwrap();
        let redirect_pos = rs.find("tcp dport 1-65535 redirect").unwrap();
        assert!(
            mark_pos < redirect_pos,
            "mark bypass must precede redirect:\n{rs}"
        );
    }

    #[test]
    fn nft_bypass_ips_are_emitted_for_v4_and_v6() {
        let bypass = [
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ];
        let rs = build_nft_ruleset("t", 1, None, &bypass);
        assert!(rs.contains("ip daddr 1.2.3.4 accept"));
        // IPv6 bypass IPs must use `ip6 daddr` — `ip daddr <v6>` is a parse
        // error that aborts the whole `nft -f -` load.
        assert!(rs.contains("ip6 daddr 2001:db8::1 accept"));
        assert!(
            !rs.contains("ip daddr 2001:db8::1"),
            "IPv6 address must not follow `ip daddr`:\n{rs}"
        );
    }

    // ─── pf (macOS) ─────────────────────────────────────────────────────────

    #[test]
    fn pf_ruleset_contains_uid_bypass_and_redirect() {
        let rs = build_pf_ruleset(501, 7893, 49152, &[]);
        assert!(
            rs.contains("pass out quick on lo0 proto tcp from any to any user 501"),
            "UID bypass missing:\n{rs}"
        );
        assert!(rs.contains("pass out quick on lo0 proto tcp from any to 127.0.0.0/8"));
        assert!(rs.contains("rdr pass on lo0 proto tcp from any to any -> 127.0.0.1 port 7893"));
    }

    #[test]
    fn pf_rdr_precedes_filter_rules() {
        // pfctl rejects a ruleset that places filtering (`pass`) before
        // translation (`rdr`) — "Rules must be in order: …, translation,
        // filtering". The `rdr` must therefore come first, or the anchor fails
        // to load and the tproxy listener never starts (regression guard).
        let rs = build_pf_ruleset(501, 7893, 49152, &[]);
        let rdr_pos = rs.find("rdr pass").unwrap();
        let uid_pos = rs.find("user 501").unwrap();
        assert!(rdr_pos < uid_pos, "rdr must precede filter rules:\n{rs}");
    }

    #[test]
    fn pf_replies_to_ephemeral_ports_are_exempt_from_rdr() {
        // Issue #354: on lo0 every packet traverses pf twice, so without this
        // exemption the listener's own SYN-ACK (destined to the client's
        // ephemeral port) re-matches the broad `rdr` inbound and is redirected
        // back into the listener — every intercepted handshake wedges.
        let rs = build_pf_ruleset(501, 7893, 49152, &[]);
        assert!(
            rs.contains("no rdr on lo0 proto tcp from any to any port 49152:65535"),
            "ephemeral-port rdr exemption missing:\n{rs}"
        );
        // Translation rules are first-match: the exemption must precede the rdr.
        let no_rdr_pos = rs.find("no rdr").unwrap();
        let rdr_pos = rs.find("rdr pass").unwrap();
        assert!(no_rdr_pos < rdr_pos, "no rdr must precede rdr:\n{rs}");
    }

    #[test]
    fn pf_ephemeral_range_is_parameterized() {
        // The exemption must track the kernel's actual ephemeral range
        // (net.inet.ip.portrange.first), not a hardcoded default.
        let rs = build_pf_ruleset(501, 7893, 10000, &[]);
        assert!(rs.contains("no rdr on lo0 proto tcp from any to any port 10000:65535"));
    }

    #[test]
    fn pf_bypass_ips_are_emitted() {
        let bypass = [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        let rs = build_pf_ruleset(501, 7893, 49152, &bypass);
        assert!(rs.contains("pass out quick on lo0 proto tcp from any to 1.1.1.1"));
    }

    // ─── Per-instance naming + stale sweep (issue #621) ──────────────────────

    #[test]
    fn managed_suffix_parses_owner() {
        assert_eq!(managed_suffix("1234_0", '_'), Some((1234, 0)));
        assert_eq!(managed_suffix("42.7", '.'), Some((42, 7)));
        // Malformed suffixes aren't ours — never swept.
        assert_eq!(managed_suffix("1234", '_'), None);
        assert_eq!(managed_suffix("abc_0", '_'), None);
        assert_eq!(managed_suffix("1234_", '_'), None);
        assert_eq!(managed_suffix("1_2_3", '_'), None);
        assert_eq!(managed_suffix("", '_'), None);
        // A leading `+` parses under `u32::parse` but is not our shape.
        assert_eq!(managed_suffix("+5_0", '_'), None);
    }

    /// A pid no live process can hold — `kill(pid, 0)` → ESRCH.
    /// (`i32::MAX` is a valid pid number but exceeds every real pid_max.)
    #[cfg(unix)]
    const DEAD_PID: u32 = i32::MAX as u32;

    #[cfg(unix)]
    #[test]
    fn stale_table_classification() {
        let live = std::process::id();
        // Legacy shared table is always stale once per-instance naming lands.
        assert!(stale_table("meow_tproxy", live, 0));
        assert!(stale_table(&format!("meow_tproxy_{DEAD_PID}_0"), live, 0));
        // pid 0 is never a real owner (`kill(0,0)` would probe our own
        // process group) — treated as stale.
        assert!(stale_table("meow_tproxy_0_0", live, 0));
        // Own-pid tables: seq >= the just-reserved one predates this boot
        // (a dead process recycled our pid) → stale; below it → a sibling
        // created earlier this boot → keep.
        assert!(stale_table(&format!("meow_tproxy_{live}_0"), live, 0));
        assert!(!stale_table(&format!("meow_tproxy_{live}_0"), live, 1));
        assert!(!stale_table(&format!("meow_tproxy_{live}_0"), live, 7));
        // pid 1 is alive but is never a meow process — a `meow_tproxy_1_*`
        // name can only be foreign-planted or a pid-reuse leftover.
        #[cfg(target_os = "linux")]
        assert!(stale_table("meow_tproxy_1_0", live, 0));
        // Foreign tables are never swept.
        assert!(!stale_table("meow_ext_fw", live, 0));
        assert!(!stale_table("meow_tproxyx_1_0", live, 0));
        assert!(!stale_table("meow_tproxy_noseq", live, 0));
    }

    #[cfg(unix)]
    #[test]
    fn stale_anchor_classification() {
        let live = std::process::id();
        assert!(stale_anchor("com.meow.tproxy", live, 0));
        assert!(stale_anchor(
            &format!("com.meow.tproxy.{DEAD_PID}.0"),
            live,
            0
        ));
        assert!(stale_anchor("com.meow.tproxy.0.0", live, 0));
        // Own-pid seq boundary — same rule as tables.
        assert!(stale_anchor(&format!("com.meow.tproxy.{live}.0"), live, 0));
        assert!(!stale_anchor(&format!("com.meow.tproxy.{live}.0"), live, 1));
        #[cfg(target_os = "macos")]
        assert!(stale_anchor("com.meow.tproxy.1.0", live, 0));
        assert!(!stale_anchor("com.apple.networking", live, 0));
        assert!(!stale_anchor("com.meow.tproxyx.1.0", live, 0));
    }
}
