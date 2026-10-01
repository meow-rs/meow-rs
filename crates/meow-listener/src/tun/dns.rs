//! OS DNS resolver configuration for the TUN inbound.
//!
//! When `dns-hijack` is active, the OS resolver must be pointed at a
//! DNS server that returns fake IPs.  On macOS/Linux this is the fake-IP
//! gateway (e.g. `198.18.0.1`) — queries enter the TUN device and are
//! answered by `dns-hijack`.  On Windows a local DNS server
//! (`tun/local_dns.rs`) is bound to `127.0.0.1:53` and `[::1]:53`, and
//! the system DNS is set to those loopback addresses.
//!
//! `DnsGuard` backs up the current resolver configuration at startup,
//! installs the DNS server addresses on all active adapters, and
//! restores the original configuration on drop.
//!
//! Individual failures are logged and skipped: a DNS configuration error
//! does not abort the TUN listener startup, and a recovery failure is
//! similarly non-fatal.

use std::net::IpAddr;
use tracing::{debug, warn};

/// RAII guard that restores original DNS settings on drop.
///
/// When created, it saves the current OS DNS state and replaces it with
/// the loopback DNS addresses on all active network interfaces. On drop,
/// the original configuration is restored. Failed operations are logged
/// at `warn!` level rather than panicking.
pub(super) struct DnsGuard {
    #[cfg(target_os = "windows")]
    backup: String,
    #[cfg(target_os = "macos")]
    backup: Vec<(String, Vec<IpAddr>)>,
    #[cfg(target_os = "linux")]
    backup: Option<linux::ResolvConfBackup>,
}

impl DnsGuard {
    /// Save current DNS settings and set all interfaces to `dns_addr`.
    /// Returns `None` on platforms without a supported backend, or when
    /// the backup fails.
    ///
    /// On Windows `dns_addr` is ignored — the system DNS is always set
    /// to `127.0.0.1` (IPv4) and `::1` (IPv6) so queries reach the
    /// local DNS server (`tun/local_dns.rs`).
    pub(super) fn setup(dns_addr: IpAddr) -> Option<Self> {
        #[cfg(target_os = "windows")]
        {
            let _ = dns_addr;
            match windows::backup() {
                Ok(backup) => {
                    if let Err(e) = windows::set_all() {
                        warn!("tun dns-guard: failed to set DNS: {e}");
                    }
                    windows::clear_dns_cache();
                    debug!("tun dns-guard: DNS set to 127.0.0.1 / ::1 (loopback)");
                    Some(Self { backup })
                }
                Err(e) => {
                    warn!("tun dns-guard: failed to back up DNS settings: {e}");
                    None
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            match macos::backup(dns_addr) {
                Ok(backup) => {
                    if let Err(e) = macos::set_all(dns_addr, &backup) {
                        warn!("tun dns-guard: failed to set DNS to {dns_addr}: {e}");
                    }
                    debug!(
                        "tun dns-guard: DNS set to {dns_addr} on {} network services",
                        backup.len()
                    );
                    Some(Self { backup })
                }
                Err(e) => {
                    warn!("tun dns-guard: failed to back up DNS settings: {e}");
                    None
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            match linux::backup_and_set(dns_addr) {
                Ok(backup) => {
                    debug!("tun dns-guard: DNS set to {dns_addr} in /etc/resolv.conf");
                    Some(Self {
                        backup: Some(backup),
                    })
                }
                Err(e) => {
                    warn!("tun dns-guard: failed to configure DNS: {e}");
                    None
                }
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            let _ = dns_addr;
            debug!("tun dns-guard: no DNS backend for this platform; skipping");
            None
        }
    }
}

// Restore runs synchronously in Drop — deliberately. `Tunnel::stop_tun`
// awaits the aborted task, so a config-reload disable→enable cannot start a
// new backup until this restore has finished; offloading to another thread
// would open that race, and the process-exit path must block anyway or the
// restore is lost. The Windows work is batched into two PowerShell
// invocations (reset-all + restore) plus a cache flush to keep the blocked
// interval short.
impl Drop for DnsGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            // Safety net: reset all adapters to DHCP first, so no
            // 127.0.0.1 or ::1 leftovers survive even if an adapter
            // wasn't captured in the backup.
            if let Err(e) = windows::reset_all_dns() {
                warn!("tun dns-guard: failed to reset all DNS to DHCP: {e}");
            }

            let backup_len = self.backup.len();
            if let Err(e) = windows::restore(&self.backup) {
                warn!(
                    "tun dns-guard: failed to restore DNS settings (backup {} bytes): {e}",
                    backup_len
                );
            } else {
                tracing::info!(
                    "tun dns-guard: DNS settings restored (backup {} bytes)",
                    backup_len
                );
            }
            windows::clear_dns_cache();
        }
        #[cfg(target_os = "macos")]
        {
            if let Err(e) = macos::restore(&self.backup) {
                warn!("tun dns-guard: failed to restore DNS settings: {e}");
            } else {
                debug!("tun dns-guard: DNS settings restored");
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(backup) = self.backup.take() {
                if let Err(e) = linux::restore(&backup) {
                    warn!("tun dns-guard: failed to restore /etc/resolv.conf: {e}");
                } else {
                    debug!("tun dns-guard: /etc/resolv.conf restored");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Windows backend — local DNS server on loopback
//
// Sets IPv4 DNS to 127.0.0.1 and IPv6 DNS to ::1 on all adapters.
// A local DNS server (tun/local_dns.rs) bound to these addresses
// answers queries using the same DnsServer::handle_query pipeline as
// the TUN dns-hijack path, returning fake IPs.
//
// This avoids all the problems with previous approaches:
// - No need to clear IPv6 DNS (WSL/Docker re-inject fec0:0:0:ffff::*)
// - No firewall rules (which didn't actually block the queries)
// - No ::1 loopback redirect without a listener (caused ECONNRESET)
// - Both IPv4 and IPv6 queries are handled directly
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod windows {
    use std::process::Command;

    const IPV6_SEPARATOR: &str = "---IPV6---";
    /// Firewall rule name from the previous (abandoned) approach.
    /// Cleaned up on startup to avoid leftover rules.
    const LEGACY_FW_RULE_NAME: &str = "meow-rs TUN IPv6 DNS Block";

    /// Back up the *statically configured* DNS on all adapters (both IPv4
    /// and IPv6), read from the registry `NameServer` values.
    ///
    /// `Get-DnsClientServerAddress` reports the *effective* servers with no
    /// DHCP/static distinction — restoring its output would statically pin a
    /// snapshot of DHCP-assigned values on adapters that should keep
    /// following DHCP. Only static entries need restoring; every other
    /// adapter is covered by the reset-to-DHCP pass in `DnsGuard::drop`.
    ///
    /// Returns a combined encoding:
    ///   IPv4 lines (one per adapter: `InterfaceAlias|server1,server2,...`)
    ///   `---IPV6---`
    ///   IPv6 lines (same format)
    pub(super) fn backup() -> std::io::Result<String> {
        let v4 = strip_own_entries(&backup_family("Tcpip")?, "127.0.0.1");
        let v6 = strip_own_entries(&backup_family("Tcpip6")?, "::1");
        Ok(format!("{v4}\n{IPV6_SEPARATOR}\n{v6}"))
    }

    /// Drop adapter lines whose server list is exactly the address meow
    /// itself installs (`127.0.0.1` / `::1`). After an unclean shutdown
    /// (crash, SIGKILL, power loss) the previous run's loopback setting is
    /// still in place; backing it up would make a later clean exit
    /// "restore" the broken state permanently. Dropped adapters fall back
    /// to the reset-to-DHCP safety net in `DnsGuard::drop`.
    fn strip_own_entries(section: &str, own: &str) -> String {
        let mut kept = Vec::new();
        for line in section.lines() {
            let is_own = line
                .split_once('|')
                .is_some_and(|(_, servers)| servers.trim() == own);
            if is_own {
                super::warn!(
                    "tun dns-guard: adapter '{}' still points at {own} (leftover from an \
                     unclean shutdown?) — excluding it from the backup, it will be reset \
                     to DHCP on exit",
                    line.split('|').next().unwrap_or(line).trim()
                );
            } else {
                kept.push(line);
            }
        }
        kept.join("\n")
    }

    /// One line per adapter with a non-empty static `NameServer` registry
    /// value under `SYSTEM\CurrentControlSet\Services\<service>\Parameters\
    /// Interfaces\<guid>` — `service` is `Tcpip` (IPv4) or `Tcpip6` (IPv6).
    ///
    /// A script that fails with a diagnostic (`check_ps_output`) is an
    /// error, not an empty backup: an empty backup would let setup hijack
    /// DNS anyway, and the drop-time reset to DHCP would then silently
    /// discard every static configuration.
    fn backup_family(service: &str) -> std::io::Result<String> {
        const TEMPLATE: &str = r#"Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object { $g = "$($_.InterfaceGuid)"; if ($g -and $g[0] -ne '{') { $g = '{' + $g + '}' }; $ns = (Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\SVCNAME\Parameters\Interfaces\" + $g) -Name NameServer -ErrorAction SilentlyContinue).NameServer; if ($ns) { $_.InterfaceAlias + '|' + ($ns -replace '[ ;]', ',') } }"#;
        let script = TEMPLATE.replace("SVCNAME", service);
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()?;
        check_ps_output(&output)?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Set IPv4 DNS to `127.0.0.1` and IPv6 DNS to `::1` on all adapters.
    ///
    /// `Set-DnsClientServerAddress` auto-detects the address family from
    /// the IP format, so `127.0.0.1` only touches IPv4 and `::1` only
    /// touches IPv6.
    pub(super) fn set_all() -> std::io::Result<()> {
        // Clean up any leftover firewall rule from the previous approach.
        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Remove-NetFirewallRule -DisplayName '{LEGACY_FW_RULE_NAME}' -ErrorAction SilentlyContinue"
                ),
            ])
            .output();

        // Step 1: set IPv4 DNS to 127.0.0.1 on all adapters that have DNS.
        set_dns_on_all("127.0.0.1", "IPv4")?;

        // Step 2: set IPv6 DNS to ::1 on all adapters that have DNS.
        set_dns_on_all("::1", "IPv6")?;

        Ok(())
    }

    fn set_dns_on_all(addr: &str, family: &str) -> std::io::Result<()> {
        let cmd = format!(
            r#"Get-DnsClientServerAddress -AddressFamily {family} -ErrorAction SilentlyContinue | Where-Object {{$_.ServerAddresses.Count -gt 0}} | ForEach-Object {{ Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ServerAddresses ('{addr}') -ErrorAction SilentlyContinue }}"#
        );
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if !stderr.is_empty() {
                return Err(std::io::Error::other(stderr));
            }
        }
        Ok(())
    }

    /// Flush the Windows DNS client cache so stale entries don't
    /// interfere with the new resolver configuration.
    pub(super) fn clear_dns_cache() {
        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Clear-DnsClientCache -ErrorAction SilentlyContinue",
            ])
            .output();
    }

    /// Reset all adapters to DHCP-obtained DNS for both IPv4 and IPv6, in a
    /// single PowerShell invocation.
    ///
    /// Used as a safety net in `DnsGuard::drop()` to clear any leftover
    /// loopback DNS entries before restoring from the backup.
    pub(super) fn reset_all_dns() -> std::io::Result<()> {
        const SCRIPT: &str = r#"foreach ($fam in 'IPv4','IPv6') { Get-DnsClientServerAddress -AddressFamily $fam -ErrorAction SilentlyContinue | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ResetServerAddresses -ErrorAction SilentlyContinue } }"#;
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", SCRIPT])
            .output()?;
        check_ps_output(&output)
    }

    /// Restore DNS from the backup string produced by `backup()`.
    ///
    /// The string is split on `---IPV6---` into IPv4 and IPv6 sections; each
    /// line is `InterfaceAlias|server1,server2,...`. All entries are applied
    /// in one batched PowerShell invocation — process spawns dominate the
    /// cost here, and this runs on the teardown path (`DnsGuard::drop`, on
    /// whatever thread drops the TUN task). `Set-DnsClientServerAddress`
    /// auto-detects the address family from the IP format, so both sections
    /// batch into the same script.
    pub(super) fn restore(backup: &str) -> std::io::Result<()> {
        let script = build_restore_script(backup);
        if script.is_empty() {
            return Ok(());
        }

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()?;
        check_ps_output(&output)
    }

    /// Translate the backup string into one PowerShell script (one
    /// `Set-DnsClientServerAddress` line per adapter entry), logging each
    /// entry being restored.
    fn build_restore_script(backup: &str) -> String {
        use std::fmt::Write as _;

        let (v4_section, v6_section) = match backup.split_once(IPV6_SEPARATOR) {
            Some((v4, v6)) => (v4.trim(), v6.trim()),
            None => (backup.trim(), ""),
        };

        let mut script = String::new();
        for line in v4_section.lines().chain(v6_section.lines()) {
            let line = line.trim();
            let Some((iface, server_list)) = line.split_once('|') else {
                continue;
            };
            let iface = iface.trim();
            let servers: Vec<&str> = server_list
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if iface.is_empty() || servers.is_empty() {
                continue;
            }
            let quoted: Vec<String> = servers
                .iter()
                .map(|s| format!("'{}'", escape_arg(s)))
                .collect();
            let _ = writeln!(
                script,
                "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses ({}) -ErrorAction SilentlyContinue",
                escape_arg(iface),
                quoted.join(","),
            );
            tracing::info!(
                "tun dns-guard: restoring DNS on '{iface}' -> [{}]",
                servers.join(", ")
            );
        }
        script
    }

    fn check_ps_output(output: &std::process::Output) -> std::io::Result<()> {
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let trimmed = stderr.trim();
            if !trimmed.is_empty() {
                return Err(std::io::Error::other(trimmed.to_string()));
            }
        }
        Ok(())
    }

    fn escape_arg(s: &str) -> String {
        s.replace('\'', "''")
    }

    // These run on the windows CI job (`cargo test -p meow-listener
    // --features listener-tun --lib`) — the whole module is
    // `cfg(target_os = "windows")`.
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn strip_drops_only_exact_own_entries() {
            let section = "Ethernet|127.0.0.1\nWi-Fi|10.0.0.1,127.0.0.1\nvEthernet|8.8.8.8";
            let kept = strip_own_entries(section, "127.0.0.1");
            // Poisoned line (exactly the address meow installs) dropped;
            // a list that merely *contains* 127.0.0.1 is user config — kept.
            assert_eq!(kept, "Wi-Fi|10.0.0.1,127.0.0.1\nvEthernet|8.8.8.8");
        }

        #[test]
        fn strip_drops_own_v6_entry() {
            let kept = strip_own_entries("Ethernet|::1\nEthernet 2|2400:3200::1", "::1");
            assert_eq!(kept, "Ethernet 2|2400:3200::1");
        }

        #[test]
        fn restore_script_batches_all_entries() {
            let backup =
                format!("Ethernet|8.8.8.8,1.1.1.1\n{IPV6_SEPARATOR}\nEthernet|2400:3200::1");
            let script = build_restore_script(&backup);
            let lines: Vec<&str> = script.lines().collect();
            assert_eq!(lines.len(), 2, "one Set- command per entry, one script");
            assert_eq!(
                lines[0],
                "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses ('8.8.8.8','1.1.1.1') -ErrorAction SilentlyContinue"
            );
            assert!(lines[1].contains("('2400:3200::1')"));
        }

        #[test]
        fn restore_script_escapes_quotes_and_skips_malformed_lines() {
            let script = build_restore_script(
                "It's Ethernet|9.9.9.9\nno-separator-line\n|1.2.3.4\nEthernet|",
            );
            let lines: Vec<&str> = script.lines().collect();
            assert_eq!(lines.len(), 1);
            assert!(
                lines[0].contains("'It''s Ethernet'"),
                "single quotes doubled"
            );
        }

        /// Read-only smoke test of the real PowerShell + registry backup
        /// path on the CI runner: must succeed and produce the documented
        /// line format. Catches PowerShell syntax or registry-path breakage
        /// that host-side compilation cannot.
        #[test]
        fn backup_runs_and_is_wellformed() {
            let backup = backup().expect("backup must succeed on a real Windows host");
            assert!(backup.contains(IPV6_SEPARATOR), "sections are separated");
            for line in backup.lines() {
                let line = line.trim();
                if line.is_empty() || line == IPV6_SEPARATOR {
                    continue;
                }
                assert!(
                    line.contains('|'),
                    "adapter line must be 'InterfaceAlias|servers': {line:?}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// macOS backend — networksetup
//
// Only services that were snapshotted are ever changed: `set_all` and
// `restore` both iterate the backup, so a service whose
// `-getdnsservers` failed (or that appeared after the snapshot) is left
// untouched rather than pointed at the fake-IP gateway with nothing to
// restore it from.
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use super::networksetup;
    use std::io;
    use std::net::IpAddr;
    use std::process::Command;

    pub(super) fn backup(dns_addr: IpAddr) -> io::Result<Vec<(String, Vec<IpAddr>)>> {
        let services = list_services()?;
        let mut result = Vec::with_capacity(services.len());
        for svc in services {
            match get_dns(&svc, dns_addr) {
                Ok(servers) => {
                    super::debug!("tun dns-guard: '{svc}' DNS before setup: {servers:?}");
                    result.push((svc, servers));
                }
                Err(e) => super::warn!(
                    "tun dns-guard: failed to get DNS for '{svc}', leaving it untouched: {e}"
                ),
            }
        }
        Ok(result)
    }

    pub(super) fn set_all(dns_addr: IpAddr, saved: &[(String, Vec<IpAddr>)]) -> io::Result<()> {
        let mut failed = 0usize;
        for (svc, _) in saved {
            if let Err(e) = set_dns(svc, std::slice::from_ref(&dns_addr)) {
                super::warn!("tun dns-guard: failed to set DNS on '{svc}': {e}");
                failed += 1;
            }
        }
        summarize(failed, saved.len())
    }

    pub(super) fn restore(saved: &[(String, Vec<IpAddr>)]) -> io::Result<()> {
        let mut failed = 0usize;
        for (svc, servers) in saved {
            if let Err(e) = set_dns(svc, servers) {
                super::warn!("tun dns-guard: failed to restore DNS on '{svc}': {e}");
                failed += 1;
            }
        }
        summarize(failed, saved.len())
    }

    fn summarize(failed: usize, total: usize) -> io::Result<()> {
        if failed == 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "{failed} of {total} network services failed"
            )))
        }
    }

    fn list_services() -> io::Result<Vec<String>> {
        let stdout = run(&["-listallnetworkservices"])?;
        Ok(networksetup::parse_services(&stdout))
    }

    fn get_dns(service: &str, own: IpAddr) -> io::Result<Vec<IpAddr>> {
        let stdout = run(&["-getdnsservers", service])?;
        Ok(networksetup::saved_dns_servers(&stdout, own))
    }

    fn set_dns(service: &str, servers: &[IpAddr]) -> io::Result<()> {
        let addrs = networksetup::dns_server_args(servers);
        let mut args = vec!["-setdnsservers", service];
        args.extend(addrs.iter().map(String::as_str));
        run(&args)?;
        Ok(())
    }

    /// Run `networksetup` and return its stdout; a non-zero exit is an
    /// error carrying networksetup's diagnostic (see `check_exit`).
    fn run(args: &[&str]) -> io::Result<String> {
        let output = Command::new("networksetup").args(args).output()?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        networksetup::check_exit(
            args.first().copied().unwrap_or_default(),
            output.status.code(),
            &stdout,
            &String::from_utf8_lossy(&output.stderr),
        )?;
        Ok(stdout)
    }
}

// ---------------------------------------------------------------------------
// networksetup output handling for the macOS backend.
//
// Pure functions, also compiled under `cfg(test)` on every platform so the
// Linux and Windows CI legs run their tests — the backend itself only
// builds on macOS. Measured `networksetup` behaviour (macOS 26, #695):
//
// - `-getdnsservers <svc>` with no manual servers: exit 0,
//   "There aren't any DNS Servers set on <svc>." — the service name, not
//   the "this device" wording an exact-match check once assumed.
// - Every failure exits 4 and prints its diagnostic on *stdout* (stderr
//   stays empty): "<svc> is not a recognized network service." /
//   "<arg> is not a valid IP address. No changes were saved...", then
//   "** Error: The parameters were not valid.".
// - `-setdnsservers` is all-or-nothing (one bad address saves nothing),
//   rejects scoped IPv6 (`fe80::1%en0`), and succeeds with exit 0 and no
//   output; the `Empty` keyword clears the manual list (DHCP/automatic).
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "macos", test))]
mod networksetup {
    use std::io;
    use std::net::IpAddr;

    /// `-setdnsservers` keyword that clears a service's manual DNS list.
    const EMPTY: &str = "Empty";

    /// Classify one `networksetup` run. Exit 0 is success; any other exit
    /// — or death by signal (`code == None`) — is an error carrying the
    /// diagnostic, which networksetup prints on stdout (stderr is appended
    /// in case that ever changes), folded onto one line for the log.
    pub(super) fn check_exit(
        subcmd: &str,
        code: Option<i32>,
        stdout: &str,
        stderr: &str,
    ) -> io::Result<()> {
        if code == Some(0) {
            return Ok(());
        }
        let status = code.map_or_else(
            || "terminated by a signal".to_owned(),
            |c| format!("exit status {c}"),
        );
        let lines: Vec<&str> = stdout
            .lines()
            .chain(stderr.lines())
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let detail = if lines.is_empty() {
            "no output".to_owned()
        } else {
            lines.join(" ")
        };
        Err(io::Error::other(format!(
            "networksetup {subcmd} failed ({status}): {detail}"
        )))
    }

    /// Enabled network services from `-listallnetworkservices` stdout.
    /// Line 1 is the "An asterisk (*) denotes that a network service is
    /// disabled." legend; disabled services carry a leading `*`.
    pub(super) fn parse_services(stdout: &str) -> Vec<String> {
        stdout
            .lines()
            .skip(1)
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('*'))
            .map(str::to_owned)
            .collect()
    }

    /// The server list to back up from `-getdnsservers` stdout (exit 0).
    ///
    /// The list is exactly the lines that parse as an IP address, so the
    /// "There aren't any DNS Servers set on <svc>." sentence — in any
    /// wording — yields an empty list, restored as `Empty`. `own` (the
    /// fake-IP gateway meow installs) is dropped too: after an unclean
    /// shutdown it is still the active DNS, and keeping it would make a
    /// later clean exit "restore" the broken state.
    pub(super) fn saved_dns_servers(stdout: &str, own: IpAddr) -> Vec<IpAddr> {
        stdout
            .lines()
            .filter_map(|l| l.trim().parse::<IpAddr>().ok())
            .filter(|ip| *ip != own)
            .collect()
    }

    /// `-setdnsservers <svc>` arguments for `servers`; an empty list
    /// becomes `Empty`.
    pub(super) fn dns_server_args(servers: &[IpAddr]) -> Vec<String> {
        if servers.is_empty() {
            vec![EMPTY.to_owned()]
        } else {
            servers.iter().map(ToString::to_string).collect()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::Ipv4Addr;

        /// The default fake-IP gateway (`198.18.0.1`).
        const OWN: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));

        /// networksetup's trailer on every parameter error.
        const PARAMS_INVALID: &str = "** Error: The parameters were not valid.";

        fn ips(list: &[&str]) -> Vec<IpAddr> {
            list.iter().map(|s| s.parse().unwrap()).collect()
        }

        #[test]
        fn no_servers_sentence_names_the_service() {
            // Real macOS 26 output (#695): the sentence names the service,
            // so the old exact match against "...on this device." missed it
            // and backed the sentence up as the server list.
            for svc in ["Ethernet", "Wi-Fi", "USB 10/100/1000 LAN"] {
                let out = format!("There aren't any DNS Servers set on {svc}.\n");
                assert!(saved_dns_servers(&out, OWN).is_empty(), "{out:?}");
            }
        }

        #[test]
        fn legacy_this_device_sentence_is_empty() {
            let out = "There aren't any DNS Servers set on this device.\n";
            assert!(saved_dns_servers(out, OWN).is_empty());
        }

        #[test]
        fn ipv4_and_ipv6_lists_are_kept_in_order() {
            assert_eq!(saved_dns_servers("9.9.9.9\n", OWN), ips(&["9.9.9.9"]));
            assert_eq!(
                saved_dns_servers("1.1.1.1\n2606:4700:4700::1111\n8.8.8.8\n", OWN),
                ips(&["1.1.1.1", "2606:4700:4700::1111", "8.8.8.8"]),
            );
        }

        #[test]
        fn tolerates_crlf_padding_and_blank_lines() {
            assert_eq!(
                saved_dns_servers("  8.8.8.8 \r\n\r\n2001:4860:4860::8888\t\r\n", OWN),
                ips(&["8.8.8.8", "2001:4860:4860::8888"]),
            );
            assert!(
                saved_dns_servers("There aren't any DNS Servers set on Ethernet. \r\n", OWN)
                    .is_empty()
            );
            assert!(saved_dns_servers("", OWN).is_empty());
        }

        #[test]
        fn own_gateway_is_never_backed_up() {
            // Cycle 2 of the #695 repro: the leaked gateway is the only
            // "original" server — it must restore as `Empty`.
            assert!(saved_dns_servers("198.18.0.1\n", OWN).is_empty());
            assert_eq!(
                saved_dns_servers("198.18.0.1\n1.1.1.1\n", OWN),
                ips(&["1.1.1.1"])
            );
        }

        #[test]
        fn scoped_ipv6_is_not_a_server() {
            // `-setdnsservers` rejects it (exit 4), so it can never be a
            // configured server — and could never be restored.
            assert_eq!(
                saved_dns_servers("1.1.1.1\nfe80::1%en0\n", OWN),
                ips(&["1.1.1.1"])
            );
        }

        #[test]
        fn error_text_never_parses_as_servers() {
            let out =
                format!("No Such Service is not a recognized network service.\n{PARAMS_INVALID}\n");
            assert!(saved_dns_servers(&out, OWN).is_empty());
            let err = check_exit("-getdnsservers", Some(4), &out, "").unwrap_err();
            assert_eq!(
                err.to_string(),
                format!(
                    "networksetup -getdnsservers failed (exit status 4): \
                     No Such Service is not a recognized network service. {PARAMS_INVALID}"
                ),
            );
        }

        #[test]
        fn check_exit_accepts_only_exit_zero() {
            assert!(check_exit("-setdnsservers", Some(0), "", "").is_ok());
            assert!(check_exit("-getdnsservers", Some(0), "9.9.9.9\n", "").is_ok());
            assert!(check_exit(
                "-getdnsservers",
                Some(0),
                "There aren't any DNS Servers set on Ethernet.\n",
                ""
            )
            .is_ok());
        }

        #[test]
        fn check_exit_surfaces_rejected_set() {
            // The exact failure #695 hid: restoring the backed-up sentence.
            let out = format!(
                "There aren't any DNS Servers set on Ethernet. is not a valid IP address. \
                 No changes were saved...\n{PARAMS_INVALID}\n"
            );
            let err = check_exit("-setdnsservers", Some(4), &out, "").unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.starts_with("networksetup -setdnsservers failed (exit status 4): "),
                "{msg}"
            );
            assert!(
                msg.contains("is not a valid IP address. No changes were saved..."),
                "{msg}"
            );
            assert!(msg.ends_with(PARAMS_INVALID), "{msg}");
            assert!(!msg.contains('\n'), "folded onto one line: {msg}");

            let out = format!(
                "bogus is not a valid IP address. No changes were saved...\n{PARAMS_INVALID}\n"
            );
            assert!(check_exit("-setdnsservers", Some(4), &out, "").is_err());
        }

        #[test]
        fn check_exit_without_output() {
            let err = check_exit("-setdnsservers", None, "", "").unwrap_err();
            assert_eq!(
                err.to_string(),
                "networksetup -setdnsservers failed (terminated by a signal): no output"
            );
            let err = check_exit("-listallnetworkservices", Some(1), "", "boom\n").unwrap_err();
            assert!(err.to_string().ends_with("(exit status 1): boom"), "{err}");
        }

        #[test]
        fn empty_list_restores_as_empty_keyword() {
            assert_eq!(dns_server_args(&[]), ["Empty"]);
            // The full #695 path for a DHCP service: snapshot the
            // no-servers sentence, restore with `Empty` (exit 0, no
            // output) — never the sentence itself.
            let saved = saved_dns_servers("There aren't any DNS Servers set on Ethernet.\n", OWN);
            assert_eq!(dns_server_args(&saved), ["Empty"]);
        }

        #[test]
        fn server_args_round_trip() {
            let servers = ips(&["1.1.1.1", "2606:4700:4700::1111"]);
            assert_eq!(
                dns_server_args(&servers),
                ["1.1.1.1", "2606:4700:4700::1111"]
            );
            let out = "1.1.1.1\n2606:4700:4700::1111\n";
            assert_eq!(saved_dns_servers(out, OWN), servers);
        }

        #[test]
        fn services_skip_legend_and_disabled() {
            let out = "An asterisk (*) denotes that a network service is disabled.\n\
                       Ethernet\nWi-Fi\n*Thunderbolt Bridge\nUSB 10/100/1000 LAN\r\n\n";
            assert_eq!(
                parse_services(out),
                ["Ethernet", "Wi-Fi", "USB 10/100/1000 LAN"]
            );
            assert!(parse_services("").is_empty());
        }
    }
}

// ---------------------------------------------------------------------------
// Linux backend — /etc/resolv.conf
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io;
    use std::net::IpAddr;
    use std::path::PathBuf;

    const MARKER: &str = "# Generated by meow-rs TUN dns-guard";
    /// On-disk copy of the pre-meow resolv.conf, written before we touch
    /// the real file so the original survives an unclean shutdown.
    const SIDECAR: &str = "/etc/resolv.conf.meow-backup";

    pub(super) struct ResolvConfBackup {
        path: PathBuf,
        content: Vec<u8>,
    }

    pub(super) fn backup_and_set(dns_addr: IpAddr) -> io::Result<ResolvConfBackup> {
        let path = PathBuf::from("/etc/resolv.conf");
        let current = fs::read(&path)?;

        let content = if current.starts_with(MARKER.as_bytes()) {
            // resolv.conf is our own generated file — a previous run exited
            // uncleanly. Recover the true original from the sidecar instead
            // of backing up (and later "restoring") the broken state.
            match fs::read(SIDECAR) {
                Ok(original) => {
                    super::warn!(
                        "tun dns-guard: /etc/resolv.conf was left over from an unclean \
                         shutdown; recovered the original from {SIDECAR}"
                    );
                    original
                }
                Err(e) => {
                    super::warn!(
                        "tun dns-guard: /etc/resolv.conf was left over from an unclean \
                         shutdown and no sidecar backup exists ({e}); will restore public \
                         resolvers on exit — reconfigure your resolver manually if needed"
                    );
                    b"# meow-rs tun dns-guard: the original /etc/resolv.conf was lost in an\n\
                      # unclean shutdown; falling back to public resolvers.\n\
                      nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
                        .to_vec()
                }
            }
        } else {
            fs::write(SIDECAR, &current)?;
            current
        };

        let new_content = format!("{MARKER}\nnameserver {dns_addr}\n");
        fs::write(&path, new_content.as_bytes())?;
        Ok(ResolvConfBackup { path, content })
    }

    pub(super) fn restore(backup: &ResolvConfBackup) -> io::Result<()> {
        fs::write(&backup.path, &backup.content)?;
        let _ = fs::remove_file(SIDECAR);
        Ok(())
    }
}
