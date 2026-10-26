//! Policy routing for global route scope on Linux.
//!
//! Split default routes in the main table (`0.0.0.0/1` + `128.0.0.0/1`)
//! send every packet the host routes into the device — including the
//! replies on connections the host *accepted* from another network, which
//! then never reach the peer: an SSH session, a server on the host, meow's
//! own `external-controller`. On Linux the device's default routes live in
//! a table of their own ([`TABLE`]) instead, and rules send to it only the
//! flows this host originates before it has chosen a source address:
//!
//! | pref | IPv4 | IPv6 |
//! |------|------|------|
//! | 9200 | `not dport 53 lookup main suppress_prefixlength 0` | same |
//! | 9201 | `iif lo from <device subnet> lookup TABLE` | same |
//! | 9202 | `iif lo from 0.0.0.0/32 lookup TABLE` | `iif lo from ::/1 goto 9205` |
//! | 9203 | | `iif lo from 8000::/1 goto 9205` |
//! | 9204 | | `iif lo lookup TABLE` |
//! | 9205 | | `nop` |
//!
//! - 9200: a main-table route more specific than its default — the LAN, a
//!   Docker bridge, a static route, the fake-IP range — keeps winning,
//!   except for DNS, so a query to a LAN resolver still reaches
//!   `dns-hijack`.
//! - The lookup an unbound socket makes on `connect` / `sendto` has no
//!   source yet; it goes to the device, the kernel picks the device's
//!   address as the source, and later lookups for the flow (9201) stay on
//!   the device.
//! - A flow that already has another source — the reply on an accepted
//!   connection, a socket bound to a physical address — falls through to
//!   the main table. IPv4 rules match the source as a plain value, so the
//!   unbound lookup is `from 0.0.0.0/32`. An IPv6 rule with a source
//!   prefix never matches a lookup without a source, so IPv6 instead skips
//!   every flow that has one (9202, 9203) and sends the rest to the device
//!   (9204).
//! - Only `iif lo`: traffic the host forwards (containers, VMs, a
//!   gateway's LAN clients) keeps the main table, where the fake-IP route
//!   still catches its domain flows. A forwarded reply is indistinguishable
//!   from any other forwarded packet here, so sending forwarded traffic to
//!   the device would break every DNAT'd service — a published Docker port
//!   — for remote clients.
//!
//! meow's own sockets are bound to the physical interface
//! (`outbound_binding`): their lookup in [`TABLE`] finds no route through
//! that interface and falls through to the main table.
//!
//! Each rule has a priority of its own: the kernel's IPv6 rules treat a
//! rule without a source as a duplicate of one with a source and otherwise
//! equal fields (`EEXIST` on add), and a delete matches loosely enough to
//! take the wrong one of two rules sharing a priority.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP,
    NLM_F_REPLACE, NLM_F_REQUEST,
};
use netlink_packet_route::route::{
    RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::rule::{
    RuleAction, RuleAttribute, RuleFlags, RuleMessage, RulePortRange,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use tracing::{debug, warn};

/// The routing table holding the device's default routes ("meow" in
/// ASCII; any id above 255 is free of the reserved tables).
pub(super) const TABLE: u32 = 0x6d65_6f77;
/// Priority of the first rule. The rules take `PRIORITY..=NOP`, clear of
/// mihomo's and sing-box's default 9000 block.
const PRIORITY: u32 = 9200;
/// Priority of the IPv6 `nop` rule the source rules jump to.
const NOP: u32 = PRIORITY + 5;
const RT_TABLE_MAIN: u8 = 254;

/// The generation whose rules are installed. A config reload starts the
/// next listener while the previous one may still be tearing down; the
/// newer generation replaces the rules, and only the generation that owns
/// them removes them.
static RULES_OWNER: AtomicU64 = AtomicU64::new(0);
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selector {
    /// `not dport 53`
    NotDns,
    /// `iif lo`, plus `from <net>` when given.
    Local(Option<IpNet>),
    /// Every packet.
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    /// `lookup main suppress_prefixlength 0`: the main table's routes
    /// except its default.
    MainWithoutDefault,
    /// `lookup TABLE`
    Device,
    /// `goto NOP`
    SkipDevice,
    Nop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rule {
    priority: u32,
    v6: bool,
    selector: Selector,
    action: Action,
}

/// The rules for a device on `v4`, and on `v6` when it has an IPv6
/// address (see the module docs).
fn rules(v4: Ipv4Net, v6: Option<Ipv6Net>) -> Vec<Rule> {
    let rule = |offset, v6, selector, action| Rule {
        priority: PRIORITY + offset,
        v6,
        selector,
        action,
    };
    let from = |net: IpNet| Selector::Local(Some(net));
    let unbound_v4 = Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 32);
    let mut rules = vec![
        rule(0, false, Selector::NotDns, Action::MainWithoutDefault),
        rule(1, false, from(v4.trunc().into()), Action::Device),
        rule(2, false, from(unbound_v4.into()), Action::Device),
    ];
    if let Some(v6) = v6 {
        let lower = Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 1);
        let upper = Ipv6Net::new_assert(Ipv6Addr::from(1u128 << 127), 1);
        rules.extend([
            rule(0, true, Selector::NotDns, Action::MainWithoutDefault),
            rule(1, true, from(v6.trunc().into()), Action::Device),
            rule(2, true, from(lower.into()), Action::SkipDevice),
            rule(3, true, from(upper.into()), Action::SkipDevice),
            rule(4, true, Selector::Local(None), Action::Device),
            rule(5, true, Selector::All, Action::Nop),
        ]);
    }
    rules
}

impl Rule {
    fn message(&self) -> RuleMessage {
        let mut msg = RuleMessage::default();
        msg.header.family = family(self.v6);
        msg.attributes.push(RuleAttribute::Priority(self.priority));
        match self.selector {
            Selector::NotDns => {
                msg.header.flags = RuleFlags::Invert;
                msg.attributes
                    .push(RuleAttribute::DestinationPortRange(RulePortRange {
                        start: 53,
                        end: 53,
                    }));
            }
            Selector::Local(from) => {
                msg.attributes.push(RuleAttribute::Iifname("lo".into()));
                if let Some(net) = from {
                    msg.header.src_len = net.prefix_len();
                    msg.attributes.push(RuleAttribute::Source(net.network()));
                }
            }
            Selector::All => {}
        }
        match self.action {
            Action::MainWithoutDefault => {
                msg.header.action = RuleAction::ToTable;
                msg.header.table = RT_TABLE_MAIN;
                msg.attributes.push(RuleAttribute::SuppressPrefixLen(0));
            }
            Action::Device => {
                // A table id above 255 goes in FRA_TABLE, the header's
                // field staying RT_TABLE_UNSPEC.
                msg.header.action = RuleAction::ToTable;
                msg.attributes.push(RuleAttribute::Table(TABLE));
            }
            Action::SkipDevice => {
                msg.header.action = RuleAction::Goto;
                msg.attributes.push(RuleAttribute::Goto(NOP));
            }
            Action::Nop => msg.header.action = RuleAction::Nop,
        }
        msg
    }
}

/// Whether a rule read back from the kernel is one of ours — left behind
/// by a crashed run or by the previous generation. Matches the priority
/// block plus what our rules do there, so a foreign rule that happens to
/// share a priority survives.
fn is_ours(msg: &RuleMessage) -> bool {
    let mut priority = None;
    let mut table = u32::from(msg.header.table);
    let mut goto = None;
    let mut suppress = None;
    for attr in &msg.attributes {
        match attr {
            RuleAttribute::Priority(p) => priority = Some(*p),
            RuleAttribute::Table(t) => table = *t,
            RuleAttribute::Goto(g) => goto = Some(*g),
            RuleAttribute::SuppressPrefixLen(s) => suppress = Some(*s),
            _ => {}
        }
    }
    let Some(priority) = priority.filter(|p| (PRIORITY..=NOP).contains(p)) else {
        return false;
    };
    match msg.header.action {
        RuleAction::ToTable => {
            table == TABLE || (table == u32::from(RT_TABLE_MAIN) && suppress == Some(0))
        }
        RuleAction::Goto => goto == Some(NOP),
        RuleAction::Nop => priority == NOP,
        _ => false,
    }
}

/// The device's default route for one family, in [`TABLE`].
fn default_route(v6: bool, if_index: u32) -> RouteMessage {
    let mut msg = RouteMessage::default();
    msg.header.address_family = family(v6);
    msg.header.protocol = RouteProtocol::Static;
    msg.header.scope = RouteScope::Universe;
    msg.header.kind = RouteType::Unicast;
    msg.attributes.push(RouteAttribute::Table(TABLE));
    msg.attributes.push(RouteAttribute::Oif(if_index));
    msg
}

fn family(v6: bool) -> AddressFamily {
    if v6 {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    }
}

/// The installed policy routing of one TUN listener; dropping it removes
/// it. Dropped before the device (`TunDevice` field order).
pub(super) struct PolicyRoutes {
    generation: u64,
    rules: Vec<Rule>,
    routes: Vec<RouteMessage>,
}

impl PolicyRoutes {
    /// Route everything the host originates into device `if_index` on
    /// `v4` (and `v6`). Rules a previous run left behind are replaced.
    /// Fails — with nothing left installed — when the kernel has no policy
    /// routing (`CONFIG_IP_MULTIPLE_TABLES`) or refuses a rule; the caller
    /// then falls back to split default routes.
    pub(super) fn setup(if_index: u32, v4: Ipv4Net, v6: Option<Ipv6Net>) -> io::Result<Self> {
        let generation = NEXT_GENERATION.fetch_add(1, Ordering::Relaxed);
        RULES_OWNER.store(generation, Ordering::Relaxed);
        let mut this = Self {
            generation,
            rules: Vec::new(),
            routes: Vec::new(),
        };
        let mut nl = Netlink::open()?;
        nl.purge_rules()?;
        // Replace, not create: a previous generation's device may still
        // hold the table's default route while it tears down.
        for v6 in [false].into_iter().chain(v6.map(|_| true)) {
            let route = default_route(v6, if_index);
            nl.request(
                RouteNetlinkMessage::NewRoute(route.clone()),
                NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            )?;
            this.routes.push(route);
        }
        // The `nop` target goes in before the rules that jump to it.
        let mut wanted = rules(v4, v6);
        wanted.sort_by_key(|r| r.action != Action::Nop);
        for rule in wanted {
            nl.request(
                RouteNetlinkMessage::NewRule(rule.message()),
                NLM_F_ACK | NLM_F_CREATE,
            )?;
            this.rules.push(rule);
        }
        // A kernel without the `dport` selector (before Linux 4.17) drops
        // it and keeps the first rule as one that never matches, which
        // would send the LAN into the device too.
        if !nl.port_selector_kept()? {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the kernel has no `dport` rule selector (Linux 4.17+)",
            ));
        }
        debug!(
            "tun auto-route: {} policy rules and {} routes in table {TABLE} via if_index {if_index}",
            this.rules.len(),
            this.routes.len(),
        );
        Ok(this)
    }
}

impl Drop for PolicyRoutes {
    fn drop(&mut self) {
        // A newer generation already replaced the rules: they are its own.
        let owner = RULES_OWNER
            .compare_exchange(self.generation, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok();
        if self.rules.is_empty() && self.routes.is_empty() {
            return;
        }
        let mut nl = match Netlink::open() {
            Ok(nl) => nl,
            Err(e) => {
                warn!("tun auto-route: cannot remove the policy routing: {e}");
                return;
            }
        };
        if owner {
            for rule in self.rules.iter().rev() {
                if let Err(e) = nl.request(RouteNetlinkMessage::DelRule(rule.message()), NLM_F_ACK)
                {
                    warn!("tun auto-route: failed to remove rule {rule:?}: {e}");
                }
            }
        }
        // Matches our device only, so a route a newer generation put in
        // its place stays. The kernel also drops it with the device.
        for route in &self.routes {
            if let Err(e) = nl.request(RouteNetlinkMessage::DelRoute(route.clone()), NLM_F_ACK) {
                debug!("tun auto-route: table {TABLE} route already gone: {e}");
            }
        }
    }
}

/// A blocking rtnetlink socket.
struct Netlink {
    socket: Socket,
    sequence: u32,
}

impl Netlink {
    fn open() -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Self {
            socket,
            sequence: 0,
        })
    }

    fn dump_rules(&mut self, family: AddressFamily) -> io::Result<Vec<RuleMessage>> {
        let mut query = RuleMessage::default();
        query.header.family = family;
        Ok(self
            .request(RouteNetlinkMessage::GetRule(query), NLM_F_DUMP)?
            .into_iter()
            .filter_map(|msg| match msg {
                RouteNetlinkMessage::NewRule(rule) => Some(rule),
                _ => None,
            })
            .collect())
    }

    /// Delete the rules [`is_ours`] recognises, in both families.
    fn purge_rules(&mut self) -> io::Result<()> {
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            let stale: Vec<RuleMessage> = self
                .dump_rules(family)?
                .into_iter()
                .filter(is_ours)
                .collect();
            for rule in stale {
                debug!("tun auto-route: removing a stale policy rule: {rule:?}");
                self.request(RouteNetlinkMessage::DelRule(rule), NLM_F_ACK)?;
            }
        }
        Ok(())
    }

    /// Whether the installed IPv4 `not dport 53` rule kept its selector.
    fn port_selector_kept(&mut self) -> io::Result<bool> {
        Ok(self.dump_rules(AddressFamily::Inet)?.iter().any(|rule| {
            rule.attributes.contains(&RuleAttribute::Priority(PRIORITY))
                && rule
                    .attributes
                    .iter()
                    .any(|a| matches!(a, RuleAttribute::DestinationPortRange(_)))
        }))
    }

    /// Send one request and collect its reply: the messages of a dump, or
    /// nothing for an acknowledged change.
    fn request(
        &mut self,
        payload: RouteNetlinkMessage,
        flags: u16,
    ) -> io::Result<Vec<RouteNetlinkMessage>> {
        self.sequence += 1;
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | flags;
        header.sequence_number = self.sequence;
        let mut packet = NetlinkMessage::new(header, NetlinkPayload::from(payload));
        packet.finalize();
        let mut buf = vec![0; packet.header.length as usize];
        packet.serialize(&mut buf);
        self.socket.send(&buf, 0)?;

        let mut replies = Vec::new();
        // The kernel sizes a dump's messages to at most 32 KiB.
        let mut buf = vec![0; 64 * 1024];
        loop {
            let len = self.socket.recv(&mut &mut buf[..], 0)?;
            let mut offset = 0;
            while offset < len {
                let msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&buf[offset..len])
                    .map_err(|e| io::Error::other(format!("netlink: {e}")))?;
                let msg_len = msg.header.length as usize;
                if msg_len == 0 {
                    break;
                }
                // Netlink messages are 4-byte aligned.
                offset += (msg_len + 3) & !3;
                if msg.header.sequence_number != self.sequence {
                    continue;
                }
                match msg.payload {
                    NetlinkPayload::Done(_) => return Ok(replies),
                    NetlinkPayload::Error(e) => {
                        return match e.code {
                            None => Ok(replies),
                            Some(_) => Err(e.to_io()),
                        };
                    }
                    NetlinkPayload::InnerMessage(msg) => replies.push(msg),
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn v4() -> Ipv4Net {
        "198.18.0.1/30".parse().unwrap()
    }

    fn v6() -> Ipv6Net {
        "fdfe:dcba:9876::1/126".parse().unwrap()
    }

    fn source(msg: &RuleMessage) -> Option<(IpAddr, u8)> {
        msg.attributes.iter().find_map(|a| match a {
            RuleAttribute::Source(ip) => Some((*ip, msg.header.src_len)),
            _ => None,
        })
    }

    /// Each rule has a priority of its own (the kernel's duplicate check
    /// ignores a missing source), inside the block `is_ours` purges.
    #[test]
    fn every_rule_has_its_own_priority_in_the_block() {
        let rules = rules(v4(), Some(v6()));
        for v6 in [false, true] {
            let mut priorities: Vec<u32> = rules
                .iter()
                .filter(|r| r.v6 == v6)
                .map(|r| r.priority)
                .collect();
            let count = priorities.len();
            priorities.dedup();
            assert_eq!(priorities.len(), count, "v6={v6}: {rules:?}");
            assert!(priorities.iter().all(|p| (PRIORITY..=NOP).contains(p)));
        }
        assert_eq!(rules.iter().filter(|r| !r.v6).count(), 3);
        assert_eq!(rules.iter().filter(|r| r.v6).count(), 6);
        // No inet6-address: IPv4 only.
        assert!(super::rules(v4(), None).iter().all(|r| !r.v6));
    }

    /// The device subnet rule names the network, not the host address, and
    /// the unbound IPv4 lookup is `from 0.0.0.0/32`.
    #[test]
    fn source_rules_name_networks() {
        let sources: Vec<_> = rules(v4(), Some(v6()))
            .iter()
            .filter_map(|r| source(&r.message()))
            .collect();
        let expect = |net: &str| {
            let net: IpNet = net.parse().unwrap();
            (net.network(), net.prefix_len())
        };
        assert_eq!(
            sources,
            [
                expect("198.18.0.0/30"),
                expect("0.0.0.0/32"),
                expect("fdfe:dcba:9876::/126"),
                expect("::/1"),
                expect("8000::/1"),
            ]
        );
    }

    /// Rules carry the table id the kernel needs: ours (above 255) in
    /// FRA_TABLE, main in the header with the default suppressed.
    #[test]
    fn rule_messages_encode_the_actions() {
        let msgs: Vec<RuleMessage> = rules(v4(), Some(v6())).iter().map(Rule::message).collect();
        let not_dns = &msgs[0];
        assert_eq!(not_dns.header.action, RuleAction::ToTable);
        assert_eq!(not_dns.header.table, RT_TABLE_MAIN);
        assert!(not_dns.header.flags.contains(RuleFlags::Invert));
        assert!(not_dns
            .attributes
            .contains(&RuleAttribute::SuppressPrefixLen(0)));
        assert!(not_dns
            .attributes
            .contains(&RuleAttribute::DestinationPortRange(RulePortRange {
                start: 53,
                end: 53
            })));

        let device = &msgs[1];
        assert_eq!(device.header.action, RuleAction::ToTable);
        assert_eq!(device.header.table, 0);
        assert!(device.attributes.contains(&RuleAttribute::Table(TABLE)));
        assert!(device
            .attributes
            .contains(&RuleAttribute::Iifname("lo".into())));

        let skip = msgs
            .iter()
            .find(|m| m.header.action == RuleAction::Goto)
            .unwrap();
        assert!(skip.attributes.contains(&RuleAttribute::Goto(NOP)));
        assert!(msgs.iter().any(|m| m.header.action == RuleAction::Nop
            && m.attributes.contains(&RuleAttribute::Priority(NOP))));
    }

    /// Everything we install is recognised as ours for the purge; a
    /// foreign rule sharing the block, or ours outside it, is not.
    #[test]
    fn purge_recognises_only_our_rules() {
        for rule in rules(v4(), Some(v6())) {
            assert!(is_ours(&rule.message()), "{rule:?}");
        }
        let mut foreign = RuleMessage::default();
        foreign.header.action = RuleAction::ToTable;
        foreign.header.table = 100;
        foreign
            .attributes
            .push(RuleAttribute::Priority(PRIORITY + 1));
        assert!(!is_ours(&foreign));
        // Plain `lookup main` (no suppression) at our priority: not ours.
        let mut main = foreign.clone();
        main.header.table = RT_TABLE_MAIN;
        assert!(!is_ours(&main));
        // Our table, but outside the block.
        let mut elsewhere = RuleMessage::default();
        elsewhere.header.action = RuleAction::ToTable;
        elsewhere.attributes.push(RuleAttribute::Table(TABLE));
        elsewhere
            .attributes
            .push(RuleAttribute::Priority(PRIORITY - 1));
        assert!(!is_ours(&elsewhere));
    }

    #[test]
    fn default_routes_go_in_our_table() {
        for v6 in [false, true] {
            let route = default_route(v6, 7);
            assert_eq!(route.header.address_family, family(v6));
            assert_eq!(route.header.destination_prefix_length, 0);
            assert!(route.attributes.contains(&RouteAttribute::Table(TABLE)));
            assert!(route.attributes.contains(&RouteAttribute::Oif(7)));
        }
    }
}
