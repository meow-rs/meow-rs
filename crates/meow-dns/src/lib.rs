//! DNS resolver, cache, snooping, and FakeIP for the meow-rs proxy kernel.
//!
//! Caching resolver with IP-to-domain reverse mapping, optional FakeIP
//! allocation, and a DNS server used by transparent proxy and TUN.

pub mod answer_hook;
pub mod cache;
pub mod client;
pub mod fakeip;
pub mod host_resolver_hook;
pub mod resolver;
pub mod respect_rules;
pub mod response_policy;
pub mod server;
pub mod upstream;

#[cfg(feature = "quic-dns")]
mod quic;

pub use cache::{DnsCache, DnsCacheSnapshotEntry, ReverseSnapshotEntry};
pub use client::{
    reset_pooled_connections, set_socket_factory, ClientError, DnsClient, SocketFactory,
};
pub use fakeip::{FileStore, MemoryStore, Pool, PoolError, Skipper, SkipperMode, Store};
pub use host_resolver_hook::ResolverHostHook;
pub use resolver::system_nameservers;
pub use resolver::{
    BootstrapError, FallbackFilter, HostEntry, NameserverPolicy, PolicyEntry, Resolver,
};
pub use respect_rules::{
    new_respect_rules_cell, RespectRulesCell, RespectRulesProxy, RESPECT_RULES_PROXY,
};
pub use server::{
    new_dns_outbound_cell, new_resolver_slot, new_resolver_slot_state, BoundDnsServer,
    DnsOutboundCell, DnsServer, LocalAnswer, ResolverGen, ResolverSlot,
};
pub use upstream::{H3Policy, HostOrIp, NameServerEntry, NameServerParseError, NameServerUrl};
