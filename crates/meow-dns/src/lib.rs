//! DNS resolver, cache, snooping, and FakeIP for the meow-rs proxy kernel.
//!
//! Caching resolver with IP-to-domain reverse mapping, optional FakeIP
//! allocation, and a DNS server used by transparent proxy and TUN.

pub mod cache;
pub mod client;
pub mod fakeip;
pub mod host_resolver_hook;
pub mod resolver;
pub mod server;
pub mod upstream;

pub use cache::{DnsCache, DnsCacheSnapshotEntry, ReverseSnapshotEntry};
pub use client::{set_socket_factory, ClientError, DnsClient, SocketFactory};
pub use fakeip::{FileStore, MemoryStore, Pool, PoolError, Skipper, SkipperMode, Store};
pub use host_resolver_hook::ResolverHostHook;
pub use resolver::{
    BootstrapError, FallbackFilter, HostEntry, NameserverPolicy, PolicyEntry, Resolver,
};
pub use server::{BoundDnsServer, DnsServer, ResolverSlot};
pub use upstream::{HostOrIp, NameServerEntry, NameServerParseError, NameServerUrl};
