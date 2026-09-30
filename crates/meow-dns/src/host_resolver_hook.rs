//! Bridge between [`crate::Resolver`] and the global
//! [`meow_common::HostResolver`] hook consulted by
//! [`meow_common::connect_tcp_host`] / [`meow_common::resolve_host`].
//!
//! Compiled on every platform (the `meow_common::HostResolver` trait is now
//! cross-platform): Android installs it alongside the `SocketProtector`, iOS
//! installs it on its own from the NE FFI engine start.
//!
//! See `meow-common/src/socket_protect.rs` for *why* this hook exists:
//! `getaddrinfo` queries from libc bypass the per-fd protection and loop DNS
//! back through meow-rs's own tunnel; even where they don't loop, they run on
//! the blocking pool one thread per lookup. Routing the lookup through
//! `Resolver::resolve_ips` instead resolves async, coalesces + caches, and
//! keeps the query off the tunnel.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use meow_common::HostResolver;

use crate::Resolver;

/// Adapter that implements `meow_common::HostResolver` by delegating to
/// `Resolver::resolve_ips` — i.e. the same path `DirectAdapter` uses, so
/// hosts file entries and fake-IP rules behave consistently between the
/// direct outbound and the socket-protect dial path.
///
/// When `dns.proxy-server-nameserver` is configured, `proxy_resolver` is
/// `Some` and takes over exclusively (mihomo `ProxyServerHostResolver`):
/// proxy server hostnames resolve only through those nameservers — there is
/// no fallback to the main resolver on failure, matching mihomo's
/// `LookupIPWithResolver`, which never retries a failed preferred resolver
/// against the default one.
pub struct ResolverHostHook {
    resolver: Arc<Resolver>,
    proxy_resolver: Option<Arc<Resolver>>,
}

impl ResolverHostHook {
    pub fn new(resolver: Arc<Resolver>) -> Self {
        Self {
            resolver,
            proxy_resolver: None,
        }
    }

    pub fn new_with_proxy_resolver(
        resolver: Arc<Resolver>,
        proxy_resolver: Option<Arc<Resolver>>,
    ) -> Self {
        Self {
            resolver,
            proxy_resolver,
        }
    }

    /// The resolver proxy server hostnames go through: the dedicated
    /// `proxy-server-nameserver` resolver when configured, else the main one.
    fn active(&self) -> &Arc<Resolver> {
        self.proxy_resolver.as_ref().unwrap_or(&self.resolver)
    }
}

#[async_trait]
impl HostResolver for ResolverHostHook {
    async fn resolve(&self, host: &str) -> io::Result<IpAddr> {
        // `Err` propagates verbatim — it carries the upstream failure's
        // `raw_os_error` (e.g. EMFILE opening the resolver socket), which
        // `is_local_resource_error` needs to see to keep local resource
        // exhaustion off the proxy-member health ledger (#682).
        match self.active().resolve_ip(host).await {
            Ok(Some(ip)) => Ok(ip),
            Ok(None) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("meow-dns resolver: no address for {host}"),
            )),
            Err(e) => Err(e),
        }
    }

    async fn resolve_all(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        match self.active().resolve_ips(host).await {
            Ok(Some(ips)) => Ok(ips),
            Ok(None) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("meow-dns resolver: no address for {host}"),
            )),
            Err(e) => Err(e),
        }
    }

    fn resolve_all_local(&self, host: &str) -> Option<Vec<IpAddr>> {
        self.active().resolve_ips_local(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::HostEntry;
    use meow_common::DnsMode;
    use meow_trie::DomainTrie;

    /// A resolver that answers only from its hosts trie — never touches the
    /// network, so tests stay offline.
    fn hosts_only_resolver(entries: &[(&str, &str)]) -> Arc<Resolver> {
        let mut trie = DomainTrie::new();
        for (host, ip) in entries {
            assert!(trie.insert(
                host,
                HostEntry::Addresses(vec![ip.parse().expect("valid IP literal")]),
            ));
        }
        Arc::new(Resolver::new(
            vec![],
            vec![],
            DnsMode::Normal,
            trie,
            true,
            true,
        ))
    }

    #[tokio::test]
    async fn without_proxy_resolver_uses_main_resolver() {
        let main = hosts_only_resolver(&[("node.example", "192.0.2.1")]);
        let hook = ResolverHostHook::new(main);
        let ip = hook.resolve("node.example").await.unwrap();
        assert_eq!(ip, "192.0.2.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn proxy_resolver_takes_precedence_over_main() {
        let main = hosts_only_resolver(&[("node.example", "192.0.2.1")]);
        let proxy = hosts_only_resolver(&[("node.example", "192.0.2.2")]);
        let hook = ResolverHostHook::new_with_proxy_resolver(main, Some(proxy));

        let ip = hook.resolve("node.example").await.unwrap();
        assert_eq!(ip, "192.0.2.2".parse::<IpAddr>().unwrap());

        let all = hook.resolve_all("node.example").await.unwrap();
        assert_eq!(all, vec!["192.0.2.2".parse::<IpAddr>().unwrap()]);

        let local = hook.resolve_all_local("node.example").unwrap();
        assert_eq!(local, vec!["192.0.2.2".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn proxy_resolver_miss_does_not_fall_back_to_main() {
        // mihomo LookupIPWithResolver: a configured ProxyServerHostResolver
        // is authoritative — failure never retries the default resolver.
        let main = hosts_only_resolver(&[("node.example", "192.0.2.1")]);
        let proxy = hosts_only_resolver(&[]);
        let hook = ResolverHostHook::new_with_proxy_resolver(main, Some(proxy));

        assert!(hook.resolve("node.example").await.is_err());
        assert!(hook.resolve_all_local("node.example").is_none());
    }
}
