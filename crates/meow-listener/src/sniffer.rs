use meow_common::sniffer::{sniff_http, sniff_tls, SnifferConfig};
use meow_common::Metadata;
use meow_trie::DomainTrie;
use std::collections::HashMap;
use tokio::net::TcpStream;
use tracing::debug;

enum Proto {
    Tls,
    Http,
}

pub struct SnifferRuntime {
    cfg: SnifferConfig,
    skip: DomainTrie<()>,
    force: DomainTrie<()>,
    port_map: HashMap<u16, Proto>,
}

impl SnifferRuntime {
    pub fn new(cfg: SnifferConfig) -> Self {
        let mut skip = DomainTrie::new();
        for d in &cfg.skip_domain {
            skip.insert(d, ());
        }
        let mut force = DomainTrie::new();
        for d in &cfg.force_domain {
            force.insert(d, ());
        }
        let mut port_map = HashMap::new();
        for &p in &cfg.tls_ports {
            port_map.insert(p, Proto::Tls);
        }
        for &p in &cfg.http_ports {
            port_map.insert(p, Proto::Http);
        }
        Self {
            cfg,
            skip,
            force,
            port_map,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.cfg.enable
    }

    /// Peek at the stream's first bytes and populate `metadata.sniff_host`.
    ///
    /// Never returns an error — all failure modes (IO error, timeout, parse
    /// failure, skip-domain discard) collapse to a silent no-op that leaves
    /// `metadata` unchanged.
    pub async fn sniff(&self, stream: &TcpStream, metadata: &mut Metadata) {
        if !self.cfg.enable {
            return;
        }

        // parse-pure-ip gate: skip if host is already a non-IP domain name,
        // unless that domain is in the force list. The IP test is the same
        // `metadata_ip_literal` the apply side uses — a `IpAddr::parse`
        // check would miss bracketed IPv6 (`[::1]` reads as a "domain" and
        // the destination would never be sniffed).
        if self.cfg.parse_pure_ip
            && !metadata.host.is_empty()
            && meow_common::metadata_ip_literal(&metadata.host).is_none()
            && self.force.search(&metadata.host).is_none()
        {
            return;
        }

        // Per-port protocol dispatch.
        let Some(proto) = self.port_map.get(&metadata.dst_port) else {
            return;
        };

        // Bounded peek (8 KiB) with configurable timeout. A TLS record can
        // arrive fragmented across segments — peek() returns whatever is
        // buffered at call time, so keep re-peeking until the declared
        // record length is buffered (peek always returns the accumulated
        // prefix, so re-peeking is cheap and idempotent) or the deadline
        // hits. HTTP and non-TLS bytes parse on the first chunk.
        let mut buf = [0u8; 8192];
        let gather = async {
            let mut poll = std::time::Duration::from_millis(5);
            loop {
                match stream.peek(&mut buf).await {
                    Ok(0) | Err(_) => return None,
                    Ok(n) => {
                        // Keep waiting only while the buffered prefix can
                        // still grow into a complete TLS record: handshake
                        // record type (0x16), TLS version major (0x03 —
                        // filters junk that happens to start with 0x16),
                        // and a short or incomplete header/record.
                        // Anything else parses on the first chunk.
                        let need_more = matches!(proto, Proto::Tls)
                            && n < buf.len()
                            && buf[0] == 0x16
                            && (n < 2 || buf[1] == 0x03)
                            && (n < 5 || n < 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize);
                        if !need_more {
                            return Some(n);
                        }
                        // peek is level-triggered — buffered data returns
                        // immediately, so poll with backoff rather than
                        // spin until the rest lands (bounded by the
                        // deadline).
                        tokio::time::sleep(poll).await;
                        poll = (poll * 2).min(std::time::Duration::from_millis(50));
                    }
                }
            }
        };
        let Ok(Some(n)) = tokio::time::timeout(self.cfg.timeout, gather).await else {
            // Peek errored or timed out — leave metadata unchanged.
            return;
        };

        let sniffed = match proto {
            Proto::Tls => sniff_tls(&buf[..n]),
            Proto::Http => sniff_http(&buf[..n]),
        };

        if let Some(host) = sniffed {
            self.maybe_apply_sniff(&host, metadata);
        }
    }

    /// Apply a pre-extracted hostname to `metadata`, honouring `skip-domain`
    /// and `override-destination`. Used for the HTTP proxy plain-request path
    /// where headers are already read into a buffer rather than peeked.
    ///
    /// Priority: an explicit domain authority already in `metadata.host` —
    /// a CONNECT target, an absolute-form URI authority, a SOCKS5 domain,
    /// anything that is neither empty nor an IP literal — outranks a
    /// conflicting sniffed name, so the sniff is not adopted then. Rules
    /// match on `sniff_host` while the dial uses `host`, so adopting a
    /// different name would route by one host and dial the other:
    /// `GET http://evil.com/` + `Host: good.example` would slip past
    /// `DOMAIN,evil.com,REJECT` yet still dial evil.com. The sniff is
    /// adopted only when the flow has no routing name of its own — an
    /// empty `host` or an IP literal — which is what sniffing exists
    /// for. Two opt-ins override that priority: `force-domain` listing
    /// `metadata.host` (the user asked that specific domain to be routed
    /// by the sniffed name anyway — e.g. a CDN front whose real SNI the
    /// authority hides), and `override-destination: true`, which rewrites
    /// `host` itself so rules and dial stay consistent.
    pub fn maybe_apply_sniff(&self, host: &str, metadata: &mut Metadata) {
        if !self.cfg.enable {
            return;
        }
        if self.skip.search(host).is_some() {
            return;
        }
        if !self.cfg.override_destination
            && !metadata.host.is_empty()
            && meow_common::metadata_ip_literal(&metadata.host).is_none()
            && self.force.search(&metadata.host).is_none()
        {
            return;
        }
        debug!("sniffer: {} → {}", metadata, host);
        metadata.sniff_host = host.into();
        if self.cfg.override_destination {
            metadata.host = host.into();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{ConnType, Network};
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn make_metadata(host: &str, port: u16) -> Metadata {
        Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Socks5,
            dst_port: port,
            host: host.into(),
            ..Default::default()
        }
    }

    fn make_runtime(cfg: SnifferConfig) -> SnifferRuntime {
        SnifferRuntime::new(cfg)
    }

    // Build a minimal TLS ClientHello with the given SNI hostname.
    fn build_client_hello(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();
        let sni_entry_len = 3 + name_bytes.len();
        let sni_list_len = sni_entry_len;
        let sni_ext_data_len = 2 + sni_list_len;

        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&[0x00, 0x00]);
        sni_ext.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        sni_ext.push(0x00);
        sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name_bytes);

        let extensions_len = sni_ext.len();
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0x00);
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
        hello.extend_from_slice(&[0x01, 0x00]);
        hello.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        hello.extend_from_slice(&sni_ext);

        let handshake_len = hello.len();
        let mut handshake = vec![
            0x01,
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&hello);

        let record_len = handshake.len();
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(record_len as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    async fn make_stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn sniffer_disabled_noop() {
        let cfg = SnifferConfig {
            enable: false,
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("example.com");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(
            meta.sniff_host, "",
            "disabled sniffer must not populate sniff_host"
        );
    }

    #[tokio::test]
    async fn sniffer_parse_pure_ip_skips_domain() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: true,
            tls_ports: vec![443],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        // host is already a domain → parse_pure_ip short-circuits
        let (_client, server) = make_stream_pair().await;
        let mut meta = make_metadata("example.com", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "");
    }

    #[tokio::test]
    async fn sniffer_force_domain_opts_into_sniffed_name() {
        // host is a subdomain matched by "+.example.com" in force_domain →
        // the parse_pure_ip short-circuit is bypassed, the sniffer runs,
        // and the force opt-in lets the sniffed name land in `sniff_host`
        // even though `host` is already a domain: force-domain is the
        // user's explicit "route this authority by what the wire says".
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: true,
            tls_ports: vec![443],
            force_domain: vec!["+.example.com".into()],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("cdn.other.example");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("www.example.com", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "cdn.other.example");
        assert_eq!(
            meta.host, "www.example.com",
            "without override-destination the dial target is unchanged"
        );

        // The apex is covered by "+.example.com" too (upstream `+.`
        // semantics include the root) — the same opt-in applies to the
        // bare domain.
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("example.com");
        client.write_all(&hello).await.unwrap();
        let mut meta = make_metadata("example.com", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(
            meta.sniff_host, "example.com",
            "+.example.com must force-sniff the apex itself"
        );
    }

    #[tokio::test]
    async fn sniffer_domain_host_outside_force_domain_is_not_adopted() {
        // Control for the force opt-in: `parse_pure_ip: false` opens the
        // peek for every flow, but `host` names a domain NOT listed in
        // force_domain → the apply step still refuses the conflicting
        // sniffed name (rules would read `sniff_host` while the dial
        // uses `host`).
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: false,
            tls_ports: vec![443],
            force_domain: vec!["+.example.com".into()],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("cdn.other.example");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("unlisted.example.org", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(
            meta.sniff_host, "",
            "a domain authority outside force-domain beats a conflicting sniffed name"
        );
        assert_eq!(meta.host, "unlisted.example.org");
    }

    #[tokio::test]
    async fn sniffer_skip_domain_discards_result() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: false,
            tls_ports: vec![443],
            skip_domain: vec!["+.example.com".into()],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("ads.example.com");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(
            meta.sniff_host, "",
            "skip-domain must discard the sniffed result"
        );

        // The apex is covered by "+.example.com" too (upstream `+.`
        // semantics include the root) — a sniffed apex hostname is
        // discarded the same way.
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("example.com");
        client.write_all(&hello).await.unwrap();
        let mut meta = make_metadata("", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(
            meta.sniff_host, "",
            "skip-domain must discard the apex result too"
        );
    }

    #[tokio::test]
    async fn sniffer_fragmented_tls_record_waits_for_full_record() {
        // A ClientHello delivered in multiple TCP segments must still be
        // parsed — the gather loop re-peeks until the declared record
        // length is buffered (a single peek would see a truncated record
        // and lose the SNI).
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: false,
            tls_ports: vec![443],
            timeout: std::time::Duration::from_secs(1),
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("sni.example.com");

        // Three fragments: a sub-header first chunk (can't even classify
        // the record), then part of the handshake, then the remainder —
        // each delayed past a poll interval so the gather loop iterates.
        client.write_all(&hello[..3]).await.unwrap();
        let mid = hello[3..20].to_vec();
        let rest = hello[20..].to_vec();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            client.write_all(&mid).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            client.write_all(&rest).await.unwrap();
        });

        let mut meta = make_metadata("", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "sni.example.com");
    }

    #[tokio::test]
    async fn sniffer_override_destination_mutates_host() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: true,
            override_destination: true,
            tls_ports: vec![443],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("example.com");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("93.184.216.34", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "example.com");
        assert_eq!(meta.host, "example.com");
    }

    #[tokio::test]
    async fn sniffer_override_destination_false_leaves_host() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: true,
            override_destination: false,
            tls_ports: vec![443],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("example.com");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("93.184.216.34", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "example.com");
        assert_eq!(meta.host, "93.184.216.34");
    }

    #[tokio::test]
    async fn sniffer_port_dispatch_no_op_for_unregistered_port() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: false,
            tls_ports: vec![443],
            http_ports: vec![80],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("example.com");
        client.write_all(&hello).await.unwrap();

        // Port 22 is not in TLS or HTTP port list.
        let mut meta = make_metadata("", 22);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "");
    }

    #[tokio::test]
    async fn sniffer_timeout_wall_time_bounded() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: false,
            timeout: std::time::Duration::from_millis(100),
            tls_ports: vec![443],
            ..Default::default()
        };
        let timeout = cfg.timeout;
        let rt = make_runtime(cfg);
        // Connect but never send data — simulates a silent client.
        let (_client, server) = make_stream_pair().await;
        let mut meta = make_metadata("", 443);

        let start = std::time::Instant::now();
        rt.sniff(&server, &mut meta).await;
        let elapsed = start.elapsed();

        assert_eq!(meta.sniff_host, "");
        let slack = std::time::Duration::from_millis(50);
        assert!(
            elapsed <= timeout + slack,
            "sniff must return within timeout + 50ms slack, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn sniffer_parse_pure_ip_runs_on_ip_host() {
        // host is a literal IP → parse_pure_ip lets sniff proceed even with the
        // gate enabled.
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: true,
            tls_ports: vec![443],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("example.com");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("93.184.216.34", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "example.com");
    }

    #[tokio::test]
    async fn sniffer_parse_pure_ip_runs_on_bracketed_ipv6_host() {
        // A bracketed literal `[::1]` is an IP literal for the gate just
        // as it is for the apply side (both use `metadata_ip_literal`) —
        // a plain `IpAddr::parse` check would misread it as a domain and
        // skip sniffing entirely.
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: true,
            tls_ports: vec![443],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("v6.example.com");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("[::1]", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "v6.example.com");
        assert_eq!(meta.host, "[::1]");
    }

    #[tokio::test]
    async fn sniffer_parse_pure_ip_disabled_runs_on_domain_host() {
        // parse_pure_ip = false → the host-already-a-domain short-circuit is
        // skipped and sniffing runs normally. With `override-destination`
        // the sniffed name lands on both fields; without it the apply
        // step would refuse — an explicit domain authority wins.
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: false,
            override_destination: true,
            tls_ports: vec![443],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("real-sni.example.com");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("placeholder.example.com", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "real-sni.example.com");
        assert_eq!(meta.host, "real-sni.example.com");
    }

    #[test]
    fn maybe_apply_sniff_cases() {
        struct Case {
            name: &'static str,
            enable: bool,
            override_destination: bool,
            skip_domain: &'static [&'static str],
            force_domain: &'static [&'static str],
            meta_host: &'static str,
            meta_port: u16,
            sniffed: &'static str,
            expected_sniff_host: &'static str,
            expected_host: &'static str,
        }

        let cases = [
            // Sniffer disabled → no-op even with override-destination on.
            Case {
                name: "disabled_is_noop",
                enable: false,
                override_destination: true,
                skip_domain: &[],
                force_domain: &[],
                meta_host: "1.2.3.4",
                meta_port: 443,
                sniffed: "example.com",
                expected_sniff_host: "",
                expected_host: "1.2.3.4",
            },
            // skip-domain match → the sniffed host is discarded entirely.
            Case {
                name: "skip_domain_drops_host",
                enable: true,
                override_destination: true,
                skip_domain: &["+.ads.example.com"],
                force_domain: &[],
                meta_host: "1.2.3.4",
                meta_port: 80,
                sniffed: "tracker.ads.example.com",
                expected_sniff_host: "",
                expected_host: "1.2.3.4",
            },
            // "+." covers the apex too (upstream semantics include the
            // root): a sniffed apex hostname is discarded like a subdomain.
            Case {
                name: "skip_domain_drops_apex",
                enable: true,
                override_destination: true,
                skip_domain: &["+.ads.example.com"],
                force_domain: &[],
                meta_host: "1.2.3.4",
                meta_port: 80,
                sniffed: "ads.example.com",
                expected_sniff_host: "",
                expected_host: "1.2.3.4",
            },
            // override-destination on → both sniff_host and host are rewritten.
            Case {
                name: "override_destination_mutates_host",
                enable: true,
                override_destination: true,
                skip_domain: &[],
                force_domain: &[],
                meta_host: "1.2.3.4",
                meta_port: 80,
                sniffed: "example.com",
                expected_sniff_host: "example.com",
                expected_host: "example.com",
            },
            // override-destination off → only sniff_host is recorded.
            Case {
                name: "override_false_keeps_host",
                enable: true,
                override_destination: false,
                skip_domain: &[],
                force_domain: &[],
                meta_host: "1.2.3.4",
                meta_port: 80,
                sniffed: "example.com",
                expected_sniff_host: "example.com",
                expected_host: "1.2.3.4",
            },
            // Priority rule: an explicit domain authority in `host` beats a
            // conflicting sniffed name — rules read `sniff_host` while the
            // dial uses `host`, so adopting here would route by one name
            // and dial the other. Nothing is adopted.
            Case {
                name: "domain_host_beats_conflicting_sniff",
                enable: true,
                override_destination: false,
                skip_domain: &[],
                force_domain: &[],
                meta_host: "evil.com",
                meta_port: 80,
                sniffed: "good.example",
                expected_sniff_host: "",
                expected_host: "evil.com",
            },
            // An empty `host` carries no routing name — the sniffed name
            // is adopted; recovering that name is what sniffing is for.
            Case {
                name: "empty_host_adopts_sniff",
                enable: true,
                override_destination: false,
                skip_domain: &[],
                force_domain: &[],
                meta_host: "",
                meta_port: 80,
                sniffed: "good.example",
                expected_sniff_host: "good.example",
                expected_host: "",
            },
            // A bracketed IPv6 literal is still an IP literal (the HTTP
            // listeners keep the brackets in `host`), so the sniff is
            // adopted like for a plain literal.
            Case {
                name: "bracketed_v6_host_adopts_sniff",
                enable: true,
                override_destination: false,
                skip_domain: &[],
                force_domain: &[],
                meta_host: "[::1]",
                meta_port: 80,
                sniffed: "good.example",
                expected_sniff_host: "good.example",
                expected_host: "[::1]",
            },
            // `override-destination` rewrites `host` with the sniffed
            // name, keeping rules and dial consistent — adoption is
            // unconditional even against a domain authority.
            Case {
                name: "override_destination_beats_domain_host",
                enable: true,
                override_destination: true,
                skip_domain: &[],
                force_domain: &[],
                meta_host: "evil.com",
                meta_port: 80,
                sniffed: "good.example",
                expected_sniff_host: "good.example",
                expected_host: "good.example",
            },
            // `force-domain` is the explicit opt-in to the reroute: a
            // domain `host` listed there is adopted anyway, so rules
            // route on the sniffed name while the dial keeps `host`.
            Case {
                name: "force_domain_hit_adopts_sniff_on_domain_host",
                enable: true,
                override_destination: false,
                skip_domain: &[],
                force_domain: &["+.example.com"],
                meta_host: "www.example.com",
                meta_port: 443,
                sniffed: "cdn.other.example",
                expected_sniff_host: "cdn.other.example",
                expected_host: "www.example.com",
            },
            // The same domain `host` outside the force list stays
            // refused — the opt-in is per-domain, not global.
            Case {
                name: "force_domain_miss_keeps_domain_authority",
                enable: true,
                override_destination: false,
                skip_domain: &[],
                force_domain: &["+.example.com"],
                meta_host: "unlisted.example.org",
                meta_port: 443,
                sniffed: "cdn.other.example",
                expected_sniff_host: "",
                expected_host: "unlisted.example.org",
            },
        ];

        let mut failures = Vec::new();
        for case in cases {
            let cfg = SnifferConfig {
                enable: case.enable,
                override_destination: case.override_destination,
                skip_domain: case.skip_domain.iter().copied().map(Into::into).collect(),
                force_domain: case.force_domain.iter().copied().map(Into::into).collect(),
                ..Default::default()
            };
            let rt = make_runtime(cfg);
            let mut meta = make_metadata(case.meta_host, case.meta_port);
            rt.maybe_apply_sniff(case.sniffed, &mut meta);
            if meta.sniff_host != case.expected_sniff_host {
                failures.push(format!(
                    "[{}] sniff_host: expected {:?}, got {:?}",
                    case.name, case.expected_sniff_host, meta.sniff_host
                ));
            }
            if meta.host != case.expected_host {
                failures.push(format!(
                    "[{}] host: expected {:?}, got {:?}",
                    case.name, case.expected_host, meta.host
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "maybe_apply_sniff cases failed:\n{}",
            failures.join("\n")
        );
    }

    #[tokio::test]
    async fn sniffer_http_port_dispatches_to_http_parser() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: false,
            http_ports: vec![80],
            tls_ports: vec![],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let mut meta = make_metadata("", 80);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "example.com");
    }
}
