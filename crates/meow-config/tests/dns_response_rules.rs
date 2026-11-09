use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use meow_config::{dns_parser::parse_dns, parse_raw_yaml, DnsConfig};
use meow_dns::{DnsServer, LocalAnswer, Resolver};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::net::UdpSocket;

struct Upstream {
    address: SocketAddr,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Upstream {
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let request = Message::from_vec(&buffer[..length]).unwrap();
                let mut response =
                    Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
                response.add_queries(request.queries.iter().cloned());
                let question = &request.queries[0];
                let data = match question.query_type {
                    RecordType::A => Some(RData::A(
                        "192.0.2.9".parse::<std::net::Ipv4Addr>().unwrap().into(),
                    )),
                    RecordType::AAAA => Some(RData::AAAA(
                        "2001:db8::9".parse::<std::net::Ipv6Addr>().unwrap().into(),
                    )),
                    RecordType::TXT => Some(RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![
                        "upstream".into(),
                    ]))),
                    _ => None,
                };
                if let Some(data) = data {
                    response.add_answer(Record::from_rdata(question.name.clone(), 60, data));
                }
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        Self {
            address,
            hits,
            task,
        }
    }
}

async fn configuration(
    upstream: SocketAddr,
    dns_options: &str,
    root_options: &str,
) -> anyhow::Result<DnsConfig> {
    let dns_options: String = dns_options
        .lines()
        .map(|line| format!("  {line}\n"))
        .collect();
    let raw = parse_raw_yaml(&format!(
        "ipv6: true\n{root_options}\ndns:\n  enable: true\n  use-system-hosts: false\n  nameserver: ['{upstream}']\n{dns_options}"
    ))?;
    parse_dns(
        &raw,
        None,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        None,
    )
    .await
}

fn query(name: &str, kind: RecordType) -> Vec<u8> {
    let mut message = Message::new(42, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.metadata.checking_disabled = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true).set_max_payload(1400);
    message.edns = Some(edns);
    message.to_vec().unwrap()
}

async fn answer(resolver: &Resolver, name: &str, kind: RecordType) -> Message {
    let request = query(name, kind);
    let local = DnsServer::try_answer_local(&request, resolver);
    let response = DnsServer::handle_query(&request, resolver).await.unwrap();
    match local {
        LocalAnswer::Answer(inline) => {
            assert_eq!(inline.response, response, "inline/task wire parity");
        }
        LocalAnswer::Upstream => {}
        LocalAnswer::Drop => panic!("valid question dropped"),
    }
    Message::from_vec(&response).unwrap()
}

#[tokio::test]
async fn ordered_types_and_static_records_answer_without_upstream() {
    let upstream = Upstream::start().await;
    let config = configuration(
        upstream.address,
        r#"response-rules:
  - {match: '+.example.test', types: [HTTPS, SVCB], action: nodata}
  - {match: '+.example.test', action: refused}
  - {match: 'static.test', action: address, address: 192.0.2.7, ttl: 42}
  - {match: 'v6.test', action: address, address: '2001:db8::7', ttl: 0}"#,
        "",
    )
    .await
    .unwrap();
    for kind in [
        RecordType::HTTPS,
        RecordType::SVCB,
        RecordType::A,
        RecordType::AAAA,
        RecordType::TXT,
    ] {
        let response = answer(&config.resolver, "www.example.test", kind).await;
        let expected = if matches!(kind, RecordType::HTTPS | RecordType::SVCB) {
            ResponseCode::NoError
        } else {
            ResponseCode::Refused
        };
        assert_eq!(response.metadata.response_code, expected);
        assert!(response.answers.is_empty());
        let edns = response.edns.unwrap();
        assert!(edns.flags().dnssec_ok);
        assert_eq!(edns.max_payload(), 1232);
        assert!(response.metadata.recursion_desired && response.metadata.checking_disabled);
    }
    let response = answer(&config.resolver, "static.test", RecordType::A).await;
    assert_eq!(response.answers[0].ttl, 42);
    assert_eq!(
        response.answers[0].data,
        RData::A("192.0.2.7".parse::<std::net::Ipv4Addr>().unwrap().into())
    );
    for kind in [RecordType::AAAA, RecordType::TXT, RecordType::HTTPS] {
        let response = answer(&config.resolver, "static.test", kind).await;
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
    }
    let response = answer(&config.resolver, "v6.test", RecordType::AAAA).await;
    assert_eq!(response.answers[0].ttl, 0);
    assert!(matches!(response.answers[0].data, RData::AAAA(_)));
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn fake_ip_rules_override_filter_but_hosts_and_forward_win() {
    let upstream = Upstream::start().await;
    let config = configuration(
        upstream.address,
        r#"enhanced-mode: fake-ip
fake-ip-filter: ['+.example.test']
response-rules:
  - {match: 'real.example.test', action: forward}
  - {match: '+.example.test', action: fake-ip}"#,
        "hosts: {'host.example.test': 192.0.2.44}",
    )
    .await
    .unwrap();
    let fake = answer(&config.resolver, "fake.example.test", RecordType::A).await;
    let RData::A(ip) = fake.answers[0].data else {
        panic!("A required");
    };
    assert!(config.resolver.is_fake_ip(ip.0.into()));
    assert!(config.resolver.fake_ip_active_for("fake.example.test"));
    assert!(!config.resolver.fake_ip_active_for("real.example.test"));
    assert!(
        answer(&config.resolver, "fake.example.test", RecordType::AAAA)
            .await
            .answers
            .is_empty()
    );
    let host = answer(&config.resolver, "host.example.test", RecordType::A).await;
    assert_eq!(
        host.answers[0].data,
        RData::A("192.0.2.44".parse::<std::net::Ipv4Addr>().unwrap().into())
    );
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
    let real = answer(&config.resolver, "real.example.test", RecordType::A).await;
    assert_eq!(
        real.answers[0].data,
        RData::A("192.0.2.9".parse::<std::net::Ipv4Addr>().unwrap().into())
    );
    let txt = answer(&config.resolver, "fake.example.test", RecordType::TXT).await;
    assert!(matches!(txt.answers[0].data, RData::TXT(_)));
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 2);
    // Outbound and proxy-server hostname resolution must use real addresses.
    let ips = config
        .resolver
        .resolve_ips("fake.example.test")
        .await
        .unwrap()
        .unwrap();
    assert!(ips.iter().all(|ip| !config.resolver.in_fake_ip_range(*ip)));
}

#[tokio::test]
async fn malformed_queries_and_edns_versions_precede_rules() {
    let upstream = Upstream::start().await;
    let config = configuration(
        upstream.address,
        "response-rules:\n  - {match: '*', action: refused}",
        "",
    )
    .await
    .unwrap();
    for kind in [RecordType::A, RecordType::AAAA, RecordType::HTTPS] {
        let good = query("example.test", kind);
        let mut duplicate = good.clone();
        duplicate[10..12].copy_from_slice(&2u16.to_be_bytes());
        duplicate.extend_from_slice(&good[good.len() - 11..]);
        let mut truncated = good.clone();
        truncated.pop();
        let mut unsupported = Message::from_vec(&good).unwrap();
        unsupported.edns.as_mut().unwrap().set_version(1);
        for (request, code) in [
            (duplicate, ResponseCode::FormErr),
            (truncated, ResponseCode::FormErr),
            (unsupported.to_vec().unwrap(), ResponseCode::BADVERS),
        ] {
            let response = DnsServer::handle_query(&request, &config.resolver)
                .await
                .unwrap();
            assert_eq!(
                u16::from(Message::from_vec(&response).unwrap().metadata.response_code),
                u16::from(code)
            );
            if let LocalAnswer::Answer(inline) =
                DnsServer::try_answer_local(&request, &config.resolver)
            {
                assert_eq!(inline.response, response);
            } else {
                assert_eq!(kind, RecordType::HTTPS);
            }
        }
    }
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_rules_fail_loading() {
    for rule in [
        "{match: '*', action: fake-ip}",
        "{match: '*', types: [], action: refused}",
        "{match: '*', types: [TYPO], action: refused}",
        "{match: '*', action: address}",
        "{match: '*', action: refused, ttl: 4}",
        "{match: '', action: refused}",
        "{match: 'rule-set:missing', action: refused}",
        "{match: 'geosite:cn', action: refused}",
        "{match: 'unknown:x', action: refused}",
        "{match: '*', action: refuesd}",
        "{match: '*', action: refused, typoes: [A]}",
    ] {
        let options = format!("response-rules:\n  - {rule}");
        assert!(
            configuration("127.0.0.1:9".parse().unwrap(), &options, "")
                .await
                .is_err(),
            "{rule}"
        );
    }
}

#[tokio::test]
async fn udp_listener_answers_generic_and_address_rules() {
    let upstream = Upstream::start().await;
    let config = configuration(
        upstream.address,
        "response-rules:\n  - {match: '*', action: refused}",
        "",
    )
    .await
    .unwrap();
    let server = DnsServer::new(Arc::clone(&config.resolver), "127.0.0.1:0".parse().unwrap())
        .bind()
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        server.run().await.unwrap();
    });
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for kind in [RecordType::A, RecordType::AAAA, RecordType::HTTPS] {
        let request = query("example.test", kind);
        socket.send_to(&request, address).await.unwrap();
        let mut buffer = [0u8; 4096];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        let expected = DnsServer::handle_query(&request, &config.resolver)
            .await
            .unwrap();
        assert_eq!(&buffer[..length], &expected);
    }
    task.abort();
    let _ = task.await;
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn per_family_fake_ip_and_hosts_precedence() {
    let upstream = Upstream::start().await;
    let config = configuration(
        upstream.address,
        r#"enhanced-mode: fake-ip
fake-ip-range: 'fd00::/112'
response-rules:
  - {match: '*', types: [A], action: nodata}
  - {match: '*', action: fake-ip}"#,
        "hosts: {'host.test': 192.0.2.44}",
    )
    .await
    .unwrap();
    assert!(answer(&config.resolver, "v6.test", RecordType::A)
        .await
        .answers
        .is_empty());
    let response = answer(&config.resolver, "v6.test", RecordType::AAAA).await;
    let RData::AAAA(ip) = response.answers[0].data else {
        panic!("AAAA required");
    };
    assert!(config.resolver.is_fake_ip(ip.0.into()));
    assert!(config.resolver.fake_ip_active_for("v6.test"));
    assert!(!config.resolver.fake_ip_active_for("host.test"));
    assert_eq!(
        answer(&config.resolver, "host.test", RecordType::A)
            .await
            .answers
            .len(),
        1
    );
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn static_v6_precedes_global_ipv6_suppression() {
    let raw = parse_raw_yaml(
        r#"ipv6: false
dns:
  enable: true
  use-system-hosts: false
  nameserver: [rcode://refused]
  response-rules:
    - {match: 'static.test', action: address, address: '2001:db8::7', ttl: 42}
"#,
    )
    .unwrap();
    let config = parse_dns(
        &raw,
        None,
        None,
        &HashMap::new(),
        None,
        &HashMap::new(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        answer(&config.resolver, "static.test", RecordType::AAAA)
            .await
            .answers
            .len(),
        1
    );
}

#[tokio::test]
async fn rule_answers_precede_warm_cache_and_echo_edns_presence() {
    let upstream = Upstream::start().await;
    let config = configuration(
        upstream.address,
        "response-rules:\n  - {match: '*', action: refused}",
        "",
    )
    .await
    .unwrap();
    assert!(config
        .resolver
        .resolve_ips("cached.test")
        .await
        .unwrap()
        .is_some());
    let hits = upstream.hits.load(Ordering::SeqCst);
    let mut request = Message::from_vec(&query("cached.test", RecordType::A)).unwrap();
    request.edns = None;
    let wire = DnsServer::handle_query(&request.to_vec().unwrap(), &config.resolver)
        .await
        .unwrap();
    let response = Message::from_vec(&wire).unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    assert!(response.edns.is_none());
    assert_eq!(upstream.hits.load(Ordering::SeqCst), hits);
}

#[tokio::test]
async fn forwarding_keeps_wire_name_and_stops_rule_scan() {
    let upstream = Upstream::start().await;
    let config = configuration(upstream.address,
        "response-rules:\n  - {match: '*', types: [TXT], action: forward}\n  - {match: '*', action: refused}", "").await.unwrap();
    let mut request = Message::from_vec(&query("example.test", RecordType::TXT)).unwrap();
    request.queries[0].name = Name::from_labels([b"a.b".as_slice(), b"example", b"test"]).unwrap();
    let wire = DnsServer::handle_query(&request.to_vec().unwrap(), &config.resolver)
        .await
        .unwrap();
    let response = Message::from_vec(&wire).unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.queries[0].name, request.queries[0].name);
    assert!(matches!(response.answers[0].data, RData::TXT(_)));
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
}
