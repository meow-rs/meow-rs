use meow_common::{DnsMode, Metadata, Network, ProxyAdapter};
use meow_dns::{HostEntry, Resolver};
use meow_proxy::direct::DirectAdapter;
use meow_trie::DomainTrie;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::net::UdpSocket;

#[tokio::test]
async fn direct_udp_loopback_works_with_outbound_interface_binding() {
    // A separate test binary isolates the process-global binding registry.
    let _binding = std::env::var("MEOW_TEST_OUTBOUND_INTERFACE")
        .ok()
        .map(|interface| meow_common::install_outbound_interface(&interface).unwrap());
    for ip in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
        let ip: IpAddr = ip.parse().unwrap();
        let echo = UdpSocket::bind((ip.to_canonical(), 0)).await.unwrap();
        let address = SocketAddr::new(ip, echo.local_addr().unwrap().port());
        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        hosts.insert("loopback.test", vec![ip].into());
        let resolver = Arc::new(Resolver::new(
            vec![],
            vec![],
            DnsMode::Normal,
            hosts,
            true,
            true,
        ));
        let adapter = DirectAdapter::new().with_resolver(resolver);
        for host_only in [false, true] {
            let metadata = Metadata {
                network: Network::Udp,
                host: if host_only {
                    "loopback.test".into()
                } else {
                    ip.to_string().into()
                },
                dst_ip: (!host_only).then_some(ip),
                dst_port: address.port(),
                ..Default::default()
            };
            let connection = adapter.dial_udp(&metadata).await.unwrap();
            connection.write_packet(b"meow", &address).await.unwrap();
            let mut buffer = [0; 16];
            let (length, source) =
                tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            echo.send_to(&buffer[..length], source).await.unwrap();
            let (length, _) =
                tokio::time::timeout(Duration::from_secs(2), connection.read_packet(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&buffer[..length], b"meow");
            assert!(source.ip().to_canonical().is_loopback());
        }
    }
}
