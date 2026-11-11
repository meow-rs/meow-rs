#![cfg(feature = "hysteria2")]
// Separate test process: the host resolver hook is process-global.
use meow_common::{HostResolver, Metadata, ProxyAdapter};
use meow_proxy::{Hy2Adapter, Hy2Options};
use std::{
    io,
    net::IpAddr,
    sync::{Arc, Weak},
};
use tokio::time::{timeout, Duration};

struct ReentrantHook(Weak<Hy2Adapter>);
#[async_trait::async_trait]
impl HostResolver for ReentrantHook {
    async fn resolve(&self, host: &str) -> io::Result<IpAddr> {
        self.resolve_all(host).await.map(|ips| ips[0])
    }
    async fn resolve_all(&self, _: &str) -> io::Result<Vec<IpAddr>> {
        // A DNS-over-proxy exchange needs the same runtime pool whose
        // server endpoint the outer call is currently resolving.
        let proxy = self.0.upgrade().unwrap();
        let _ = proxy.dial_udp(&Metadata::default()).await;
        Err(io::Error::other("fixture stops after transport initiation"))
    }
    fn resolve_all_local(&self, _: &str) -> Option<Vec<IpAddr>> {
        // Existing reentry protection can use this answer only if the
        // nested dial reaches resolution instead of waiting on its own lock.
        Some(vec!["127.0.0.1".parse().unwrap()])
    }
}
struct ClearHook;
impl Drop for ClearHook {
    fn drop(&mut self) {
        meow_common::socket_protect::clear_host_resolver();
    }
}
#[tokio::test]
async fn pooled_endpoint_resolution_can_reenter_before_connect_lock() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy = Arc::new(
        Hy2Adapter::new(Hy2Options {
            name: "bootstrap-fixture".into(),
            server: "bootstrap.invalid".into(),
            port: socket.local_addr().unwrap().port(),
            password: "fixture".into(),
            sni: Some("localhost".into()),
            skip_cert_verify: true,
            udp: true,
            up_bps: 0,
            down_bps: 0,
            obfs: None,
            obfs_password: None,
            ports: None,
            hop_interval: None,
            fingerprint: None,
            fast_open: false,
            windows: Default::default(),
        })
        .unwrap(),
    );
    meow_common::socket_protect::set_host_resolver(Arc::new(ReentrantHook(Arc::downgrade(&proxy))));
    let _clear = ClearHook;
    // Drop/cancel the same future after observing a real QUIC Initial. This
    // fixture does not complete QUIC authentication or a DNS response.
    let local = {
        let mut packet = [0u8; 2048];
        let metadata = Metadata::default();
        let dial = proxy.dial_udp(&metadata);
        tokio::pin!(dial);
        let reached = timeout(Duration::from_secs(2), async {
            tokio::select! {
                reply = &mut dial => panic!("unexpected dial completion: {}", reply.is_ok()),
                received = socket.recv_from(&mut packet) => received.unwrap().1,
            }
        })
        .await;
        assert!(
            reached.is_ok(),
            "nested bootstrap blocked before sending QUIC Initial"
        );
        reached.unwrap()
    };
    timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(rebound) = tokio::net::UdpSocket::bind(local).await {
                drop(rebound);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelling nested bootstrap retained the UDP socket");
}
