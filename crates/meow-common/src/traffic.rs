//! Per-proxy byte totals, shared by the tunnel's statistics and the
//! `dialer-proxy` front hops that count into them.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::atomic::{AtomicI, Int};

/// Bytes relayed through one proxy since the tunnel started: the TCP
/// connections whose chain starts at it (`chains[0]`, the leaf that dials),
/// the UDP flows dialled through it, and the `dialer-proxy` hops it carried
/// for another proxy. Flows hold the `Arc` and bump it directly, so the relay
/// never looks a proxy up per chunk.
#[derive(Debug, Default)]
pub struct ProxyTraffic {
    upload: AtomicI,
    download: AtomicI,
}

impl ProxyTraffic {
    pub fn add_upload(&self, n: Int) {
        self.upload.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_download(&self, n: Int) {
        self.download.fetch_add(n, Ordering::Relaxed);
    }

    pub fn upload_bytes(&self) -> Int {
        self.upload.load(Ordering::Relaxed)
    }

    pub fn download_bytes(&self) -> Int {
        self.download.load(Ordering::Relaxed)
    }
}

/// Where a `dialer-proxy` front hop finds the totals of the member that
/// carries it. The tunnel's statistics implement it.
pub trait ProxyTrafficSource: Send + Sync {
    /// `proxy`'s totals, created on its first flow; `None` when per-proxy
    /// totals are off. Setup path only, never per chunk.
    fn proxy_counters(&self, proxy: &str) -> Option<Arc<ProxyTraffic>>;
}
