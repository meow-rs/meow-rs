#[derive(Debug, Clone, Default)]
pub struct Config {
    pub server_addr: String,
    pub server_name: String,
    pub auth: String,
    pub insecure: bool,
    pub rx_bps: u64,
    pub obfs: Option<ObfsConfig>,
    pub hop_ports: String,
    pub hop_interval_min_secs: u64,
    pub hop_interval_max_secs: u64,
    pub pin_sha256: String,
    /// Return after sending the request instead of waiting for the remote dial response.
    pub fast_open: bool,
    /// QUIC flow-control windows (mihomo's `*-receive-window`); `None` picks
    /// the default.
    pub windows: ReceiveWindows,
}

/// mihomo's `initial-/max-stream-receive-window` and
/// `initial-/max-connection-receive-window`, in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReceiveWindows {
    pub initial_stream: Option<u64>,
    pub max_stream: Option<u64>,
    pub initial_conn: Option<u64>,
    pub max_conn: Option<u64>,
}

/// UDP datagram obfuscation below QUIC (`obfs:`).
#[derive(Debug, Clone)]
pub enum ObfsConfig {
    Salamander {
        password: String,
    },
    /// Salamander plus handshake fragmentation. The sizes are the resolved
    /// wire-datagram range (see [`super::gecko_packet_sizes`]).
    Gecko {
        password: String,
        min_packet_size: u16,
        max_packet_size: u16,
    },
}
