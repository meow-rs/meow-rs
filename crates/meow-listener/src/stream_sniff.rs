//! First-payload sniff window shared by the userspace-stack inbounds —
//! the TUN lwIP path and the WireGuard inbound's smoltcp path.
//!
//! Both terminate the client's TCP inside a userspace stack, so no kernel
//! `peek` exists: the sniffer has to consume real bytes to see a hostname.
//! The contract is the TUN one (issue #695):
//!
//! - `Ok(bytes)` — the client spoke first; `bytes` is the relay prefix.
//! - `Ok(empty)` — the window expired in silence: dial anyway, the server
//!   may be the one to speak first. No allocation is kept.
//! - `Err(_)` — EOF or reset before any payload: drop the flow.

use std::io;
use std::time::Duration;

use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

/// How long an accepted inner-TCP flow may take to produce its first
/// payload before we dial it blind.
pub(crate) const STREAM_SNIFF_WINDOW: Duration = Duration::from_millis(200);

/// Bytes a single sniff read asks for — enough to start a TLS record or
/// an HTTP request line; longer reads are gathered by the caller's
/// `tls_record_incomplete` loop instead.
const STREAM_FIRST_READ: usize = 256;

/// Upper bound on the prefix the caller may gather while completing a
/// fragmented TLS record — a ClientHello fits comfortably inside it.
pub(crate) const STREAM_SNIFF_GATHER_MAX: usize = 16 * 1024;

/// Sniff the client's first payload within [`STREAM_SNIFF_WINDOW`] (the
/// TCP handshake is already done by the userspace stack).
pub(crate) async fn sniff_first_payload<R>(tcp: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    sniff_first_payload_within(tcp, STREAM_SNIFF_WINDOW).await
}

/// [`sniff_first_payload`] with an explicit window. The stream stays usable
/// after the window expires: `poll_read` on the stream shims only consumes
/// a chunk on the poll that returns it, so dropping the pending read loses
/// nothing — the relay picks up whatever arrives later.
pub(crate) async fn sniff_first_payload_within<R>(
    tcp: &mut R,
    window: Duration,
) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; STREAM_FIRST_READ];
    let Ok(read) = timeout(window, tcp.read(&mut buf)).await else {
        return Ok(Vec::new());
    };
    let n = read?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed before sending payload",
        ));
    }
    buf.truncate(n);
    Ok(buf)
}
