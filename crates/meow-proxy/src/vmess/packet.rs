//! Plain VMess UDP: a `CommandUDP` (0x02) request whose body is a chunk
//! stream carrying exactly one datagram per record, in both directions.
//!
//! Wire reference: sing-vmess `client.go` — `DialPacketConn` runs
//! `dialRaw(.., CommandUDP, ..)`; `clientPacketConn.WriteTo` is one
//! `writer.Write(p)` (one chunk) and `ReadFrom` one `reader.Read(p)` (one
//! chunk, no `ChunkReader` re-slicing for UDP, `readBuffer` stays false).
//! The destination is fixed by the request header; per-packet addresses
//! do not exist on the wire.

use async_trait::async_trait;
use meow_common::{MeowError, ProxyPacketConn, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicBool;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use super::body::BodyCipher;
use super::header::{read_aead_response_header, response_body_keys, SealedHeader, Security};

/// Largest datagram one record can carry: u16 record length minus the AEAD tag.
const MAX_DATAGRAM: usize = u16::MAX as usize - crate::aead::TAG_LEN;

type Half = Box<dyn meow_transport::Stream>;

struct Reader {
    half: ReadHalf<Half>,
    cipher: BodyCipher,
    /// Response header is consumed lazily on the first read: a server may
    /// hold it back until it has seen the first request datagram.
    header_pending: bool,
    resp_key: [u8; 16],
    resp_iv: [u8; 16],
    resp_v: u8,
    buf: Vec<u8>,
}

pub(super) struct VmessPacketConn {
    reader: Mutex<Reader>,
    writer: Mutex<(WriteHalf<Half>, BodyCipher)>,
    poisoned: AtomicBool,
    remote: SocketAddr,
}

impl VmessPacketConn {
    /// `stream` must already carry the sealed `CommandUDP` request header.
    pub(super) fn new(
        stream: Half,
        sealed: &SealedHeader,
        security: Security,
        remote: SocketAddr,
    ) -> Self {
        let (resp_key, resp_iv) = response_body_keys(&sealed.req_key, &sealed.req_iv);
        let (rd, wr) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(Reader {
                half: rd,
                cipher: BodyCipher::from_response_keys(security, &resp_key, &resp_iv),
                header_pending: true,
                resp_key,
                resp_iv,
                resp_v: sealed.resp_v,
                buf: Vec::new(),
            }),
            writer: Mutex::new((
                wr,
                BodyCipher::new_writer(security, &sealed.req_key, &sealed.req_iv),
            )),
            poisoned: AtomicBool::new(false),
            remote,
        }
    }
}

#[async_trait]
impl ProxyPacketConn for VmessPacketConn {
    /// Returns the bound destination as the source: VMess UDP carries no
    /// per-packet address (unspecified IP when the destination is a name).
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        crate::check_not_desynced(&self.poisoned)?;
        let mut r = self.reader.lock().await;
        crate::check_not_desynced(&self.poisoned)?;
        let mut guard = crate::PoisonOnIncomplete::new(&self.poisoned);

        let r = &mut *r;
        if r.header_pending {
            read_aead_response_header(&mut r.half, &r.resp_key, &r.resp_iv, r.resp_v)
                .await
                .map_err(MeowError::Io)?;
            r.header_pending = false;
        }
        // A truncated datagram is still one datagram: copy what fits.
        match r
            .cipher
            .read_record_into(&mut r.half, &mut r.buf)
            .await
            .map_err(MeowError::Io)?
        {
            Some(()) => {
                let n = r.buf.len().min(buf.len());
                buf[..n].copy_from_slice(&r.buf[..n]);
                guard.complete = true;
                Ok((n, self.remote))
            }
            None => Err(MeowError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "vmess udp: peer closed the association",
            ))),
        }
    }

    /// The destination is fixed by the request header; `addr` is ignored.
    async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> Result<usize> {
        crate::check_not_desynced(&self.poisoned)?;
        if buf.len() > MAX_DATAGRAM {
            return Err(MeowError::Proxy(format!(
                "vmess udp: packet too large ({} > {MAX_DATAGRAM})",
                buf.len()
            )));
        }
        // A zero-length record is the chunk-stream terminator (xray/sing
        // read it as EOF), so an empty datagram must not reach the wire.
        if buf.is_empty() {
            return Ok(0);
        }
        let mut w = self.writer.lock().await;
        crate::check_not_desynced(&self.poisoned)?;
        let mut guard = crate::PoisonOnIncomplete::new(&self.poisoned);
        let (half, cipher) = &mut *w;
        cipher
            .write_record(half, buf)
            .await
            .map_err(MeowError::Io)?;
        guard.complete = true;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}
