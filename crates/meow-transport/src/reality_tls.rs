use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce, Tag,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    tls::{RealityConfig, TlsConfig},
    Result, Stream, Transport, TransportError,
};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const TLS_RECORD_HANDSHAKE: u8 = 22;
const TLS_RECORD_APPLICATION_DATA: u8 = 23;
const TLS_RECORD_ALERT: u8 = 21;
const TLS_RECORD_CHANGE_CIPHER_SPEC: u8 = 20;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_NEW_SESSION_TICKET: u8 = 4;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

const TLS_AES_128_GCM_SHA256: u16 = 0x1301;

const GROUP_X25519: u16 = 0x001d;

// ─── Pre-authentication server-flight bounds (issue #430) ─────────────────
//
// Everything the loop below accepts before `Finished` is unauthenticated:
// the REALITY HMAC check (`verify_reality_certificate`) only runs after the
// loop exits. Without a cap, a peer that merely echoes the ClientHello
// `session_id` — which is enough to get past `read_plain_handshake` and
// derive valid handshake keys, but says nothing about who they are — could
// stream EncryptedExtensions/Certificate/CertificateVerify messages forever
// and grow `transcript` without bound. A real TLS 1.3 server flight is a
// few KB; `read_record` already caps a single record at 18 KiB, so a
// legitimate flight cannot come close to either limit below. Mirrors
// `MAX_GUN_FRAME_LEN` in `grpc.rs` and the size caps in `ws.rs`.
//
// The two constants below are not equally load-bearing, and it matters
// which is which when the size math changes.
//
// `ServerFlightGuard`'s flight-ordering check admits at most 3 messages
// (EncryptedExtensions / Certificate / CertificateVerify, each exactly once,
// in order), each at most ~36 KiB — a message must complete within one
// 18 KiB record plus whatever partial tail the previous record left
// buffered, or `pop_handshake_message` fails the loop.
//
// `MAX_PRE_AUTH_HS_MESSAGES` (32) is therefore pure defense-in-depth: the
// ordering guard caps the count at 3, so 32 is unreachable while that guard
// holds.
//
// `MAX_PRE_AUTH_TRANSCRIPT_LEN` (64 KiB) is *not* — it is the binding limit
// on a large flight. At ~36 KiB per message, two messages already exceed
// 64 KiB, so the transcript check in `ServerFlightGuard::admit` is what
// actually rejects an oversized Certificate flight, before the message
// count ever reaches 3. Treat it as a real bound: raising the per-message
// size or the record cap without revisiting it changes what this code
// accepts pre-authentication.
const MAX_PRE_AUTH_HS_MESSAGES: usize = 32;
const MAX_PRE_AUTH_TRANSCRIPT_LEN: usize = 64 * 1024;

/// Upper bound on the whole REALITY handshake (ClientHello write through the
/// authenticated Finished exchange). Independent of the size cap above: a
/// peer that stays within the caps but drips messages slowly, or simply
/// never sends `Finished`, would otherwise pin the dial task (and its
/// buffers) open indefinitely.
const REALITY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub(crate) struct RealityTlsLayer {
    server_name: String,
    alpn: Vec<String>,
    reality: RealityConfig,
}

impl RealityTlsLayer {
    pub(crate) fn new(config: &TlsConfig) -> Result<Self> {
        let server_name = config.sni.clone().ok_or_else(|| {
            TransportError::Config(
                "Reality TLS requires sni to be Some; set `servername` or `server`.".into(),
            )
        })?;
        let reality = config.reality.clone().ok_or_else(|| {
            TransportError::Config("RealityTlsLayer requires TlsConfig.reality".into())
        })?;

        if config.ech.is_some() {
            return Err(TransportError::Config(
                "reality-opts cannot be combined with ech-opts on the same TLS layer".into(),
            ));
        }
        if config.client_cert.is_some() {
            return Err(TransportError::Config(
                "Reality TLS client certificates are not supported".into(),
            ));
        }
        if config.skip_cert_verify {
            tracing::warn!(
                "skip-cert-verify=true is ignored for Reality TLS; Reality HMAC authentication is still required"
            );
        }
        if config.verify_name.is_some() {
            tracing::warn!(
                "verify_name is ignored for Reality TLS; the server name comes from reality-opts"
            );
        }
        if config.cert_pin.is_some() {
            tracing::warn!(
                "cert_pin is ignored for Reality TLS; the Reality handshake owns authentication"
            );
        }

        Ok(Self {
            server_name,
            alpn: config.alpn.clone(),
            reality,
        })
    }
}

#[async_trait::async_trait]
impl Transport for RealityTlsLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let state = tokio::time::timeout(
            REALITY_HANDSHAKE_TIMEOUT,
            reality_handshake(inner, &self.server_name, &self.alpn, &self.reality),
        )
        .await
        .map_err(|_| {
            TransportError::Tls(format!(
                "Reality TLS: handshake did not complete within {REALITY_HANDSHAKE_TIMEOUT:?}"
            ))
        })??;
        Ok(spawn_reality_stream(state))
    }
}

struct RealityConnected {
    inner: Box<dyn Stream>,
    read_key: RecordKey,
    write_key: RecordKey,
}

async fn reality_handshake(
    mut inner: Box<dyn Stream>,
    server_name: &str,
    alpn: &[String],
    reality: &RealityConfig,
) -> Result<RealityConnected> {
    let mut client_private = rand::random::<[u8; 32]>();
    clamp_x25519_private(&mut client_private);
    let client_public = x25519_public_from_private(&client_private);
    let auth_key = x25519(&client_private, &reality.public_key)?;

    let mut client_random = rand::random::<[u8; 32]>();
    let (client_hello, reality_auth_key) = build_reality_client_hello(
        server_name,
        alpn,
        &client_random,
        &client_public,
        &auth_key,
        reality,
    )?;
    inner
        .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, &client_hello)?)
        .await?;
    inner.flush().await?;

    let mut transcript = Vec::with_capacity(4096);
    transcript.extend_from_slice(&client_hello);

    let server_hello = read_plain_handshake(&mut inner, HS_SERVER_HELLO).await?;
    let parsed_server_hello = parse_server_hello(&server_hello)?;
    tracing::debug!(
        cipher_suite = format_args!("0x{:04x}", parsed_server_hello.cipher_suite),
        session_id_len = parsed_server_hello.session_id.len(),
        "Reality TLS received ServerHello"
    );
    if parsed_server_hello.session_id != client_hello[39..71] {
        return Err(TransportError::Tls(
            "Reality TLS: server did not echo ClientHello session_id".into(),
        ));
    }
    let shared_secret = x25519(&client_private, &parsed_server_hello.key_share)?;
    transcript.extend_from_slice(&server_hello);

    let cipher = CipherSuite::try_from(parsed_server_hello.cipher_suite)?;
    let hs = HandshakeKeys::derive(cipher, &shared_secret, &transcript);
    let mut server_hs = hs.server;
    let mut client_hs = hs.client;

    let mut handshake_buf = VecDeque::new();
    let mut leaf_cert = None;
    let mut flight = ServerFlightGuard::default();
    let server_finished;

    loop {
        fill_decrypted_handshake(&mut inner, &mut server_hs, &mut handshake_buf).await?;
        let msg = pop_handshake_message(&mut handshake_buf).ok_or_else(|| {
            TransportError::Tls("Reality TLS: decrypted empty handshake record".into())
        })?;
        match msg.typ {
            HS_ENCRYPTED_EXTENSIONS | HS_CERTIFICATE | HS_CERTIFICATE_VERIFY => {
                flight.admit(&mut transcript, &msg)?;
                if msg.typ == HS_CERTIFICATE {
                    leaf_cert = Some(parse_leaf_certificate(&msg.body)?);
                }
            }
            HS_FINISHED => {
                if !flight.complete() {
                    return Err(TransportError::Tls(
                        "Reality TLS: incomplete server handshake".into(),
                    ));
                }
                server_finished = msg.raw;
                verify_finished(&hs.server_secret, &transcript, &msg.body)?;
                break;
            }
            HS_NEW_SESSION_TICKET => {
                // NewSessionTicket is a TLS 1.3 *post*-handshake message; a
                // compliant server never sends it before Finished. Treating
                // it as ignorable (as the old code did) let an attacker
                // spin the loop forever without ever touching the transcript
                // caps below — reject it outright instead (issue #430).
                return Err(TransportError::Tls(
                    "Reality TLS: NewSessionTicket before Finished".into(),
                ));
            }
            other => {
                return Err(TransportError::Tls(format!(
                    "Reality TLS: unexpected handshake message {other}"
                )));
            }
        }
    }

    let leaf_cert =
        leaf_cert.ok_or_else(|| TransportError::Tls("Reality TLS: missing certificate".into()))?;
    verify_reality_certificate(&leaf_cert, &reality_auth_key)?;

    transcript.extend_from_slice(&server_finished);
    let app = ApplicationKeys::derive(cipher, &hs.master_secret, &transcript);

    let client_finished_body = finished_verify_data(&hs.client_secret, &transcript);
    let mut client_finished = Vec::with_capacity(4 + client_finished_body.len());
    client_finished.push(HS_FINISHED);
    put_u24(client_finished_body.len(), &mut client_finished);
    client_finished.extend_from_slice(&client_finished_body);
    let encrypted_finished = client_hs.seal(TLS_RECORD_HANDSHAKE, &client_finished)?;
    inner.write_all(&encrypted_finished).await?;
    inner.flush().await?;

    client_random.fill(0);
    client_private.fill(0);

    tracing::debug!("Reality TLS handshake complete");
    Ok(RealityConnected {
        inner,
        read_key: app.server,
        write_key: app.client,
    })
}

pub(crate) struct RealityTlsStream {
    inner: Box<dyn Stream>,
    read_key: RecordKey,
    write_key: RecordKey,
    read_raw_passthrough: bool,
    write_raw_passthrough: bool,
    read_plain: VecDeque<u8>,
    read_state: StreamReadState,
    write_pending: Option<StreamPendingWrite>,
}

impl RealityTlsStream {
    pub(crate) fn enable_raw_read_passthrough(&mut self) {
        self.read_raw_passthrough = true;
        tracing::debug!("Reality TLS raw read passthrough enabled");
    }

    pub(crate) fn enable_raw_write_passthrough(&mut self) {
        self.write_raw_passthrough = true;
        tracing::debug!("Reality TLS raw write passthrough enabled");
    }

    fn drain_read_plain(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.read_plain.is_empty() {
            return false;
        }
        let n = buf.remaining().min(self.read_plain.len());
        for b in self.read_plain.drain(..n) {
            buf.put_slice(&[b]);
        }
        true
    }

    fn drain_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(pending) = &mut self.write_pending else {
            return Poll::Ready(Ok(()));
        };

        while pending.pos < pending.frame.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &pending.frame[pending.pos..])? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "reality tls: zero write",
                    )));
                }
                Poll::Ready(n) => pending.pos += n,
            }
        }

        self.write_pending.take().expect("pending checked above");
        Poll::Ready(Ok(()))
    }
}

enum StreamReadState {
    Header {
        buf: [u8; 5],
        pos: usize,
    },
    Payload {
        header: [u8; 5],
        typ: u8,
        payload: Vec<u8>,
        pos: usize,
    },
}

struct StreamPendingWrite {
    frame: Vec<u8>,
    pos: usize,
}

impl AsyncRead for RealityTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Plaintext already opened from the last record comes before any
        // raw byte, so it must drain first even after the raw switch.
        if self.drain_read_plain(buf) {
            return Poll::Ready(Ok(()));
        }
        if self.read_raw_passthrough {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }

        loop {
            let state = std::mem::replace(
                &mut self.read_state,
                StreamReadState::Header {
                    buf: [0; 5],
                    pos: 0,
                },
            );
            match state {
                StreamReadState::Header {
                    buf: mut h,
                    mut pos,
                } => {
                    while pos < h.len() {
                        let mut rb = ReadBuf::new(&mut h[pos..]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => {
                                self.read_state = StreamReadState::Header { buf: h, pos };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => {
                                self.read_state = StreamReadState::Header { buf: h, pos };
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    self.read_state = StreamReadState::Header { buf: h, pos };
                                    return Poll::Ready(Ok(()));
                                }
                                pos += n;
                            }
                        }
                    }

                    let len = u16::from_be_bytes([h[3], h[4]]) as usize;
                    if len > 18 * 1024 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("TLS record too large: {len}"),
                        )));
                    }
                    self.read_state = StreamReadState::Payload {
                        header: h,
                        typ: h[0],
                        payload: vec![0; len],
                        pos: 0,
                    };
                }
                StreamReadState::Payload {
                    header,
                    typ,
                    mut payload,
                    mut pos,
                } => {
                    while pos < payload.len() {
                        let mut rb = ReadBuf::new(&mut payload[pos..]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => {
                                self.read_state = StreamReadState::Payload {
                                    header,
                                    typ,
                                    payload,
                                    pos,
                                };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => {
                                self.read_state = StreamReadState::Payload {
                                    header,
                                    typ,
                                    payload,
                                    pos,
                                };
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    self.read_state = StreamReadState::Payload {
                                        header,
                                        typ,
                                        payload,
                                        pos,
                                    };
                                    return Poll::Ready(Ok(()));
                                }
                                pos += n;
                            }
                        }
                    }

                    self.read_state = StreamReadState::Header {
                        buf: [0; 5],
                        pos: 0,
                    };
                    if typ != TLS_RECORD_APPLICATION_DATA {
                        continue;
                    }
                    let (inner_type, plaintext) = self
                        .read_key
                        .open(&header, &payload)
                        .map_err(transport_io_error)?;
                    match inner_type {
                        TLS_RECORD_APPLICATION_DATA => {
                            self.read_plain.extend(plaintext);
                            if self.drain_read_plain(buf) {
                                return Poll::Ready(Ok(()));
                            }
                        }
                        TLS_RECORD_HANDSHAKE => {
                            continue;
                        }
                        TLS_RECORD_ALERT => return Poll::Ready(Ok(())),
                        _ => continue,
                    }
                }
            }
        }
    }
}

impl AsyncWrite for RealityTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Drain any in-flight record first.  If the drain is still
        // Pending, nothing from the incoming `buf` has been consumed —
        // return Pending so the caller retries with the same buffer.
        // If the drain completes, fall through to seal the new buffer
        // rather than reporting the *old* record's length against the
        // new buffer (AsyncWrite does not guarantee the same buffer is
        // presented after a Pending).
        if self.write_pending.is_some() {
            match self.drain_pending_write(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {} // drained — fall through
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if self.write_raw_passthrough {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        // TLS records carry a u16 length: chunk large writes into
        // standard 16 KiB records instead of letting the length field
        // wrap (which would desynchronise the peer's TLS reader).
        let chunk_len = buf.len().min(16 * 1024);
        let frame = self
            .write_key
            .seal(TLS_RECORD_APPLICATION_DATA, &buf[..chunk_len])
            .map_err(transport_io_error)?;
        self.write_pending = Some(StreamPendingWrite { frame, pos: 0 });
        // The record is buffered; report chunk_len immediately whether
        // or not the drain completes now.  The next poll_write /
        // poll_flush / poll_shutdown drains it.  Returning Pending here
        // would be unsafe: the sealed record's plaintext length would
        // be reported against whatever buffer arrives on the next poll.
        match self.drain_pending_write(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            _ => Poll::Ready(Ok(chunk_len)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn spawn_reality_stream(state: RealityConnected) -> Box<dyn Stream> {
    Box::new(RealityTlsStream {
        inner: state.inner,
        read_key: state.read_key,
        write_key: state.write_key,
        read_raw_passthrough: false,
        write_raw_passthrough: false,
        read_plain: VecDeque::new(),
        read_state: StreamReadState::Header {
            buf: [0; 5],
            pos: 0,
        },
        write_pending: None,
    })
}

fn transport_io_error(e: TransportError) -> io::Error {
    io::Error::other(e)
}

fn build_reality_client_hello(
    server_name: &str,
    alpn: &[String],
    random: &[u8; 32],
    key_share: &[u8; 32],
    auth_key: &[u8; 32],
    reality: &RealityConfig,
) -> Result<(Vec<u8>, [u8; 32])> {
    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(random);
    body.push(32);
    body.extend_from_slice(&[0u8; 32]);

    let ciphers = [TLS_AES_128_GCM_SHA256];
    put_u16((ciphers.len() * 2) as u16, &mut body);
    for cipher in ciphers {
        put_u16(cipher, &mut body);
    }
    body.extend_from_slice(&[1, 0]);

    let mut exts = Vec::new();
    push_ext(&mut exts, 0, &server_name_ext(server_name)?);
    push_ext(
        &mut exts,
        10,
        &u16_list_ext(&[GROUP_X25519, 0x0017, 0x0018]),
    );
    push_ext(&mut exts, 11, &[1, 0]);
    push_ext(
        &mut exts,
        13,
        &u16_list_ext(&[0x0807, 0x0403, 0x0804, 0x0805]),
    );
    if !alpn.is_empty() {
        push_ext(&mut exts, 16, &alpn_ext(alpn)?);
    }
    push_ext(&mut exts, 35, &[]);
    push_ext(&mut exts, 43, &[4, 0x03, 0x04, 0x03, 0x03]);
    push_ext(&mut exts, 45, &[1, 1]);
    push_ext(&mut exts, 51, &key_share_ext(key_share));

    put_u16(exts.len() as u16, &mut body);
    body.extend_from_slice(&exts);

    let mut hello = Vec::with_capacity(4 + body.len());
    hello.push(HS_CLIENT_HELLO);
    put_u24(body.len(), &mut hello);
    hello.extend_from_slice(&body);

    let auth_key = hkdf_sha256(auth_key, &hello[4 + 2..4 + 2 + 20], b"REALITY", 32);
    let mut aead_key = [0u8; 32];
    aead_key.copy_from_slice(&auth_key);

    let mut reality_plain = [0u8; 16];
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| TransportError::Tls(format!("system clock before UNIX_EPOCH: {e}")))?
        .as_secs() as u32;
    // Auth payload layout must match the server's expectation.  The first
    // three bytes are the REALITY ClientVer triple.  sing-box hardcodes
    // [1, 8, 1] (common/tls/reality_client.go:186-188); xray-core uses its
    // own version bytes (transport/internet/reality/reality.go:143-145).
    // Neither server validates these bytes — they are part of the 16-byte
    // AES-GCM auth payload, and the server only checks the short_id and
    // timestamp after decryption.  Using sing-box's value is the safe
    // interop choice: it works with both sing-box and xray servers.
    reality_plain[0] = 1;
    reality_plain[1] = 8;
    reality_plain[2] = 1;
    reality_plain[3] = 0;
    reality_plain[4..8].copy_from_slice(&unix.to_be_bytes());
    reality_plain[8..16].copy_from_slice(&reality.short_id);

    let cipher = Aes256Gcm::new_from_slice(&aead_key)
        .map_err(|e| TransportError::Tls(format!("Reality AES-GCM key: {e}")))?;
    let nonce = Nonce::from_slice(&random[20..32]);
    let mut session_id = reality_plain.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, &hello, &mut session_id)
        .map_err(|e| TransportError::Tls(format!("Reality session_id seal: {e}")))?;
    session_id.extend_from_slice(&tag);
    if session_id.len() != 32 {
        return Err(TransportError::Tls(
            "Reality session_id must be exactly 32 bytes".into(),
        ));
    }
    hello[39..71].copy_from_slice(&session_id);
    Ok((hello, aead_key))
}

fn server_name_ext(server_name: &str) -> Result<Vec<u8>> {
    if server_name.len() > u16::MAX as usize {
        return Err(TransportError::Config("SNI is too long".into()));
    }
    let mut name = Vec::new();
    name.push(0);
    put_u16(server_name.len() as u16, &mut name);
    name.extend_from_slice(server_name.as_bytes());

    let mut out = Vec::new();
    put_u16(name.len() as u16, &mut out);
    out.extend_from_slice(&name);
    Ok(out)
}

fn alpn_ext(alpn: &[String]) -> Result<Vec<u8>> {
    let mut list = Vec::new();
    for protocol in alpn {
        let bytes = protocol.as_bytes();
        if bytes.len() > u8::MAX as usize {
            return Err(TransportError::Config(format!(
                "ALPN protocol id '{protocol}' is too long"
            )));
        }
        list.push(bytes.len() as u8);
        list.extend_from_slice(bytes);
    }
    let mut out = Vec::new();
    put_u16(list.len() as u16, &mut out);
    out.extend_from_slice(&list);
    Ok(out)
}

fn u16_list_ext(values: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + values.len() * 2);
    put_u16((values.len() * 2) as u16, &mut out);
    for value in values {
        put_u16(*value, &mut out);
    }
    out
}

fn key_share_ext(public_key: &[u8; 32]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(4 + public_key.len());
    put_u16(GROUP_X25519, &mut entry);
    put_u16(public_key.len() as u16, &mut entry);
    entry.extend_from_slice(public_key);

    let mut out = Vec::with_capacity(2 + entry.len());
    put_u16(entry.len() as u16, &mut out);
    out.extend_from_slice(&entry);
    out
}

fn push_ext(out: &mut Vec<u8>, typ: u16, data: &[u8]) {
    put_u16(typ, out);
    put_u16(data.len() as u16, out);
    out.extend_from_slice(data);
}

fn wrap_plain_record(typ: u8, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(TransportError::Tls("TLS record payload too large".into()));
    }
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(typ);
    out.extend_from_slice(&[0x03, 0x01]);
    put_u16(payload.len() as u16, &mut out);
    out.extend_from_slice(payload);
    Ok(out)
}

async fn read_plain_handshake<R: AsyncRead + Unpin>(r: &mut R, expected: u8) -> Result<Vec<u8>> {
    loop {
        let record = read_record(r).await?.ok_or_else(|| {
            TransportError::Tls("Reality TLS: EOF while reading ServerHello".into())
        })?;
        if record.typ == TLS_RECORD_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record.typ != TLS_RECORD_HANDSHAKE {
            return Err(TransportError::Tls(format!(
                "Reality TLS: expected handshake record, got {}",
                record.typ
            )));
        }
        if record.payload.len() < 4 || record.payload[0] != expected {
            return Err(TransportError::Tls(
                "Reality TLS: unexpected plaintext handshake".into(),
            ));
        }
        let len = read_u24(&record.payload[1..4]);
        if record.payload.len() != 4 + len {
            return Err(TransportError::Tls(
                "Reality TLS: fragmented plaintext ServerHello is not supported".into(),
            ));
        }
        return Ok(record.payload);
    }
}

async fn fill_decrypted_handshake<R: AsyncRead + Unpin>(
    r: &mut R,
    key: &mut RecordKey,
    out: &mut VecDeque<u8>,
) -> Result<()> {
    loop {
        let record = read_record(r).await?.ok_or_else(|| {
            TransportError::Tls("Reality TLS: EOF during encrypted handshake".into())
        })?;
        if record.typ == TLS_RECORD_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record.typ != TLS_RECORD_APPLICATION_DATA {
            return Err(TransportError::Tls(format!(
                "Reality TLS: expected encrypted record, got {}",
                record.typ
            )));
        }
        tracing::debug!(
            record_version = format_args!("{:02x}{:02x}", record.header[1], record.header[2]),
            record_len = record.payload.len(),
            "Reality TLS decrypting encrypted handshake record"
        );
        let (inner_type, plaintext) = key.open(&record.header, &record.payload)?;
        match inner_type {
            TLS_RECORD_HANDSHAKE => {
                out.extend(plaintext);
                return Ok(());
            }
            TLS_RECORD_ALERT => {
                return Err(TransportError::Tls("Reality TLS: server alert".into()));
            }
            _ => {}
        }
    }
}

struct TlsRecord {
    header: [u8; 5],
    typ: u8,
    payload: Vec<u8>,
}

async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<TlsRecord>> {
    let mut header = [0u8; 5];
    match r.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > 18 * 1024 {
        return Err(TransportError::Tls(format!("TLS record too large: {len}")));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(Some(TlsRecord {
        header,
        typ: header[0],
        payload,
    }))
}

struct ParsedServerHello {
    cipher_suite: u16,
    session_id: Vec<u8>,
    key_share: [u8; 32],
}

fn parse_server_hello(raw: &[u8]) -> Result<ParsedServerHello> {
    if raw.len() < 42 || raw[0] != HS_SERVER_HELLO {
        return Err(TransportError::Tls("invalid ServerHello".into()));
    }
    let body_len = read_u24(&raw[1..4]);
    if raw.len() != 4 + body_len {
        return Err(TransportError::Tls("truncated ServerHello".into()));
    }
    let body = &raw[4..];
    if body[0..2] != [0x03, 0x03] {
        return Err(TransportError::Tls(
            "Reality TLS: server selected a non-TLS1.3 legacy version".into(),
        ));
    }
    if body[2..34]
        == [
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
            0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
            0xc8, 0xa8, 0x33, 0x9c,
        ]
    {
        return Err(TransportError::Tls(
            "Reality TLS: HelloRetryRequest is not supported".into(),
        ));
    }
    let mut pos = 34;
    let sid_len = take_u8(body, &mut pos)? as usize;
    let session_id = take(body, &mut pos, sid_len)?.to_vec();
    let cipher_suite = take_u16(body, &mut pos)?;
    let compression = take_u8(body, &mut pos)?;
    if compression != 0 {
        return Err(TransportError::Tls(
            "Reality TLS: invalid ServerHello compression".into(),
        ));
    }
    let ext_len = take_u16(body, &mut pos)? as usize;
    let exts = take(body, &mut pos, ext_len)?;
    let mut key_share = None;
    let mut tls13 = false;
    let mut epos = 0;
    while epos < exts.len() {
        let typ = take_u16(exts, &mut epos)?;
        let len = take_u16(exts, &mut epos)? as usize;
        let data = take(exts, &mut epos, len)?;
        match typ {
            43 => tls13 = data == [0x03, 0x04],
            51 => {
                let mut p = 0;
                let group = take_u16(data, &mut p)?;
                let klen = take_u16(data, &mut p)? as usize;
                let bytes = take(data, &mut p, klen)?;
                tracing::debug!(
                    group = format_args!("0x{group:04x}"),
                    key_len = bytes.len(),
                    "Reality TLS ServerHello key_share"
                );
                if group == GROUP_X25519 && bytes.len() == 32 {
                    let mut share = [0u8; 32];
                    share.copy_from_slice(bytes);
                    key_share = Some(share);
                }
            }
            _ => {}
        }
    }
    if !tls13 {
        return Err(TransportError::Tls(
            "Reality TLS: server did not negotiate TLS 1.3".into(),
        ));
    }
    Ok(ParsedServerHello {
        cipher_suite,
        session_id,
        key_share: key_share
            .ok_or_else(|| TransportError::Tls("Reality TLS: missing X25519 key share".into()))?,
    })
}

struct HandshakeMessage {
    typ: u8,
    body: Vec<u8>,
    raw: Vec<u8>,
}

/// Enforces the pre-authentication server-flight bounds from issue #430:
/// `EncryptedExtensions`, `Certificate` and `CertificateVerify` must each
/// appear at most once, in that order, and the running transcript may not
/// exceed [`MAX_PRE_AUTH_HS_MESSAGES`] messages / [`MAX_PRE_AUTH_TRANSCRIPT_LEN`]
/// bytes. `admit` is the only way `transcript` grows during the loop in
/// [`reality_handshake`], so every accepted message is checked before it is
/// appended.
#[derive(Default)]
struct ServerFlightGuard {
    message_count: usize,
    saw_encrypted_extensions: bool,
    saw_certificate: bool,
    saw_certificate_verify: bool,
}

impl ServerFlightGuard {
    /// Validate and, if accepted, append `msg.raw` to `transcript`. Only
    /// called for `EncryptedExtensions` / `Certificate` / `CertificateVerify`
    /// — `Finished` and `NewSessionTicket` are handled by the caller.
    fn admit(&mut self, transcript: &mut Vec<u8>, msg: &HandshakeMessage) -> Result<()> {
        self.message_count += 1;
        if self.message_count > MAX_PRE_AUTH_HS_MESSAGES {
            return Err(TransportError::Tls(format!(
                "Reality TLS: server flight exceeded {MAX_PRE_AUTH_HS_MESSAGES} pre-authentication handshake messages"
            )));
        }
        if transcript.len() + msg.raw.len() > MAX_PRE_AUTH_TRANSCRIPT_LEN {
            return Err(TransportError::Tls(format!(
                "Reality TLS: server flight transcript exceeded {MAX_PRE_AUTH_TRANSCRIPT_LEN} bytes"
            )));
        }
        match msg.typ {
            HS_ENCRYPTED_EXTENSIONS => {
                if self.saw_encrypted_extensions || self.saw_certificate || self.saw_certificate_verify
                {
                    return Err(TransportError::Tls(
                        "Reality TLS: unexpected EncryptedExtensions in server flight".into(),
                    ));
                }
                self.saw_encrypted_extensions = true;
            }
            HS_CERTIFICATE => {
                if !self.saw_encrypted_extensions || self.saw_certificate || self.saw_certificate_verify
                {
                    return Err(TransportError::Tls(
                        "Reality TLS: unexpected Certificate in server flight".into(),
                    ));
                }
                self.saw_certificate = true;
            }
            HS_CERTIFICATE_VERIFY => {
                if !self.saw_certificate || self.saw_certificate_verify {
                    return Err(TransportError::Tls(
                        "Reality TLS: unexpected CertificateVerify in server flight".into(),
                    ));
                }
                self.saw_certificate_verify = true;
            }
            other => unreachable!(
                "ServerFlightGuard::admit called for handshake type {other}, which is not part of the pre-Finished flight"
            ),
        }
        transcript.extend_from_slice(&msg.raw);
        Ok(())
    }

    /// True once all three mandatory pre-`Finished` flight messages have
    /// been seen exactly once, in order.
    fn complete(&self) -> bool {
        self.saw_encrypted_extensions && self.saw_certificate && self.saw_certificate_verify
    }
}

fn pop_handshake_message(buf: &mut VecDeque<u8>) -> Option<HandshakeMessage> {
    if buf.len() < 4 {
        return None;
    }
    let header: Vec<u8> = buf.iter().copied().take(4).collect();
    let len = read_u24(&header[1..4]);
    if buf.len() < 4 + len {
        return None;
    }
    let raw = buf.drain(..4 + len).collect::<Vec<_>>();
    let body = raw[4..].to_vec();
    Some(HandshakeMessage {
        typ: raw[0],
        body,
        raw,
    })
}

fn parse_leaf_certificate(body: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;
    let ctx_len = take_u8(body, &mut pos)? as usize;
    take(body, &mut pos, ctx_len)?;
    let list_len = take_u24(body, &mut pos)?;
    let list = take(body, &mut pos, list_len)?;
    let mut list_pos = 0;
    let cert_len = take_u24(list, &mut list_pos)?;
    let cert = take(list, &mut list_pos, cert_len)?.to_vec();
    Ok(cert)
}

fn verify_reality_certificate(cert_der: &[u8], auth_key: &[u8; 32]) -> Result<()> {
    let Some((ed25519_pubkey, cert_signature)) = extract_ed25519_cert_parts(cert_der) else {
        return Err(TransportError::Tls(
            "Reality authentication failed: leaf certificate is not Ed25519".into(),
        ));
    };
    let mut h = <HmacSha512 as Mac>::new_from_slice(auth_key)
        .map_err(|e| TransportError::Tls(format!("Reality HMAC-SHA512 init: {e}")))?;
    h.update(&ed25519_pubkey);
    let expected = h.finalize().into_bytes();
    if expected.as_slice() == cert_signature.as_slice() {
        Ok(())
    } else {
        Err(TransportError::Tls(
            "Reality authentication failed: certificate signature HMAC mismatch".into(),
        ))
    }
}

fn extract_ed25519_cert_parts(cert: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    let mut pos = 0;
    let cert_seq = der_read(cert, &mut pos)?;
    if cert_seq.tag != 0x30 {
        return None;
    }
    let mut cpos = 0;
    let tbs = der_read(cert_seq.value, &mut cpos)?;
    let _sig_alg = der_read(cert_seq.value, &mut cpos)?;
    let sig = der_read(cert_seq.value, &mut cpos)?;
    if tbs.tag != 0x30 || sig.tag != 0x03 || sig.value.first().copied()? != 0 {
        return None;
    }

    let mut children = Vec::new();
    let mut tpos = 0;
    while tpos < tbs.value.len() {
        children.push(der_read(tbs.value, &mut tpos)?);
    }
    let base = if children.first().is_some_and(|n| n.tag == 0xa0) {
        1
    } else {
        0
    };
    let spki = *children.get(base + 5)?;
    let pubkey = extract_ed25519_spki(spki.value)?;
    Some((pubkey, sig.value[1..].to_vec()))
}

fn extract_ed25519_spki(spki_value: &[u8]) -> Option<[u8; 32]> {
    let mut pos = 0;
    let alg = der_read(spki_value, &mut pos)?;
    let bit_string = der_read(spki_value, &mut pos)?;
    if alg.tag != 0x30 || bit_string.tag != 0x03 {
        return None;
    }
    let mut alg_pos = 0;
    let oid = der_read(alg.value, &mut alg_pos)?;
    if oid.tag != 0x06 || oid.value != [0x2b, 0x65, 0x70] {
        return None;
    }
    if bit_string.value.len() != 33 || bit_string.value[0] != 0 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bit_string.value[1..]);
    Some(out)
}

#[derive(Clone, Copy)]
struct DerNode<'a> {
    tag: u8,
    value: &'a [u8],
}

fn der_read<'a>(input: &'a [u8], pos: &mut usize) -> Option<DerNode<'a>> {
    let tag = *input.get(*pos)?;
    *pos += 1;
    let first_len = *input.get(*pos)?;
    *pos += 1;
    let len = if first_len & 0x80 == 0 {
        first_len as usize
    } else {
        let count = (first_len & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..count {
            len = (len << 8) | (*input.get(*pos)? as usize);
            *pos += 1;
        }
        len
    };
    let end = pos.checked_add(len)?;
    let value = input.get(*pos..end)?;
    *pos = end;
    Some(DerNode { tag, value })
}

#[derive(Clone, Copy)]
enum CipherSuite {
    Aes128GcmSha256,
}

impl CipherSuite {
    fn try_from(value: u16) -> Result<Self> {
        match value {
            TLS_AES_128_GCM_SHA256 => Ok(Self::Aes128GcmSha256),
            other => Err(TransportError::Tls(format!(
                "Reality TLS: unsupported cipher suite 0x{other:04x}"
            ))),
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
        }
    }
}

struct HandshakeKeys {
    client: RecordKey,
    server: RecordKey,
    client_secret: [u8; 32],
    server_secret: [u8; 32],
    master_secret: [u8; 32],
}

impl HandshakeKeys {
    fn derive(cipher: CipherSuite, shared_secret: &[u8; 32], transcript: &[u8]) -> Self {
        let zero = [0u8; 32];
        let empty_hash = Sha256::digest([]);
        let early_secret = hkdf_extract(&zero, &zero);
        let derived = derive_secret(&early_secret, b"derived", &empty_hash);
        let handshake_secret = hkdf_extract(&derived, shared_secret);
        let transcript_hash = Sha256::digest(transcript);
        let client_secret = derive_secret(&handshake_secret, b"c hs traffic", &transcript_hash);
        let server_secret = derive_secret(&handshake_secret, b"s hs traffic", &transcript_hash);
        let derived = derive_secret(&handshake_secret, b"derived", &empty_hash);
        let master_secret = hkdf_extract(&derived, &zero);
        Self {
            client: RecordKey::new(cipher, &client_secret),
            server: RecordKey::new(cipher, &server_secret),
            client_secret,
            server_secret,
            master_secret,
        }
    }
}

struct ApplicationKeys {
    client: RecordKey,
    server: RecordKey,
}

impl ApplicationKeys {
    fn derive(cipher: CipherSuite, master_secret: &[u8; 32], transcript: &[u8]) -> Self {
        let transcript_hash = Sha256::digest(transcript);
        let client_secret = derive_secret(master_secret, b"c ap traffic", &transcript_hash);
        let server_secret = derive_secret(master_secret, b"s ap traffic", &transcript_hash);
        Self {
            client: RecordKey::new(cipher, &client_secret),
            server: RecordKey::new(cipher, &server_secret),
        }
    }
}

enum AeadCipher {
    Aes128(Box<Aes128Gcm>),
}

struct RecordKey {
    cipher: AeadCipher,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKey {
    fn new(cipher_suite: CipherSuite, secret: &[u8; 32]) -> Self {
        let key = hkdf_expand_label(secret, b"key", &[], cipher_suite.key_len());
        let iv = hkdf_expand_label(secret, b"iv", &[], 12);
        let mut iv_arr = [0u8; 12];
        iv_arr.copy_from_slice(&iv);
        let cipher = match cipher_suite {
            CipherSuite::Aes128GcmSha256 => AeadCipher::Aes128(Box::new(
                Aes128Gcm::new_from_slice(&key).expect("AES-128 key"),
            )),
        };
        Self {
            cipher,
            iv: iv_arr,
            seq: 0,
        }
    }

    fn seal(&mut self, inner_type: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(plaintext.len() + 1 + 16);
        body.extend_from_slice(plaintext);
        body.push(inner_type);

        let record_len = body.len() + 16;
        if record_len > u16::MAX as usize {
            return Err(TransportError::Tls(format!(
                "TLS record exceeds u16 length: {record_len}"
            )));
        }
        let mut header = Vec::with_capacity(5);
        header.push(TLS_RECORD_APPLICATION_DATA);
        header.extend_from_slice(&[0x03, 0x03]);
        put_u16(record_len as u16, &mut header);
        let nonce = self.next_nonce();
        let tag = self.encrypt_detached(&nonce, &header, &mut body)?;
        let mut out = header;
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn open(&mut self, header: &[u8; 5], ciphertext: &[u8]) -> Result<(u8, Vec<u8>)> {
        if ciphertext.len() < 16 {
            return Err(TransportError::Tls("TLS ciphertext too short".into()));
        }
        let split = ciphertext.len() - 16;
        let mut body = ciphertext[..split].to_vec();
        let tag = Tag::from_slice(&ciphertext[split..]);
        let nonce = self.next_nonce();
        self.decrypt_detached(&nonce, header, &mut body, tag)?;

        let Some(pos) = body.iter().rposition(|b| *b != 0) else {
            return Err(TransportError::Tls(
                "TLS inner plaintext missing type".into(),
            ));
        };
        let inner_type = body[pos];
        body.truncate(pos);
        Ok((inner_type, body))
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq = self.seq.to_be_bytes();
        for (dst, src) in nonce[4..].iter_mut().zip(seq) {
            *dst ^= src;
        }
        self.seq += 1;
        nonce
    }

    fn encrypt_detached(&self, nonce: &[u8; 12], aad: &[u8], body: &mut [u8]) -> Result<Tag> {
        match &self.cipher {
            AeadCipher::Aes128(c) => c
                .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, body)
                .map_err(|e| TransportError::Tls(format!("TLS AES-128-GCM encrypt: {e}"))),
        }
    }

    fn decrypt_detached(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        body: &mut [u8],
        tag: &Tag,
    ) -> Result<()> {
        match &self.cipher {
            AeadCipher::Aes128(c) => c
                .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, body, tag)
                .map_err(|e| TransportError::Tls(format!("TLS AES-128-GCM decrypt: {e}"))),
        }
    }
}

fn verify_finished(secret: &[u8; 32], transcript: &[u8], received: &[u8]) -> Result<()> {
    let expected = finished_verify_data(secret, transcript);
    if expected.as_slice() == received {
        Ok(())
    } else {
        Err(TransportError::Tls(
            "Reality TLS: server Finished verify_data mismatch".into(),
        ))
    }
}

fn finished_verify_data(secret: &[u8; 32], transcript: &[u8]) -> Vec<u8> {
    let finished_key = hkdf_expand_label(secret, b"finished", &[], 32);
    let transcript_hash = Sha256::digest(transcript);
    let mut h = <HmacSha256 as Mac>::new_from_slice(&finished_key).expect("HMAC key");
    h.update(&transcript_hash);
    h.finalize().into_bytes().to_vec()
}

fn derive_secret(secret: &[u8; 32], label: &[u8], transcript_hash: &[u8]) -> [u8; 32] {
    let expanded = hkdf_expand_label(secret, label, transcript_hash, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&expanded);
    out
}

fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    put_u16(len as u16, &mut info);
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, len)
}

fn hkdf_sha256(secret: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let prk = hkdf_extract(salt, secret);
    hkdf_expand(&prk, info, len)
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut h = <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
    h.update(ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize().into_bytes());
    out
}

fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = Vec::with_capacity(len);
    let mut previous = Vec::new();
    let mut counter = 1u8;
    while okm.len() < len {
        let mut h = <HmacSha256 as Mac>::new_from_slice(prk).expect("HMAC accepts any key length");
        h.update(&previous);
        h.update(info);
        h.update(&[counter]);
        previous = h.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&previous);
        counter = counter.checked_add(1).expect("HKDF output too long");
    }
    okm.truncate(len);
    okm
}

fn clamp_x25519_private(private: &mut [u8; 32]) {
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
}

fn x25519_public_from_private(private: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*private, x25519_dalek::X25519_BASEPOINT_BYTES)
}

fn x25519(private: &[u8; 32], peer_public: &[u8; 32]) -> Result<[u8; 32]> {
    let out = x25519_dalek::x25519(*private, *peer_public);
    // An all-zero shared secret means the peer sent a low-order point; BoringSSL's
    // `X25519` reports that as a failure and RFC 7748 §6.1 requires rejecting it.
    if out == [0u8; 32] {
        return Err(TransportError::Tls("X25519 ECDH failed".into()));
    }
    Ok(out)
}

fn take<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| TransportError::Tls("TLS parser offset overflow".into()))?;
    let out = input
        .get(*pos..end)
        .ok_or_else(|| TransportError::Tls("TLS parser truncated input".into()))?;
    *pos = end;
    Ok(out)
}

fn take_u8(input: &[u8], pos: &mut usize) -> Result<u8> {
    Ok(take(input, pos, 1)?[0])
}

fn take_u16(input: &[u8], pos: &mut usize) -> Result<u16> {
    let b = take(input, pos, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn take_u24(input: &[u8], pos: &mut usize) -> Result<usize> {
    let b = take(input, pos, 3)?;
    Ok(read_u24(b))
}

fn read_u24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
}

fn put_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u24(value: usize, out: &mut Vec<u8>) {
    out.push(((value >> 16) & 0xff) as u8);
    out.push(((value >> 8) & 0xff) as u8);
    out.push((value & 0xff) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_client_hello_writes_32_byte_session_id() {
        let reality = RealityConfig {
            public_key: [9u8; 32],
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
            support_x25519_mlkem768: false,
        };
        let random = [7u8; 32];
        let client_public = [3u8; 32];
        let auth_key = [5u8; 32];
        let (hello, _) = build_reality_client_hello(
            "example.com",
            &[],
            &random,
            &client_public,
            &auth_key,
            &reality,
        )
        .expect("client hello");
        assert_eq!(hello[0], HS_CLIENT_HELLO);
        assert_eq!(hello[38], 32);
        assert_ne!(&hello[39..71], &[0u8; 32]);
    }

    #[test]
    fn hkdf_expand_label_finished_len() {
        let secret = [1u8; 32];
        let out = hkdf_expand_label(&secret, b"finished", &[], 32);
        assert_eq!(out.len(), 32);
    }

    // ─── AEAD record layer ───────────────────────────────────────────────────

    /// Two `RecordKey`s derived from the same secret model the matched
    /// write/read pair on the two ends of a connection. Sealing then opening
    /// must round-trip, and the per-record nonce sequence must advance in
    /// lockstep so the second record also decrypts.
    #[test]
    fn record_key_seal_open_round_trips_and_sequences() {
        let secret = [0x2bu8; 32];
        let mut sender = RecordKey::new(CipherSuite::Aes128GcmSha256, &secret);
        let mut receiver = RecordKey::new(CipherSuite::Aes128GcmSha256, &secret);

        for payload in [b"first record".as_slice(), b"second record".as_slice()] {
            let record = sender
                .seal(TLS_RECORD_APPLICATION_DATA, payload)
                .expect("seal");
            let header: [u8; 5] = record[..5].try_into().unwrap();
            let (inner_type, plaintext) = receiver.open(&header, &record[5..]).expect("open");
            assert_eq!(inner_type, TLS_RECORD_APPLICATION_DATA);
            assert_eq!(plaintext, payload);
        }
        // Both counters advanced once per record.
        assert_eq!(sender.seq, 2);
        assert_eq!(receiver.seq, 2);
    }

    /// A flipped authentication-tag byte must make `open` fail rather than
    /// return forged plaintext.
    #[test]
    fn record_key_open_rejects_tampered_ciphertext() {
        let secret = [0x42u8; 32];
        let mut sender = RecordKey::new(CipherSuite::Aes128GcmSha256, &secret);
        let mut receiver = RecordKey::new(CipherSuite::Aes128GcmSha256, &secret);

        let mut record = sender
            .seal(TLS_RECORD_APPLICATION_DATA, b"authentic")
            .expect("seal");
        let header: [u8; 5] = record[..5].try_into().unwrap();
        let last = record.len() - 1;
        record[last] ^= 0xff;
        assert!(receiver.open(&header, &record[5..]).is_err());
    }

    // ─── Reality certificate authentication (anti-MITM gate) ──────────────────

    /// Minimal DER TLV writer (definite length, short or long form).
    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = value.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let bytes = len.to_be_bytes();
            let first = bytes.iter().position(|&b| b != 0).unwrap();
            let trimmed = &bytes[first..];
            out.push(0x80 | trimmed.len() as u8);
            out.extend_from_slice(trimmed);
        }
        out.extend_from_slice(value);
        out
    }

    /// Build a minimal X.509 cert carrying an Ed25519 SPKI and a signature
    /// `BIT STRING` containing `signature`, just enough for
    /// `extract_ed25519_cert_parts` / `verify_reality_certificate`.
    fn build_test_ed25519_cert(pubkey: &[u8; 32], signature: &[u8]) -> Vec<u8> {
        let oid = der(0x06, &[0x2b, 0x65, 0x70]); // 1.3.101.112 (Ed25519)
        let alg = der(0x30, &oid);
        let mut spki_bits = vec![0u8]; // unused-bits count
        spki_bits.extend_from_slice(pubkey);
        let spki_bitstring = der(0x03, &spki_bits);
        let mut spki_body = alg;
        spki_body.extend_from_slice(&spki_bitstring);
        let spki = der(0x30, &spki_body);

        // tbsCertificate children: version[0], serial, sigAlg, issuer, validity,
        // subject, subjectPublicKeyInfo — SPKI at index 6 (base 1 + 5).
        let mut tbs_body = Vec::new();
        tbs_body.extend_from_slice(&der(0xa0, &der(0x02, &[0x00]))); // version
        tbs_body.extend_from_slice(&der(0x02, &[0x01])); // serial
        tbs_body.extend_from_slice(&der(0x30, &[])); // sigAlg
        tbs_body.extend_from_slice(&der(0x30, &[])); // issuer
        tbs_body.extend_from_slice(&der(0x30, &[])); // validity
        tbs_body.extend_from_slice(&der(0x30, &[])); // subject
        tbs_body.extend_from_slice(&spki);
        let tbs = der(0x30, &tbs_body);

        let mut sig_bits = vec![0u8]; // unused-bits count
        sig_bits.extend_from_slice(signature);
        let sig_bitstring = der(0x03, &sig_bits);

        let mut cert_body = tbs;
        cert_body.extend_from_slice(&der(0x30, &[])); // outer signatureAlgorithm
        cert_body.extend_from_slice(&sig_bitstring);
        der(0x30, &cert_body)
    }

    fn reality_cert_hmac(auth_key: &[u8], pubkey: &[u8; 32]) -> Vec<u8> {
        let mut mac = <HmacSha512 as Mac>::new_from_slice(auth_key).unwrap();
        mac.update(pubkey);
        mac.finalize().into_bytes().to_vec()
    }

    #[test]
    fn verify_reality_certificate_accepts_matching_hmac() {
        let auth_key = [0x11u8; 32];
        let pubkey = [0x22u8; 32];
        let sig = reality_cert_hmac(&auth_key, &pubkey);
        let cert = build_test_ed25519_cert(&pubkey, &sig);
        verify_reality_certificate(&cert, &auth_key).expect("authentic Reality cert must verify");
    }

    #[test]
    fn verify_reality_certificate_rejects_wrong_hmac() {
        let auth_key = [0x11u8; 32];
        let pubkey = [0x22u8; 32];

        // Garbage signature is rejected.
        let cert = build_test_ed25519_cert(&pubkey, &[0u8; 64]);
        assert!(verify_reality_certificate(&cert, &auth_key).is_err());

        // A correctly-formed cert verified against the wrong auth key is
        // rejected — this is the anti-MITM property.
        let sig = reality_cert_hmac(&auth_key, &pubkey);
        let cert_ok = build_test_ed25519_cert(&pubkey, &sig);
        assert!(verify_reality_certificate(&cert_ok, &[0x99u8; 32]).is_err());
    }

    #[test]
    fn verify_reality_certificate_rejects_non_ed25519_leaf() {
        // RSA-ish OID instead of Ed25519: parser must refuse the leaf.
        let oid = der(
            0x06,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
        );
        let alg = der(0x30, &oid);
        let mut bits = vec![0u8];
        bits.extend_from_slice(&[1u8; 32]);
        let spki = der(0x30, &{
            let mut b = alg;
            b.extend_from_slice(&der(0x03, &bits));
            b
        });
        assert!(extract_ed25519_spki(&spki[2..]).is_none());
    }

    // ─── Split + concurrent direction polling (mux regression) ───────────────

    /// Deterministic chunk bytes for a (seq, len) pair.
    fn chunk(seq: u32, len: usize) -> Vec<u8> {
        let mut state = seq.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push((state >> 24) as u8);
        }
        out
    }

    /// Invariant test backing the mux corruption investigation: the REALITY
    /// record layer, driven through tokio split (read and write halves
    /// polled from two tasks concurrently), must preserve data byte-exact.
    /// The stress-era corruption was traced to the mux layer's stored-future
    /// write (a Pending re-poll re-framed the same chunk, duplicating it),
    /// NOT to this layer — this test locks that conclusion in: if split
    /// driving ever corrupts here, the layer needs its own fix.
    /// (see proxy-mux.md §6)
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn split_concurrent_read_write_preserves_data() {
        let (client_io, server_io) = tokio::io::duplex(512 * 1024);
        let secret = [0x5Au8; 32];

        let client_stream = RealityTlsStream {
            inner: Box::new(client_io),
            read_key: RecordKey::new(CipherSuite::Aes128GcmSha256, &secret),
            write_key: RecordKey::new(CipherSuite::Aes128GcmSha256, &secret),
            read_raw_passthrough: false,
            write_raw_passthrough: false,
            read_plain: VecDeque::new(),
            read_state: StreamReadState::Header {
                buf: [0; 5],
                pos: 0,
            },
            write_pending: None,
        };
        let server_stream = RealityTlsStream {
            inner: Box::new(server_io),
            read_key: RecordKey::new(CipherSuite::Aes128GcmSha256, &secret),
            write_key: RecordKey::new(CipherSuite::Aes128GcmSha256, &secret),
            read_raw_passthrough: false,
            write_raw_passthrough: false,
            read_plain: VecDeque::new(),
            read_state: StreamReadState::Header {
                buf: [0; 5],
                pos: 0,
            },
            write_pending: None,
        };

        // Server: read [u32 LE len][data] plaintext frames, echo them back.
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut s = server_stream;
            loop {
                let mut len_b = [0u8; 4];
                if s.read_exact(&mut len_b).await.is_err() {
                    return;
                }
                let len = u32::from_le_bytes(len_b) as usize;
                if len == 0 {
                    return;
                }
                let mut data = vec![0u8; len];
                if s.read_exact(&mut data).await.is_err() {
                    return;
                }
                if s.write_all(&len_b).await.is_err()
                    || s.write_all(&data).await.is_err()
                    || s.flush().await.is_err()
                {
                    return;
                }
            }
        });

        let (rd, wr) = tokio::io::split(Box::new(client_stream) as Box<dyn Stream>);

        // Reader task: verify every echoed chunk against the deterministic
        // generator — any corruption shows up as a mismatch.
        let reader = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut rd = rd;
            let mut seq = 0u32;
            let mut bad = 0u32;
            let mut count = 0u32;
            loop {
                let mut len_b = [0u8; 4];
                if rd.read_exact(&mut len_b).await.is_err() {
                    return (count, bad);
                }
                let len = u32::from_le_bytes(len_b) as usize;
                if len == 0 {
                    return (count, bad);
                }
                let mut data = vec![0u8; len];
                if rd.read_exact(&mut data).await.is_err() {
                    return (count, bad);
                }
                if data != chunk(seq, len) {
                    bad += 1;
                }
                count += 1;
                seq += 1;
            }
        });

        // Writer task: full-duplex pressure against the parked reader.
        let write_task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut wr = wr;
            for seq in 0..2000u32 {
                let len = 1 + ((seq.wrapping_mul(2_654_435_761)) % 8192) as usize;
                let data = chunk(seq, len);
                let mut frame = Vec::with_capacity(4 + len);
                frame.extend_from_slice(&(len as u32).to_le_bytes());
                frame.extend_from_slice(&data);
                if wr.write_all(&frame).await.is_err() || wr.flush().await.is_err() {
                    return;
                }
            }
            let _ = wr.write_all(&[0u8; 4]).await;
            let _ = wr.flush().await;
        });
        write_task.await.unwrap();

        let (count, bad) = reader.await.unwrap();
        assert_eq!(bad, 0, "corrupted echoes under concurrent split polling");
        assert_eq!(count, 2000, "all chunks must be echoed");
    }

    // ─── Reality ClientHello session_id seal ──────────────────────────────────

    /// The 32-byte session_id must decrypt, under the key/nonce/AAD a real
    /// Reality server reconstructs, to the authentication payload
    /// (`[1, 8, 1, 0] || timestamp || short_id`). Asserting the plaintext —
    /// not just the length — is what proves the server could authenticate us.
    #[test]
    fn reality_client_hello_session_id_decrypts_to_auth_payload() {
        let reality = RealityConfig {
            public_key: [9u8; 32],
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
            support_x25519_mlkem768: false,
        };
        let random = [7u8; 32];
        let client_public = [3u8; 32];
        let auth_key = [5u8; 32];
        let (hello, returned_key) = build_reality_client_hello(
            "example.com",
            &[],
            &random,
            &client_public,
            &auth_key,
            &reality,
        )
        .expect("client hello");

        // Key the server derives: HKDF(auth_key, salt = random[0..20], "REALITY").
        let aead_key = hkdf_sha256(&auth_key, &random[..20], b"REALITY", 32);
        assert_eq!(returned_key.as_slice(), aead_key.as_slice());

        // AAD is the ClientHello with the session_id field zeroed (its state at
        // seal time); nonce is the trailing 12 bytes of client_random.
        let mut aad = hello.clone();
        for b in &mut aad[39..71] {
            *b = 0;
        }
        let (ciphertext, tag) = hello[39..71].split_at(16);
        let cipher = Aes256Gcm::new_from_slice(&aead_key).unwrap();
        let nonce = Nonce::from_slice(&random[20..32]);
        let mut buf = ciphertext.to_vec();
        cipher
            .decrypt_in_place_detached(nonce, &aad, &mut buf, Tag::from_slice(tag))
            .expect("session_id must decrypt under the server-derived key");

        // ClientVer triple [1, 8, 1] — sing-box's hardcoded value
        // (common/tls/reality_client.go:186-188). Neither sing-box nor
        // xray servers validate these bytes; they are part of the
        // AES-GCM auth payload and the server only checks short_id
        // and timestamp after decryption.
        assert_eq!(&buf[0..4], &[1, 8, 1, 0], "reality auth header");
        assert_eq!(&buf[8..16], &reality.short_id, "short_id echoed");
    }

    // ─── Adversarial parser inputs ────────────────────────────────────────────

    #[test]
    fn der_read_rejects_truncated_and_overlong_length() {
        // Claims 4 content bytes, only 1 present.
        let mut pos = 0;
        assert!(der_read(&[0x04, 0x04, 0xaa], &mut pos).is_none());
        // Length-of-length > 4 is refused.
        let mut pos = 0;
        assert!(der_read(&[0x04, 0x85, 0, 0, 0, 0, 0], &mut pos).is_none());
    }

    #[test]
    fn parse_server_hello_rejects_malformed_input() {
        assert!(parse_server_hello(&[]).is_err());
        assert!(parse_server_hello(&[HS_SERVER_HELLO; 10]).is_err()); // < 42 bytes
        let mut buf = vec![0u8; 50];
        buf[0] = HS_CLIENT_HELLO; // wrong handshake type
        assert!(parse_server_hello(&buf).is_err());
    }

    // ─── poll_write changed-buffer safety ─────────────────────────────────────

    /// A mock inner stream whose first `poll_write` returns `Pending`
    /// (after self-waking) so that `drain_pending_write` can't complete
    /// on the initial seal.  Subsequent calls accept all bytes.
    struct PendingOnce {
        pending: bool,
        written: Vec<u8>,
    }

    impl AsyncRead for PendingOnce {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for PendingOnce {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.pending {
                self.pending = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for PendingOnce {}

    /// After `poll_write` seals a record and the inner stream returns
    /// `Pending`, the caller is told `Ok(chunk_len)` immediately (the
    /// record is buffered).  A *second* `poll_write` with a different
    /// buffer must drain the pending record first, then seal and report
    /// the *new* buffer's length — never the old record's length.
    ///
    /// This is the changed-buffer hazard from the #413 review: before
    /// the fix the top path returned `Ok(consumed)` (the old record's
    /// plaintext length) against whatever buffer arrived, sending stale
    /// bytes while claiming the new buffer was consumed.
    #[test]
    fn poll_write_reports_new_chunk_len_after_pending_drain() {
        let secret = [0x5Au8; 32];
        let mut stream = RealityTlsStream {
            inner: Box::new(PendingOnce {
                pending: true,
                written: Vec::new(),
            }),
            read_key: RecordKey::new(CipherSuite::Aes128GcmSha256, &secret),
            write_key: RecordKey::new(CipherSuite::Aes128GcmSha256, &secret),
            read_raw_passthrough: false,
            write_raw_passthrough: false,
            read_plain: VecDeque::new(),
            read_state: StreamReadState::Header {
                buf: [0; 5],
                pos: 0,
            },
            write_pending: None,
        };

        use tokio::io::AsyncWriteExt;

        // First write: 10 bytes.  Inner returns Pending → drain returns
        // Pending → poll_write returns Ok(10) with the record buffered.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let n = stream.write(&[0xAA; 10]).await.unwrap();
            assert_eq!(n, 10, "first write: chunk_len reported immediately");
        });

        // The pending record is buffered (not fully drained).
        assert!(
            stream.write_pending.is_some(),
            "record buffered after Pending drain"
        );

        // Second write: 5 different bytes.  The top path drains the
        // pending record (inner now accepts), then seals the new buffer.
        // Must report 5 (the new chunk_len), NOT 10 (the old record).
        rt.block_on(async {
            let n = stream.write(&[0xBB; 5]).await.unwrap();
            assert_eq!(n, 5, "second write: new chunk_len, not old record's length");
        });

        // The pending record from the second write should also be
        // drainable (inner accepts everything now).
        assert!(
            stream.write_pending.is_none(),
            "second record drained on this call"
        );
    }

    // ─── Pre-auth server-flight caps (issue #430) ─────────────────────────────

    fn handshake_message(typ: u8, body: Vec<u8>) -> HandshakeMessage {
        let mut raw = vec![typ];
        put_u24(body.len(), &mut raw);
        raw.extend_from_slice(&body);
        HandshakeMessage { typ, body, raw }
    }

    #[test]
    fn server_flight_guard_accepts_well_formed_flight() {
        let mut transcript = Vec::new();
        let mut flight = ServerFlightGuard::default();
        flight
            .admit(
                &mut transcript,
                &handshake_message(HS_ENCRYPTED_EXTENSIONS, vec![1, 2, 3]),
            )
            .expect("EncryptedExtensions accepted");
        flight
            .admit(
                &mut transcript,
                &handshake_message(HS_CERTIFICATE, vec![4, 5]),
            )
            .expect("Certificate accepted");
        flight
            .admit(
                &mut transcript,
                &handshake_message(HS_CERTIFICATE_VERIFY, vec![6]),
            )
            .expect("CertificateVerify accepted");
        assert!(flight.complete());
        // transcript accumulated exactly the three framed messages, in order.
        let expected: Vec<u8> = [
            handshake_message(HS_ENCRYPTED_EXTENSIONS, vec![1, 2, 3]).raw,
            handshake_message(HS_CERTIFICATE, vec![4, 5]).raw,
            handshake_message(HS_CERTIFICATE_VERIFY, vec![6]).raw,
        ]
        .concat();
        assert_eq!(transcript, expected);
    }

    #[test]
    fn server_flight_guard_rejects_duplicate_encrypted_extensions() {
        let mut transcript = Vec::new();
        let mut flight = ServerFlightGuard::default();
        flight
            .admit(
                &mut transcript,
                &handshake_message(HS_ENCRYPTED_EXTENSIONS, vec![]),
            )
            .expect("first EncryptedExtensions accepted");
        let err = flight
            .admit(
                &mut transcript,
                &handshake_message(HS_ENCRYPTED_EXTENSIONS, vec![]),
            )
            .expect_err("second EncryptedExtensions must be rejected");
        assert!(matches!(err, TransportError::Tls(msg) if msg.contains("EncryptedExtensions")));
    }

    #[test]
    fn server_flight_guard_rejects_certificate_before_encrypted_extensions() {
        let mut transcript = Vec::new();
        let mut flight = ServerFlightGuard::default();
        let err = flight
            .admit(&mut transcript, &handshake_message(HS_CERTIFICATE, vec![]))
            .expect_err("Certificate before EncryptedExtensions must be rejected");
        assert!(matches!(err, TransportError::Tls(msg) if msg.contains("Certificate")));
    }

    #[test]
    fn server_flight_guard_rejects_certificate_verify_before_certificate() {
        let mut transcript = Vec::new();
        let mut flight = ServerFlightGuard::default();
        flight
            .admit(
                &mut transcript,
                &handshake_message(HS_ENCRYPTED_EXTENSIONS, vec![]),
            )
            .expect("EncryptedExtensions accepted");
        let err = flight
            .admit(
                &mut transcript,
                &handshake_message(HS_CERTIFICATE_VERIFY, vec![]),
            )
            .expect_err("CertificateVerify before Certificate must be rejected");
        assert!(matches!(err, TransportError::Tls(msg) if msg.contains("CertificateVerify")));
    }

    /// Pins the fix's message-count cap: a peer that keeps sending
    /// (distinct-looking, but never-completing) flight messages must be cut
    /// off at `MAX_PRE_AUTH_HS_MESSAGES`, not accumulate forever. We drive
    /// this directly against `ServerFlightGuard` — the real state machine
    /// would reject a duplicate `EncryptedExtensions` long before the count
    /// cap fires (see the duplicate test above), so this isolates the cap
    /// itself rather than the ordering check.
    #[test]
    fn server_flight_guard_enforces_message_count_cap() {
        let mut transcript = Vec::new();
        let mut flight = ServerFlightGuard {
            message_count: MAX_PRE_AUTH_HS_MESSAGES,
            ..Default::default()
        };
        let err = flight
            .admit(
                &mut transcript,
                &handshake_message(HS_ENCRYPTED_EXTENSIONS, vec![]),
            )
            .expect_err("message beyond the count cap must be rejected");
        assert!(
            matches!(err, TransportError::Tls(msg) if msg.contains("pre-authentication handshake messages"))
        );
    }

    /// Pins the fix's cumulative-byte cap.
    #[test]
    fn server_flight_guard_enforces_transcript_byte_cap() {
        let mut transcript = vec![0u8; MAX_PRE_AUTH_TRANSCRIPT_LEN - 4];
        let mut flight = ServerFlightGuard::default();
        // A 5-byte message (the minimum non-empty framed message) pushes the
        // transcript one byte past the cap.
        let err = flight
            .admit(
                &mut transcript,
                &handshake_message(HS_ENCRYPTED_EXTENSIONS, vec![0]),
            )
            .expect_err("message pushing transcript past the byte cap must be rejected");
        assert!(matches!(err, TransportError::Tls(msg) if msg.contains("bytes")));
    }

    // ─── Full handshake: unbounded pre-auth flood is rejected (issue #430) ────

    /// Extract the client's X25519 key share from a raw (framed) ClientHello,
    /// mirroring the layout `build_reality_client_hello` writes, so the fake
    /// server below can complete the ECDH and derive matching handshake keys.
    fn extract_client_key_share(client_hello: &[u8]) -> [u8; 32] {
        assert_eq!(client_hello[0], HS_CLIENT_HELLO);
        let mut pos = 4 + 2 + 32; // header + legacy_version + random
        let sid_len = client_hello[pos] as usize;
        pos += 1 + sid_len;
        let cs_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
        pos += 2 + cs_len;
        let cm_len = client_hello[pos] as usize;
        pos += 1 + cm_len;
        let ext_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
        pos += 2;
        let exts_end = pos + ext_len;
        while pos < exts_end {
            let typ = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]);
            let len = u16::from_be_bytes([client_hello[pos + 2], client_hello[pos + 3]]) as usize;
            let data = &client_hello[pos + 4..pos + 4 + len];
            if typ == 51 {
                // ClientHello key_share carries a 2-byte list length, then
                // one KeyShareEntry (group u16, len u16, key bytes).
                let group = u16::from_be_bytes([data[2], data[3]]);
                assert_eq!(group, GROUP_X25519, "test only supports X25519");
                let mut key = [0u8; 32];
                key.copy_from_slice(&data[6..38]);
                return key;
            }
            pos += 4 + len;
        }
        panic!("ClientHello carried no key_share extension");
    }

    /// Build a minimal, well-formed plaintext ServerHello: TLS 1.3, echoes
    /// `session_id`, negotiates `TLS_AES_128_GCM_SHA256`, and carries an
    /// unwrapped (server-style) X25519 `key_share`. Matches what
    /// `parse_server_hello` expects.
    fn build_fake_server_hello(session_id: &[u8], server_public: &[u8; 32]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xAAu8; 32]); // random; must not be the HRR magic
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        put_u16(TLS_AES_128_GCM_SHA256, &mut body);
        body.push(0); // compression

        let mut exts = Vec::new();
        push_ext(&mut exts, 43, &[0x03, 0x04]); // supported_versions: TLS 1.3
        let mut key_share_entry = Vec::new();
        put_u16(GROUP_X25519, &mut key_share_entry);
        put_u16(server_public.len() as u16, &mut key_share_entry);
        key_share_entry.extend_from_slice(server_public);
        push_ext(&mut exts, 51, &key_share_entry);

        put_u16(exts.len() as u16, &mut body);
        body.extend_from_slice(&exts);

        let mut hello = vec![HS_SERVER_HELLO];
        put_u24(body.len(), &mut hello);
        hello.extend_from_slice(&body);
        hello
    }

    /// Drives `reality_handshake` against an in-memory duplex peer that
    /// completes the ServerHello key exchange like a real (or on-path
    /// attacker) peer would, then floods oversized `EncryptedExtensions`
    /// messages instead of ever sending `Finished`. Before the fix this grew
    /// `transcript` without bound; asserts it now errors out immediately
    /// after the state-machine's duplicate check rejects the second message,
    /// rather than after accumulating any of the flood.
    #[tokio::test]
    async fn reality_handshake_rejects_unbounded_encrypted_extensions_flood() {
        let (client_io, server_io): (tokio::io::DuplexStream, tokio::io::DuplexStream) =
            tokio::io::duplex(1024 * 1024);

        let reality = RealityConfig {
            public_key: [0x11u8; 32],
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
            support_x25519_mlkem768: false,
        };

        let server_task = tokio::spawn(async move {
            let mut server_io = server_io;

            let client_hello_record = read_record(&mut server_io)
                .await
                .expect("read ClientHello")
                .expect("ClientHello present");
            let client_hello = client_hello_record.payload;
            let client_public = extract_client_key_share(&client_hello);
            let session_id = client_hello[39..71].to_vec();

            let mut server_eph_private = rand::random::<[u8; 32]>();
            clamp_x25519_private(&mut server_eph_private);
            let server_eph_public = x25519_public_from_private(&server_eph_private);
            let shared_secret =
                x25519(&server_eph_private, &client_public).expect("ECDH with client key share");

            let server_hello = build_fake_server_hello(&session_id, &server_eph_public);
            server_io
                .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, &server_hello).unwrap())
                .await
                .expect("write ServerHello");
            server_io.flush().await.expect("flush ServerHello");

            let mut transcript = client_hello.clone();
            transcript.extend_from_slice(&server_hello);
            let hs =
                HandshakeKeys::derive(CipherSuite::Aes128GcmSha256, &shared_secret, &transcript);
            let mut server_hs = hs.server;

            // Every EncryptedExtensions below is the largest that fits in a
            // single TLS record (`read_record`'s 18 KiB cap), so — pre-fix —
            // a handful of these alone would already push `transcript` past
            // a hundred KiB with no end in sight.
            let oversized_ee =
                handshake_message(HS_ENCRYPTED_EXTENSIONS, vec![0xABu8; 16 * 1024]).raw;

            // First one is legitimate and must be accepted by the client.
            server_io
                .write_all(&server_hs.seal(TLS_RECORD_HANDSHAKE, &oversized_ee).unwrap())
                .await
                .expect("write first EncryptedExtensions");
            server_io
                .flush()
                .await
                .expect("flush first EncryptedExtensions");

            // Keep flooding; the client must stop reading well before this
            // loop's nominal end. Ignore write errors once the client has
            // hung up (it errors out and drops its side of the duplex).
            for _ in 0..64 {
                let record = server_hs.seal(TLS_RECORD_HANDSHAKE, &oversized_ee).unwrap();
                if server_io.write_all(&record).await.is_err() {
                    break;
                }
                if server_io.flush().await.is_err() {
                    break;
                }
            }
        });

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            reality_handshake(Box::new(client_io), "example.com", &[], &reality),
        )
        .await
        .expect("handshake must not hang while the flood is rejected");

        let Err(err) = result else {
            panic!("flooded EncryptedExtensions must be rejected, not accepted");
        };
        assert!(
            matches!(&err, TransportError::Tls(msg) if msg.contains("unexpected EncryptedExtensions")),
            "unexpected error: {err:?}"
        );

        server_task.await.expect("server task must not panic");
    }
}
