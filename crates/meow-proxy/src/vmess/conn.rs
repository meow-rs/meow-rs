use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::body::BodyCipher;
use super::header::{read_aead_response_header, response_body_keys};
use crate::tasked_duplex::TaskedDuplex;

/// Spawn a VMess relay task that handles AEAD body record framing.
///
/// Returns a `TaskedDuplex` that the caller reads/writes plain bytes on.
/// The background read task first consumes the AEAD-sealed response header
/// (validating the per-connection `resp_v` byte), then encrypts writes into
/// body records and decrypts reads from body records on the underlying stream.
///
/// Dropping the returned endpoint aborts both relay tasks — the bounded
/// cleanup path for a silent upstream that never sends data, FIN, or RST
/// (issue #514). A write-side `shutdown()` alone does not cancel anything:
/// the read direction keeps delivering upstream data (half-close download).
pub fn spawn_vmess_relay(
    stream: Box<dyn meow_transport::Stream>,
    mut read_cipher: BodyCipher,
    mut write_cipher: BodyCipher,
    req_key: [u8; 16],
    req_iv: [u8; 16],
    resp_v: u8,
) -> TaskedDuplex {
    let (client, proxy) = tokio::io::duplex(32768);
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (mut proxy_rd, mut proxy_wr) = tokio::io::split(proxy);

    // Upstream: consume the response header, then stream → decrypt →
    // proxy_wr. This runs concurrently with the write side: a conformant
    // server commonly waits for request data before sending its response
    // header, so awaiting the header before forwarding the request would
    // deadlock every request/response protocol.
    let read_task = tokio::spawn(async move {
        let (resp_body_key, resp_body_iv) = response_body_keys(&req_key, &req_iv);
        if let Err(e) =
            read_aead_response_header(&mut rd, &resp_body_key, &resp_body_iv, resp_v).await
        {
            tracing::warn!("vmess: response header decode failed: {e}");
            let _ = proxy_wr.shutdown().await;
            return;
        }

        loop {
            match read_cipher.read_record(&mut rd).await {
                Ok(plaintext) => {
                    if proxy_wr.write_all(&plaintext).await.is_err() {
                        break;
                    }
                }
                // UnexpectedEof is the ordinary close path (peer FIN or a
                // zero-length terminator record) — not worth a warn. The
                // rest covers decrypt failures and nonce-budget
                // exhaustion (issue #513), which otherwise look like an
                // unexplained ~1 GiB disconnect.
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::UnexpectedEof {
                        tracing::warn!("vmess: read side closed: {e}");
                    }
                    break;
                }
            }
        }
        let _ = proxy_wr.shutdown().await;
    });

    // Downstream: proxy_rd → encrypt → stream
    let write_task = tokio::spawn(async move {
        let mut buf = vec![0u8; BodyCipher::max_plaintext()];
        loop {
            let n = match proxy_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if let Err(e) = write_cipher.write_record(&mut wr, &buf[..n]).await {
                // Same visibility: seal failure or nonce-budget
                // exhaustion (issue #513).
                tracing::warn!("vmess: write side closed: {e}");
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    let aborts = [read_task.abort_handle(), write_task.abort_handle()];

    // When the read side ends — upstream close, decode failure, or nonce
    // budget — the exchange is over: stop the write side too. If the client
    // endpoint is dropped first, `TaskedDuplex` aborts both tasks and this
    // supervisor resolves immediately.
    tokio::spawn(async move {
        let _ = read_task.await;
        write_task.abort();
    });

    TaskedDuplex::new(client, aborts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmess::header::Security;
    use crate::vmess::kdf::{kdf12, kdf16};
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn seal_response_header(req_key: &[u8; 16], req_iv: &[u8; 16], resp_v: u8) -> Vec<u8> {
        let (resp_key, resp_iv) = response_body_keys(req_key, req_iv);
        let header = [resp_v, 0, 0, 0];

        let len_key = kdf16(&resp_key, &[b"AEAD Resp Header Len Key"]);
        let len_iv = kdf12(&resp_iv, &[b"AEAD Resp Header Len IV"]);
        let len_ct = Aes128Gcm::new_from_slice(&len_key)
            .unwrap()
            .encrypt(
                Nonce::from_slice(&len_iv),
                (header.len() as u16).to_be_bytes().as_ref(),
            )
            .unwrap();

        let header_key = kdf16(&resp_key, &[b"AEAD Resp Header Key"]);
        let header_iv = kdf12(&resp_iv, &[b"AEAD Resp Header IV"]);
        let header_ct = Aes128Gcm::new_from_slice(&header_key)
            .unwrap()
            .encrypt(Nonce::from_slice(&header_iv), header.as_ref())
            .unwrap();

        [len_ct, header_ct].concat()
    }

    #[tokio::test]
    async fn forwards_request_body_before_response_header_arrives() {
        let req_key = [0x11; 16];
        let req_iv = [0x22; 16];
        let resp_v = 0x5a;
        let (transport, mut server) = tokio::io::duplex(4096);
        let read_cipher = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, resp_v);
        let write_cipher = BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, resp_v);
        let mut app = spawn_vmess_relay(
            Box::new(transport),
            read_cipher,
            write_cipher,
            req_key,
            req_iv,
            resp_v,
        );

        app.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();

        // A real server does not send the response header until it has read
        // the request. The relay must therefore forward a body record first.
        let mut len = [0u8; 2];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.read_exact(&mut len),
        )
        .await
        .expect("request body was blocked behind response-header read")
        .unwrap();
        let mut ciphertext = vec![0u8; u16::from_be_bytes(len) as usize];
        server.read_exact(&mut ciphertext).await.unwrap();
        assert_eq!(ciphertext.len(), b"GET / HTTP/1.1\r\n\r\n".len() + 16);

        server
            .write_all(&seal_response_header(&req_key, &req_iv, resp_v))
            .await
            .unwrap();
    }

    /// Issue #514: dropping the returned endpoint must abort both relay
    /// tasks and release the transport even when the upstream stays silent
    /// (no data, FIN, or RST). Before the fix the read task parked on
    /// `read_record` forever and pinned the transport open.
    #[tokio::test]
    async fn drop_releases_silent_upstream_transport() {
        let req_key = [0x11; 16];
        let req_iv = [0x22; 16];
        let (transport, mut server) = tokio::io::duplex(4096);
        let app = spawn_vmess_relay(
            Box::new(transport),
            BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x5a),
            BodyCipher::new(Security::Aes128Gcm, &req_key, &req_iv, 0x5a),
            req_key,
            req_iv,
            0x5a,
        );
        drop(app);

        tokio::time::timeout(std::time::Duration::from_secs(2), async move {
            // The write half of the transport is held by the write task: once
            // aborted, reads on the server end see EOF.
            assert_eq!(
                server.read(&mut [0u8; 1]).await.unwrap(),
                0,
                "transport write half must be released"
            );
            // The read half is held by the read task parked on the silent
            // upstream: once aborted, writes on the server end must fail
            // instead of buffering into a dead peer.
            loop {
                match server.write(b"x").await {
                    Err(_) => break,
                    Ok(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("relay tasks must be aborted promptly on drop");
    }

    /// Issue #514 counterpart: a write-side half-close must NOT abort the
    /// read direction — a legitimate half-close download still completes.
    #[tokio::test]
    async fn write_half_close_keeps_read_side_open() {
        let req_key = [0x11; 16];
        let req_iv = [0x22; 16];
        let resp_v = 0x5a;
        let (transport, mut server) = tokio::io::duplex(4096);
        let mut app = spawn_vmess_relay(
            Box::new(transport),
            BodyCipher::new(Security::None, &req_key, &req_iv, resp_v),
            BodyCipher::new(Security::None, &req_key, &req_iv, resp_v),
            req_key,
            req_iv,
            resp_v,
        );

        // Client half-closes its write direction (e.g. request fully sent).
        app.shutdown().await.unwrap();
        // The transport's write half is shut down: the server observes EOF.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            assert_eq!(server.read(&mut [0u8; 1]).await.unwrap(), 0);
        })
        .await
        .expect("server must observe the client half-close");

        // The server can still answer: header + one plain (Security::None)
        // record must reach the client through the still-open read half.
        server
            .write_all(&seal_response_header(&req_key, &req_iv, resp_v))
            .await
            .unwrap();
        let payload = b"late download bytes";
        server
            .write_all(&(payload.len() as u16).to_be_bytes())
            .await
            .unwrap();
        server.write_all(payload).await.unwrap();

        let mut out = vec![0u8; payload.len()];
        tokio::time::timeout(std::time::Duration::from_secs(2), app.read_exact(&mut out))
            .await
            .expect("read side must stay open after write half-close")
            .unwrap();
        assert_eq!(&out, payload);
    }
}
