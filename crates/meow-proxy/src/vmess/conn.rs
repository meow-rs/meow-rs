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
    //
    // Returns `true` when the exchange ended on a clean EOF (peer FIN at a
    // record boundary / terminator record) — the write direction may still
    // have data in flight, so the supervisor leaves it running. `false`
    // marks a fatal end (handshake failure, decode error, transport error,
    // or the client endpoint gone), where the write side is stopped too.
    let read_task = tokio::spawn(async move {
        let (resp_body_key, resp_body_iv) = response_body_keys(&req_key, &req_iv);
        if let Err(e) =
            read_aead_response_header(&mut rd, &resp_body_key, &resp_body_iv, resp_v).await
        {
            tracing::warn!("vmess: response header decode failed: {e}");
            let _ = proxy_wr.shutdown().await;
            return false;
        }

        let clean_eof = loop {
            match read_cipher.read_record(&mut rd).await {
                Ok(Some(plaintext)) => {
                    if proxy_wr.write_all(&plaintext).await.is_err() {
                        break false;
                    }
                }
                // FIN at a record boundary or the explicit terminator
                // record — the clean half-close; not worth a warn.
                Ok(None) => break true,
                // Everything else is a corrupt session: FIN mid-record
                // (partial length prefix or short body), decrypt failure,
                // nonce-budget exhaustion (issue #513 — otherwise an
                // unexplained ~1 GiB disconnect), or a transport error.
                // Fatal: the write side is stopped too.
                Err(e) => {
                    tracing::warn!("vmess: read side closed: {e}");
                    break false;
                }
            }
        };
        let _ = proxy_wr.shutdown().await;
        clean_eof
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

    let read_abort = read_task.abort_handle();
    let write_abort = write_task.abort_handle();

    // When the read side ends on a FATAL path — decode failure, transport
    // error, nonce budget — the exchange is over: stop the write side too.
    // A clean EOF (peer FIN at a record boundary) only half-closes the
    // exchange: the client may still be uploading, so the write side keeps
    // running until the caller half-closes or drops the endpoint (issue
    // #514 review follow-up). If the client endpoint is dropped first,
    // `TaskedDuplex` aborts both tasks and this supervisor resolves
    // immediately.
    tokio::spawn(async move {
        let clean_eof = match read_task.await {
            Ok(clean) => clean,
            Err(e) => {
                if e.is_panic() {
                    tracing::error!("vmess: read task panicked: {e}");
                }
                false
            }
        };
        if !clean_eof {
            write_abort.abort();
        }
    });

    TaskedDuplex::new(client, read_abort, write_task)
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

    /// Issue #514 review follow-up: the reverse half-close — when the
    /// server sends FIN at a record boundary (clean EOF on the read side),
    /// the write direction must stay alive: a client still uploading must
    /// keep reaching the server instead of having its writer task aborted
    /// with the read loop.
    #[tokio::test]
    async fn upstream_half_close_keeps_write_side_open() {
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

        // Server answers the response header, then half-closes its send
        // direction while continuing to read uploads.
        server
            .write_all(&seal_response_header(&req_key, &req_iv, resp_v))
            .await
            .unwrap();
        server.shutdown().await.unwrap();

        // The client observes EOF on its read direction.
        let mut sink = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            app.read_to_end(&mut sink),
        )
        .await
        .expect("client read side must observe the server FIN")
        .unwrap();

        // Give the supervisor a scheduling slice: under the buggy version
        // it aborts the write task as soon as the read loop ends.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // A post-FIN upload must still reach the server.
        app.write_all(b"post-fin upload").await.unwrap();
        let mut len = [0u8; 2];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            server.read_exact(&mut len),
        )
        .await
        .expect("write side must stay open after upstream half-close")
        .unwrap();
        let mut rec = vec![0u8; u16::from_be_bytes(len) as usize];
        server.read_exact(&mut rec).await.unwrap();
        assert_eq!(&rec, b"post-fin upload");
    }

    /// Issue #514 review: a FIN landing MID-record is not a half-close —
    /// it is a corrupt session. The read task must classify it fatal so
    /// the supervisor aborts the write side instead of letting uploads
    /// keep pumping into a broken connection. Covers both truncation
    /// points: inside the length prefix and inside the body.
    #[tokio::test]
    async fn upstream_truncated_record_aborts_write_side() {
        for tail in [
            // One byte of the two-byte length prefix, then FIN.
            vec![0x00u8].as_slice(),
            // Full prefix promising 8 body bytes, only 3 arrive, then FIN.
            [0x00, 0x08, 1, 2, 3].as_slice(),
        ] {
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

            server
                .write_all(&seal_response_header(&req_key, &req_iv, resp_v))
                .await
                .unwrap();
            server.write_all(tail).await.unwrap();
            server.shutdown().await.unwrap();

            // The client still observes EOF on its read direction.
            let mut sink = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                app.read_to_end(&mut sink),
            )
            .await
            .expect("client read side must observe the upstream close")
            .unwrap();

            // Fatal classification ⇒ supervisor aborted the write task:
            // the transport's write half is released, so the server's read
            // side sees EOF — and client writes fail instead of
            // disappearing into a dead session.
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                assert_eq!(
                    server.read(&mut [0u8; 1]).await.unwrap(),
                    0,
                    "transport write half must be released after truncation"
                );
            })
            .await
            .expect("write task must be aborted after truncation");
            app.write_all(b"late upload")
                .await
                .expect_err("writes must fail once the session is dead");
        }
    }
}
