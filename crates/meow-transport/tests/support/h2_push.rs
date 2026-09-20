//! An h2 server that pushes a fixed response body *without* waiting for
//! the client to read — the client's advertised receive windows are the
//! only thing pacing it, which makes them observable from a test.
// Feature unification compiles this module into every test binary of the
// crate (tls_test, ws_test, …) while only the h2-based suites use it; the
// dead-code warning there is expected and suppressed (same policy as
// loopback.rs).
#![allow(dead_code)]

use std::future::poll_fn;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

/// Accept one request on `io`, answer `200` immediately, hand `body` to h2
/// as fast as the *client's* flow-control windows allow, then end the
/// stream.  Resolves with the body length once every byte has been
/// accepted by h2 (i.e. covered by client-granted window).  Against h2's
/// default 65 535-byte windows the loop parks after the first 64 KiB until
/// the client reads, so a client that never reads makes the receiver hang
/// — the caller's timeout is the regression signal.
pub fn spawn_h2_push_server<S>(io: S, body: Vec<u8>) -> oneshot::Receiver<usize>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (done_tx, done_rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut conn = h2::server::handshake(io)
            .await
            .expect("push server: handshake");
        let (request, mut respond) = conn
            .accept()
            .await
            .expect("push server: one request")
            .expect("push server: accept");
        // Keep the connection driven so DATA / WINDOW_UPDATE frames flow.
        tokio::spawn(async move { while conn.accept().await.is_some() {} });

        let response = http::Response::builder()
            .status(200)
            .body(())
            .expect("static response");
        let mut send = respond
            .send_response(response, false)
            .expect("push server: send_response");

        let mut remaining = Bytes::from(body);
        let total = remaining.len();
        while !remaining.is_empty() {
            send.reserve_capacity(remaining.len());
            let granted = poll_fn(|cx| send.poll_capacity(cx))
                .await
                .expect("push server: stream closed while pushing")
                .expect("push server: capacity error");
            let chunk = remaining.split_to(granted.min(remaining.len()));
            send.send_data(chunk, false)
                .expect("push server: send_data");
        }
        send.send_data(Bytes::new(), true)
            .expect("push server: end of stream");
        // The request body stays alive (unread) until here so h2 never
        // resets the stream from under the response.
        drop(request);
        let _ = done_tx.send(total);
    });
    done_rx
}
