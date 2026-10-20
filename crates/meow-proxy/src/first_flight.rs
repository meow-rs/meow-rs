//! Recover once after EOF/reset, before any decrypted reply, for a fresh ClientHello.
//! No HTTP payload, TLS application record, or established TLS session is replayed.
use meow_common::ProxyConn;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
type Conn = Box<dyn ProxyConn>;
type DialFuture = Pin<Box<dyn Future<Output = io::Result<Conn>> + Send>>;
pub(crate) type Redial = Arc<dyn Fn() -> DialFuture + Send + Sync>;
const CAP: usize = 16389;

// Conservative non-PSK suites. Unknown suites remain transparent but cannot
// establish replay eligibility; TLS 1.2 PSK does not require extension 41.
fn fresh_cipher(suite: u16) -> bool {
    matches!(
        suite,
        0x000a
            | 0x002f
            | 0x0035
            | 0x003c
            | 0x003d
            | 0x009c
            | 0x009d
            | 0xc009
            | 0xc00a
            | 0xc012
            | 0xc013
            | 0xc014
            | 0xc023
            | 0xc024
            | 0xc027
            | 0xc028
            | 0xc02b
            | 0xc02c
            | 0xc02f
            | 0xc030
            | 0xcca8
            | 0xcca9
            | 0x1301..=0x1305
    )
}

fn exceeds_record(prefix: &[u8], next: &[u8]) -> bool {
    if prefix.len() + next.len() > CAP {
        return true;
    }
    let mut header = [0; 5];
    let n = prefix.len().min(5);
    header[..n].copy_from_slice(&prefix[..n]);
    let m = next.len().min(5 - n);
    header[n..n + m].copy_from_slice(&next[..m]);
    n + m == 5
        && prefix.len() + next.len() > 5 + u16::from_be_bytes([header[3], header[4]]) as usize
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Flight {
    More,
    Ready,
    Reject,
}
pub(crate) fn classify(b: &[u8]) -> Flight {
    if b.is_empty() {
        return Flight::More;
    }
    if b[0] != 22 {
        return Flight::Reject;
    }
    if b.len() < 5 {
        return Flight::More;
    }
    if b[1] != 3 || !(1..=3).contains(&b[2]) {
        return Flight::Reject;
    }
    let n = u16::from_be_bytes([b[3], b[4]]) as usize;
    if !(45..=16384).contains(&n) || b.len() > n + 5 {
        return Flight::Reject;
    }
    if b.len() < n + 5 {
        return Flight::More;
    }
    if b[5] != 1 || ((b[6] as usize) << 16 | (b[7] as usize) << 8 | b[8] as usize) != n - 4 {
        return Flight::Reject;
    }
    // legacy_version, random, session id, cipher suites, compression, extensions.
    if b[9] != 3 || b[10] != 3 {
        return Flight::Reject;
    }
    let mut p = 43;
    let sid = b[p] as usize;
    p += 1;
    // A nonempty legacy ID is ambiguous with TLS 1.2 resumption, even when
    // used merely for TLS 1.3 compatibility. Do not guess whether it is fresh.
    if sid != 0 || p + sid + 2 > b.len() {
        return Flight::Reject;
    }
    p += sid;
    let c = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 2;
    if c < 2 || !c.is_multiple_of(2) || p + c + 1 > b.len() {
        return Flight::Reject;
    }
    let mut known_cipher = false;
    for &bytes in b[p..p + c].as_chunks::<2>().0 {
        let suite = u16::from_be_bytes(bytes);
        if fresh_cipher(suite) {
            known_cipher = true;
        } else if !matches!(suite, 0x00ff | 0x5600)
            && !(bytes[0] == bytes[1] && bytes[0] & 0x0f == 0x0a)
        {
            return Flight::Reject;
        }
    }
    if !known_cipher {
        return Flight::Reject;
    }
    p += c;
    let comp = b[p] as usize;
    p += 1;
    if comp == 0 || p + comp > b.len() {
        return Flight::Reject;
    }
    p += comp;
    if p == b.len() {
        return Flight::Ready;
    }
    if p + 2 > b.len() {
        return Flight::Reject;
    }
    let ext = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 2;
    if p + ext != b.len() {
        return Flight::Reject;
    }
    while p < b.len() {
        if p + 4 > b.len() {
            return Flight::Reject;
        }
        let kind = u16::from_be_bytes([b[p], b[p + 1]]);
        let len = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        p += 4;
        // ECH can hide PSK / early_data in its inner ClientHello.
        if matches!(kind, 35 | 41 | 42 | 0xfe0d) || p + len > b.len() {
            return Flight::Reject;
        }
        p += len;
    }
    Flight::Ready
}

pub(crate) struct FirstFlight {
    inner: Option<Conn>,
    redial: Redial,
    flow: u64,
    flight: Vec<u8>,
    disabled: bool,
    retried: bool,
    pending: Mutex<Option<DialFuture>>,
    recovery_timer: Option<Pin<Box<tokio::time::Sleep>>>,
    recovery_timeout: Duration,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}
impl FirstFlight {
    pub(crate) fn new(inner: Conn, redial: Redial, flow: u64) -> Self {
        Self {
            inner: Some(inner),
            redial,
            flow,
            flight: Vec::new(),
            disabled: false,
            retried: false,
            pending: Mutex::new(None),
            recovery_timer: None,
            recovery_timeout: Duration::from_secs(4),
            read_waker: None,
            write_waker: None,
        }
    }
    fn remember(&mut self, b: &[u8]) {
        if self.disabled || self.retried || b.is_empty() {
            return;
        }
        // Never cache plaintext application requests, even transiently.
        if (self.flight.is_empty() && b[0] != 22) || self.flight.len() + b.len() > CAP {
            self.disable();
            return;
        }
        self.flight.extend_from_slice(b);
        if classify(&self.flight) == Flight::Reject {
            self.disable();
        }
    }
    fn disable(&mut self) {
        self.disabled = true;
        self.flight.clear();
        self.recovery_timer = None;
    }
    fn wake_waiters(&mut self) {
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
    }
    fn retry(&mut self, reason: &str) -> bool {
        if self.disabled || self.retried || classify(&self.flight) != Flight::Ready {
            return false;
        }
        self.retried = true;
        let flight = std::mem::take(&mut self.flight);
        let dial = Arc::clone(&self.redial);
        // The first connection has no internal deadline. Only a terminal peer
        // read event starts this budget, including dial, replay and first reply.
        let deadline = tokio::time::Instant::now() + self.recovery_timeout;
        drop(self.inner.take());
        tracing::info!(
            flow = self.flow,
            reason,
            bytes = flight.len(),
            "socket-trace event=tls-first-flight-retry fresh_cipher=true maximum_retries=1"
        );
        *self.pending.get_mut().unwrap() = Some(Box::pin(async move {
            let attempt = async move {
                let mut conn = (dial)().await?;
                conn.write_all(&flight).await?;
                conn.flush().await?;
                Ok(conn)
            };
            tokio::time::timeout_at(deadline, attempt)
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "TLS first-flight redial budget")
                })?
        }));
        self.recovery_timer = Some(Box::pin(tokio::time::sleep_until(deadline)));
        true
    }
    fn connected(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let pending = self.pending.get_mut().unwrap();
        if let Some(future) = pending.as_mut() {
            let conn = match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(r) => r,
            };
            *pending = None;
            match conn {
                Ok(conn) => self.inner = Some(conn),
                Err(e) => {
                    self.disable();
                    self.wake_waiters();
                    return Poll::Ready(Err(e));
                }
            }
            self.wake_waiters();
        }
        if self.inner.is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TLS recovery connection unavailable",
            )))
        }
    }
}
impl AsyncRead for FirstFlight {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        s.read_waker = Some(cx.waker().clone());
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match s.connected(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                _ => {}
            }
            let before = buf.filled().len();
            let result = Pin::new(s.inner.as_mut().unwrap()).poll_read(cx, buf);
            if buf.filled().len() > before {
                s.disable();
                return result;
            }
            match result {
                Poll::Ready(Ok(())) => {
                    if s.retry("peer-eof-before-tls-response") {
                        continue;
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) => {
                    if matches!(
                        e.kind(),
                        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                    ) && s.retry("peer-error-before-tls-response")
                    {
                        continue;
                    }
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    if s.recovery_timer
                        .as_mut()
                        .is_some_and(|t| t.as_mut().poll(cx).is_ready())
                    {
                        drop(s.inner.take());
                        s.disable();
                        s.wake_waiters();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "TLS first-flight recovery budget",
                        )));
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}
impl AsyncWrite for FirstFlight {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let s = self.get_mut();
        s.write_waker = Some(cx.waker().clone());
        // A codec may already emit part of this write before returning Pending
        // or an error. Never move those additional bytes to a fresh session.
        if !buf.is_empty()
            && !s.disabled
            && !s.retried
            && (classify(&s.flight) == Flight::Ready || exceeds_record(&s.flight, buf))
        {
            s.disable();
        }
        match s.connected(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            _ => {}
        }
        let result = Pin::new(s.inner.as_mut().unwrap()).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            s.remember(&buf[..n]);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        s.write_waker = Some(cx.waker().clone());
        match s.connected(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            _ => Pin::new(s.inner.as_mut().unwrap()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        s.disable();
        if s.pending.get_mut().unwrap().take().is_some() {
            s.wake_waiters();
        }
        if let Some(conn) = s.inner.as_mut() {
            Pin::new(conn).poll_shutdown(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
impl ProxyConn for FirstFlight {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    fn hello() -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.extend([0, 0, 2, 0x13, 1, 1, 0]);
        let n = body.len() + 4;
        let mut b = vec![22, 3, 1, (n >> 8) as u8, n as u8, 1, 0, 0, body.len() as u8];
        b.extend(body);
        b
    }
    async fn setup() -> (FirstFlight, TcpListener, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let initial = TcpStream::connect(addr).await.unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&count);
        let redial: Redial = Arc::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(Box::new(TcpStream::connect(addr).await?) as Conn) })
        });
        (
            FirstFlight::new(Box::new(initial), redial, 0),
            listener,
            count,
        )
    }
    #[derive(Clone, Copy)]
    enum ExtraWrite {
        Pending,
        Error,
        Zero,
    }
    struct MockConn {
        first_remaining: usize,
        write_limit: usize,
        extra_write: ExtraWrite,
        extra_calls: Arc<AtomicUsize>,
        read_error: Option<io::ErrorKind>,
    }
    impl AsyncRead for MockConn {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.read_error {
                Some(kind) => Poll::Ready(Err(kind.into())),
                None => Poll::Ready(Ok(())),
            }
        }
    }
    impl AsyncWrite for MockConn {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let s = self.get_mut();
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if s.first_remaining > 0 {
                let n = buf.len().min(s.first_remaining).min(s.write_limit);
                s.first_remaining -= n;
                return Poll::Ready(Ok(n));
            }
            s.extra_calls.fetch_add(1, Ordering::SeqCst);
            match s.extra_write {
                ExtraWrite::Pending => Poll::Pending,
                ExtraWrite::Error => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                ExtraWrite::Zero => Poll::Ready(Ok(0)),
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl ProxyConn for MockConn {}
    fn mock_conn(extra_write: ExtraWrite, write_limit: usize) -> (Conn, Arc<AtomicUsize>) {
        let extra_calls = Arc::new(AtomicUsize::new(0));
        (
            Box::new(MockConn {
                first_remaining: hello().len(),
                write_limit,
                extra_write,
                extra_calls: Arc::clone(&extra_calls),
                read_error: None,
            }),
            extra_calls,
        )
    }
    #[derive(Default)]
    struct CountWake(AtomicUsize);
    impl std::task::Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    async fn controlled_recovery() -> (FirstFlight, tokio::sync::oneshot::Sender<()>) {
        let (release, wait) = tokio::sync::oneshot::channel();
        let wait = Arc::new(Mutex::new(Some(wait)));
        let redial: Redial = Arc::new(move || {
            let wait = wait.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let _ = wait.await;
                Err(io::Error::other("controlled redial failure"))
            })
        });
        let (inner, _) = mock_conn(ExtraWrite::Pending, usize::MAX);
        let mut conn = FirstFlight::new(inner, redial, 0);
        conn.write_all(&hello()).await.unwrap();
        (conn, release)
    }
    #[tokio::test]
    async fn extra_write_disables_recovery_even_when_not_reported_as_written() {
        for extra_write in [ExtraWrite::Pending, ExtraWrite::Error, ExtraWrite::Zero] {
            let calls = Arc::new(AtomicUsize::new(0));
            let retries = Arc::clone(&calls);
            let redial: Redial = Arc::new(move || {
                retries.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Err(io::Error::other("unexpected redial")) })
            });
            let (inner, extra_calls) = mock_conn(extra_write, usize::MAX);
            let mut conn = FirstFlight::new(inner, redial, 0);
            conn.write_all(&hello()).await.unwrap();
            let waker = Waker::from(Arc::new(CountWake::default()));
            let mut cx = Context::from_waker(&waker);
            let _ = Pin::new(&mut conn).poll_write(&mut cx, &[23, 3, 3, 0, 1, 0]);
            assert_eq!(extra_calls.load(Ordering::SeqCst), 1);
            assert!(conn.disabled);
            assert!(conn.flight.is_empty());
            assert!(conn.recovery_timer.is_none());
            let mut b = [0; 1];
            assert!(matches!(
                Pin::new(&mut conn).poll_read(&mut cx, &mut ReadBuf::new(&mut b)),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn coalesced_extra_data_disables_recovery_before_a_partial_write() {
        let calls = Arc::new(AtomicUsize::new(0));
        let retries = Arc::clone(&calls);
        let redial: Redial = Arc::new(move || {
            retries.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(io::Error::other("unexpected redial")) })
        });
        let (inner, _) = mock_conn(ExtraWrite::Pending, usize::MAX);
        let mut conn = FirstFlight::new(inner, redial, 0);
        let mut wire = hello();
        wire.extend([23, 3, 3, 0, 1, 0]);
        assert_eq!(conn.write(&wire).await.unwrap(), hello().len());
        assert!(conn.disabled);
        assert!(conn.flight.is_empty());
        assert_eq!(conn.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn partial_hello_writes_and_empty_writes_keep_recovery_eligible() {
        let (inner, extra_calls) = mock_conn(ExtraWrite::Pending, 7);
        let redial: Redial = Arc::new(|| Box::pin(async { Err(io::Error::other("unused")) }));
        let mut conn = FirstFlight::new(inner, redial, 0);
        conn.write_all(&hello()).await.unwrap();
        assert_eq!(conn.write(&[]).await.unwrap(), 0);
        assert!(!conn.disabled);
        assert_eq!(classify(&conn.flight), Flight::Ready);
        assert!(
            conn.recovery_timer.is_none(),
            "CH alone must not arm a timer"
        );
        assert_eq!(extra_calls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn redial_failure_wakes_waiting_write_and_flush() {
        for flush in [false, true] {
            let (mut conn, release) = controlled_recovery().await;
            let reader = Arc::new(CountWake::default());
            let writer = Arc::new(CountWake::default());
            let read_waker = Waker::from(reader);
            let write_waker = Waker::from(Arc::clone(&writer));
            let mut read_cx = Context::from_waker(&read_waker);
            let mut write_cx = Context::from_waker(&write_waker);
            let mut b = [0; 1];
            assert!(Pin::new(&mut conn)
                .poll_read(&mut read_cx, &mut ReadBuf::new(&mut b))
                .is_pending());
            if flush {
                assert!(Pin::new(&mut conn).poll_flush(&mut write_cx).is_pending());
            } else {
                assert!(Pin::new(&mut conn)
                    .poll_write(&mut write_cx, b"next")
                    .is_pending());
            }
            // The reader owns the redial future's latest registered waker.
            assert!(Pin::new(&mut conn)
                .poll_read(&mut read_cx, &mut ReadBuf::new(&mut b))
                .is_pending());
            let before = writer.0.load(Ordering::SeqCst);
            release.send(()).unwrap();
            assert!(matches!(
                Pin::new(&mut conn).poll_read(&mut read_cx, &mut ReadBuf::new(&mut b)),
                Poll::Ready(Err(_))
            ));
            assert!(writer.0.load(Ordering::SeqCst) > before);
            assert!(matches!(
                Pin::new(&mut conn).poll_flush(&mut write_cx),
                Poll::Ready(Err(_))
            ));
        }
    }
    #[tokio::test]
    async fn shutdown_cancels_pending_redial_and_wakes_both_halves() {
        let (mut conn, release) = controlled_recovery().await;
        let reader = Arc::new(CountWake::default());
        let writer = Arc::new(CountWake::default());
        let read_waker = Waker::from(Arc::clone(&reader));
        let write_waker = Waker::from(Arc::clone(&writer));
        let mut read_cx = Context::from_waker(&read_waker);
        let mut write_cx = Context::from_waker(&write_waker);
        let mut b = [0; 1];
        assert!(Pin::new(&mut conn)
            .poll_read(&mut read_cx, &mut ReadBuf::new(&mut b))
            .is_pending());
        assert!(Pin::new(&mut conn).poll_flush(&mut write_cx).is_pending());
        let read_before = reader.0.load(Ordering::SeqCst);
        let write_before = writer.0.load(Ordering::SeqCst);
        assert!(matches!(
            Pin::new(&mut conn).poll_shutdown(&mut write_cx),
            Poll::Ready(Ok(()))
        ));
        assert!(release.send(()).is_err(), "pending redial was not dropped");
        assert!(reader.0.load(Ordering::SeqCst) > read_before);
        assert!(writer.0.load(Ordering::SeqCst) > write_before);
        assert!(matches!(
            Pin::new(&mut conn).poll_read(&mut read_cx, &mut ReadBuf::new(&mut b)),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Pin::new(&mut conn).poll_flush(&mut write_cx),
            Poll::Ready(Err(_))
        ));
    }
    #[test]
    fn strict_flight_validation_rejects_plaintext_extra_records_and_early_data() {
        let mut b = hello();
        assert_eq!(classify(&b), Flight::Ready);
        for n in 0..b.len() {
            assert_eq!(classify(&b[..n]), Flight::More);
        }
        assert_eq!(classify(b"POST / HTTP/1.1\r\n"), Flight::Reject);
        b.extend([23, 3, 3, 0, 1, 0]);
        assert_eq!(classify(&b), Flight::Reject);
        let mut b = hello();
        b.extend([0, 4, 0, 42, 0, 0]);
        let n = b.len() - 5;
        b[3] = (n >> 8) as u8;
        b[4] = n as u8;
        b[8] = (n - 4) as u8;
        assert_eq!(classify(&b), Flight::Reject);
        let extension = b.len() - 4;
        b[extension] = 0xfe;
        b[extension + 1] = 0x0d;
        assert_eq!(classify(&b), Flight::Reject, "ECH must not be retried");
    }
    #[tokio::test]
    async fn resumable_psk_unknown_and_partial_hellos_are_transparent_without_replay() {
        let mut flights = Vec::new();
        for suite in [0x002c_u16, 0x008c, 0x00a8, 0xc035, 0xccab, 0xd001, 0xffff] {
            let mut b = hello();
            b[46..48].copy_from_slice(&suite.to_be_bytes());
            flights.push(b);
        }
        let mut b = hello();
        b[43] = 1;
        b.insert(44, 1);
        b[4] += 1;
        b[8] += 1;
        flights.push(b);
        for kind in [35_u16, 41, 42, 0xfe0d] {
            let mut b = hello();
            b.extend([0, 4, (kind >> 8) as u8, kind as u8, 0, 0]);
            b[4] += 6;
            b[8] += 6;
            flights.push(b);
        }
        let mut partial = hello();
        partial.pop();
        flights.push(partial);
        for wire in flights {
            assert_ne!(classify(&wire), Flight::Ready);
            let (mut conn, listener, calls) = setup().await;
            let expected = wire.clone();
            let server = tokio::spawn(async move {
                let (mut peer, _) = listener.accept().await.unwrap();
                let mut got = vec![0; expected.len()];
                peer.read_exact(&mut got).await.unwrap();
                assert_eq!(got, expected);
            });
            conn.write_all(&wire).await.unwrap();
            assert_eq!(conn.read(&mut [0; 1]).await.unwrap(), 0);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            server.await.unwrap();
        }
    }
    #[tokio::test]
    async fn eof_before_any_response_redials_once_and_replays_only_client_hello() {
        let (mut conn, listener, calls) = setup().await;
        let expected = hello();
        let wire = expected.clone();
        let server = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut peer, _) = listener.accept().await.unwrap();
                let mut got = vec![0; wire.len()];
                peer.read_exact(&mut got).await.unwrap();
                assert_eq!(got, wire);
                if attempt == 1 {
                    peer.write_all(b"TLS").await.unwrap();
                }
            }
        });
        conn.write_all(&expected).await.unwrap();
        let mut response = [0; 3];
        tokio::time::timeout(Duration::from_secs(2), conn.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response, b"TLS");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn plaintext_post_is_never_cached_or_replayed() {
        let (mut conn, listener, calls) = setup().await;
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut b = [0; 4];
            peer.read_exact(&mut b).await.unwrap();
        });
        conn.write_all(b"POST").await.unwrap();
        assert!(conn.flight.is_empty());
        let mut b = [0; 1];
        assert_eq!(conn.read(&mut b).await.unwrap(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn any_response_commits_session_and_prevents_replay() {
        let (mut conn, listener, calls) = setup().await;
        let h = hello();
        let size = h.len();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut b = vec![0; size];
            peer.read_exact(&mut b).await.unwrap();
            peer.write_all(b"S").await.unwrap();
        });
        conn.write_all(&h).await.unwrap();
        let mut b = [0; 1];
        assert_eq!(conn.read(&mut b).await.unwrap(), 1);
        assert_eq!(conn.read(&mut b).await.unwrap(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn tls_application_data_before_response_disables_recovery() {
        let (mut conn, listener, calls) = setup().await;
        let mut h = hello();
        h.extend([23, 3, 3, 0, 1, 0]);
        let size = h.len();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut b = vec![0; size];
            peer.read_exact(&mut b).await.unwrap();
        });
        conn.write_all(&h).await.unwrap();
        assert!(conn.disabled);
        let mut b = [0; 1];
        assert_eq!(conn.read(&mut b).await.unwrap(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn delayed_first_reply_does_not_start_recovery_budget() {
        let (mut conn, listener, calls) = setup().await;
        conn.recovery_timeout = Duration::from_millis(10);
        let h = hello();
        let size = h.len();
        let server = tokio::spawn(async move {
            let (mut held, _) = listener.accept().await.unwrap();
            let mut b = vec![0; size];
            held.read_exact(&mut b).await.unwrap();
            // Inject a short budget; the original connection outlives it.
            tokio::time::sleep(Duration::from_millis(50)).await;
            held.write_all(b"S").await.unwrap();
        });
        conn.write_all(&h).await.unwrap();
        let mut b = [0; 1];
        tokio::time::timeout(Duration::from_secs(2), conn.read_exact(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b, b"S");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn silent_original_survives_caller_read_timeout_without_replay() {
        let (mut conn, listener, calls) = setup().await;
        conn.recovery_timeout = Duration::from_millis(5);
        let h = hello();
        let size = h.len();
        let (release, wait) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut held, _) = listener.accept().await.unwrap();
            let mut b = vec![0; size];
            held.read_exact(&mut b).await.unwrap();
            wait.await.unwrap();
            held.write_all(b"S").await.unwrap();
        });
        conn.write_all(&h).await.unwrap();
        let mut b = [0; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(30), conn.read(&mut b))
                .await
                .is_err()
        );
        assert!(!conn.retried);
        assert!(conn.recovery_timer.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        release.send(()).unwrap();
        assert_eq!(conn.read(&mut b).await.unwrap(), 1);
        assert_eq!(&b, b"S");
        server.await.unwrap();
    }
    #[tokio::test]
    async fn local_read_errors_never_start_recovery() {
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::InvalidData,
            io::ErrorKind::Other,
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let retries = Arc::clone(&calls);
            let redial: Redial = Arc::new(move || {
                retries.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Err(io::Error::other("unexpected redial")) })
            });
            let inner = MockConn {
                first_remaining: hello().len(),
                write_limit: usize::MAX,
                extra_write: ExtraWrite::Pending,
                extra_calls: Arc::new(AtomicUsize::new(0)),
                read_error: Some(kind),
            };
            let mut conn = FirstFlight::new(Box::new(inner), redial, 0);
            conn.write_all(&hello()).await.unwrap();
            assert_eq!(conn.read(&mut [0; 1]).await.unwrap_err().kind(), kind);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn terminal_read_errors_can_start_only_one_recovery() {
        for kind in [io::ErrorKind::UnexpectedEof, io::ErrorKind::ConnectionReset] {
            let calls = Arc::new(AtomicUsize::new(0));
            let retries = Arc::clone(&calls);
            let redial: Redial = Arc::new(move || {
                retries.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Err(io::Error::other("controlled dial failure")) })
            });
            let inner = MockConn {
                first_remaining: hello().len(),
                write_limit: usize::MAX,
                extra_write: ExtraWrite::Pending,
                extra_calls: Arc::new(AtomicUsize::new(0)),
                read_error: Some(kind),
            };
            let mut conn = FirstFlight::new(Box::new(inner), redial, 0);
            conn.write_all(&hello()).await.unwrap();
            assert!(conn.read(&mut [0; 1]).await.is_err());
            assert!(conn.read(&mut [0; 1]).await.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
    #[tokio::test]
    async fn recovery_budget_bounds_pending_redial_and_wakes_writer() {
        let (mut conn, release) = controlled_recovery().await;
        conn.recovery_timeout = Duration::from_millis(15);
        let writer = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&writer));
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut conn)
            .poll_read(&mut cx, &mut ReadBuf::new(&mut [0; 1]))
            .is_pending());
        assert!(Pin::new(&mut conn).poll_flush(&mut cx).is_pending());
        let before = writer.0.load(Ordering::SeqCst);
        let error = tokio::time::timeout(Duration::from_secs(1), conn.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(release.send(()).is_err());
        assert!(writer.0.load(Ordering::SeqCst) > before);
    }
    #[tokio::test]
    async fn recovery_budget_includes_first_reply_on_the_fresh_connection() {
        let (mut conn, listener, calls) = setup().await;
        conn.recovery_timeout = Duration::from_millis(30);
        let size = hello().len();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            first.read_exact(&mut vec![0; size]).await.unwrap();
            drop(first);
            let (mut fresh, _) = listener.accept().await.unwrap();
            fresh.read_exact(&mut vec![0; size]).await.unwrap();
            assert_eq!(
                fresh.read(&mut [0; 1]).await.unwrap(),
                0,
                "expired recovery must release the fresh socket"
            );
        });
        conn.write_all(&hello()).await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), conn.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn repeated_eof_does_not_create_an_infinite_reconnect_loop() {
        let (mut conn, listener, calls) = setup().await;
        let h = hello();
        let size = h.len();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut peer, _) = listener.accept().await.unwrap();
                let mut b = vec![0; size];
                peer.read_exact(&mut b).await.unwrap();
            }
        });
        conn.write_all(&h).await.unwrap();
        let mut b = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), conn.read(&mut b))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.await.unwrap();
    }
}
