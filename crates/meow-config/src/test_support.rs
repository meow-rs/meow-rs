//! Test helpers shared by this crate's unit tests.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use meow_common::adapter::Proxy;
use meow_common::logbook::{self, Entry, Query};
use meow_common::Metadata;
use parking_lot::{Mutex, MutexGuard};

/// A provider origin the test steers: counts requests, answers with the
/// current body (503 while `None`) and `subscription-userinfo` header (none
/// while `None`), and holds each request until the gate is open.
pub(crate) struct Origin {
    pub(crate) url: String,
    hits: Arc<AtomicUsize>,
    pub(crate) body: Arc<Mutex<Option<&'static str>>>,
    pub(crate) userinfo: Arc<Mutex<Option<&'static str>>>,
    pub(crate) gate: tokio::sync::watch::Sender<bool>,
}

impl Origin {
    pub(crate) async fn spawn(body: Option<&'static str>, open: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/payload.yaml", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let body = Arc::new(Mutex::new(body));
        let userinfo = Arc::new(Mutex::new(None));
        let (gate, _) = tokio::sync::watch::channel(open);
        let (task_hits, task_body, task_userinfo, task_gate) = (
            Arc::clone(&hits),
            Arc::clone(&body),
            Arc::clone(&userinfo),
            gate.clone(),
        );
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                task_hits.fetch_add(1, Ordering::SeqCst);
                let body = Arc::clone(&task_body);
                let userinfo = Arc::clone(&task_userinfo);
                let mut gate = task_gate.subscribe();
                tokio::spawn(async move {
                    let mut sink = [0u8; 2048];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut sink).await;
                    let _ = gate.wait_for(|open| *open).await;
                    let userinfo = userinfo
                        .lock()
                        .map(|value| format!("subscription-userinfo: {value}\r\n"))
                        .unwrap_or_default();
                    let response = match *body.lock() {
                        Some(body) => format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{userinfo}\r\n{body}",
                            body.len()
                        ),
                        None => "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
                            .to_string(),
                    };
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
                });
            }
        });
        Self {
            url,
            hits,
            body,
            userinfo,
            gate,
        }
    }

    pub(crate) fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

pub(crate) async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    for _ in 0..500 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// Captures WARN lines while held. `set_default` is thread-local, so the
/// guard spans the awaits of a current-thread `#[tokio::test]` and never
/// sees a parallel test's lines.
pub(crate) struct WarnCapture {
    sink: WarnSink,
    _guard: tracing::subscriber::DefaultGuard,
}

#[derive(Clone)]
struct WarnSink(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for WarnSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for WarnSink {
    type Writer = WarnSink;
    fn make_writer(&'a self) -> WarnSink {
        self.clone()
    }
}

impl WarnCapture {
    pub(crate) fn start() -> Self {
        let sink = WarnSink(Arc::default());
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        Self {
            sink,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    /// The lines captured since the last call.
    pub(crate) fn take(&self) -> String {
        let captured = std::mem::take(&mut *self.sink.0.lock().unwrap());
        String::from_utf8_lossy(&captured).into_owned()
    }
}

/// `tracing` caches per-callsite `Interest` process-globally, and any
/// `with_default` enter/exit rebuilds that cache. A `warn!` evaluated on
/// a parallel test thread while no subscriber is active then caches
/// `Interest::never` — and the event is dropped *even inside a later
/// `with_default` scope*, which flakes the scoped warn-capture tests.
/// Installing a discarding GLOBAL default once makes bare threads
/// register `always`/`never` under it instead, so a `never` can only
/// stick for callsites this level would filter anyway. `WARN` matches
/// every capture site; raise it if a test ever captures below WARN.
/// `set_global_default` is once-per-process — later calls fail and are
/// ignored.
pub(crate) fn install_global_discard_subscriber() {
    let _ = tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_writer(std::io::sink)
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish(),
    );
}

/// The process-wide logbook, installed in a temporary directory for one
/// test at a time and uninstalled on drop. Tests that do not take it record
/// into it meanwhile, so a test reads its own subjects only.
pub(crate) struct TestLogbook {
    _dir: tempfile::TempDir,
    _serial: MutexGuard<'static, ()>,
}

static LOGBOOK: Mutex<()> = Mutex::new(());

impl TestLogbook {
    pub(crate) fn install() -> Self {
        let serial = LOGBOOK.lock();
        let dir = tempfile::tempdir().unwrap();
        logbook::install(dir.path(), logbook::Options::default()).unwrap();
        Self {
            _dir: dir,
            _serial: serial,
        }
    }

    /// The entries about `subject`, newest first.
    pub(crate) fn entries(&self, subject: &str) -> Vec<Entry> {
        let query = Query {
            subject: Some(subject.to_owned()),
            ..Query::default()
        };
        logbook::query(&query).unwrap().unwrap().entries
    }
}

impl Drop for TestLogbook {
    fn drop(&mut self) {
        logbook::uninstall();
    }
}

/// Serializes tests that observe [`crate::ech_dns::ECH_LOOKUPS`] — a
/// process-global counter a parallel test doing a real lookup could
/// otherwise interleave. Tokio-aware so it may be held across `.await`
/// (plain `#[test]` callers use `blocking_lock()`).
pub(crate) fn ech_dns_serial() -> &'static tokio::sync::Mutex<()> {
    static SERIAL: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// How a [`ScriptedProxy`]'s `dial_tcp` behaves.
#[derive(Clone, Copy)]
pub(crate) enum Dial {
    /// Fails at once — an unreachable upstream refusing the connect.
    Fail,
    /// Never completes — an upstream with no protocol-level connect timeout.
    Hang,
    /// Moves the paused clock `by`, resumes it, then hangs. Under
    /// `start_paused` that expires a dial timeout of `by` or less at once,
    /// while any later real socket I/O runs on the real clock: with a plain
    /// [`Dial::Hang`], tokio's auto-advance would also expire timeouts that
    /// wait on real I/O (a direct fallback's loopback connect).
    Expire { by: Duration },
}

/// A `Proxy` whose TCP dial follows a [`Dial`] script. It counts dials.
pub(crate) struct ScriptedProxy {
    name: &'static str,
    dial: Dial,
    dials: AtomicUsize,
    health: meow_common::ProxyHealth,
}

impl ScriptedProxy {
    pub(crate) fn arc(name: &'static str, dial: Dial) -> Arc<dyn Proxy> {
        Arc::new(Self {
            name,
            dial,
            dials: AtomicUsize::new(0),
            health: meow_common::ProxyHealth::new(),
        })
    }
}

#[async_trait::async_trait]
impl meow_common::ProxyAdapter for ScriptedProxy {
    fn name(&self) -> &str {
        self.name
    }
    fn adapter_type(&self) -> meow_common::AdapterType {
        meow_common::AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        false
    }
    async fn dial_tcp(
        &self,
        _m: &Metadata,
    ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
        self.dials.fetch_add(1, Ordering::SeqCst);
        match self.dial {
            Dial::Fail => Err(meow_common::MeowError::NotSupported(format!(
                "{}: connect refused",
                self.name
            ))),
            Dial::Hang => std::future::pending().await,
            Dial::Expire { by } => {
                tokio::time::advance(by).await;
                tokio::time::resume();
                std::future::pending().await
            }
        }
    }
    async fn dial_udp(
        &self,
        _m: &Metadata,
    ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
        Err(meow_common::MeowError::NotSupported(format!(
            "{}: dial_udp",
            self.name
        )))
    }
    fn health(&self) -> &meow_common::ProxyHealth {
        &self.health
    }
}

impl Proxy for ScriptedProxy {
    fn alive(&self) -> bool {
        true
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        true
    }
    fn last_delay(&self) -> u16 {
        0
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        0
    }
    fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
        Vec::new()
    }
}

/// Serve a `200 OK` carrying `body` to every connection accepted on
/// `127.0.0.1`, counting them — a direct fallback or a multi-DB download
/// dials more than once, and "this URL was never dialed" is a zero count.
pub(crate) async fn serve_body(body: &'static [u8]) -> (SocketAddr, Arc<AtomicUsize>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    tokio::spawn({
        let hits = Arc::clone(&hits);
        async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                hits.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf).await;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                });
            }
        }
    });
    (addr, hits)
}
