//! Test helpers shared by the provider modules.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use meow_common::logbook::{self, Entry, Query};
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
