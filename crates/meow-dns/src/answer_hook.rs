//! Observer of the address answers the DNS server hands its clients — the
//! `dns.nftset` hook. The hook's work may block (the nftables netlink add
//! waits for its ack), so it is packaged as a [`PendingHook`] the caller
//! runs off the receive loop and finishes before the answer is sent — a
//! firewall set it fills is current before the client can connect.

use std::net::IpAddr;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use crate::Resolver;

pub trait AnswerHook: Send + Sync {
    fn on_answer(&self, domain: &str, ip: IpAddr, ttl: Duration);
}

static HOOK: RwLock<Option<Arc<dyn AnswerHook>>> = RwLock::new(None);

/// Install (or with `None` remove) the process-wide answer hook.
pub fn install(hook: Option<Arc<dyn AnswerHook>>) {
    *HOOK.write().unwrap_or_else(PoisonError::into_inner) = hook;
}

/// One deferred `on_answer` call: the hook and the `(domain, ip, ttl)`
/// triple it observes. `Send + 'static` so receive loops can hand it to
/// `tokio::task::spawn_blocking` along with the send it must precede.
pub struct PendingHook {
    hook: Arc<dyn AnswerHook>,
    domain: String,
    ip: IpAddr,
    ttl: Duration,
}

impl PendingHook {
    /// Run the hook. May block on a netlink ack — never on a runtime
    /// thread; async contexts use `run_blocking` instead.
    pub fn run(self) {
        // A panicking hook must not kill the worker or cost the answer
        // it rode in with: the caller still sends after this returns —
        // ordering bends in the pathological case, losing answers must
        // not.
        let this = self;
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            this.hook.on_answer(&this.domain, this.ip, this.ttl);
        }))
        .is_err()
        {
            tracing::error!("dns answer hook panicked");
        }
    }
}

impl std::fmt::Debug for PendingHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingHook")
            .field("domain", &self.domain)
            .field("ip", &self.ip)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

/// `work.run()` on the blocking pool — the async-context form for spawned
/// query tasks, where running inline would park the runtime worker. The
/// caller keeps ordering by awaiting this before sending the answer.
pub(crate) async fn run_blocking(work: PendingHook) {
    // A JoinError means the blocking task died; `run` already catches a
    // hook panic, so this is pathological — the answer must go out
    // anyway.
    let _ = tokio::task::spawn_blocking(move || work.run()).await;
}

/// The hook call for this answer, packaged to run later — `None` when no
/// hook is installed (the cheap common case). Fake-IP answers are
/// skipped: the firewall intercepts the fake range as a whole.
pub(crate) fn pending(
    resolver: &Resolver,
    domain: &str,
    ip: IpAddr,
    ttl: Duration,
) -> Option<PendingHook> {
    let hook = HOOK
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()?;
    if resolver.is_fake_ip(ip) {
        return None;
    }
    Some(PendingHook {
        hook,
        domain: domain.into(),
        ip,
        ttl,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakeip::{MemoryStore, Pool};
    use meow_common::DnsMode;
    use std::sync::Mutex as StdMutex;

    /// `HOOK` is process-global: serialise these tests so installs cannot
    /// interleave, and always restore `None` — a stray hook left behind
    /// would reach other tests' answers through `pending`.
    static TEST_LOCK: StdMutex<()> = StdMutex::new(());

    struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            install(None);
        }
    }

    fn locked() -> (std::sync::MutexGuard<'static, ()>, HookGuard) {
        (
            TEST_LOCK.lock().unwrap_or_else(PoisonError::into_inner),
            HookGuard,
        )
    }

    fn empty_resolver() -> Resolver {
        Resolver::new(
            Vec::new(),
            Vec::new(),
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        )
    }

    /// Records each `on_answer` triple — `Arc` inside, `Mutex` over the
    /// log so `run` can take it by move.
    struct Recorder(Arc<StdMutex<Vec<(String, IpAddr, Duration)>>>);
    impl AnswerHook for Recorder {
        fn on_answer(&self, domain: &str, ip: IpAddr, ttl: Duration) {
            self.0.lock().unwrap_or_else(PoisonError::into_inner).push((
                domain.to_string(),
                ip,
                ttl,
            ));
        }
    }

    fn install_recorder() -> Arc<StdMutex<Vec<(String, IpAddr, Duration)>>> {
        let log = Arc::new(StdMutex::new(Vec::new()));
        install(Some(Arc::new(Recorder(Arc::clone(&log)))));
        log
    }

    #[test]
    fn pending_is_none_without_a_hook() {
        let (_l, _g) = locked();
        install(None);
        let resolver = empty_resolver();
        let ip = "192.0.2.1".parse().unwrap();
        assert!(pending(&resolver, "example.com", ip, Duration::from_secs(60)).is_none());
    }

    #[test]
    fn pending_packages_the_triple_and_run_delivers_it() {
        let (_l, _g) = locked();
        let log = install_recorder();
        let resolver = empty_resolver();
        let ip = "192.0.2.1".parse().unwrap();
        let ttl = Duration::from_secs(300);

        let work = pending(&resolver, "hooked.example", ip, ttl)
            .expect("a real IP with a hook installed must package the call");
        work.run();

        let log = log.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(
            log.iter()
                .any(|(d, i, t)| d == "hooked.example" && *i == ip && *t == ttl),
            "hook must observe the exact (domain, ip, ttl) the answer carried"
        );
    }

    #[test]
    fn pending_skips_active_fake_ips() {
        let (_l, _g) = locked();
        let log = install_recorder();
        let mut resolver = Resolver::new(
            Vec::new(),
            Vec::new(),
            DnsMode::FakeIp,
            meow_trie::DomainTrie::new(),
            false,
            true,
        );
        let pool = Arc::new(
            Pool::new(
                "198.18.0.0/16".parse().unwrap(),
                Arc::new(MemoryStore::new(16)),
            )
            .unwrap(),
        );
        resolver.set_fakeip_v4(Arc::clone(&pool));

        // `lookup` allocates — the returned address is an active fake IP.
        let fake = pool.lookup("faked.example");
        assert!(resolver.is_fake_ip(fake));
        assert!(pending(&resolver, "faked.example", fake, Duration::from_secs(1)).is_none());

        // A real answer for the same resolver still packages.
        let real = "192.0.2.9".parse().unwrap();
        assert!(pending(&resolver, "real.example", real, Duration::from_secs(1)).is_some());
        assert!(log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .all(|(d, _, _)| d != "faked.example"));
    }

    #[test]
    fn run_survives_a_panicking_hook() {
        let (_l, _g) = locked();
        struct Bomber;
        impl AnswerHook for Bomber {
            fn on_answer(&self, _: &str, _: IpAddr, _: Duration) {
                panic!("netlink went sideways");
            }
        }
        install(Some(Arc::new(Bomber)));
        let resolver = empty_resolver();
        let work = pending(
            &resolver,
            "boom.example",
            "192.0.2.3".parse().unwrap(),
            Duration::from_secs(1),
        )
        .unwrap();
        // Must return normally: the caller still sends the answer after this.
        work.run();
    }

    #[tokio::test]
    async fn run_blocking_delivers_on_the_blocking_pool() {
        // `pending` copies the hook `Arc` into `work`, so the test lock
        // (and the `install(None)` restore on its drop) can end before
        // the await — a std guard must not live across one.
        let ip = "192.0.2.7".parse().unwrap();
        let (log, work) = {
            let (_l, _g) = locked();
            let log = install_recorder();
            let resolver = empty_resolver();
            (
                log,
                pending(&resolver, "async.example", ip, Duration::from_secs(30)).unwrap(),
            )
        };

        run_blocking(work).await;

        assert!(log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|(d, i, _)| d == "async.example" && *i == ip));
    }
}
