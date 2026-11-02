//! Observer of the address answers the DNS server hands its clients — the
//! `dns.nftset` hook. It runs synchronously before the
//! answer is built, so a firewall set it fills is current before the client
//! can connect.

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

/// Fake-IP answers are skipped: the firewall intercepts the fake range as a
/// whole.
pub(crate) fn notify(resolver: &Resolver, domain: &str, ip: IpAddr, ttl: Duration) {
    let hook = HOOK.read().unwrap_or_else(PoisonError::into_inner).clone();
    if let Some(hook) = hook {
        if !resolver.is_fake_ip(ip) {
            hook.on_answer(domain, ip, ttl);
        }
    }
}
