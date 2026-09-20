use super::selector_store::SelectorStore;
use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, ProviderSlot, Proxy, ProxyAdapter, ProxyConn,
    ProxyHealth, ProxyPacketConn, ProxySelection, Result,
};
use parking_lot::RwLock;
use smol_str::SmolStr;
use std::sync::Arc;

pub struct SelectorGroup {
    name: SmolStr,
    static_proxies: Vec<Arc<dyn Proxy>>,
    provider_slots: Vec<ProviderSlot>,
    /// Name of the currently selected proxy; `None` means use the first.
    selected: RwLock<Option<SmolStr>>,
    /// Optional write-through persistence; primed at construction.
    store: Option<Arc<SelectorStore>>,
    health: ProxyHealth,
}

impl SelectorGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>) -> Self {
        Self {
            name: SmolStr::from(name),
            static_proxies: proxies,
            provider_slots: Vec::new(),
            selected: RwLock::new(None),
            store: None,
            health: ProxyHealth::new(),
        }
    }

    pub fn new_with_providers(
        name: &str,
        proxies: Vec<Arc<dyn Proxy>>,
        slots: Vec<ProviderSlot>,
    ) -> Self {
        Self {
            name: SmolStr::from(name),
            static_proxies: proxies,
            provider_slots: slots,
            selected: RwLock::new(None),
            store: None,
            health: ProxyHealth::new(),
        }
    }

    /// Attach a persistent store. The previously-saved choice (if any) is
    /// loaded into `selected` immediately so the group dials it on first use.
    /// Subsequent successful `select()` calls flush back through the store.
    #[must_use]
    pub fn with_store(mut self, store: Arc<SelectorStore>) -> Self {
        if let Some(prev) = store.get(&self.name) {
            *self.selected.write() = Some(SmolStr::from(prev));
        }
        self.store = Some(store);
        self
    }

    fn contains_name(&self, name: &str) -> bool {
        if self.static_proxies.iter().any(|p| p.name() == name) {
            return true;
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            if guard.iter().any(|p| p.name() == name) {
                return true;
            }
        }
        false
    }

    /// Select the proxy with the given name. Returns `true` if found.
    /// Selection survives provider refreshes because it is stored by name.
    pub fn select(&self, name: &str) -> bool {
        if self.contains_name(name) {
            *self.selected.write() = Some(SmolStr::from(name));
            if let Some(store) = &self.store {
                store.set(&self.name, name);
            }
            true
        } else {
            false
        }
    }

    /// Resolve `selected` to an `Arc<dyn Proxy>` without allocating a unified
    /// `Vec`. Walks `static_proxies` then provider slots; falls back to the
    /// first proxy if `selected` is unset or names something no longer present.
    pub fn selected_proxy(&self) -> Option<Arc<dyn Proxy>> {
        let sel: Option<SmolStr> = self.selected.read().clone();
        let mut first_any: Option<Arc<dyn Proxy>> = None;
        if let Some(name) = sel {
            for p in &self.static_proxies {
                if first_any.is_none() {
                    first_any = Some(Arc::clone(p));
                }
                if p.name() == name {
                    return Some(Arc::clone(p));
                }
            }
            for slot in &self.provider_slots {
                let guard = slot.read();
                for p in guard.iter() {
                    if first_any.is_none() {
                        first_any = Some(Arc::clone(p));
                    }
                    if p.name() == name {
                        return Some(Arc::clone(p));
                    }
                }
            }
            return first_any;
        }
        if let Some(p) = self.static_proxies.first() {
            return Some(Arc::clone(p));
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            if let Some(p) = guard.first() {
                return Some(Arc::clone(p));
            }
        }
        None
    }

    pub fn proxy_names(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .static_proxies
            .iter()
            .map(|p| p.name().to_string())
            .collect();
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                out.push(p.name().to_string());
            }
        }
        out
    }

    /// Static members followed by every provider-slot member, in
    /// `proxy_names` order.
    fn member_proxy_list(&self) -> Vec<Arc<dyn Proxy>> {
        let mut out: Vec<Arc<dyn Proxy>> = self.static_proxies.iter().map(Arc::clone).collect();
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                out.push(Arc::clone(p));
            }
        }
        out
    }
}

#[async_trait]
impl ProxyAdapter for SelectorGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Selector
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        self.selected_proxy().is_some_and(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let proxy = self
            .selected_proxy()
            .ok_or_else(|| MeowError::Proxy("no proxy selected".into()))?;
        proxy.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let proxy = self
            .selected_proxy()
            .ok_or_else(|| MeowError::Proxy("no proxy selected".into()))?;
        proxy.dial_udp(metadata).await
    }

    fn unwrap_proxy(&self, _metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.selected_proxy()
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for SelectorGroup {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn alive(&self) -> bool {
        self.selected_proxy().is_some_and(|p| p.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.selected_proxy().is_some_and(|p| p.alive_for_url(url))
    }

    fn last_delay(&self) -> u16 {
        self.selected_proxy().map_or(0, |p| p.last_delay())
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.selected_proxy()
            .map_or(0, |p| p.last_delay_for_url(url))
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.selected_proxy()
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }

    fn members(&self) -> Option<Vec<String>> {
        Some(self.proxy_names())
    }

    fn member_proxies(&self) -> Option<Vec<Arc<dyn Proxy>>> {
        Some(self.member_proxy_list())
    }

    fn current(&self) -> Option<String> {
        self.selected_proxy().map(|p| p.name().into())
    }

    fn selection(&self) -> Option<&dyn ProxySelection> {
        Some(self)
    }
}

#[async_trait]
impl ProxySelection for SelectorGroup {
    async fn set(&self, name: &str) -> Result<()> {
        if self.select(name) {
            Ok(())
        } else {
            Err(MeowError::Proxy("proxy not exist".into()))
        }
    }

    fn force_set(&self, name: Option<&str>) {
        // SelectorGroup is a manual-pick group with no automatic fallback.
        // Clearing (None) is intentionally a no-op — a selector without a
        // selection has no sensible routing target. Automatic groups (UrlTest,
        // Fallback) handle None by reverting to auto mode.
        if let Some(name) = name {
            *self.selected.write() = Some(SmolStr::from(name));
            if let Some(store) = &self.store {
                store.set(&self.name, name);
            }
        }
    }

    fn fixed(&self) -> Option<String> {
        None
    }

    fn can_unfix(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::test_support::MockProxy;
    use meow_common::Metadata;

    /// `member_proxies()` must cover provider-slot members (issue #543
    /// item 1) and list them in `proxy_names()` order.
    #[test]
    fn member_proxies_include_provider_slots_in_proxy_names_order() {
        let slot: ProviderSlot = Arc::new(RwLock::new(vec![
            MockProxy::new("p1") as Arc<dyn Proxy>,
            MockProxy::new("p2") as Arc<dyn Proxy>,
        ]));
        let g = SelectorGroup::new_with_providers(
            "sel",
            vec![MockProxy::new("a"), MockProxy::new("b")],
            vec![slot],
        );
        let names: Vec<String> = g
            .member_proxies()
            .expect("groups expose members")
            .iter()
            .map(|p| p.name().to_string())
            .collect();
        assert_eq!(names, g.proxy_names());
        assert_eq!(names, vec!["a", "b", "p1", "p2"]);
    }

    #[test]
    fn unselected_falls_back_to_first_static() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        let g = SelectorGroup::new("sel", vec![a, b]);
        assert_eq!(g.selected_proxy().unwrap().name(), "a");
        assert_eq!(g.proxy_names(), vec!["a", "b"]);
    }

    #[test]
    fn select_changes_target_and_returns_true_only_when_present() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        let g = SelectorGroup::new("sel", vec![a, b]);
        assert!(g.select("b"));
        assert_eq!(g.selected_proxy().unwrap().name(), "b");
        assert!(!g.select("nope"));
        // Unknown name must not clobber the previous choice.
        assert_eq!(g.selected_proxy().unwrap().name(), "b");
    }

    #[test]
    fn selection_falls_back_when_named_proxy_disappears() {
        // Simulates a provider refresh that removed the previously-selected
        // node. Manually poke the selection to a missing name (the public
        // `select` would reject it; this mirrors the post-refresh state).
        let a = MockProxy::new("a");
        let g = SelectorGroup::new("sel", vec![a]);
        *g.selected.write() = Some("ghost".into());
        assert_eq!(g.selected_proxy().unwrap().name(), "a");
    }

    #[test]
    fn store_primes_initial_selection_and_persists_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sel.json");
        let store = crate::group::selector_store::SelectorStore::open(path.clone());
        store.set("sel", "b");

        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        let g = SelectorGroup::new("sel", vec![a, b]).with_store(Arc::clone(&store));
        assert_eq!(
            g.selected_proxy().unwrap().name(),
            "b",
            "primed selection should load from store"
        );

        assert!(g.select("a"));
        drop(store);
        let store2 = crate::group::selector_store::SelectorStore::open(path);
        assert_eq!(store2.get("sel").as_deref(), Some("a"));
    }

    #[test]
    fn support_udp_reflects_selected_target() {
        let tcp = MockProxy::new("tcp-only");
        let udp = MockProxy::new_udp("udp-able");
        let g = SelectorGroup::new("sel", vec![tcp, udp]);
        assert!(!g.support_udp(), "default selection is tcp-only");
        assert!(g.select("udp-able"));
        assert!(g.support_udp(), "switching selection updates udp support");
    }

    #[tokio::test]
    async fn dial_tcp_routes_to_selected_member() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        let g = SelectorGroup::new("sel", vec![a, b]);
        assert!(g.select("b"));
        let _ = g.dial_tcp(&Metadata::default()).await; // mock returns Err
        assert_eq!(a_ref.dials(), 0);
        assert_eq!(b_ref.dials(), 1);
    }
}
