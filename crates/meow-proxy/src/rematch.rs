//! `type: rematch` control outbound (issue #974, mihomo's `C.Rematch`).
//!
//! A rematch node is not a transport: it carries no address and never
//! opens a socket. When a routing scan selects it, the tunnel applies
//! [`RematchAction`] to the flow's metadata and restarts the rule scan.
//! Every dial-path entry fails loudly instead, so a leaf that escapes the
//! scan layer — a forced/global/health/dialer-front probe that reached it
//! without unwrapping — cannot silently fall back to a direct dial.

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn,
    RematchAction, Result,
};
use smol_str::SmolStr;

pub struct RematchAdapter {
    name: SmolStr,
    /// `target-rematch-name` — `Some("")` is the explicit clear form;
    /// `None` leaves the flow's marker untouched.
    rematch_name: Option<SmolStr>,
    /// `target-sub-rule` — the `sub-rules:` block the next scan reads;
    /// `Some("")` returns to the top-level rule list.
    sub_rule: Option<SmolStr>,
    health: ProxyHealth,
}

impl RematchAdapter {
    /// `rematch_name`/`sub_rule` take the raw field values verbatim —
    /// the parser already normalized missing/`null` to `None` and kept
    /// explicit `""` as `Some("")` so the clear form survives to the
    /// transition.
    pub fn new(name: &str, rematch_name: Option<&str>, sub_rule: Option<&str>) -> Self {
        Self {
            name: SmolStr::from(name),
            rematch_name: rematch_name.map(SmolStr::from),
            sub_rule: sub_rule.map(SmolStr::from),
            health: ProxyHealth::new(),
        }
    }

    fn control_error(&self) -> MeowError {
        MeowError::Proxy(format!(
            "rematch '{}' is a control outbound — it cannot open a socket",
            self.name
        ))
    }
}

#[async_trait]
impl ProxyAdapter for RematchAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Rematch
    }

    /// No address — a control node has nothing to dial.
    fn addr(&self) -> &str {
        ""
    }

    /// Claims UDP like every built-in nop: the capability gate must not
    /// decide whether a UDP flow may take this hop — the rematch
    /// transition does, before any transport check (issue #974).
    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        Err(self.control_error())
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(self.control_error())
    }

    async fn connect_over(
        &self,
        _stream: Box<dyn ProxyConn>,
        _metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        Err(self.control_error())
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }

    fn rematch_action(&self) -> Option<RematchAction<'_>> {
        Some(RematchAction {
            rematch_name: self.rematch_name.as_deref(),
            sub_rule: self.sub_rule.as_deref(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_no_transport() {
        let a = RematchAdapter::new("inspect", Some("stage1"), Some("second-pass"));
        assert_eq!(a.adapter_type(), AdapterType::Rematch);
        assert_eq!(a.name(), "inspect");
        assert_eq!(a.addr(), "");
        assert!(
            a.support_udp(),
            "capability gate must not preempt the transition"
        );
    }

    #[test]
    fn action_reports_supplied_fields_verbatim() {
        let a = RematchAdapter::new("inspect", Some("stage1"), Some(" second-pass "));
        let action = a.rematch_action().unwrap();
        assert_eq!(action.rematch_name, Some("stage1"));
        assert_eq!(action.sub_rule, Some(" second-pass "));

        let clear = RematchAdapter::new("clear", Some(""), Some(""));
        let action = clear.rematch_action().unwrap();
        assert_eq!(action.rematch_name, Some(""));
        assert_eq!(action.sub_rule, Some(""));

        let none = RematchAdapter::new("noop", None, None);
        let action = none.rematch_action().unwrap();
        assert_eq!(action.rematch_name, None);
        assert_eq!(action.sub_rule, None);
    }

    #[tokio::test]
    async fn every_dial_path_fails_closed() {
        let a = RematchAdapter::new("inspect", Some("stage1"), None);
        for result in [
            a.dial_tcp(&Metadata::default()).await.map(|_| ()),
            a.dial_udp(&Metadata::default()).await.map(|_| ()),
        ] {
            let Err(err) = result else {
                panic!("a rematch leaf must never dial");
            };
            assert!(err.to_string().contains("control outbound"), "{err}");
        }
    }
}
