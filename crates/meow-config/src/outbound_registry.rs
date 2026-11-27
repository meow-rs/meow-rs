//! Registration of out-of-tree outbound adapters.
//!
//! An embedder registers its factories before calling the config parser.
//! Factories may receive inline or provider-supplied nodes and should validate
//! their options before constructing an adapter. Configuration matches the
//! registered type spelling exactly.
//!
//! ```no_run
//! use meow_config::outbound_registry::{register_outbound, OutboundContext, RegisterError};
//! use meow_common::ProxyAdapter;
//! use std::sync::Arc;
//!
//! # fn build_adapter(_: &OutboundContext<'_>) -> Result<Box<dyn ProxyAdapter>, String> {
//! #     unimplemented!("provide a factory for the outbound adapter")
//! # }
//! fn main() -> Result<(), RegisterError> {
//!     register_outbound("ExampleOutbound", Arc::new(build_adapter))
//! }
//! ```

use meow_common::ProxyAdapter;
use meow_dns::{DnsOutboundCell, ResolverSlot};
use meow_proxy::dialer::TcpDialer;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

/// Constructs an outbound from one configured node. The returned adapter must
/// report [`meow_common::AdapterType::External`] with [`OutboundContext::type_name`].
pub type OutboundFactory =
    Arc<dyn Fn(&OutboundContext<'_>) -> Result<Box<dyn ProxyAdapter>, String> + Send + Sync>;

/// Inputs to a registered outbound factory.
pub struct OutboundContext<'a> {
    type_name: &'static str,
    name: &'a str,
    config: &'a HashMap<String, Value>,
    dialer: &'a Arc<dyn TcpDialer>,
    resolver: Option<&'a DnsOutboundCell>,
    ipv6: bool,
}

impl<'a> OutboundContext<'a> {
    pub(crate) fn new(
        type_name: &'static str,
        name: &'a str,
        config: &'a HashMap<String, Value>,
        dialer: &'a Arc<dyn TcpDialer>,
        resolver: Option<&'a DnsOutboundCell>,
        ipv6: bool,
    ) -> Self {
        Self {
            type_name,
            name,
            config,
            dialer,
            resolver,
            ipv6,
        }
    }

    /// The canonical spelling originally passed to [`register_outbound`].
    pub fn type_name(&self) -> &'static str {
        self.type_name
    }

    /// The configured node name.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// The node's option map, including the shared fields.
    pub fn config(&self) -> &'a HashMap<String, Value> {
        self.config
    }

    /// The transport dialer for the node's server. Clone it into the adapter
    /// so dials follow the configured `dialer-proxy` and socket options.
    pub fn dialer(&self) -> &'a Arc<dyn TcpDialer> {
        self.dialer
    }

    /// The current resolver slot, if installed.
    pub fn resolver_slot(&self) -> Option<ResolverSlot> {
        self.resolver_cell()?.read().clone()
    }

    /// The live resolver indirection. Clone it when the adapter must see slots
    /// installed or replaced after parsing, as with provider nodes at startup.
    pub fn resolver_cell(&self) -> Option<&'a DnsOutboundCell> {
        self.resolver
    }

    /// Whether the configuration enables IPv6.
    pub fn ipv6(&self) -> bool {
        self.ipv6
    }
}

/// A registration that would conflict with a configured outbound type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// A built-in type name is reserved even when its feature is disabled.
    BuiltIn(&'static str),
    /// A factory already owns this type name.
    Duplicate(&'static str),
}

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BuiltIn(name) => write!(f, "outbound type '{name}' is reserved by a built-in"),
            Self::Duplicate(name) => write!(f, "outbound type '{name}' is already registered"),
        }
    }
}

impl std::error::Error for RegisterError {}

type Entry = (&'static str, OutboundFactory);
static REGISTRY: OnceLock<parking_lot::RwLock<HashMap<&'static str, OutboundFactory>>> =
    OnceLock::new();

/// Register a process-wide factory. Configuration and controller responses
/// use this exact spelling. Built-in reservations and duplicate checks ignore
/// ASCII case.
pub fn register_outbound(
    type_name: &'static str,
    factory: OutboundFactory,
) -> Result<(), RegisterError> {
    let key = type_name.to_ascii_lowercase();
    if crate::validation::known_node_keys(&key).is_some() {
        return Err(RegisterError::BuiltIn(type_name));
    }
    let mut registry = REGISTRY.get_or_init(Default::default).write();
    if registry
        .keys()
        .any(|name| name.eq_ignore_ascii_case(type_name))
    {
        return Err(RegisterError::Duplicate(type_name));
    }
    registry.insert(type_name, factory);
    Ok(())
}

pub(crate) fn lookup(type_name: &str) -> Option<Entry> {
    let registry = REGISTRY.get()?.read();
    // Clone before invoking user code so factories may re-enter the parser.
    registry
        .get_key_value(type_name)
        .map(|(&name, factory)| (name, Arc::clone(factory)))
}
