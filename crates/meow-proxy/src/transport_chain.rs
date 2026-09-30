//! Transport-layer chain builder for proxy adapters.
//!
//! `TransportChain` applies a sequence of [`meow_transport::Transport`] layers
//! to a raw TCP stream. Layers are applied left-to-right (TLS wraps TCP first;
//! WS wraps TLS+TCP second).
//!
//! # Example
//!
//! ```text
//! // VLESS over WS over TLS:
//! let mut chain = TransportChain::empty();
//! chain.push(Box::new(TlsLayer::new(&tls_cfg)?));
//! chain.push(Box::new(WsLayer::new(ws_cfg)));
//! let stream = chain.connect(Box::new(tcp)).await?;
//! ```
//!
//! TODO: deduplicate with vmess::transport_chain once M1.B-1 lands (VMess PR).

use meow_common::Result;
use meow_transport::{Stream, Transport};

/// An ordered sequence of transport layers applied to a TCP stream.
///
/// `len()` is the number of layers; 0 means plain TCP (no wrapping).
pub struct TransportChain {
    layers: Vec<Box<dyn Transport>>,
}

impl TransportChain {
    pub fn empty() -> Self {
        Self { layers: Vec::new() }
    }

    /// Number of layers in the chain (0 = plain TCP).
    pub fn len(&self) -> usize {
        self.layers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Append a layer to the end of the chain (applied last).
    pub fn push(&mut self, layer: Box<dyn Transport>) {
        self.layers.push(layer);
    }

    /// Apply all layers in order to `raw`, returning the fully-wrapped stream.
    pub async fn connect(&self, raw: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let mut stream = raw;
        for layer in &self.layers {
            stream = layer
                .connect(stream)
                .await
                .map_err(crate::transport_to_proxy_err)?;
        }
        Ok(stream)
    }
}
