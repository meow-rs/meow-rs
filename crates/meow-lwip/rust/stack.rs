use std::{io, pin::Pin};

use futures::sink::Sink;
use futures::stream::Stream;
use futures::task::{Context, Poll};
use tokio::sync::{mpsc::Receiver, watch};
use tokio_util::sync::PollSender;

use super::core::LwipCore;
use super::tcp_listener::TcpListener;
use super::udp::UdpSocket;
use crate::Error;

/// Ingress/egress handle for the netstack. `Sink` feeds raw IP frames to the
/// core task (bounded channel — backpressure parks the caller); `Stream`
/// yields egress frames produced by the netif output hook.
///
/// Dropping the `NetStack` is the teardown trigger: the core task observes
/// the ingress channel closing, tears down every pcb deterministically on its
/// own thread, and then signals [`NetStack::core_done`]. Consumers that
/// restart generations MUST await that signal before building a new stack —
/// lwIP's pcb lists and netif are process globals, so two live cores would
/// corrupt them (the same one-live-stack contract the old global-mutex design
/// had, now enforced in exactly one place).
pub struct NetStack {
    ingress: PollSender<Vec<u8>>,
    egress_rx: Receiver<Vec<u8>>,
    done_rx: watch::Receiver<bool>,
}

impl NetStack {
    pub fn new() -> Result<(Self, TcpListener, Box<UdpSocket>), Error> {
        Self::with_mtu(1500)
    }

    /// Use the TUN device's MTU for both IP families. Values below the
    /// IPv6 minimum (1280) are rejected before touching the global stack.
    pub fn with_mtu(mtu: u16) -> Result<(Self, TcpListener, Box<UdpSocket>), Error> {
        Self::with_buffer_size_and_mtu(512, 64, mtu)
    }

    /// Build the stack and spawn the single-owner core task on the current
    /// tokio runtime. Must be called from within a runtime context.
    pub fn with_buffer_size(
        stack_buffer_size: usize,
        udp_buffer_size: usize,
    ) -> Result<(Self, TcpListener, Box<UdpSocket>), Error> {
        Self::with_buffer_size_and_mtu(stack_buffer_size, udp_buffer_size, 1500)
    }

    fn with_buffer_size_and_mtu(
        stack_buffer_size: usize,
        udp_buffer_size: usize,
        mtu: u16,
    ) -> Result<(Self, TcpListener, Box<UdpSocket>), Error> {
        if mtu < 1280 {
            return Err(Error::InvalidMtu(mtu));
        }
        let parts = LwipCore::build(stack_buffer_size, udp_buffer_size, mtu)?;

        let stack = NetStack {
            ingress: PollSender::new(parts.ingress_tx),
            egress_rx: parts.egress_rx,
            done_rx: parts.done_rx,
        };
        let listener = TcpListener::new(parts.accept_rx, parts.cmd_tx.clone());
        let udp = UdpSocket::new(
            parts.udp_local_addr,
            parts.udp_in_rx,
            parts.udp_out_tx,
            parts.cmd_tx,
        );

        tokio::spawn(parts.core.run());

        Ok((stack, listener, udp))
    }

    /// A watch that flips to `true` once the core task has finished its full
    /// teardown (every pcb closed, hooks cleared). Await
    /// `rx.wait_for(|done| *done)` after dropping the stack handles before
    /// constructing a successor generation.
    pub fn core_done(&self) -> watch::Receiver<bool> {
        self.done_rx.clone()
    }
}

impl Stream for NetStack {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.egress_rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => Poll::Ready(Some(Ok(pkt))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Vec<u8>> for NetStack {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.ingress
            .poll_reserve(cx)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "netstack core gone"))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.ingress
            .send_item(item)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "netstack core gone"))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.ingress.close();
        Poll::Ready(Ok(()))
    }
}
