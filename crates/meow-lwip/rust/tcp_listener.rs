use std::{net::SocketAddr, pin::Pin};

use futures::stream::Stream;
use futures::task::{Context, Poll};
use tokio::sync::mpsc::{Receiver, UnboundedSender};

use super::core::Cmd;
use super::tcp_stream::TcpStream;

/// Accept-queue handle. Streams are fully constructed inside `tcp_accept_cb`
/// on the core task and arrive here ready to use.
pub struct TcpListener {
    accept_rx: Receiver<(TcpStream, SocketAddr, SocketAddr)>,
    cmd_tx: UnboundedSender<Cmd>,
}

impl TcpListener {
    pub(crate) fn new(
        accept_rx: Receiver<(TcpStream, SocketAddr, SocketAddr)>,
        cmd_tx: UnboundedSender<Cmd>,
    ) -> Self {
        TcpListener { accept_rx, cmd_tx }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Cmd::CloseListener);
    }
}

impl Stream for TcpListener {
    type Item = (TcpStream, SocketAddr, SocketAddr);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.accept_rx.poll_recv(cx)
    }
}
