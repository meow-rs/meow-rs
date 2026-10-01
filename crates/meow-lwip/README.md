> **Vendored in meow-rs.** This is `meow-lwip`, a vendored copy of the
> [madeye/lwip](https://github.com/madeye/lwip) fork of
> [`lwip`](https://crates.io/crates/lwip) (ssrlive/lwip), published as part of
> the meow-rs workspace at the shared workspace version.
>
> The Rust layer diverges from upstream: the core is single-owner (`LWIP_MUTEX`
> removed entirely), with fixes for a data race / use-after-free in
> `Stream::poll_next`, a `poll_flush` Pending-without-waker deadlock, a
> FIN_WAIT_2 pcb leak, a timer-task livelock and a use-after-free on
> TIME_WAIT pcbs that lwIP recycles without an error callback. The C lwIP
> sources under `old-src/` are unmodified upstream lwIP (BSD-3-Clause, see
> `COPYING`).
>
> Dependents use it as `lwip = { package = "meow-lwip", … }`, so `use lwip::…`
> paths are unchanged.

lwip - A Rust wrapper for lwIP
==============================

[![Version](https://img.shields.io/crates/v/lwip.svg?style=flat)](https://crates.io/crates/lwip)
[![Documentation](https://img.shields.io/badge/docs-release-brightgreen.svg?style=flat)](https://docs.rs/lwip)
[![Download](https://img.shields.io/crates/d/lwip.svg)](https://crates.io/crates/lwip)

A netstack for the special purpose of turning packets from/to a TUN interface into TCP streams and UDP packets.
It uses `lwIP` as the backend netstack.

```rust, ignore
use futures::{SinkExt, StreamExt};

let (stack, mut tcp_listener, udp_socket) = ::lwip::NetStack::new().unwrap();
let (mut stack_sink, mut stack_stream) = stack.split();

// tun device is assumed implementing `Stream` and `Sink`
let (mut tun_sink, mut tun_stream) = tun.split();

// Reads packet from stack and sends to TUN.
tokio::spawn(async move {
    while let Some(pkt) = stack_stream.next().await {
        if let Ok(pkt) = pkt {
            tun_sink.send(pkt).await.unwrap();
        }
    }
});

// Reads packet from TUN and sends to stack.
tokio::spawn(async move {
    while let Some(pkt) = tun_stream.next().await {
        if let Ok(pkt) = pkt {
            stack_sink.send(pkt).await.unwrap();
        }
    }
});

// Extracts TCP connections from stack and sends them to the dispatcher.
tokio::spawn(async move {
    while let Some((stream, local_addr, remote_addr)) = tcp_listener.next().await {
        tokio::spawn(handle_inbound_stream(stream, local_addr, remote_addr));
    }
});

// Receive and send UDP packets between netstack and NAT manager. The NAT
// manager would maintain UDP sessions and send them to the dispatcher.
tokio::spawn(async move {
    handle_inbound_datagram(udp_socket).await;
});
```
