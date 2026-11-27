//! Allocation-bound evidence for the Vision server codec (spec §6): the
//! steady-state read/write paths must not allocate, and peer-controlled
//! u16 length fields must not be able to force allocation either.
//!
//! Counting is thread-local, so the counting allocator is safe in a
//! parallel test binary: only the driving thread's allocations measure.
//! Everything is polled manually with a no-op waker — no runtime, no
//! worker threads, no noise.

#![cfg(feature = "vless-vision")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(feature = "mux")]
use meow_proxy::mux::xudp::{
    encode_reply_keep_data, XudpAction, XudpAddr, XudpDecoder, XudpFrame, XudpNetwork, XudpServer,
    XudpTarget,
};
use meow_proxy::vless_inbound::{VisionServerConn, VisionServerMode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.with(Cell::get) {
            ALLOCATIONS.with(|a| a.set(a.get() + 1));
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn allocation_count<T>(f: impl FnOnce() -> T) -> (usize, T) {
    COUNTING.with(|c| c.set(true));
    ALLOCATIONS.with(|a| a.set(0));
    let out = f();
    COUNTING.with(|c| c.set(false));
    (ALLOCATIONS.with(Cell::get), out)
}

/// Scripted in-memory peer: reads come from a preloaded byte queue, writes
/// are counted (and the first bytes kept for inspection).  Never pends, so
/// manual polling with a no-op waker drives the whole codec.
struct ScriptStream {
    inbound: VecDeque<u8>,
    written_len: usize,
    written_prefix: Vec<u8>,
}

impl ScriptStream {
    fn new(inbound: Vec<u8>) -> Self {
        Self {
            inbound: inbound.into(),
            written_len: 0,
            written_prefix: Vec::with_capacity(64 * 1024),
        }
    }
}

impl AsyncRead for ScriptStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let want = buf.remaining().min(self.inbound.len());
        for _ in 0..want {
            buf.put_slice(&[self.inbound.pop_front().expect("bounded by len")]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written_len += buf.len();
        if self.written_prefix.len() < self.written_prefix.capacity() {
            let room = self.written_prefix.capacity() - self.written_prefix.len();
            self.written_prefix
                .extend_from_slice(&buf[..buf.len().min(room)]);
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

const UUID: [u8; 16] = [0x71; 16];

fn frame(
    command: u8,
    with_uuid: bool,
    content_len: usize,
    padding_len: usize,
    fill: u8,
) -> Vec<u8> {
    let mut out = Vec::new();
    if with_uuid {
        out.extend_from_slice(&UUID);
    }
    out.push(command);
    out.extend_from_slice(&(content_len as u16).to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.resize(out.len() + content_len + padding_len, fill);
    out
}

/// Drive one read into a fixed caller buffer, returning bytes delivered.
fn drive_read(conn: &mut VisionServerConn, buf: &mut [u8]) -> usize {
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut read_buf = ReadBuf::new(buf);
    match Pin::new(conn).poll_read(&mut cx, &mut read_buf) {
        Poll::Ready(Ok(())) => read_buf.filled().len(),
        Poll::Ready(Err(error)) => panic!("read failed: {error}"),
        Poll::Pending => panic!("scripted stream never pends"),
    }
}

fn drive_write(conn: &mut VisionServerConn, buf: &[u8]) -> usize {
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    match Pin::new(conn).poll_write(&mut cx, buf) {
        Poll::Ready(Ok(n)) => n,
        Poll::Ready(Err(error)) => panic!("write failed: {error}"),
        Poll::Pending => panic!("scripted stream never pends"),
    }
}

#[test]
fn steady_state_read_path_allocates_nothing() {
    // Twenty content-bearing CONTINUE frames, then an END frame: exactly
    // the shape of a padded downlink in flight.
    let mut wire = Vec::new();
    for i in 0..20u8 {
        wire.extend(frame(0x00, i == 0, 512, 400, i));
    }
    wire.extend(frame(0x01, false, 512, 0, 0xfe));

    let stream = ScriptStream::new(wire);
    let mut conn = VisionServerConn::new(Box::new(stream), UUID, VisionServerMode::Tcp);

    // Warm-up read: nothing in the read path may lazily allocate either.
    // One frame's content (512 bytes) is delivered per poll at most.
    let mut buf = [0u8; 4096];
    assert_eq!(drive_read(&mut conn, &mut buf), 512);

    let (allocs, total) = allocation_count(|| {
        let mut total = 0usize;
        loop {
            let n = drive_read(&mut conn, &mut buf);
            if n == 0 {
                break;
            }
            total += n;
        }
        total
    });
    assert_eq!(allocs, 0, "steady-state read path allocated {allocs} times");
    // 19 remaining CONTINUE frames plus the END frame's content.
    assert_eq!(total, 20 * 512);
}

#[test]
fn steady_state_write_path_allocates_nothing() {
    let stream = ScriptStream::new(Vec::new());
    let mut conn = VisionServerConn::new(Box::new(stream), UUID, VisionServerMode::Tcp);

    // Warm up: first frame construction may fill the pre-reserved buffer
    // for the first time.  Everything after that must be allocation-free.
    let payload = [7u8; 1000];
    assert_eq!(drive_write(&mut conn, &payload), payload.len());

    let (allocs, written) = allocation_count(|| {
        let mut written = 0usize;
        for _ in 0..50 {
            written += drive_write(&mut conn, &payload);
        }
        written
    });
    assert_eq!(
        allocs, 0,
        "steady-state write path allocated {allocs} times"
    );
    assert_eq!(written, 50 * payload.len());
}

#[test]
fn hostile_u16_lengths_cannot_force_allocation() {
    // content_len and padding_len at their u16 maxima, delivered in small
    // odd-sized pieces: the decoder must bound its work by fixed scratch
    // sizes, never by the attacker's declared lengths.
    let mut wire = Vec::new();
    // First frame: maximal everything.
    wire.extend_from_slice(&UUID);
    wire.push(0x00);
    wire.extend_from_slice(&(u16::MAX).to_be_bytes());
    wire.extend_from_slice(&(u16::MAX).to_be_bytes());
    wire.resize(
        wire.len() + usize::from(u16::MAX) + usize::from(u16::MAX),
        0xab,
    );
    // Follow-up frames across the boundary, so the state machine cycles.
    wire.extend(frame(0x01, false, 3, 0, 0x00));

    let stream = ScriptStream::new(wire);
    let mut conn = VisionServerConn::new(Box::new(stream), UUID, VisionServerMode::Tcp);

    let mut buf = [0u8; 2048];
    // The scripted stream never pends, so the warm-up read fills the whole
    // caller buffer with the maximal frame's first content chunk.
    assert_eq!(drive_read(&mut conn, &mut buf), 2048);

    let (allocs, total) = allocation_count(|| {
        let mut total = 0usize;
        loop {
            let n = drive_read(&mut conn, &mut buf);
            if n == 0 {
                break;
            }
            total += n;
        }
        total
    });
    assert_eq!(
        allocs, 0,
        "maximal hostile lengths allocated {allocs} times"
    );
    // 65535 + 3 content bytes declared, 2048 already delivered by the
    // warm-up: every declared content byte — and nothing else — arrives.
    assert_eq!(total, usize::from(u16::MAX) + 3 - 2048);
}

#[cfg(feature = "mux")]
fn xudp_keep_data_wire(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&4u16.to_be_bytes()); // meta_len: sid + status + option
    out.extend_from_slice(&0u16.to_be_bytes());
    out.push(0x02); // Keep
    out.push(0x01); // Data
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// XUDP owns datagrams as `Bytes` while they sit in the listener's queues.
/// Once the fixed slab metadata is warm, recycling those owned buffers must
/// make both codec directions allocation-free; the traffic below exceeds the
/// pool's total backing store several times over.
#[cfg(feature = "mux")]
#[test]
fn xudp_steady_state_codec_paths_allocate_nothing() {
    const DEPTH: usize = 8;
    const ITERATIONS: usize = 320;

    let target = XudpTarget {
        addr: XudpAddr::Ipv4(std::net::Ipv4Addr::new(192, 0, 2, 53)),
        port: 53,
    };
    let payload = vec![0x5au8; 1024];
    let wire = xudp_keep_data_wire(&payload);

    let mut decoder = XudpDecoder::new();
    let mut server = XudpServer::new(true);
    server
        .handle_frame(XudpFrame::New {
            session_id: 0,
            network: XudpNetwork::Udp,
            target: target.clone(),
            global_id: None,
            payload: None,
        })
        .unwrap();

    let mut ingress_in_flight = Vec::with_capacity(DEPTH);
    for _ in 0..64 {
        decoder.feed(&wire).unwrap();
        let frame = decoder.next_frame().unwrap();
        let action = server.handle_frame(frame).unwrap().unwrap();
        ingress_in_flight.push(action);
        if ingress_in_flight.len() == DEPTH {
            ingress_in_flight.clear();
        }
    }
    ingress_in_flight.clear();

    let (ingress_allocs, ingress_bytes) = allocation_count(|| {
        let mut bytes = 0usize;
        for _ in 0..ITERATIONS {
            decoder.feed(&wire).unwrap();
            let frame = decoder.next_frame().unwrap();
            let action = server.handle_frame(frame).unwrap().unwrap();
            if let XudpAction::Datagram { payload, .. } = &action {
                bytes += payload.len();
            }
            ingress_in_flight.push(action);
            if ingress_in_flight.len() == DEPTH {
                ingress_in_flight.clear();
            }
        }
        bytes
    });
    assert_eq!(ingress_bytes, ITERATIONS * payload.len());

    let reply_payload = vec![0xa5u8; 1024];
    const REPLY_WIRE_LEN: usize = 2 + 4 + 8 + 2 + 1024;
    let mut egress_in_flight = Vec::with_capacity(DEPTH);
    let mut warmup_hold = Vec::new();
    for index in 0..320 {
        let frame = encode_reply_keep_data(0, Some(&target), &reply_payload).unwrap();
        if index == 0 {
            assert_eq!(frame.len(), REPLY_WIRE_LEN);
        }
        warmup_hold.push(frame);
    }
    drop(warmup_hold);

    let (egress_allocs, egress_bytes) = allocation_count(|| {
        let mut bytes = 0usize;
        for _ in 0..ITERATIONS {
            let frame = encode_reply_keep_data(0, Some(&target), &reply_payload).unwrap();
            bytes += frame.len();
            egress_in_flight.push(frame);
            if egress_in_flight.len() == DEPTH {
                egress_in_flight.clear();
            }
        }
        bytes
    });
    assert_eq!(egress_bytes, ITERATIONS * REPLY_WIRE_LEN);

    assert_eq!(
        ingress_allocs, 0,
        "XUDP ingress allocated {ingress_allocs} times in steady state"
    );
    assert_eq!(
        egress_allocs, 0,
        "XUDP egress allocated {egress_allocs} times in steady state"
    );
}
