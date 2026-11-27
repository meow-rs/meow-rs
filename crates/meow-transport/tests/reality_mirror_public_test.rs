#![cfg(all(feature = "tls", feature = "reality"))]

use meow_transport::reality_server::{AuthenticatedMirrorContext, RealityServer};
use tokio::io::AsyncReadExt;
use tokio::task::JoinSet;

/// Type-checking harness for the listener's actual scheduling shape: the
/// scanner is created before an asynchronous target read and is still needed
/// after that `.await`, so the connection future is spawnable only when the
/// scanner is `Send`.  The function is never called; constructing real
/// authenticated state is unnecessary because the property being proven here
/// is a compile-time property of the public call chain.
fn joinset_with_scanner_alive_across_target_read(
    server: RealityServer,
    context: AuthenticatedMirrorContext,
) -> JoinSet<()> {
    let mut connections = JoinSet::new();
    connections.spawn(async move {
        let mut scanner = server
            .target_flight_scanner(&context)
            .expect("mirror profile admission");
        let (mut target, peer) = tokio::io::duplex(1);
        drop(peer);
        let mut byte = [0u8; 1];
        let read = target.read(&mut byte).await.expect("target read");
        let _state = scanner
            .push(&byte[..read])
            .expect("scanner input is within its advertised window");
    });
    connections
}

#[test]
fn scanner_send_compile_gate_is_typechecked() {
    let _gate: fn(RealityServer, AuthenticatedMirrorContext) -> JoinSet<()> =
        joinset_with_scanner_alive_across_target_read;
}
