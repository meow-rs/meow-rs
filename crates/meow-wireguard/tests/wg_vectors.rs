// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Independent integration-level checks for the vendored noise
//! implementation (spec §7.1/§7.3). These run entirely through the crate's
//! public API — no network, no external binaries — and must keep passing
//! across vendor bumps. The crypto-facade vectors themselves live in
//! `src/crypto.rs`'s unit tests (the facade is `pub(crate)` and not visible
//! to integration tests).

use meow_wireguard::x25519::{PublicKey, StaticSecret};
use meow_wireguard::{Tunn, TunnResult};

/// Fixed 20-byte IPv4 header + 4-byte payload, matching what the in-crate
/// `one_ip_packet` test encapsulates (the tunnel only inspects the version
/// nibble, the total-length field and the source address).
fn build_test_ipv4_packet() -> Vec<u8> {
    Vec::from([
        0x45, 0x00, 0x00, 0x18, // v4+ihl5, dscp=0, total_len=24
        0x00, 0x00, 0x00, 0x00, // id, flags+fragment offset
        0x40, 0x00, 0x00, 0x00, // ttl=64, proto=0, checksum=0
        10, 0, 0, 1, // src
        10, 0, 0, 2, // dst
        0xde, 0xad, 0xbe, 0xef, // payload
    ])
}

/// Two `Tunn` instances — one initiator, one responder — exchanging packets
/// in-process. Proves the ring replacement is behavior-preserving end to
/// end: Noise handshake, keepalive, and a data packet decrypted
/// byte-for-byte on the other side. Deterministic (fixed test key material).
#[test]
fn two_tunn_handshake_and_transport_roundtrip() {
    // 1. Fixed test keypairs (any 32 bytes are a valid unclamped secret).
    let initiator_private = StaticSecret::from([0x11u8; 32]);
    let initiator_public = PublicKey::from(&initiator_private);
    let responder_private = StaticSecret::from([0x22u8; 32]);
    let responder_public = PublicKey::from(&responder_private);

    // 2. Create Tunn instances (no PSK, no keepalive, local index 1/2).
    let mut initiator = Tunn::new(initiator_private, responder_public, None, None, 1, None);
    let mut responder = Tunn::new(responder_private, initiator_public, None, None, 2, None);

    let mut src = vec![0u8; 2048];
    let mut dst = vec![0u8; 2048];

    // 3. Handshake: initiator produces an initiation message.
    let init_pkt = match initiator.format_handshake_initiation(&mut src, false) {
        TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        other => panic!("expected WriteToNetwork, got {other:?}"),
    };

    // 4. Responder handles the initiation and produces a response.
    let resp_pkt = match responder.decapsulate(None, &init_pkt, &mut dst) {
        TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        other => panic!("responder expected WriteToNetwork response, got {other:?}"),
    };

    // 5. Initiator handles the response; the session is established and a
    //    keepalive packet is emitted for the responder to consume.
    let keepalive = match initiator.decapsulate(None, &resp_pkt, &mut dst) {
        TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        other => panic!("initiator expected keepalive WriteToNetwork, got {other:?}"),
    };
    match responder.decapsulate(None, &keepalive, &mut dst) {
        TunnResult::Done => {}
        other => panic!("responder expected Done after keepalive, got {other:?}"),
    }

    // 6. Initiator encapsulates an IP payload.
    let ip_payload = build_test_ipv4_packet();
    let data_pkt = match initiator.encapsulate(&ip_payload, &mut src) {
        TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        other => panic!("expected WriteToNetwork for data, got {other:?}"),
    };

    // 7. Responder decapsulates it.
    let plaintext = match responder.decapsulate(None, &data_pkt, &mut dst) {
        TunnResult::WriteToTunnelV4(plain, _addr) => plain.to_vec(),
        other => panic!("expected WriteToTunnelV4, got {other:?}"),
    };

    // 8. Decrypted plaintext must match the original payload byte-for-byte.
    assert_eq!(
        plaintext, ip_payload,
        "decrypted payload must match original"
    );

    // 9. Second data packet: the wire counter must advance (LE at bytes
    //    8..16 of the transport message) and still decrypt — a
    //    wrong-but-symmetric nonce mapping is invisible to a single-packet
    //    roundtrip. The counters start at 1, not 0: the handshake
    //    keepalive is an empty transport packet that consumes counter 0.
    assert_eq!(
        u64::from_le_bytes(data_pkt[8..16].try_into().unwrap()),
        1,
        "keepalive consumed counter 0; first data packet is 1"
    );
    let data_pkt2 = match initiator.encapsulate(&ip_payload, &mut src) {
        TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        other => panic!("expected WriteToNetwork for second data, got {other:?}"),
    };
    assert_eq!(
        u64::from_le_bytes(data_pkt2[8..16].try_into().unwrap()),
        2,
        "second data packet uses counter 2"
    );
    let plaintext2 = match responder.decapsulate(None, &data_pkt2, &mut dst) {
        TunnResult::WriteToTunnelV4(plain, _addr) => plain.to_vec(),
        other => panic!("expected WriteToTunnelV4, got {other:?}"),
    };
    assert_eq!(plaintext2, ip_payload);
}
