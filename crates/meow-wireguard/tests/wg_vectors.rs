// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Independent integration-level checks for the vendored noise
//! implementation (spec §7.1/§7.3). These run entirely through the crate's
//! public API — no network, no external binaries — and must keep passing
//! across vendor bumps. The crypto-facade vectors themselves live in
//! `src/crypto.rs`'s unit tests (the facade is `pub(crate)` and not visible
//! to integration tests).

use meow_wireguard::x25519::{PublicKey, StaticSecret};
use meow_wireguard::{Tunn, TunnResult, DATA_PAYLOAD_OFF};

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

/// PATCH(17): `decapsulate_in_place` produces the same plaintext as
/// `decapsulate` — but inside the caller's own datagram buffer, which is
/// what makes the pump's `Bytes::from(receive_vec)` hand-off zero-copy.
/// Two assertions pin the contract: byte-identical plaintext, and the
/// returned slice physically inside the datagram (in place, not into a
/// scratch). Handshake and keepalive legs ride the same method so the
/// whole receive path can go through it.
#[test]
fn decapsulate_in_place_decrypts_inside_the_datagram() {
    let initiator_private = StaticSecret::from([0x33u8; 32]);
    let initiator_public = PublicKey::from(&initiator_private);
    let responder_private = StaticSecret::from([0x44u8; 32]);
    let responder_public = PublicKey::from(&responder_private);

    let mut initiator = Tunn::new(initiator_private, responder_public, None, None, 1, None);
    let mut responder = Tunn::new(responder_private, initiator_public, None, None, 2, None);

    let mut src = vec![0u8; 2048];
    let mut dst = vec![0u8; 2048];

    // Handshake through `decapsulate_in_place` — non-data packets behave
    // exactly like `decapsulate`, producing their output in `dst`.
    let init_pkt = match initiator.format_handshake_initiation(&mut src, false) {
        TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        other => panic!("expected WriteToNetwork, got {other:?}"),
    };
    let mut init_wire = init_pkt;
    let resp_pkt = match responder.decapsulate_in_place(None, &mut init_wire, &mut dst) {
        TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        other => panic!("responder expected WriteToNetwork response, got {other:?}"),
    };
    let mut resp_wire = resp_pkt;
    let keepalive = match initiator.decapsulate_in_place(None, &mut resp_wire, &mut dst) {
        TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        other => panic!("initiator expected keepalive WriteToNetwork, got {other:?}"),
    };
    let mut keepalive_wire = keepalive;
    match responder.decapsulate_in_place(None, &mut keepalive_wire, &mut dst) {
        TunnResult::Done => {}
        other => panic!("responder expected Done after keepalive, got {other:?}"),
    }

    // Data leg: encrypt on the initiator, move the wire datagram into an
    // owned Vec (the pump's receive-slot shape), decrypt in place.
    let ip_payload = build_test_ipv4_packet();
    let data_pkt = match initiator.encapsulate(&ip_payload, &mut src) {
        TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        other => panic!("expected WriteToNetwork for data, got {other:?}"),
    };
    let mut slot = data_pkt;
    let slot_base = slot.as_ptr() as usize;
    let slot_end = slot_base + slot.len();

    let (plain_len, plain_ptr) = match responder.decapsulate_in_place(None, &mut slot, &mut dst) {
        TunnResult::WriteToTunnelV4(plain, _addr) => (plain.len(), plain.as_ptr() as usize),
        other => panic!("expected WriteToTunnelV4, got {other:?}"),
    };

    // The plaintext view starts exactly at the payload offset inside the
    // receive buffer — proof the decrypt happened in place, and the exact
    // slice shape the pump hands to `Bytes::slice`.
    assert_eq!(
        plain_ptr,
        slot_base + DATA_PAYLOAD_OFF,
        "in-place plaintext must start at the datagram payload offset"
    );
    assert!(
        plain_ptr + plain_len <= slot_end,
        "plaintext view must stay inside the datagram buffer"
    );
    assert_eq!(
        &slot[DATA_PAYLOAD_OFF..DATA_PAYLOAD_OFF + plain_len],
        ip_payload.as_slice(),
        "in-place plaintext must match the original payload byte-for-byte"
    );

    // A second data packet still decrypts (counter advanced to 2 after
    // the keepalive consumed 0 and the first data packet 1).
    let data_pkt2 = match initiator.encapsulate(&ip_payload, &mut src) {
        TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        other => panic!("expected WriteToNetwork for second data, got {other:?}"),
    };
    let mut slot2 = data_pkt2;
    match responder.decapsulate_in_place(None, &mut slot2, &mut dst) {
        TunnResult::WriteToTunnelV4(plain, _addr) => {
            assert_eq!(plain, ip_payload.as_slice());
        }
        other => panic!("expected WriteToTunnelV4, got {other:?}"),
    }
}
