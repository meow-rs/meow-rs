//! Programmable REALITY mirror target shared by the cross-compiled Docker
//! target and the host-side negative/full-data-plane fixtures.
//!
//! This is test tooling, not a TLS server: its encrypted record bodies are
//! deterministic filler because the mirror probe must never decrypt them.
//! The ServerHello it emits is nevertheless length- and shape-valid TLS 1.3,
//! with a non-low-order X25519 public key in every key-share variant.
#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const T5_X25519_1301_PORT: u16 = 11101;
pub const T5_X25519_1302_PORT: u16 = 11102;
pub const T5_X25519_1303_PORT: u16 = 11103;
pub const T5_HYBRID_1302_PORT: u16 = 11104;

pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_X25519MLKEM768: u16 = 0x11ec;
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
pub const COMPAT_CCS: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum T5RecordPlan {
    Single,
    Multi,
    SmallFirst,
}

impl T5RecordPlan {
    pub fn name(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Multi => "multi",
            Self::SmallFirst => "small-first",
        }
    }

    pub fn lengths(self) -> &'static [u16] {
        match self {
            // C=1007: enough for either M=301 or M=317 in one bucket.
            Self::Single => &[1024],
            // The fixed multi-bucket vector from the specification; its
            // first bucket also exercises a small-first-bucket split.
            Self::Multi => &[25, 3217, 281, 69],
            // A separate deterministic small-first vector with no first
            // bucket large enough to hold even EE by itself as a whole
            // flight assumption would imply.
            Self::SmallFirst => &[25, 1024],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum T5ShVariant {
    Normal,
    Hrr,
    PreSharedKey,
    UnknownGroup,
}

#[derive(Clone, Copy, Debug)]
pub struct T5TargetSpec {
    pub group: u16,
    pub cipher: u16,
    pub plan: T5RecordPlan,
    pub ccs: bool,
    pub variant: T5ShVariant,
}

impl T5TargetSpec {
    pub const fn normal(group: u16, cipher: u16, plan: T5RecordPlan, ccs: bool) -> Self {
        Self {
            group,
            cipher,
            plan,
            ccs,
            variant: T5ShVariant::Normal,
        }
    }

    pub fn negative(group: u16, cipher: u16, variant: T5ShVariant) -> Self {
        Self {
            group,
            cipher,
            plan: T5RecordPlan::Single,
            ccs: true,
            variant,
        }
    }
}

pub fn docker_t5_specs() -> [(u16, T5TargetSpec); 4] {
    [
        (
            T5_X25519_1301_PORT,
            T5TargetSpec::normal(
                GROUP_X25519,
                TLS_AES_128_GCM_SHA256,
                T5RecordPlan::Single,
                true,
            ),
        ),
        (
            T5_X25519_1302_PORT,
            T5TargetSpec::normal(
                GROUP_X25519,
                TLS_AES_256_GCM_SHA384,
                T5RecordPlan::Multi,
                true,
            ),
        ),
        (
            T5_X25519_1303_PORT,
            T5TargetSpec::normal(
                GROUP_X25519,
                TLS_CHACHA20_POLY1305_SHA256,
                T5RecordPlan::SmallFirst,
                false,
            ),
        ),
        (
            T5_HYBRID_1302_PORT,
            T5TargetSpec::normal(
                GROUP_X25519MLKEM768,
                TLS_AES_256_GCM_SHA384,
                T5RecordPlan::Multi,
                false,
            ),
        ),
    ]
}

#[derive(Clone, Debug, Default)]
pub struct ClientHelloEvidence {
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub key_shares: Vec<(u16, usize)>,
    pub signature_algorithms: Vec<u16>,
    pub has_pre_shared_key: bool,
    pub has_early_data: bool,
    pub wire_len: usize,
    pub sha256: [u8; 32],
}

fn take<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = pos.checked_add(len)?;
    let out = bytes.get(*pos..end)?;
    *pos = end;
    Some(out)
}

fn take_u8(bytes: &[u8], pos: &mut usize) -> Option<u8> {
    take(bytes, pos, 1).map(|v| v[0])
}

fn take_u16(bytes: &[u8], pos: &mut usize) -> Option<u16> {
    take(bytes, pos, 2).map(|v| u16::from_be_bytes([v[0], v[1]]))
}

fn u16_list(data: &[u8]) -> Option<Vec<u16>> {
    if data.len() < 2 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    if len != data.len() - 2 || len % 2 != 0 {
        return None;
    }
    Some(
        data[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .collect(),
    )
}

/// Parse the single-record ClientHello shape pinned clients produce in this
/// harness.  This deliberately returns None for fragmentation or trailing
/// handshake bytes: accepting them here would hide a client-shape surprise
/// rather than report it as a test failure.
pub fn parse_client_hello_record(wire: &[u8]) -> Option<ClientHelloEvidence> {
    if wire.len() < 5 || wire[0] != 0x16 {
        return None;
    }
    let record_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
    if wire.len() != 5 + record_len || record_len < 4 {
        return None;
    }
    let body = &wire[5..];
    if body[0] != 0x01 {
        return None;
    }
    let hello_len =
        (usize::from(body[1]) << 16) | (usize::from(body[2]) << 8) | usize::from(body[3]);
    if body.len() != 4 + hello_len {
        return None;
    }
    let mut pos = 4;
    let _legacy_version = take(body, &mut pos, 2)?;
    let _random = take(body, &mut pos, 32)?;
    let sid_len = usize::from(take_u8(body, &mut pos)?);
    let session_id = take(body, &mut pos, sid_len)?.to_vec();
    let suites_len = usize::from(take_u16(body, &mut pos)?);
    let suites_wire = take(body, &mut pos, suites_len)?;
    if suites_len == 0 || suites_len % 2 != 0 {
        return None;
    }
    let cipher_suites = suites_wire
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .collect();
    let compression_len = usize::from(take_u8(body, &mut pos)?);
    let _compression = take(body, &mut pos, compression_len)?;
    let extensions_len = usize::from(take_u16(body, &mut pos)?);
    let extensions = take(body, &mut pos, extensions_len)?;
    if pos != body.len() {
        return None;
    }

    let mut evidence = ClientHelloEvidence {
        session_id,
        cipher_suites,
        wire_len: wire.len(),
        ..Default::default()
    };
    let mut epos = 0usize;
    while epos < extensions.len() {
        let kind = take_u16(extensions, &mut epos)?;
        let len = usize::from(take_u16(extensions, &mut epos)?);
        let data = take(extensions, &mut epos, len)?;
        match kind {
            0x002b => {
                if data.is_empty() {
                    return None;
                }
                let len = usize::from(data[0]);
                if len != data.len() - 1 || len % 2 != 0 {
                    return None;
                }
                evidence.supported_versions = data[1..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_be_bytes(*pair))
                    .collect();
            }
            0x000a => evidence.supported_groups = u16_list(data)?,
            0x000d => evidence.signature_algorithms = u16_list(data)?,
            0x0033 => {
                if data.len() < 2 {
                    return None;
                }
                let list_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
                if list_len != data.len() - 2 {
                    return None;
                }
                let mut spos = 2usize;
                while spos < data.len() {
                    let group = u16::from_be_bytes([data[spos], data[spos + 1]]);
                    let share_len =
                        usize::from(u16::from_be_bytes([data[spos + 2], data[spos + 3]]));
                    spos += 4;
                    if spos + share_len > data.len() {
                        return None;
                    }
                    evidence.key_shares.push((group, share_len));
                    spos += share_len;
                }
            }
            0x0029 => evidence.has_pre_shared_key = true,
            0x002a => evidence.has_early_data = true,
            _ => {}
        }
    }
    if epos != extensions.len() {
        return None;
    }
    evidence.sha256 = Sha256::digest(wire).into();
    Some(evidence)
}

fn ext(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn x25519_public() -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from([9u8; 32]);
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}

fn target_share(group: u16) -> (u16, Vec<u8>) {
    let x = x25519_public();
    match group {
        GROUP_X25519 => (group, x.to_vec()),
        GROUP_X25519MLKEM768 => {
            let mut share = Vec::with_capacity(1120);
            // Synthetic ML-KEM ciphertext filler.  The mirror contract only
            // bounds its length; the probe must not decapsulate target bytes.
            for index in 0..1088u32 {
                share.push((index.wrapping_mul(31).wrapping_add(17) & 0xff) as u8);
            }
            share.extend_from_slice(&x);
            (group, share)
        }
        other => (other, x.to_vec()),
    }
}

const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Clone, Debug)]
pub struct T5Flight {
    pub wire: Vec<u8>,
    pub sh_record_masked: Vec<u8>,
    pub ccs: Option<[u8; 6]>,
    pub record_heads: Vec<[u8; 5]>,
    pub group: u16,
    pub cipher: u16,
    pub plan: T5RecordPlan,
    pub variant: T5ShVariant,
}

pub fn build_t5_flight(session_id: &[u8], spec: T5TargetSpec) -> T5Flight {
    assert_eq!(
        session_id.len(),
        32,
        "REALITY harness clients use a 32-byte session id"
    );
    let (mut group, share) = target_share(spec.group);
    if spec.variant == T5ShVariant::UnknownGroup {
        group = 0x002f;
    }
    let mut key_share_body = Vec::new();
    key_share_body.extend_from_slice(&group.to_be_bytes());
    key_share_body.extend_from_slice(&(share.len() as u16).to_be_bytes());
    key_share_body.extend_from_slice(&share);
    let versions = ext(0x002b, &0x0304u16.to_be_bytes());
    let key_share = ext(0x0033, &key_share_body);
    let mut exts = Vec::new();
    exts.extend_from_slice(&versions);
    exts.extend_from_slice(&key_share);
    if spec.variant == T5ShVariant::PreSharedKey {
        exts.extend_from_slice(&ext(0x0029, &0u16.to_be_bytes()));
    }

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    let random = if spec.variant == T5ShVariant::Hrr {
        HRR_RANDOM
    } else {
        [0x66; 32]
    };
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&spec.cipher.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut sh = vec![0x02];
    sh.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
    sh.extend_from_slice(&body);
    let mut sh_record = Vec::new();
    sh_record.extend_from_slice(&[0x16, 0x03, 0x03]);
    sh_record.extend_from_slice(&(sh.len() as u16).to_be_bytes());
    sh_record.extend_from_slice(&sh);

    // Mask exactly the ServerHello random and the complete server share in
    // the logged canonical form.  Every other byte — including lengths,
    // cipher, extension order and the session-id echo — remains comparable.
    let mut masked = sh_record.clone();
    masked[5 + 4 + 2..5 + 4 + 2 + 32].fill(0);
    let share_offset = sh_record
        .windows(share.len())
        .position(|window| window == share.as_slice())
        .expect("generated ServerHello contains its complete share");
    masked[share_offset..share_offset + share.len()].fill(0);

    let mut wire = sh_record.clone();
    let ccs = spec.ccs.then_some(COMPAT_CCS);
    if let Some(ccs) = ccs {
        wire.extend_from_slice(&ccs);
    }
    let mut record_heads = Vec::new();
    for (index, len) in spec.plan.lengths().iter().copied().enumerate() {
        let head = [0x17, 0x03, 0x03, (len >> 8) as u8, len as u8];
        record_heads.push(head);
        wire.extend_from_slice(&head);
        let fill = 0x40u8.wrapping_add(index as u8);
        wire.resize(wire.len() + usize::from(len), fill);
    }

    T5Flight {
        wire,
        sh_record_masked: masked,
        ccs,
        record_heads,
        group,
        cipher: spec.cipher,
        plan: spec.plan,
        variant: spec.variant,
    }
}

#[derive(Clone, Debug)]
pub struct T5TargetObservation {
    pub port: u16,
    pub connection: usize,
    pub hello: ClientHelloEvidence,
    pub selected_group: u16,
    pub selected_cipher: u16,
    pub plan: T5RecordPlan,
    pub sh_record_masked: Vec<u8>,
    pub ccs: Option<[u8; 6]>,
    pub record_heads: Vec<[u8; 5]>,
    pub flight_len: usize,
    pub wrote_flight: bool,
}

impl T5TargetObservation {
    pub fn to_json(&self) -> Value {
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        json!({
            "event": "t5-target-observation",
            "port": self.port,
            "connection": self.connection,
            "selected_group": format!("0x{:04x}", self.selected_group),
            "selected_cipher": format!("0x{:04x}", self.selected_cipher),
            "plan": self.plan.name(),
            "sh_record_masked_hex": hex(&self.sh_record_masked),
            "ccs_hex": self.ccs.map(|bytes| hex(&bytes)),
            "record_heads_hex": self.record_heads.iter().map(|head| hex(head)).collect::<Vec<_>>(),
            "flight_len": self.flight_len,
            "wrote_flight": self.wrote_flight,
            "hello": {
                "wire_len": self.hello.wire_len,
                "sha256": hex(&self.hello.sha256),
                "cipher_suites": self.hello.cipher_suites.iter().map(|v| format!("0x{v:04x}")).collect::<Vec<_>>(),
                "supported_versions": self.hello.supported_versions.iter().map(|v| format!("0x{v:04x}")).collect::<Vec<_>>(),
                "supported_groups": self.hello.supported_groups.iter().map(|v| format!("0x{v:04x}")).collect::<Vec<_>>(),
                "key_shares": self.hello.key_shares.iter().map(|(group, len)| json!({"group": format!("0x{group:04x}"), "len": len})).collect::<Vec<_>>(),
                "signature_algorithms": self.hello.signature_algorithms.iter().map(|v| format!("0x{v:04x}")).collect::<Vec<_>>(),
                "signature_algorithms_has_ed25519": self.hello.signature_algorithms.contains(&0x0807),
                "has_pre_shared_key": self.hello.has_pre_shared_key,
                "has_early_data": self.hello.has_early_data,
            }
        })
    }
}

/// Serve one controlled target connection.  The nominal path writes exactly
/// one scripted flight and then reads silently until peer EOF; it never
/// appends a tail byte and never closes first.
pub async fn serve_t5_connection(
    mut stream: TcpStream,
    port: u16,
    connection: usize,
    spec: T5TargetSpec,
) -> Option<T5TargetObservation> {
    let mut head = [0u8; 5];
    stream.read_exact(&mut head).await.ok()?;
    let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
    if !(1..=16384).contains(&len) {
        return None;
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.ok()?;
    let mut ch = head.to_vec();
    ch.extend_from_slice(&body);
    let hello = parse_client_hello_record(&ch)?;
    let flight = build_t5_flight(&hello.session_id, spec);
    stream.write_all(&flight.wire).await.ok()?;
    stream.flush().await.ok()?;
    let observation = T5TargetObservation {
        port,
        connection,
        hello,
        selected_group: flight.group,
        selected_cipher: flight.cipher,
        plan: flight.plan,
        sh_record_masked: flight.sh_record_masked,
        ccs: flight.ccs,
        record_heads: flight.record_heads,
        flight_len: flight.wire.len(),
        wrote_flight: true,
    };
    let mut sink = [0u8; 4096];
    while matches!(stream.read(&mut sink).await, Ok(n) if n != 0) {}
    Some(observation)
}

pub async fn bind_t5_target(listener: TcpListener, port: u16, spec: T5TargetSpec) {
    static CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let connection = CONNECTIONS.fetch_add(1, Ordering::Relaxed) + 1;
        tokio::spawn(async move {
            if let Some(observation) = serve_t5_connection(stream, port, connection, spec).await {
                println!("t5-target-observation {}", observation.to_json());
            }
        });
    }
}

pub async fn serve_host_t5_target(
    listener: TcpListener,
    port: u16,
    spec: T5TargetSpec,
    observations: Arc<tokio::sync::Mutex<Vec<T5TargetObservation>>>,
) {
    let mut connection = 0usize;
    while let Ok((stream, _)) = listener.accept().await {
        connection += 1;
        let observations = Arc::clone(&observations);
        tokio::spawn(async move {
            if let Some(observation) = serve_t5_connection(stream, port, connection, spec).await {
                observations.lock().await.push(observation);
            }
        });
    }
}
