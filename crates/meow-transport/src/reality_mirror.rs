//! REALITY v2 target-flight mirroring primitives.

use std::fmt;
use std::ops::Range;

use crate::reality_hello::{GROUP_X25519, GROUP_X25519_MLKEM768};
use subtle::ConstantTimeEq;
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

use crate::reality_server::{
    certificate_message, certificate_verify_input, encapsulate_server_share, handshake_message,
    hybrid_key_share_usable, x25519_public_key_usable, AuthenticatedMirrorContext, ChosenKeyShare,
    ClientKeyShares, OfferedCipherSuites, RealityCertificate, SupportedGroups, VerifiedHello,
    SIG_ED25519,
};
use crate::reality_tls::{
    finished_verify_data_with_hash, put_u16, read_u24, x25519, x25519_public_from_private,
    ApplicationKeys, CipherSuite, HandshakeKeys, HashAlg, RecordKey, TranscriptHasher,
    HS_CERTIFICATE_VERIFY, HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_RECORD_APPLICATION_DATA,
    TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE,
};
use crate::{Result as TransportResult, Stream, TransportError};

pub(crate) const MAX_MIRRORED_RECORDS: usize = 16;
pub(crate) const COMPAT_CCS_RECORD: [u8; 6] =
    [TLS_RECORD_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MirrorPlanError {
    Empty,
    TooManyRecords,
    BadRecordType,
    BadRecordVersion,
    BadRecordLength,
    LengthOverflow,
    Infeasible,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MirroredRecordPlan {
    pub(crate) head: [u8; 5],
    pub(crate) range: Range<usize>,
    pub(crate) pad: usize,
}

/// Greedy TLS-handshake fragmentation plan specified by the v2 mirror
/// contract: every bucket carries at least one byte, and each bucket takes
/// the most bytes that still leaves one byte for every suffix bucket.
pub(crate) fn plan_mirrored_records(
    m: usize,
    heads: &[[u8; 5]],
) -> std::result::Result<Vec<MirroredRecordPlan>, MirrorPlanError> {
    if heads.is_empty() {
        return Err(MirrorPlanError::Empty);
    }
    if heads.len() > MAX_MIRRORED_RECORDS {
        return Err(MirrorPlanError::TooManyRecords);
    }
    let mut capacities = Vec::with_capacity(heads.len());
    let mut total_capacity = 0usize;
    for head in heads {
        if head[0] != TLS_RECORD_APPLICATION_DATA {
            return Err(MirrorPlanError::BadRecordType);
        }
        if head[1..3] != [0x03, 0x03] {
            return Err(MirrorPlanError::BadRecordVersion);
        }
        let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
        if !(18..=16401).contains(&len) {
            return Err(MirrorPlanError::BadRecordLength);
        }
        let capacity = len - 17;
        capacities.push(capacity);
        total_capacity = total_capacity
            .checked_add(capacity)
            .ok_or(MirrorPlanError::LengthOverflow)?;
    }
    if m < heads.len() || m > total_capacity {
        return Err(MirrorPlanError::Infeasible);
    }

    let mut out = Vec::with_capacity(heads.len());
    let mut offset = 0usize;
    for (index, (head, capacity)) in heads.iter().zip(capacities).enumerate() {
        let suffix_count = heads.len() - index - 1;
        let remaining = m
            .checked_sub(offset)
            .ok_or(MirrorPlanError::LengthOverflow)?;
        let available = remaining
            .checked_sub(suffix_count)
            .ok_or(MirrorPlanError::Infeasible)?;
        let take = capacity.min(available);
        if take == 0 {
            return Err(MirrorPlanError::Infeasible);
        }
        let end = offset
            .checked_add(take)
            .ok_or(MirrorPlanError::LengthOverflow)?;
        out.push(MirroredRecordPlan {
            head: *head,
            range: offset..end,
            pad: capacity - take,
        });
        offset = end;
    }
    if offset != m {
        return Err(MirrorPlanError::Infeasible);
    }
    Ok(out)
}

const EXT_RECORD_SIZE_LIMIT_VALUE: u16 = 16385;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const TLS13_VERSION_BYTES: [u8; 2] = [0x03, 0x04];
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];
const DOWNGRADE_TLS12: &[u8; 8] = b"DOWNGRD\x01";
const DOWNGRADE_PRE_TLS12: &[u8; 8] = b"DOWNGRD\x00";
const HYBRID_CLIENT_SHARE_LEN: usize = 1184 + 32;
const HYBRID_SERVER_SHARE_LEN: usize = 1088 + 32;

/// ClientHello restrictions that apply only to the mirrored dial-first path.
/// They are deliberately not part of static REALITY authentication: the v1
/// `off` path keeps accepting the same ClientHello shape it always did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MirrorClientProfileError {
    PreSharedKey,
    EarlyData,
    RecordSizeLimit,
    MalformedKeyShare,
    NoUsableGroup,
}

impl fmt::Display for MirrorClientProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PreSharedKey => "ClientHello carries pre_shared_key",
            Self::EarlyData => "ClientHello carries early_data",
            Self::RecordSizeLimit => "ClientHello record_size_limit is absent or not 16385",
            Self::MalformedKeyShare => "ClientHello key_share is malformed",
            Self::NoUsableGroup => "ClientHello has no usable mirrored key-share group",
        })
    }
}

impl std::error::Error for MirrorClientProfileError {}

pub(crate) trait MirrorHelloView {
    fn session_id(&self) -> &[u8; 32];
    fn cipher_suites(&self) -> &OfferedCipherSuites;
    fn supported_groups(&self) -> &SupportedGroups;
    fn key_shares(&self) -> &ClientKeyShares;
    fn auth_key(&self) -> &[u8; 32];
    fn transcript_hasher(&self, hash: HashAlg) -> TranscriptHasher;
    fn profile(&self) -> (bool, bool, Option<u16>, bool, bool);
}

impl MirrorHelloView for VerifiedHello {
    fn session_id(&self) -> &[u8; 32] {
        &self.hello.session_id
    }
    fn cipher_suites(&self) -> &OfferedCipherSuites {
        &self.hello.cipher_suites
    }
    fn supported_groups(&self) -> &SupportedGroups {
        &self.hello.supported_groups
    }
    fn key_shares(&self) -> &ClientKeyShares {
        &self.hello.key_shares
    }
    fn auth_key(&self) -> &[u8; 32] {
        &self.auth_key
    }
    fn transcript_hasher(&self, hash: HashAlg) -> TranscriptHasher {
        // Compatibility shim for the pre-split API.  The production upload
        // path uses AuthenticatedMirrorContext and does not repeat this scan.
        let mut out = TranscriptHasher::new(hash);
        out.update(&self.hello.raw);
        out
    }
    fn profile(&self) -> (bool, bool, Option<u16>, bool, bool) {
        (
            self.hello.has_pre_shared_key,
            self.hello.has_early_data,
            self.hello.record_size_limit,
            self.hello.record_size_limit_malformed,
            self.hello.key_share_malformed,
        )
    }
}

impl MirrorHelloView for AuthenticatedMirrorContext {
    fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
    fn cipher_suites(&self) -> &OfferedCipherSuites {
        &self.cipher_suites
    }
    fn supported_groups(&self) -> &SupportedGroups {
        &self.supported_groups
    }
    fn key_shares(&self) -> &ClientKeyShares {
        &self.key_shares
    }
    fn auth_key(&self) -> &[u8; 32] {
        &self.auth_key
    }
    fn transcript_hasher(&self, hash: HashAlg) -> TranscriptHasher {
        match hash {
            HashAlg::Sha256 => self.transcript_sha256.clone(),
            HashAlg::Sha384 => self.transcript_sha384.clone(),
        }
    }
    fn profile(&self) -> (bool, bool, Option<u16>, bool, bool) {
        (
            self.has_pre_shared_key,
            self.has_early_data,
            self.record_size_limit,
            self.record_size_limit_malformed,
            self.key_share_malformed,
        )
    }
}

fn mirror_profile_view(
    view: &dyn MirrorHelloView,
) -> std::result::Result<(), MirrorClientProfileError> {
    let (has_psk, has_early, rsl, rsl_malformed, key_malformed) = view.profile();
    if has_psk {
        return Err(MirrorClientProfileError::PreSharedKey);
    }
    if has_early {
        return Err(MirrorClientProfileError::EarlyData);
    }
    if rsl_malformed || matches!(rsl, Some(value) if value != EXT_RECORD_SIZE_LIMIT_VALUE) {
        return Err(MirrorClientProfileError::RecordSizeLimit);
    }
    if key_malformed {
        return Err(MirrorClientProfileError::MalformedKeyShare);
    }
    let x = client_key_share_usable(view, GROUP_X25519);
    let hybrid = client_key_share_usable(view, GROUP_X25519_MLKEM768);
    if !x && !hybrid {
        return Err(MirrorClientProfileError::NoUsableGroup);
    }
    Ok(())
}

impl VerifiedHello {
    /// Whether this authenticated ClientHello is eligible for v2 mirroring.
    /// Authentication has already happened; this check only describes the
    /// outer TLS profile needed to construct a compatible local flight.
    pub fn mirror_profile(&self) -> std::result::Result<(), MirrorClientProfileError> {
        if self.hello.has_pre_shared_key {
            return Err(MirrorClientProfileError::PreSharedKey);
        }
        if self.hello.has_early_data {
            return Err(MirrorClientProfileError::EarlyData);
        }
        if self.hello.record_size_limit_malformed
            || matches!(self.hello.record_size_limit, Some(value) if value != EXT_RECORD_SIZE_LIMIT_VALUE)
        {
            return Err(MirrorClientProfileError::RecordSizeLimit);
        }
        if self.hello.key_share_malformed {
            return Err(MirrorClientProfileError::MalformedKeyShare);
        }
        let usable = [GROUP_X25519, GROUP_X25519_MLKEM768]
            .into_iter()
            .any(|group| client_key_share_usable(self, group));
        if !usable {
            return Err(MirrorClientProfileError::NoUsableGroup);
        }
        Ok(())
    }
}

fn client_key_share_entry(view: &dyn MirrorHelloView, group: u16) -> Option<&[u8]> {
    view.key_shares().bytes(group)
}

fn client_key_share_usable(view: &dyn MirrorHelloView, group: u16) -> bool {
    if !view.supported_groups().declares(group) {
        return false;
    }
    let Some(entry) = client_key_share_entry(view, group) else {
        return false;
    };
    match group {
        GROUP_X25519 => x25519_public_key_usable(entry),
        GROUP_X25519_MLKEM768 => hybrid_key_share_usable(entry),
        _ => false,
    }
}

/// Why a probed target prefix cannot serve as the mirror template.  These
/// variants are stable categories for the listener's cover decision; they
/// deliberately carry no peer bytes or target identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MirrorTemplateError {
    ClientProfile(MirrorClientProfileError),
    Incomplete,
    InvalidServerHelloRecord,
    MalformedServerHello,
    HelloRetryRequest,
    DowngradeMarker,
    UnsupportedVersion,
    SessionIdMismatch,
    UnsupportedCipher,
    CipherNotOffered,
    MissingExtension,
    DuplicateExtension,
    UnsupportedExtension,
    UnsupportedGroup,
    GroupNotOffered,
    KeyShareNotProvided,
    InvalidClientKeyShare,
    InvalidServerKeyShare,
    InvalidChangeCipherSpec,
    PlaintextAlert,
    UnexpectedRecord,
    RecordVersion,
    RecordLength,
    TooManyRecords,
    MissingApplicationRecords,
    TrailingData,
}

impl fmt::Display for MirrorTemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientProfile(error) => write!(f, "client profile is not mirrorable: {error}"),
            other => write!(f, "mirror template rejected: {other:?}"),
        }
    }
}

impl std::error::Error for MirrorTemplateError {}

/// Validated target-flight shape.  The only SH payload retained is the single
/// logical message that will be patched in place during preparation; target
/// ciphertext bodies are never copied into the template.
#[derive(PartialEq, Eq)]
pub struct MirrorTemplate {
    pub(crate) client_session_id: [u8; 32],
    pub(crate) target_prefix: Vec<u8>,
    pub(crate) server_hello_range: Range<usize>,
    pub(crate) share_range: Range<usize>,
    pub(crate) group: u16,
    pub(crate) cipher: CipherSuite,
    pub(crate) has_ccs: bool,
    pub(crate) record_heads: Vec<[u8; 5]>,
}

impl fmt::Debug for MirrorTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MirrorTemplate")
            .field("group", &format_args!("0x{:04x}", self.group))
            .field("cipher", &self.cipher)
            .field("has_ccs", &self.has_ccs)
            .field("record_count", &self.record_heads.len())
            .finish_non_exhaustive()
    }
}

impl MirrorTemplate {
    pub(crate) fn server_hello(&self) -> &[u8] {
        &self.target_prefix[self.server_hello_range.clone()]
    }
}

struct ParsedServerHello {
    share_range: Range<usize>,
    group: u16,
    cipher: CipherSuite,
}

fn take_bytes<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = pos.checked_add(len)?;
    let out = input.get(*pos..end)?;
    *pos = end;
    Some(out)
}

fn take_sh_u8(input: &[u8], pos: &mut usize) -> Option<u8> {
    Some(*take_bytes(input, pos, 1)?.first()?)
}

fn take_sh_u16(input: &[u8], pos: &mut usize) -> Option<u16> {
    let bytes = take_bytes(input, pos, 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn parse_template_server_hello(
    verified: &dyn MirrorHelloView,
    sh: &[u8],
) -> std::result::Result<ParsedServerHello, MirrorTemplateError> {
    if sh.len() < 4 || sh[0] != 0x02 || read_u24(&sh[1..4]) + 4 != sh.len() {
        return Err(MirrorTemplateError::MalformedServerHello);
    }
    let mut pos = 4;
    if take_bytes(sh, &mut pos, 2) != Some(&[0x03, 0x03]) {
        return Err(MirrorTemplateError::MalformedServerHello);
    }
    let random = take_bytes(sh, &mut pos, 32).ok_or(MirrorTemplateError::MalformedServerHello)?;
    if random == HRR_RANDOM {
        return Err(MirrorTemplateError::HelloRetryRequest);
    }
    if random.ends_with(DOWNGRADE_TLS12) || random.ends_with(DOWNGRADE_PRE_TLS12) {
        return Err(MirrorTemplateError::DowngradeMarker);
    }
    let sid_len = take_sh_u8(sh, &mut pos).ok_or(MirrorTemplateError::MalformedServerHello)?;
    if sid_len != 32 {
        return Err(MirrorTemplateError::SessionIdMismatch);
    }
    let session_id =
        take_bytes(sh, &mut pos, 32).ok_or(MirrorTemplateError::MalformedServerHello)?;
    if session_id != verified.session_id() {
        return Err(MirrorTemplateError::SessionIdMismatch);
    }
    let cipher_value =
        take_sh_u16(sh, &mut pos).ok_or(MirrorTemplateError::MalformedServerHello)?;
    let cipher = match cipher_value {
        TLS_AES_128_GCM_SHA256 => CipherSuite::Aes128GcmSha256,
        TLS_AES_256_GCM_SHA384 => CipherSuite::Aes256GcmSha384,
        TLS_CHACHA20_POLY1305_SHA256 => CipherSuite::ChaCha20Poly1305Sha256,
        _ => return Err(MirrorTemplateError::UnsupportedCipher),
    };
    if !verified.cipher_suites().contains(cipher_value) {
        return Err(MirrorTemplateError::CipherNotOffered);
    }
    if take_sh_u8(sh, &mut pos) != Some(0) {
        return Err(MirrorTemplateError::MalformedServerHello);
    }
    let extensions_len =
        take_sh_u16(sh, &mut pos).ok_or(MirrorTemplateError::MalformedServerHello)? as usize;
    let extensions_end = pos
        .checked_add(extensions_len)
        .ok_or(MirrorTemplateError::MalformedServerHello)?;
    if extensions_end != sh.len() {
        return Err(MirrorTemplateError::MalformedServerHello);
    }

    let mut saw_versions = false;
    let mut saw_key_share = false;
    let mut selected = None;
    while pos < extensions_end {
        let ext_type =
            take_sh_u16(sh, &mut pos).ok_or(MirrorTemplateError::MalformedServerHello)?;
        let ext_len =
            take_sh_u16(sh, &mut pos).ok_or(MirrorTemplateError::MalformedServerHello)? as usize;
        let data_start = pos;
        let data_end = data_start
            .checked_add(ext_len)
            .ok_or(MirrorTemplateError::MalformedServerHello)?;
        if data_end > extensions_end {
            return Err(MirrorTemplateError::MalformedServerHello);
        }
        let data = &sh[data_start..data_end];
        pos = data_end;
        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                if saw_versions {
                    return Err(MirrorTemplateError::DuplicateExtension);
                }
                saw_versions = true;
                if data != TLS13_VERSION_BYTES {
                    return Err(MirrorTemplateError::UnsupportedVersion);
                }
            }
            EXT_KEY_SHARE => {
                if saw_key_share {
                    return Err(MirrorTemplateError::DuplicateExtension);
                }
                saw_key_share = true;
                if data.len() < 4 {
                    return Err(MirrorTemplateError::MalformedServerHello);
                }
                let group = u16::from_be_bytes([data[0], data[1]]);
                let share_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
                if share_len + 4 != data.len() {
                    return Err(MirrorTemplateError::MalformedServerHello);
                }
                let share_start = data_start + 4;
                selected = Some((group, share_start..share_start + share_len));
            }
            _ => return Err(MirrorTemplateError::UnsupportedExtension),
        }
    }
    if pos != extensions_end {
        return Err(MirrorTemplateError::MalformedServerHello);
    }
    if !saw_versions || !saw_key_share {
        return Err(MirrorTemplateError::MissingExtension);
    }
    let (group, share_range) = selected.ok_or(MirrorTemplateError::MissingExtension)?;
    let share = &sh[share_range.clone()];
    match group {
        GROUP_X25519 => {
            if share.len() != 32 || !x25519_public_key_usable(share) {
                return Err(MirrorTemplateError::InvalidServerKeyShare);
            }
        }
        GROUP_X25519_MLKEM768 => {
            if share.len() != HYBRID_SERVER_SHARE_LEN
                || !x25519_public_key_usable(&share[HYBRID_SERVER_SHARE_LEN - 32..])
            {
                return Err(MirrorTemplateError::InvalidServerKeyShare);
            }
        }
        _ => return Err(MirrorTemplateError::UnsupportedGroup),
    }

    if !verified.supported_groups().declares(group) {
        return Err(MirrorTemplateError::GroupNotOffered);
    }
    if !verified.key_shares().present(group) {
        return Err(MirrorTemplateError::KeyShareNotProvided);
    }
    if !client_key_share_usable(verified, group) {
        return Err(MirrorTemplateError::InvalidClientKeyShare);
    }

    Ok(ParsedServerHello {
        share_range,
        group,
        cipher,
    })
}

impl MirrorTemplate {
    /// Parse one frozen target prefix consisting of one SH record, at most one
    /// exact compatibility CCS, and complete application-data records.  The
    /// input is a scan boundary: a trailing half header or half body is a
    /// shape error here, while the listener's probe loop simply does not ask
    /// for a template until it reaches a complete record boundary.
    pub fn parse(
        verified: &VerifiedHello,
        prefix: &[u8],
    ) -> std::result::Result<Self, MirrorTemplateError> {
        Self::parse_owned(verified, prefix.to_vec())
    }

    pub(crate) fn parse_context(
        context: &AuthenticatedMirrorContext,
        prefix: Vec<u8>,
    ) -> std::result::Result<Self, MirrorTemplateError> {
        Self::parse_owned(context, prefix)
    }

    fn parse_owned(
        verified: &dyn MirrorHelloView,
        prefix_buf: Vec<u8>,
    ) -> std::result::Result<Self, MirrorTemplateError> {
        let prefix = &prefix_buf[..];
        mirror_profile_view(verified).map_err(MirrorTemplateError::ClientProfile)?;
        if prefix.len() < 5 {
            return Err(MirrorTemplateError::Incomplete);
        }
        if prefix[..3] != [0x16, 0x03, 0x03] {
            return Err(MirrorTemplateError::InvalidServerHelloRecord);
        }
        let sh_len = usize::from(u16::from_be_bytes([prefix[3], prefix[4]]));
        if sh_len == 0 || sh_len > 16 * 1024 {
            return Err(MirrorTemplateError::InvalidServerHelloRecord);
        }
        let sh_end = 5usize
            .checked_add(sh_len)
            .ok_or(MirrorTemplateError::Incomplete)?;
        if prefix.len() < sh_end {
            return Err(MirrorTemplateError::Incomplete);
        }
        let server_hello = &prefix[5..sh_end];
        let parsed = parse_template_server_hello(verified, server_hello)?;

        let mut pos = sh_end;
        let mut has_ccs = false;
        if pos < prefix.len() && prefix[pos] == TLS_RECORD_CHANGE_CIPHER_SPEC {
            if prefix.len() - pos < COMPAT_CCS_RECORD.len()
                || prefix[pos..pos + COMPAT_CCS_RECORD.len()] != COMPAT_CCS_RECORD
            {
                return Err(MirrorTemplateError::InvalidChangeCipherSpec);
            }
            has_ccs = true;
            pos += COMPAT_CCS_RECORD.len();
        }
        if pos == prefix.len() {
            return Err(MirrorTemplateError::MissingApplicationRecords);
        }

        let mut record_heads = Vec::new();
        while pos < prefix.len() {
            if record_heads.len() == MAX_MIRRORED_RECORDS {
                return Err(MirrorTemplateError::TooManyRecords);
            }
            if prefix.len() - pos < 5 {
                return Err(MirrorTemplateError::TrailingData);
            }
            let head: [u8; 5] = prefix[pos..pos + 5]
                .try_into()
                .expect("five-byte record header");
            if head[0] == 0x15 {
                return Err(MirrorTemplateError::PlaintextAlert);
            }
            if head[0] != TLS_RECORD_APPLICATION_DATA {
                return Err(MirrorTemplateError::UnexpectedRecord);
            }
            if head[1..3] != [0x03, 0x03] {
                return Err(MirrorTemplateError::RecordVersion);
            }
            let body_len = usize::from(u16::from_be_bytes([head[3], head[4]]));
            if !(18..=16401).contains(&body_len) {
                return Err(MirrorTemplateError::RecordLength);
            }
            let record_end = pos
                .checked_add(5)
                .and_then(|start| start.checked_add(body_len))
                .ok_or(MirrorTemplateError::TrailingData)?;
            if record_end > prefix.len() {
                return Err(MirrorTemplateError::TrailingData);
            }
            record_heads.push(head);
            pos = record_end;
        }
        if record_heads.is_empty() {
            return Err(MirrorTemplateError::MissingApplicationRecords);
        }

        let client_session_id = *verified.session_id();
        Ok(Self {
            client_session_id,
            target_prefix: prefix_buf,
            server_hello_range: 5..sh_end,
            share_range: parsed.share_range,
            group: parsed.group,
            cipher: parsed.cipher,
            has_ccs,
            record_heads,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MirrorCoverReason {
    DestProfile,
    Hrr,
    UnsupportedCipher,
    UnsupportedGroup,
    UnsupportedExt,
    RecordLimit,
    Capacity,
    DestAlert,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetScanState {
    NeedBytes,
    CapacityTemporarilyInsufficient,
    Freezable,
    Incompatible(MirrorCoverReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetScanPhase {
    ServerHelloHeader,
    ServerHelloBody { end: usize },
    AfterServerHello,
    CompatCcs { end: usize },
    RecordHeader,
    RecordBody { end: usize, capacity: usize },
}

/// Incremental, socket-independent scanner for the target prefix.  It owns
/// only the W+1 byte prefix arena and a monotonically advancing parse cursor;
/// cryptography and ClientHello binding are deferred to `freeze`.
pub struct TargetFlightScanner {
    prefix: Vec<u8>,
    cursor: usize,
    phase: TargetScanPhase,
    has_ccs: bool,
    record_count: usize,
    capacity_sum: usize,
    flight_len: usize,
    incompatible: Option<MirrorCoverReason>,
}

impl Default for TargetFlightScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetFlightScanner {
    pub fn new() -> Self {
        Self {
            prefix: Vec::with_capacity(65_537),
            cursor: 0,
            phase: TargetScanPhase::ServerHelloHeader,
            has_ccs: false,
            record_count: 0,
            capacity_sum: 0,
            flight_len: 301,
            incompatible: None,
        }
    }

    pub fn remaining_capacity(&self) -> usize {
        65_537usize.saturating_sub(self.prefix.len())
    }

    pub fn push(&mut self, bytes: &[u8]) -> TargetScanState {
        debug_assert!(bytes.len() <= self.remaining_capacity());
        let take = bytes.len().min(self.remaining_capacity());
        self.prefix.extend_from_slice(&bytes[..take]);
        self.scan_available();
        self.state()
    }

    pub fn state(&self) -> TargetScanState {
        if let Some(reason) = self.incompatible {
            return TargetScanState::Incompatible(reason);
        }
        if self.prefix.len() == 65_537 {
            return TargetScanState::Incompatible(MirrorCoverReason::Capacity);
        }
        if self.record_count == 0 || self.cursor != self.prefix.len() {
            return TargetScanState::NeedBytes;
        }
        if self.capacity_sum < self.flight_len {
            TargetScanState::CapacityTemporarilyInsufficient
        } else {
            TargetScanState::Freezable
        }
    }

    fn scan_available(&mut self) {
        loop {
            if self.incompatible.is_some() || self.prefix.len() == 65_537 {
                return;
            }
            match self.phase {
                TargetScanPhase::ServerHelloHeader => {
                    if self.prefix.len() < 5 {
                        return;
                    }
                    let len = usize::from(u16::from_be_bytes([self.prefix[3], self.prefix[4]]));
                    if self.prefix[..3] != [0x16, 0x03, 0x03] || len == 0 || len > 16 * 1024 {
                        self.incompatible = Some(MirrorCoverReason::DestProfile);
                        return;
                    }
                    self.phase = TargetScanPhase::ServerHelloBody { end: 5 + len };
                }
                TargetScanPhase::ServerHelloBody { end } => {
                    if self.prefix.len() < end {
                        return;
                    }
                    match scan_server_hello_shape(&self.prefix[5..end]) {
                        Ok(m) => self.flight_len = m,
                        Err(reason) => {
                            self.incompatible = Some(reason);
                            return;
                        }
                    }
                    self.cursor = end;
                    self.phase = TargetScanPhase::AfterServerHello;
                }
                TargetScanPhase::AfterServerHello => {
                    if self.prefix.len() == self.cursor {
                        return;
                    }
                    if self.prefix[self.cursor] == TLS_RECORD_CHANGE_CIPHER_SPEC {
                        if self.prefix.len() - self.cursor < COMPAT_CCS_RECORD.len() {
                            return;
                        }
                        self.phase = TargetScanPhase::CompatCcs {
                            end: self.cursor + COMPAT_CCS_RECORD.len(),
                        };
                    } else {
                        self.phase = TargetScanPhase::RecordHeader;
                    }
                }
                TargetScanPhase::CompatCcs { end } => {
                    if self.prefix.len() < end {
                        return;
                    }
                    if self.prefix[self.cursor..end] != COMPAT_CCS_RECORD {
                        self.incompatible = Some(MirrorCoverReason::DestProfile);
                        return;
                    }
                    self.has_ccs = true;
                    self.cursor = end;
                    self.phase = TargetScanPhase::RecordHeader;
                }
                TargetScanPhase::RecordHeader => {
                    if self.prefix.len() == self.cursor {
                        return;
                    }
                    if self.record_count == MAX_MIRRORED_RECORDS {
                        self.incompatible = Some(MirrorCoverReason::RecordLimit);
                        return;
                    }
                    if self.prefix.len() - self.cursor < 5 {
                        return;
                    }
                    let pos = self.cursor;
                    let typ = self.prefix[pos];
                    let len = usize::from(u16::from_be_bytes([
                        self.prefix[pos + 3],
                        self.prefix[pos + 4],
                    ]));
                    if typ == 0x15 {
                        self.incompatible = Some(MirrorCoverReason::DestAlert);
                        return;
                    }
                    if typ != TLS_RECORD_APPLICATION_DATA
                        || self.prefix[pos + 1..pos + 3] != [0x03, 0x03]
                        || !(18..=16401).contains(&len)
                    {
                        self.incompatible = Some(MirrorCoverReason::DestProfile);
                        return;
                    }
                    self.phase = TargetScanPhase::RecordBody {
                        end: pos + 5 + len,
                        capacity: len - 17,
                    };
                }
                TargetScanPhase::RecordBody { end, capacity } => {
                    if self.prefix.len() < end {
                        return;
                    }
                    self.cursor = end;
                    self.capacity_sum += capacity;
                    self.record_count += 1;
                    self.phase = TargetScanPhase::RecordHeader;
                }
            }
        }
    }

    pub fn freeze(
        self,
        verified: &VerifiedHello,
    ) -> std::result::Result<MirrorTemplate, MirrorTemplateError> {
        if self.state() != TargetScanState::Freezable {
            return Err(MirrorTemplateError::Incomplete);
        }
        MirrorTemplate::parse_owned(verified, self.prefix)
    }

    pub fn freeze_context(
        self,
        context: &AuthenticatedMirrorContext,
    ) -> std::result::Result<MirrorTemplate, MirrorTemplateError> {
        if self.state() != TargetScanState::Freezable {
            return Err(MirrorTemplateError::Incomplete);
        }
        MirrorTemplate::parse_context(context, self.prefix)
    }
}

fn scan_server_hello_shape(sh: &[u8]) -> std::result::Result<usize, MirrorCoverReason> {
    if sh.len() < 46
        || sh[0] != 0x02
        || read_u24(&sh[1..4]) + 4 != sh.len()
        || sh[4..6] != [0x03, 0x03]
    {
        return Err(MirrorCoverReason::DestProfile);
    }
    let random = &sh[6..38];
    if random == HRR_RANDOM {
        return Err(MirrorCoverReason::Hrr);
    }
    if random.ends_with(DOWNGRADE_TLS12) || random.ends_with(DOWNGRADE_PRE_TLS12) {
        return Err(MirrorCoverReason::DestProfile);
    }
    if sh[38] != 32 || sh.len() < 77 || sh[71 + 2] != 0 {
        return Err(MirrorCoverReason::DestProfile);
    }
    let cipher = u16::from_be_bytes([sh[71], sh[72]]);
    let flight_len = match cipher {
        TLS_AES_128_GCM_SHA256 | TLS_CHACHA20_POLY1305_SHA256 => 301,
        TLS_AES_256_GCM_SHA384 => 317,
        _ => return Err(MirrorCoverReason::UnsupportedCipher),
    };
    let ext_len = usize::from(u16::from_be_bytes([sh[74], sh[75]]));
    if 76 + ext_len != sh.len() {
        return Err(MirrorCoverReason::DestProfile);
    }
    let mut pos = 76;
    let mut saw_versions = false;
    let mut saw_key_share = false;
    while pos < sh.len() {
        if pos + 4 > sh.len() {
            return Err(MirrorCoverReason::DestProfile);
        }
        let typ = u16::from_be_bytes([sh[pos], sh[pos + 1]]);
        let len = usize::from(u16::from_be_bytes([sh[pos + 2], sh[pos + 3]]));
        pos += 4;
        if pos + len > sh.len() {
            return Err(MirrorCoverReason::DestProfile);
        }
        let data = &sh[pos..pos + len];
        pos += len;
        match typ {
            EXT_SUPPORTED_VERSIONS if !saw_versions && data == TLS13_VERSION_BYTES => {
                saw_versions = true;
            }
            EXT_KEY_SHARE if !saw_key_share && data.len() >= 4 => {
                saw_key_share = true;
                let group = u16::from_be_bytes([data[0], data[1]]);
                let share_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
                let expected = match group {
                    GROUP_X25519 => 32,
                    GROUP_X25519_MLKEM768 => HYBRID_SERVER_SHARE_LEN,
                    _ => return Err(MirrorCoverReason::UnsupportedGroup),
                };
                if share_len != expected || share_len + 4 != data.len() {
                    return Err(MirrorCoverReason::DestProfile);
                }
            }
            EXT_SUPPORTED_VERSIONS | EXT_KEY_SHARE => {
                return Err(MirrorCoverReason::UnsupportedExt)
            }
            _ => return Err(MirrorCoverReason::UnsupportedExt),
        }
    }
    if !saw_versions || !saw_key_share {
        return Err(MirrorCoverReason::UnsupportedExt);
    }
    Ok(flight_len)
}

#[derive(Clone)]
pub(crate) struct MirrorCryptoInput {
    pub(crate) server_random: [u8; 32],
    pub(crate) x25519_private: Zeroizing<[u8; 32]>,
    pub(crate) mlkem_ciphertext: Option<Vec<u8>>,
    pub(crate) mlkem_secret: Option<Zeroizing<Vec<u8>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MirrorTranscriptHashes {
    pub(crate) t0: Vec<u8>,
    pub(crate) t1: Vec<u8>,
    pub(crate) t2: Vec<u8>,
    pub(crate) t3: Vec<u8>,
}

struct BuiltMirrorFlight {
    plaintext: Vec<u8>,
    handshake: HandshakeKeys,
    hashes: MirrorTranscriptHashes,
    expected_client_finished: Zeroizing<Vec<u8>>,
}

fn valid_server_random(random: [u8; 32]) -> bool {
    random != HRR_RANDOM
        && !random.ends_with(DOWNGRADE_TLS12)
        && !random.ends_with(DOWNGRADE_PRE_TLS12)
}

fn mirror_server_random(fixed: Option<&MirrorCryptoInput>) -> TransportResult<[u8; 32]> {
    if let Some(fixed) = fixed {
        if !valid_server_random(fixed.server_random) {
            return Err(TransportError::Crypto(
                "fixed REALITY mirror ServerHello random is a sentinel".into(),
            ));
        }
        return Ok(fixed.server_random);
    }
    for _ in 0..64 {
        let random = rand::random::<[u8; 32]>();
        if valid_server_random(random) {
            return Ok(random);
        }
    }
    Err(TransportError::Crypto(
        "REALITY mirror ServerHello random rejection sampling exhausted".into(),
    ))
}

fn fixed_ephemeral_exchange(
    verified: &dyn MirrorHelloView,
    group: u16,
    fixed: &MirrorCryptoInput,
) -> TransportResult<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let entry = client_key_share_entry(verified, group)
        .ok_or_else(|| TransportError::Tls("REALITY mirror client key share disappeared".into()))?;
    let client_x_offset = match group {
        GROUP_X25519 => 0,
        GROUP_X25519_MLKEM768 => HYBRID_CLIENT_SHARE_LEN - 32,
        _ => {
            return Err(TransportError::Tls(
                "unsupported REALITY mirror group".into(),
            ))
        }
    };
    let client_x: [u8; 32] = entry
        .get(client_x_offset..client_x_offset + 32)
        .ok_or_else(|| TransportError::Tls("REALITY mirror client X25519 share length".into()))?
        .try_into()
        .expect("slice length checked");
    let x_public = x25519_public_from_private(&fixed.x25519_private);
    let x_secret = x25519(&fixed.x25519_private, &client_x)?;
    if group == GROUP_X25519 {
        return Ok((x_public.to_vec(), Zeroizing::new(x_secret[..].to_vec())));
    }
    let ciphertext = fixed
        .mlkem_ciphertext
        .as_ref()
        .ok_or_else(|| TransportError::Crypto("fixed REALITY ML-KEM ciphertext missing".into()))?;
    let mlkem_secret = fixed
        .mlkem_secret
        .as_ref()
        .ok_or_else(|| TransportError::Crypto("fixed REALITY ML-KEM secret missing".into()))?;
    if ciphertext.len() != 1088 || mlkem_secret.len() != 32 {
        return Err(TransportError::Crypto(
            "fixed REALITY ML-KEM injection length".into(),
        ));
    }
    let mut server_share = Vec::with_capacity(1120);
    server_share.extend_from_slice(ciphertext);
    server_share.extend_from_slice(&x_public);
    let mut tls_dh = Zeroizing::new(Vec::with_capacity(64));
    tls_dh.extend_from_slice(&mlkem_secret[..]);
    tls_dh.extend_from_slice(&x_secret[..]);
    Ok((server_share, tls_dh))
}

fn ephemeral_exchange(
    verified: &dyn MirrorHelloView,
    group: u16,
    fixed: Option<&MirrorCryptoInput>,
) -> TransportResult<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    if let Some(fixed) = fixed {
        return fixed_ephemeral_exchange(verified, group, fixed);
    }
    let entry = client_key_share_entry(verified, group)
        .ok_or_else(|| TransportError::Tls("REALITY mirror client key share disappeared".into()))?;
    encapsulate_server_share(&ChosenKeyShare {
        group,
        client_share: entry.to_vec(),
    })
}

fn build_mirror_flight(
    certificate: &RealityCertificate,
    verified: &dyn MirrorHelloView,
    patched_server_hello: &[u8],
    cipher: CipherSuite,
    tls_dh: &[u8],
) -> TransportResult<BuiltMirrorFlight> {
    let hash = cipher.hash();
    let mut transcript = verified.transcript_hasher(hash);
    transcript.update(patched_server_hello);
    let t0 = transcript.finalize_clone();
    let hs = HandshakeKeys::derive_with_transcript_hash(cipher, tls_dh, &t0);

    let ee = handshake_message(HS_ENCRYPTED_EXTENSIONS, &[0, 0]);
    transcript.update(&ee);
    let certificate_der = certificate.for_auth_key(verified.auth_key());
    let certificate_msg = certificate_message(&certificate_der);
    transcript.update(&certificate_msg);
    let t1 = transcript.finalize_clone();

    let mut cv_body = Vec::with_capacity(2 + 2 + 64);
    put_u16(SIG_ED25519, &mut cv_body);
    put_u16(64, &mut cv_body);
    let signature = certificate.sign(&certificate_verify_input(&t1))?;
    debug_assert_eq!(signature.len(), 64);
    cv_body.extend_from_slice(&signature);
    let certificate_verify = handshake_message(HS_CERTIFICATE_VERIFY, &cv_body);
    transcript.update(&certificate_verify);
    let t2 = transcript.finalize_clone();

    let server_finished_body = finished_verify_data_with_hash(hash, &hs.server_secret, &t2);
    let server_finished = handshake_message(HS_FINISHED, &server_finished_body);
    transcript.update(&server_finished);
    let t3 = transcript.finalize_clone();
    let expected_client_finished = finished_verify_data_with_hash(hash, &hs.client_secret, &t3);

    let mut plaintext = Vec::with_capacity(
        ee.len() + certificate_msg.len() + certificate_verify.len() + server_finished.len(),
    );
    plaintext.extend_from_slice(&ee);
    plaintext.extend_from_slice(&certificate_msg);
    plaintext.extend_from_slice(&certificate_verify);
    plaintext.extend_from_slice(&server_finished);
    Ok(BuiltMirrorFlight {
        plaintext,
        handshake: hs,
        hashes: MirrorTranscriptHashes { t0, t1, t2, t3 },
        expected_client_finished,
    })
}

/// Fully sealed server flight plus the state needed to verify the client's
/// Finished.  The wire half is deliberately separable so the listener can
/// monitor the probed target while emitting it.
pub struct PreparedFlight {
    wire: Vec<u8>,
    completion: MirroredHandshakeCompletion,
}

impl fmt::Debug for PreparedFlight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedFlight")
            .field("wire_len", &self.wire.len())
            .finish_non_exhaustive()
    }
}

impl PreparedFlight {
    pub fn into_wire_and_completion(self) -> (Vec<u8>, MirroredHandshakeCompletion) {
        (self.wire, self.completion)
    }
}

/// Opaque post-emit handshake state.  It contains handshake secrets and is
/// neither cloneable nor publicly constructible.
pub struct MirroredHandshakeCompletion {
    cipher: CipherSuite,
    client_handshake: RecordKey,
    master_secret: Zeroizing<Vec<u8>>,
    transcript_t3_hash: Vec<u8>,
    expected_client_finished: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for MirroredHandshakeCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MirroredHandshakeCompletion")
            .finish_non_exhaustive()
    }
}

impl MirroredHandshakeCompletion {
    /// Read and verify the strict post-commit client Finished, then install
    /// fresh application record keys on the original client stream.
    pub async fn finish(self, mut inner: Box<dyn Stream>) -> TransportResult<Box<dyn Stream>> {
        let mut client_handshake = self.client_handshake;
        let finished = read_mirrored_client_finished(
            &mut inner,
            &mut client_handshake,
            self.cipher.hash().len(),
        )
        .await?;
        let verify_data = &finished.bytes[4..finished.len];
        if verify_data.len() != self.expected_client_finished.len()
            || !bool::from(verify_data.ct_eq(&self.expected_client_finished))
        {
            return Err(TransportError::Tls(
                "REALITY mirrored client Finished verify_data mismatch".into(),
            ));
        }
        let app = ApplicationKeys::derive_with_transcript_hash(
            self.cipher,
            &self.master_secret,
            &self.transcript_t3_hash,
        );
        Ok(Box::new(crate::reality_tls::RealityTlsStream::new(
            inner, app.client, app.server,
        )))
    }
}

#[derive(Debug)]
struct MirroredFinishedMessage {
    len: usize,
    bytes: Zeroizing<[u8; 52]>,
}

async fn read_mirrored_client_finished(
    inner: &mut Box<dyn Stream>,
    key: &mut RecordKey,
    finished_len: usize,
) -> TransportResult<MirroredFinishedMessage> {
    let mut total_wire = 0usize;
    let mut ignored_ccs = false;
    let mut body = Zeroizing::new(Vec::with_capacity(16401));
    let mut handshake = MirroredFinishedMessage {
        len: 0,
        bytes: Zeroizing::new([0; 52]),
    };
    for _ in 0..32 {
        let mut header = [0u8; 5];
        inner.read_exact(&mut header).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                TransportError::Tls("EOF before REALITY mirrored client Finished".into())
            } else {
                TransportError::Io(e)
            }
        })?;
        total_wire = total_wire.checked_add(5).ok_or_else(|| {
            TransportError::ResourceLimit("REALITY Finished wire overflow".into())
        })?;
        if total_wire > 65_536 {
            return Err(TransportError::ResourceLimit(
                "REALITY mirrored client Finished exceeds 64 KiB".into(),
            ));
        }
        let record_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if total_wire
            .checked_add(record_len)
            .ok_or_else(|| TransportError::ResourceLimit("REALITY Finished wire overflow".into()))?
            > 65_536
        {
            return Err(TransportError::ResourceLimit(
                "REALITY mirrored client Finished exceeds 64 KiB".into(),
            ));
        }

        // Header-level admission happens before the body allocation is filled
        // or copied.  In particular, a second CCS and an over-budget length
        // are rejected without reading their payload bytes.
        if header[0] == TLS_RECORD_CHANGE_CIPHER_SPEC {
            if ignored_ccs || header != [0x14, 0x03, 0x03, 0x00, 0x01] || record_len != 1 {
                return Err(TransportError::Tls(
                    "REALITY mirrored client Finished carries a non-canonical CCS".into(),
                ));
            }
        } else {
            if header[0] != TLS_RECORD_APPLICATION_DATA {
                return Err(TransportError::Tls(
                    "REALITY mirrored client Finished record type".into(),
                ));
            }
            if header[1..3] != [0x03, 0x03] {
                return Err(TransportError::Tls(
                    "REALITY mirrored client Finished record version".into(),
                ));
            }
            if !(18..=16401).contains(&record_len) {
                return Err(TransportError::Tls(
                    "REALITY mirrored client Finished record length".into(),
                ));
            }
        }

        body.clear();
        body.resize(record_len, 0);
        inner
            .read_exact(&mut body)
            .await
            .map_err(TransportError::Io)?;
        total_wire += record_len;
        if header[0] == TLS_RECORD_CHANGE_CIPHER_SPEC {
            if body[..] != [1] {
                return Err(TransportError::Tls(
                    "REALITY mirrored client Finished carries a non-canonical CCS".into(),
                ));
            }
            ignored_ccs = true;
            continue;
        }

        let (inner_type, len) = key.open_in_place(&header, &mut body)?;
        body.truncate(len);
        if inner_type != TLS_RECORD_HANDSHAKE || body.is_empty() {
            return Err(TransportError::Tls(
                "REALITY mirrored client Finished inner record type".into(),
            ));
        }
        if handshake.len == 0 && body[0] != HS_FINISHED {
            return Err(TransportError::Tls(
                "REALITY mirrored client handshake message is not Finished".into(),
            ));
        }
        if handshake.len + body.len() > 4 + finished_len {
            return Err(TransportError::Tls(
                "REALITY bytes after mirrored client Finished".into(),
            ));
        }
        handshake.bytes[handshake.len..handshake.len + body.len()].copy_from_slice(&body);
        handshake.len += body.len();
        if handshake.len >= 4 {
            if handshake.bytes[0] != HS_FINISHED || read_u24(&handshake.bytes[1..4]) != finished_len
            {
                return Err(TransportError::Tls(
                    "REALITY mirrored client Finished length".into(),
                ));
            }
            if handshake.len == 4 + finished_len {
                return Ok(handshake);
            }
        }
    }
    Err(TransportError::ResourceLimit(
        "REALITY mirrored client Finished exceeded record limit".into(),
    ))
}

#[allow(clippy::needless_pass_by_value)] // ownership is an explicit pre-commit barrier
pub(crate) fn prepare_mirrored_flight(
    certificate: &RealityCertificate,
    verified: &VerifiedHello,
    template: MirrorTemplate,
    fixed_crypto: Option<&MirrorCryptoInput>,
) -> TransportResult<PreparedFlight> {
    prepare_mirrored_flight_view(certificate, verified, template, fixed_crypto)
}

#[allow(clippy::needless_pass_by_value)] // ownership is an explicit pre-commit barrier
pub(crate) fn prepare_mirrored_flight_context(
    certificate: &RealityCertificate,
    verified: &AuthenticatedMirrorContext,
    template: MirrorTemplate,
    fixed_crypto: Option<&MirrorCryptoInput>,
) -> TransportResult<PreparedFlight> {
    prepare_mirrored_flight_view(certificate, verified, template, fixed_crypto)
}

#[allow(clippy::needless_pass_by_value)] // consuming the template prevents reuse after commit preparation
fn prepare_mirrored_flight_view(
    certificate: &RealityCertificate,
    verified: &dyn MirrorHelloView,
    template: MirrorTemplate,
    fixed_crypto: Option<&MirrorCryptoInput>,
) -> TransportResult<PreparedFlight> {
    if *verified.session_id() != template.client_session_id {
        return Err(TransportError::Tls(
            "REALITY mirror template is bound to a different ClientHello".into(),
        ));
    }
    let random = mirror_server_random(fixed_crypto)?;
    let (server_share, tls_dh) = ephemeral_exchange(verified, template.group, fixed_crypto)?;
    if server_share.len() != template.share_range.len() {
        return Err(TransportError::Tls(
            "REALITY mirror server share length does not match template".into(),
        ));
    }
    let template_sh_len = template.server_hello().len();
    if template_sh_len < 38 || template.share_range.end > template_sh_len {
        return Err(TransportError::Tls(
            "REALITY mirror template patch range is out of bounds".into(),
        ));
    }

    let sh_len = u16::try_from(template_sh_len)
        .map_err(|_| TransportError::Tls("REALITY mirror ServerHello length".into()))?;
    let capacity = 5
        + template_sh_len
        + usize::from(template.has_ccs) * COMPAT_CCS_RECORD.len()
        + template
            .record_heads
            .iter()
            .map(|head| 5 + usize::from(u16::from_be_bytes([head[3], head[4]])))
            .sum::<usize>();
    let mut wire = Vec::with_capacity(capacity);
    wire.extend_from_slice(&[0x16, 0x03, 0x03]);
    wire.extend_from_slice(&sh_len.to_be_bytes());
    wire.extend_from_slice(template.server_hello());
    wire[5 + 6..5 + 38].copy_from_slice(&random);
    let share_out = 5 + template.share_range.start..5 + template.share_range.end;
    wire[share_out].copy_from_slice(&server_share);
    let built = {
        let patched_server_hello = &wire[5..5 + template_sh_len];
        build_mirror_flight(
            certificate,
            verified,
            patched_server_hello,
            template.cipher,
            &tls_dh,
        )?
    };
    let plans =
        plan_mirrored_records(built.plaintext.len(), &template.record_heads).map_err(|_| {
            TransportError::ResourceLimit(
                "REALITY mirror template capacity cannot hold the flight".into(),
            )
        })?;

    if template.has_ccs {
        wire.extend_from_slice(&COMPAT_CCS_RECORD);
    }

    let mut hs = built.handshake;
    for plan in plans {
        let start = wire.len();
        hs.server.seal_with_padding_into(
            &mut wire,
            TLS_RECORD_HANDSHAKE,
            &built.plaintext[plan.range.clone()],
            plan.pad,
        )?;
        if wire[start..start + 5] != plan.head {
            return Err(TransportError::Crypto(
                "REALITY mirror sealed record head diverged from template".into(),
            ));
        }
    }

    let completion = MirroredHandshakeCompletion {
        cipher: template.cipher,
        client_handshake: hs.client,
        master_secret: hs.master_secret,
        transcript_t3_hash: built.hashes.t3.clone(),
        expected_client_finished: built.expected_client_finished,
    };
    // tls_dh and every unneeded handshake secret are dropped (and erased)
    // here, before the caller ever sees the prepared flight.
    Ok(PreparedFlight { wire, completion })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality_server::{
        ClientHello, ClientKeyShares, FixedServerName, OfferedCipherSuites, RealityCertificate,
        SupportedGroups, VerifiedHello,
    };
    use crate::reality_tls::{x25519_public_from_private, CipherSuite};
    use boring::mlkem::{Algorithm as MlKemAlgorithm, MlKemPrivateKey};

    const HRR_RANDOM: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ];

    fn x25519_public(seed: u8) -> Vec<u8> {
        x25519_public_from_private(&[seed; 32]).to_vec()
    }

    fn hybrid_client_share() -> Vec<u8> {
        let (public, _private) =
            MlKemPrivateKey::generate(MlKemAlgorithm::MlKem768).expect("ML-KEM key generation");
        let mut share = public.as_bytes().to_vec();
        share.extend_from_slice(&x25519_public(0x31));
        share
    }

    fn hybrid_target_share() -> Vec<u8> {
        let mut share = vec![0x55; 1088];
        share.extend_from_slice(&x25519_public(0x32));
        share
    }

    #[allow(clippy::too_many_arguments)]
    fn verified_hello(
        groups: Vec<u16>,
        shares: Vec<(u16, Vec<u8>)>,
        ciphers: Vec<u16>,
        has_psk: bool,
        has_early_data: bool,
        record_size_limit: Option<u16>,
    ) -> VerifiedHello {
        let selected = shares
            .iter()
            .find(|(group, _)| *group == 0x001d)
            .or_else(|| shares.first())
            .expect("test hello carries a share")
            .0;
        let mut offered = OfferedCipherSuites::default();
        for cipher in ciphers {
            offered.insert(cipher);
        }
        let mut supported = SupportedGroups::default();
        if !groups.is_empty() {
            supported.mark_nonempty();
        }
        for group in groups {
            supported.insert(group);
        }
        let mut share_slots = ClientKeyShares::default();
        for (group, bytes) in shares {
            share_slots.insert(group, &bytes);
        }
        VerifiedHello {
            issuer: std::sync::Arc::new(()),
            hello: ClientHello {
                raw: vec![1, 0, 0, 0],
                random: [0x11; 32],
                session_id: [0x42; 32],
                server_name: FixedServerName::from_test("www.example.com"),
                cipher_suites: offered,
                supported_groups: supported,
                key_shares: share_slots,
                offers_tls13: true,
                reality_session_id_layout: true,
                duplicate_extension: false,
                sni_malformed: false,
                key_share_malformed: false,
                has_pre_shared_key: has_psk,
                has_early_data,
                record_size_limit,
                record_size_limit_malformed: false,
                parse_explicit_arena_bytes: 0,
            },
            ch_wire: Vec::new(),
            auth_key: Zeroizing::new([0x23; 32]),
            local_cipher: CipherSuite::Aes128GcmSha256,
            local_key_group: selected,
        }
    }

    fn x25519_verified() -> VerifiedHello {
        verified_hello(
            vec![0x001d],
            vec![(0x001d, x25519_public(0x30))],
            vec![0x1301, 0x1302, 0x1303],
            false,
            false,
            None,
        )
    }

    fn hybrid_verified() -> VerifiedHello {
        verified_hello(
            vec![0x11ec, 0x001d],
            vec![
                (0x11ec, hybrid_client_share()),
                (0x001d, x25519_public(0x30)),
            ],
            vec![0x1301, 0x1302, 0x1303],
            false,
            false,
            None,
        )
    }

    struct ServerHelloParts {
        message: Vec<u8>,
        share_range: Range<usize>,
    }

    fn extension(typ: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn server_hello(
        hello: &VerifiedHello,
        cipher: u16,
        group: u16,
        share: &[u8],
        key_share_first: bool,
        random: [u8; 32],
        compression: u8,
        extra_extension: Option<(u16, Vec<u8>)>,
        duplicate_key_share: bool,
        supported_version: u16,
    ) -> ServerHelloParts {
        let versions = extension(0x002b, &supported_version.to_be_bytes());
        let mut key_share_body = Vec::new();
        key_share_body.extend_from_slice(&group.to_be_bytes());
        key_share_body.extend_from_slice(&(share.len() as u16).to_be_bytes());
        key_share_body.extend_from_slice(share);
        let key_share = extension(0x0033, &key_share_body);
        let mut extensions = Vec::new();
        if key_share_first {
            extensions.extend_from_slice(&key_share);
            if duplicate_key_share {
                extensions.extend_from_slice(&key_share);
            }
            extensions.extend_from_slice(&versions);
        } else {
            extensions.extend_from_slice(&versions);
            extensions.extend_from_slice(&key_share);
            if duplicate_key_share {
                extensions.extend_from_slice(&key_share);
            }
        }
        if let Some((typ, data)) = extra_extension {
            extensions.extend_from_slice(&extension(typ, &data));
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(32);
        body.extend_from_slice(&hello.hello.session_id);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(compression);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut message = Vec::new();
        message.push(0x02);
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        message.extend_from_slice(&body);

        let needle = key_share_body[4..].to_vec();
        let start = message
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("share occurs once in synthetic SH");
        ServerHelloParts {
            message,
            share_range: start..start + needle.len(),
        }
    }

    fn target_prefix(sh: &[u8], ccs: bool, record_lengths: &[u16]) -> Vec<u8> {
        target_prefix_with_mutation(sh, ccs, record_lengths, None)
    }

    fn target_prefix_with_mutation(
        sh: &[u8],
        ccs: bool,
        record_lengths: &[u16],
        mutate_record: Option<(usize, [u8; 5])>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0x16, 0x03, 0x03]);
        out.extend_from_slice(&(sh.len() as u16).to_be_bytes());
        out.extend_from_slice(sh);
        if ccs {
            out.extend_from_slice(&COMPAT_CCS_RECORD);
        }
        for (index, len) in record_lengths.iter().enumerate() {
            let header = mutate_record
                .filter(|(record_index, _)| *record_index == index)
                .map_or_else(|| head(*len), |(_, header)| header);
            out.extend_from_slice(&header);
            let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            out.resize(out.len() + body_len, 0x5a);
        }
        out
    }

    fn valid_x25519_sh(hello: &VerifiedHello, key_share_first: bool) -> ServerHelloParts {
        server_hello(
            hello,
            0x1301,
            0x001d,
            &x25519_public(0x40),
            key_share_first,
            [0x77; 32],
            0,
            None,
            false,
            0x0304,
        )
    }

    fn valid_hybrid_sh(hello: &VerifiedHello, key_share_first: bool) -> ServerHelloParts {
        server_hello(
            hello,
            0x1302,
            0x11ec,
            &hybrid_target_share(),
            key_share_first,
            [0x77; 32],
            0,
            None,
            false,
            0x0304,
        )
    }

    fn head(len: u16) -> [u8; 5] {
        [0x17, 0x03, 0x03, (len >> 8) as u8, len as u8]
    }

    fn enumerate_allocations(
        capacities: &[usize],
        m: usize,
        index: usize,
        prefix: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if index == capacities.len() {
            if prefix.iter().sum::<usize>() == m {
                out.push(prefix.clone());
            }
            return;
        }
        for take in 1..=capacities[index] {
            prefix.push(take);
            enumerate_allocations(capacities, m, index + 1, prefix, out);
            prefix.pop();
        }
    }

    #[test]
    fn template_accepts_both_groups_in_both_extension_orders_and_ranges_shares() {
        for key_share_first in [false, true] {
            let hello = x25519_verified();
            let sh = valid_x25519_sh(&hello, key_share_first);
            let prefix = target_prefix(&sh.message, key_share_first, &[25, 3217, 281, 69]);
            let template = MirrorTemplate::parse(&hello, &prefix).expect("X25519 template");
            assert_eq!(template.group, 0x001d);
            assert_eq!(template.cipher, CipherSuite::Aes128GcmSha256);
            assert_eq!(template.has_ccs, key_share_first);
            assert_eq!(template.share_range, sh.share_range);
            assert_eq!(template.share_range.len(), 32);
            assert_eq!(
                template.server_hello()[template.share_range.clone()],
                x25519_public(0x40)[..]
            );
            assert_eq!(
                template.record_heads,
                [head(25), head(3217), head(281), head(69)]
            );

            let hello = hybrid_verified();
            let sh = valid_hybrid_sh(&hello, key_share_first);
            let prefix = target_prefix(&sh.message, key_share_first, &[25, 3217, 281, 69]);
            let template = MirrorTemplate::parse(&hello, &prefix).expect("hybrid template");
            assert_eq!(template.group, 0x11ec);
            assert_eq!(template.cipher, CipherSuite::Aes256GcmSha384);
            assert_eq!(template.share_range, sh.share_range);
            assert_eq!(template.share_range.len(), 1120);
            assert_eq!(
                template.server_hello()[template.share_range.clone()],
                hybrid_target_share()[..]
            );
        }
    }

    #[test]
    fn template_rejects_target_and_client_share_matrix() {
        let hello = x25519_verified();
        for (group, share, name) in [
            (0x0017, x25519_public(0x40), "unknown group"),
            (0x001d, vec![0x44; 31], "short X25519 server share"),
        ] {
            let sh = server_hello(
                &hello, 0x1301, group, &share, false, [0x77; 32], 0, None, false, 0x0304,
            );
            let prefix = target_prefix(&sh.message, false, &[18]);
            assert!(
                MirrorTemplate::parse(&hello, &prefix).is_err(),
                "{name} must reject"
            );
        }

        let hybrid_only_declared_x = verified_hello(
            vec![0x001d],
            vec![
                (0x11ec, hybrid_client_share()),
                (0x001d, x25519_public(0x30)),
            ],
            vec![0x1302],
            false,
            false,
            None,
        );
        let sh = valid_hybrid_sh(&hybrid_only_declared_x, false);
        let prefix = target_prefix(&sh.message, false, &[18]);
        assert_eq!(
            MirrorTemplate::parse(&hybrid_only_declared_x, &prefix),
            Err(MirrorTemplateError::GroupNotOffered)
        );

        let missing_hybrid_share = verified_hello(
            vec![0x11ec, 0x001d],
            vec![(0x001d, x25519_public(0x30))],
            vec![0x1302],
            false,
            false,
            None,
        );
        assert_eq!(
            MirrorTemplate::parse(&missing_hybrid_share, &prefix),
            Err(MirrorTemplateError::KeyShareNotProvided)
        );

        for len in [1215, 1217] {
            let mut share = hybrid_client_share();
            share.resize(len, 0x33);
            let hello = verified_hello(
                vec![0x11ec, 0x001d],
                vec![(0x11ec, share), (0x001d, x25519_public(0x30))],
                vec![0x1302],
                false,
                false,
                None,
            );
            let sh = valid_hybrid_sh(&hello, false);
            let prefix = target_prefix(&sh.message, false, &[18]);
            assert_eq!(
                MirrorTemplate::parse(&hello, &prefix),
                Err(MirrorTemplateError::InvalidClientKeyShare),
                "client hybrid share length {len}"
            );
        }

        for len in [1119, 1121] {
            let mut share = hybrid_target_share();
            share.resize(len, 0x44);
            let hello = hybrid_verified();
            let sh = server_hello(
                &hello, 0x1302, 0x11ec, &share, false, [0x77; 32], 0, None, false, 0x0304,
            );
            let prefix = target_prefix(&sh.message, false, &[18]);
            assert_eq!(
                MirrorTemplate::parse(&hello, &prefix),
                Err(MirrorTemplateError::InvalidServerKeyShare),
                "server hybrid share length {len}"
            );
        }

        let mut bad_mlkem = vec![0xff; 1184];
        bad_mlkem.extend_from_slice(&x25519_public(0x31));
        let bad_mlkem_hello = verified_hello(
            vec![0x11ec, 0x001d],
            vec![(0x11ec, bad_mlkem), (0x001d, x25519_public(0x30))],
            vec![0x1302],
            false,
            false,
            None,
        );
        let sh = valid_hybrid_sh(&bad_mlkem_hello, false);
        let prefix = target_prefix(&sh.message, false, &[18]);
        assert_eq!(
            MirrorTemplate::parse(&bad_mlkem_hello, &prefix),
            Err(MirrorTemplateError::InvalidClientKeyShare),
            "bad ML-KEM encapsulation key"
        );

        let mut low_order_client = hybrid_client_share();
        low_order_client[1184..].copy_from_slice(&[0; 32]);
        let low_order_hello = verified_hello(
            vec![0x11ec, 0x001d],
            vec![(0x11ec, low_order_client), (0x001d, x25519_public(0x30))],
            vec![0x1302],
            false,
            false,
            None,
        );
        let sh = valid_hybrid_sh(&low_order_hello, false);
        let prefix = target_prefix(&sh.message, false, &[18]);
        assert_eq!(
            MirrorTemplate::parse(&low_order_hello, &prefix),
            Err(MirrorTemplateError::InvalidClientKeyShare),
            "low-order client hybrid suffix"
        );

        let mut low_order_target = vec![0x55; 1088];
        low_order_target.extend_from_slice(&[0; 32]);
        let hello = hybrid_verified();
        let sh = server_hello(
            &hello,
            0x1302,
            0x11ec,
            &low_order_target,
            false,
            [0x77; 32],
            0,
            None,
            false,
            0x0304,
        );
        let prefix = target_prefix(&sh.message, false, &[18]);
        assert_eq!(
            MirrorTemplate::parse(&hello, &prefix),
            Err(MirrorTemplateError::InvalidServerKeyShare),
            "low-order target hybrid suffix"
        );
    }

    #[test]
    fn template_rejects_sh_shape_cipher_extension_and_sid_matrix() {
        let hello = x25519_verified();
        let cases: Vec<(ServerHelloParts, MirrorTemplateError, &str)> = vec![
            (
                server_hello(
                    &hello,
                    0x1301,
                    0x001d,
                    &x25519_public(0x40),
                    false,
                    HRR_RANDOM,
                    0,
                    None,
                    false,
                    0x0304,
                ),
                MirrorTemplateError::HelloRetryRequest,
                "HRR random",
            ),
            (
                server_hello(
                    &hello,
                    0x1301,
                    0x001d,
                    &x25519_public(0x40),
                    false,
                    [0x77; 32],
                    0,
                    None,
                    false,
                    0x0303,
                ),
                MirrorTemplateError::UnsupportedVersion,
                "TLS 1.2 supported_versions",
            ),
            (
                server_hello(
                    &hello,
                    0x1304,
                    0x001d,
                    &x25519_public(0x40),
                    false,
                    [0x77; 32],
                    0,
                    None,
                    false,
                    0x0304,
                ),
                MirrorTemplateError::UnsupportedCipher,
                "cipher outside whitelist",
            ),
            (
                server_hello(
                    &hello,
                    0x1301,
                    0x001d,
                    &x25519_public(0x40),
                    false,
                    [0x77; 32],
                    1,
                    None,
                    false,
                    0x0304,
                ),
                MirrorTemplateError::MalformedServerHello,
                "nonzero compression",
            ),
            (
                server_hello(
                    &hello,
                    0x1301,
                    0x001d,
                    &x25519_public(0x40),
                    false,
                    [0x77; 32],
                    0,
                    Some((0x0029, Vec::new())),
                    false,
                    0x0304,
                ),
                MirrorTemplateError::UnsupportedExtension,
                "PSK extension",
            ),
            (
                server_hello(
                    &hello,
                    0x1301,
                    0x001d,
                    &x25519_public(0x40),
                    false,
                    [0x77; 32],
                    0,
                    Some((0xffff, vec![1])),
                    false,
                    0x0304,
                ),
                MirrorTemplateError::UnsupportedExtension,
                "unknown extension",
            ),
            (
                server_hello(
                    &hello,
                    0x1301,
                    0x001d,
                    &x25519_public(0x40),
                    false,
                    [0x77; 32],
                    0,
                    None,
                    true,
                    0x0304,
                ),
                MirrorTemplateError::DuplicateExtension,
                "duplicate key_share",
            ),
        ];
        for (sh, error, name) in cases {
            let prefix = target_prefix(&sh.message, false, &[18]);
            assert_eq!(MirrorTemplate::parse(&hello, &prefix), Err(error), "{name}");
        }

        for marker in [*b"DOWNGRD\x00", *b"DOWNGRD\x01"] {
            let mut random = [0x77; 32];
            random[24..].copy_from_slice(&marker);
            let sh = server_hello(
                &hello,
                0x1301,
                0x001d,
                &x25519_public(0x40),
                false,
                random,
                0,
                None,
                false,
                0x0304,
            );
            let prefix = target_prefix(&sh.message, false, &[18]);
            assert_eq!(
                MirrorTemplate::parse(&hello, &prefix),
                Err(MirrorTemplateError::DowngradeMarker)
            );
        }

        let sh = valid_x25519_sh(&hello, false);
        let mut wrong_sid = sh.message.clone();
        wrong_sid[39] ^= 1;
        let prefix = target_prefix(&wrong_sid, false, &[18]);
        assert_eq!(
            MirrorTemplate::parse(&hello, &prefix),
            Err(MirrorTemplateError::SessionIdMismatch)
        );

        let mut legacy_12 = sh.message;
        legacy_12[5] = 0x01;
        let prefix = target_prefix(&legacy_12, false, &[18]);
        assert!(
            MirrorTemplate::parse(&hello, &prefix).is_err(),
            "legacy_version other than 0303"
        );

        let cipher_not_offered = verified_hello(
            vec![0x001d],
            vec![(0x001d, x25519_public(0x30))],
            vec![0x1301],
            false,
            false,
            None,
        );
        let sh = server_hello(
            &cipher_not_offered,
            0x1302,
            0x001d,
            &x25519_public(0x40),
            false,
            [0x77; 32],
            0,
            None,
            false,
            0x0304,
        );
        let prefix = target_prefix(&sh.message, false, &[18]);
        assert_eq!(
            MirrorTemplate::parse(&cipher_not_offered, &prefix),
            Err(MirrorTemplateError::CipherNotOffered)
        );
    }

    #[test]
    fn template_rejects_client_profile_restrictions() {
        for (has_psk, has_early, rsl, error, name) in [
            (
                true,
                false,
                None,
                MirrorClientProfileError::PreSharedKey,
                "CH PSK",
            ),
            (
                false,
                true,
                None,
                MirrorClientProfileError::EarlyData,
                "CH early_data",
            ),
            (
                false,
                false,
                Some(16384),
                MirrorClientProfileError::RecordSizeLimit,
                "reduced RSL",
            ),
        ] {
            let hello = verified_hello(
                vec![0x001d],
                vec![(0x001d, x25519_public(0x30))],
                vec![0x1301],
                has_psk,
                has_early,
                rsl,
            );
            assert_eq!(hello.mirror_profile(), Err(error), "{name}");
            let sh = valid_x25519_sh(&hello, false);
            let prefix = target_prefix(&sh.message, false, &[18]);
            assert_eq!(
                MirrorTemplate::parse(&hello, &prefix),
                Err(MirrorTemplateError::ClientProfile(error)),
                "{name} must reject before accepting an otherwise valid template"
            );
        }

        let legal_rsl = verified_hello(
            vec![0x001d],
            vec![(0x001d, x25519_public(0x30))],
            vec![0x1301],
            false,
            false,
            Some(16385),
        );
        assert_eq!(legal_rsl.mirror_profile(), Ok(()));
    }

    #[test]
    fn prepare_patches_only_random_and_complete_share_and_preserves_shape() {
        for (group, cipher, fixed_share, make_sh, expected_sh_len) in [
            (
                0x001d,
                0x1301,
                x25519_public(0x91),
                valid_x25519_sh as fn(&VerifiedHello, bool) -> ServerHelloParts,
                122usize,
            ),
            (
                0x11ec,
                0x1302,
                {
                    let mut share = vec![0xa5; 1088];
                    share.extend_from_slice(&x25519_public(0x91));
                    share
                },
                valid_hybrid_sh as fn(&VerifiedHello, bool) -> ServerHelloParts,
                1210usize,
            ),
        ] {
            let hello = if group == 0x001d {
                x25519_verified()
            } else {
                hybrid_verified()
            };
            let sh = make_sh(&hello, false);
            assert_eq!(sh.message.len(), expected_sh_len);
            let prefix = target_prefix(&sh.message, true, &[25, 3217, 281, 69]);
            let template = MirrorTemplate::parse(&hello, &prefix).expect("template");
            let fixed = MirrorCryptoInput {
                server_random: [0x66; 32],
                x25519_private: Zeroizing::new([0x91; 32]),
                mlkem_ciphertext: (group == 0x11ec).then(|| vec![0xa5; 1088]),
                mlkem_secret: (group == 0x11ec).then(|| Zeroizing::new(vec![0x77; 32])),
            };
            let certificate = RealityCertificate::generate().expect("test certificate");
            let prepared = prepare_mirrored_flight(&certificate, &hello, template, Some(&fixed))
                .expect("prepare mirrored flight");
            let expected_len = 5
                + expected_sh_len
                + COMPAT_CCS_RECORD.len()
                + [25, 3217, 281, 69].iter().map(|len| 5 + len).sum::<usize>();
            assert_eq!(prepared.wire.len(), expected_len);
            assert_eq!(&prepared.wire[..3], &[0x16, 0x03, 0x03]);
            assert_eq!(
                u16::from_be_bytes([prepared.wire[3], prepared.wire[4]]) as usize,
                expected_sh_len
            );
            let patched = &prepared.wire[5..5 + expected_sh_len];
            assert_eq!(&patched[6..38], &[0x66; 32]);
            assert_eq!(patched[sh.share_range.clone()], fixed_share[..]);

            let mut original_mask = sh.message.clone();
            let mut patched_mask = patched.to_vec();
            original_mask[6..38].fill(0);
            patched_mask[6..38].fill(0);
            original_mask[sh.share_range.clone()].fill(0);
            patched_mask[sh.share_range].fill(0);
            assert_eq!(patched_mask, original_mask, "SH mask for group {group:#x}");

            let mut pos = 5 + expected_sh_len;
            assert_eq!(
                &prepared.wire[pos..pos + COMPAT_CCS_RECORD.len()],
                &COMPAT_CCS_RECORD
            );
            pos += COMPAT_CCS_RECORD.len();
            for len in [25u16, 3217, 281, 69] {
                assert_eq!(&prepared.wire[pos..pos + 5], &head(len));
                pos += 5 + usize::from(len);
            }
            assert_eq!(pos, prepared.wire.len());
            let _ = cipher;
        }
    }

    #[test]
    fn template_rejects_bad_ccs_record_sequence_version_and_trailing_shapes() {
        let hello = x25519_verified();
        let sh = valid_x25519_sh(&hello, false);

        let mut bad_version = head(18);
        bad_version[2] = 0x01;
        let prefix =
            target_prefix_with_mutation(&sh.message, false, &[18, 18], Some((1, bad_version)));
        assert_eq!(
            MirrorTemplate::parse(&hello, &prefix),
            Err(MirrorTemplateError::RecordVersion),
            "a later record may not inherit the first record's version"
        );

        let bad_type = [0x15, 0x03, 0x03, 0, 2];
        let prefix = target_prefix_with_mutation(&sh.message, false, &[18], Some((0, bad_type)));
        assert_eq!(
            MirrorTemplate::parse(&hello, &prefix),
            Err(MirrorTemplateError::PlaintextAlert)
        );

        let ccs_as_app = COMPAT_CCS_RECORD[..5].try_into().unwrap();
        let prefix = target_prefix_with_mutation(&sh.message, false, &[18], Some((0, ccs_as_app)));
        assert!(MirrorTemplate::parse(&hello, &prefix).is_err(), "extra CCS");

        let prefix = target_prefix(&sh.message, false, &[]);
        assert_eq!(
            MirrorTemplate::parse(&hello, &prefix),
            Err(MirrorTemplateError::MissingApplicationRecords)
        );

        let mut prefix = target_prefix(&sh.message, false, &[18]);
        prefix.truncate(prefix.len() - 1);
        assert_eq!(
            MirrorTemplate::parse(&hello, &prefix),
            Err(MirrorTemplateError::TrailingData)
        );

        let mut bad_ccs = target_prefix(&sh.message, false, &[18]);
        let insert_at = 5 + sh.message.len();
        bad_ccs.splice(insert_at..insert_at, [0x14, 0x03, 0x03, 0, 1, 2]);
        assert_eq!(
            MirrorTemplate::parse(&hello, &bad_ccs),
            Err(MirrorTemplateError::InvalidChangeCipherSpec)
        );
    }

    fn finished_record_keys() -> (RecordKey, RecordKey) {
        let key = [0x42; 16];
        let iv = [0x24; 12];
        (
            RecordKey::from_key_iv(CipherSuite::Aes128GcmSha256, &key, &iv),
            RecordKey::from_key_iv(CipherSuite::Aes128GcmSha256, &key, &iv),
        )
    }

    fn finished_message() -> Vec<u8> {
        let mut out = Vec::with_capacity(36);
        out.push(HS_FINISHED);
        out.extend_from_slice(&[0, 0, 32]);
        out.extend_from_slice(&[0x5a; 32]);
        out
    }

    async fn run_finished_reader(wire: Vec<u8>) -> TransportResult<MirroredFinishedMessage> {
        use tokio::io::AsyncWriteExt;
        let (mut tx, rx) = tokio::io::duplex(128 * 1024);
        tx.write_all(&wire).await.expect("write Finished test wire");
        drop(tx);
        let (_seal, mut open) = finished_record_keys();
        let mut stream: Box<dyn Stream> = Box::new(rx);
        read_mirrored_client_finished(&mut stream, &mut open, 32).await
    }

    fn seal_finished_wire(chunks: &[&[u8]], pads: &[usize]) -> Vec<u8> {
        let (mut seal, _open) = finished_record_keys();
        let mut wire = Vec::new();
        for (chunk, pad) in chunks.iter().zip(pads) {
            seal.seal_with_padding_into(&mut wire, TLS_RECORD_HANDSHAKE, chunk, *pad)
                .expect("seal Finished test record");
        }
        wire
    }

    #[tokio::test]
    async fn finished_reader_accepts_zero_or_one_compat_ccs_and_max_padding() {
        let message = finished_message();
        let wire = seal_finished_wire(&[&message], &[0]);
        let finished = run_finished_reader(wire).await.expect("no-CCS Finished");
        assert_eq!(&finished.bytes[..finished.len], message);

        let mut one_ccs = COMPAT_CCS_RECORD.to_vec();
        one_ccs.extend_from_slice(&seal_finished_wire(&[&message], &[16348]));
        let finished = run_finished_reader(one_ccs)
            .await
            .expect("one canonical CCS and maximum padding");
        assert_eq!(&finished.bytes[..finished.len], message);
    }

    #[tokio::test]
    async fn finished_reader_rejects_repeated_ccs_before_reading_its_body() {
        let mut wire = COMPAT_CCS_RECORD.to_vec();
        // Only the second CCS header is present.  Reaching this error proves
        // the header-level repeated-CCS decision happened before a body read;
        // a body-first implementation hits EOF instead.
        wire.extend_from_slice(&COMPAT_CCS_RECORD[..5]);
        let error = run_finished_reader(wire).await.expect_err("repeated CCS");
        assert!(error.to_string().contains("non-canonical CCS"), "{error}");
    }

    #[tokio::test]
    async fn finished_reader_rejects_empty_and_trailing_plaintext() {
        let empty = seal_finished_wire(&[&[]], &[1]);
        let error = run_finished_reader(empty)
            .await
            .expect_err("empty inner plaintext");
        assert!(error.to_string().contains("inner record type"), "{error}");

        let mut trailing = finished_message();
        trailing.push(0xaa);
        let wire = seal_finished_wire(&[&trailing], &[0]);
        let error = run_finished_reader(wire)
            .await
            .expect_err("trailing bytes after Finished");
        assert!(error.to_string().contains("bytes after"), "{error}");
    }

    #[tokio::test]
    async fn finished_reader_enforces_wire_budget_before_reading_over_budget_body() {
        let message = finished_message();
        let chunks = [&message[..1], &message[1..2], &message[2..3]];
        // Three maximum-length valid records are below the cap.  The fourth
        // maximum-length header already proves that its body would exceed W;
        // omitting that body makes a body-first implementation fail with EOF,
        // while the required implementation reports the budget error first.
        let mut wire = seal_finished_wire(&chunks, &[16382, 16382, 16382]);
        wire.extend_from_slice(&[TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0x40, 0x11]);
        let error = run_finished_reader(wire).await.expect_err("wire budget");
        assert!(error.to_string().contains("exceeds 64 KiB"), "{error}");
    }

    #[test]
    fn incremental_target_scanner_reaches_freezable_only_at_complete_boundaries() {
        let hello = x25519_verified();
        let sh = valid_x25519_sh(&hello, true);
        let prefix = target_prefix(&sh.message, true, &[25, 3217, 281, 69]);
        let mut scanner = TargetFlightScanner::new();
        let split = 5 + sh.message.len() + COMPAT_CCS_RECORD.len() + 5 + 10;
        assert_eq!(scanner.push(&prefix[..split]), TargetScanState::NeedBytes);
        let mut saw_capacity_wait = false;
        for byte in &prefix[split..] {
            let state = scanner.push(&[*byte]);
            if state == TargetScanState::CapacityTemporarilyInsufficient {
                saw_capacity_wait = true;
            }
        }
        assert!(
            saw_capacity_wait,
            "small first buckets are temporarily insufficient"
        );
        assert_eq!(scanner.state(), TargetScanState::Freezable);
        let cursor_before_freeze = scanner.cursor;
        let template = scanner.freeze(&hello).expect("freeze scanner prefix");
        assert_eq!(template.target_prefix, prefix);
        assert_eq!(template.server_hello(), sh.message);
        assert!(
            cursor_before_freeze > 0,
            "scan cursor advanced incrementally"
        );
    }

    #[test]
    fn incremental_target_scanner_types_incompatibility_and_w_sentinel() {
        let hello = x25519_verified();
        let sh = valid_x25519_sh(&hello, false);

        let mut scanner = TargetFlightScanner::new();
        let repeated = target_prefix(&sh.message, true, &[18])
            .into_iter()
            .take(5 + sh.message.len() + COMPAT_CCS_RECORD.len())
            .chain(COMPAT_CCS_RECORD)
            .collect::<Vec<_>>();
        for chunk in repeated.chunks(7) {
            scanner.push(chunk);
        }
        assert_eq!(
            scanner.state(),
            TargetScanState::Incompatible(MirrorCoverReason::DestProfile)
        );

        let mut scanner = TargetFlightScanner::new();
        let mut prefix = target_prefix(&sh.message, false, &[16401, 16401, 16401]);
        let remaining = 65_536 - prefix.len();
        // Add a fourth maximum-size header and as much of its body as fits in
        // W.  That body is necessarily incomplete; one further byte is the
        // lossless cover sentinel and turns the scan into typed capacity
        // incompatibility rather than a successful freeze.
        prefix.extend_from_slice(&[0x17, 0x03, 0x03, 0x40, 0x11]);
        let body_room = remaining - 5;
        prefix.extend(std::iter::repeat_n(0, body_room));
        assert_eq!(prefix.len(), 65_536);
        scanner.push(&prefix);
        assert_eq!(scanner.state(), TargetScanState::NeedBytes);
        scanner.push(&[0xaa]);
        assert_eq!(
            scanner.state(),
            TargetScanState::Incompatible(MirrorCoverReason::Capacity)
        );
        assert_eq!(
            scanner.prefix.len(),
            65_537,
            "sentinel is retained for cover"
        );
    }

    #[test]
    fn small_capacity_plans_match_independent_greedy_enumeration() {
        let lengths = [18u16, 19, 20, 19];
        let heads = lengths.map(head);
        let capacities = lengths.map(|len| usize::from(len) - 17);
        for m in capacities.len()..=capacities.iter().sum::<usize>() {
            let plan = plan_mirrored_records(m, &heads).expect("feasible small plan");
            let takes = plan
                .iter()
                .map(|entry| entry.range.len())
                .collect::<Vec<_>>();
            let mut prefix = Vec::new();
            let mut allocations = Vec::new();
            enumerate_allocations(&capacities, m, 0, &mut prefix, &mut allocations);
            assert!(
                allocations.iter().any(|allocation| allocation == &takes),
                "planned allocation {takes:?} must be legal for M={m}"
            );
            for index in 0..capacities.len() {
                let max_feasible = allocations
                    .iter()
                    .filter(|allocation| allocation[..index] == takes[..index])
                    .map(|allocation| allocation[index])
                    .max()
                    .expect("the planned prefix has at least one completion");
                assert_eq!(
                    takes[index], max_feasible,
                    "bucket {index} must greedily take the most bytes that still leaves a completion for M={m}"
                );
            }
        }
    }

    #[test]
    fn boundary_plans_cover_m_equals_n_sum_and_single_bucket() {
        let heads = [head(18), head(19), head(20)];
        let m_equals_n = plan_mirrored_records(3, &heads).expect("M=N");
        assert_eq!(
            m_equals_n
                .iter()
                .map(|entry| entry.range.len())
                .collect::<Vec<_>>(),
            vec![1, 1, 1]
        );
        let sum = plan_mirrored_records(6, &heads).expect("M=sum(C)");
        assert_eq!(
            sum.iter()
                .map(|entry| entry.range.len())
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(sum.iter().all(|entry| entry.pad == 0));

        let single = [head(18)];
        let one = plan_mirrored_records(1, &single).expect("single exact bucket");
        assert_eq!(one[0].range, 0..1);
        assert_eq!(one[0].pad, 0);
    }

    #[test]
    fn rejects_infeasible_counts_capacities_and_record_lengths() {
        assert!(plan_mirrored_records(1, &[]).is_err(), "N=0");
        assert!(plan_mirrored_records(0, &[head(18)]).is_err(), "M<N");
        assert!(plan_mirrored_records(2, &[head(18)]).is_err(), "M>sum(C)");
        assert!(
            plan_mirrored_records(1, &[head(17)]).is_err(),
            "L=17 has no capacity"
        );
        assert!(
            plan_mirrored_records(1, &[head(18)]).is_ok(),
            "L=18 is the minimum"
        );
        assert!(
            plan_mirrored_records(16384, &[head(16401)]).is_ok(),
            "L=16401 is the maximum"
        );
        assert!(
            plan_mirrored_records(1, &[head(16402)]).is_err(),
            "L=16402 is out of range"
        );
    }

    #[test]
    fn rejects_bad_type_or_version_and_preserves_each_header() {
        let mut bad_type = head(18);
        bad_type[0] = 0x16;
        assert!(plan_mirrored_records(1, &[bad_type]).is_err());
        let mut bad_version = head(18);
        bad_version[2] = 0x01;
        assert!(plan_mirrored_records(1, &[bad_version]).is_err());

        let heads = [head(25), head(18)];
        let plan = plan_mirrored_records(2, &heads).expect("valid heads");
        assert_eq!(plan[0].head, heads[0]);
        assert_eq!(plan[1].head, heads[1]);
    }

    #[test]
    fn acceptance_bucket_shape_leaves_only_suffix_capacity_as_padding() {
        let heads = [head(25), head(3217), head(281), head(69)];
        let sha256 = plan_mirrored_records(301, &heads).expect("SHA-256 flight fits");
        assert_eq!(
            sha256
                .iter()
                .map(|entry| entry.range.len())
                .collect::<Vec<_>>(),
            vec![8, 291, 1, 1]
        );
        assert_eq!(
            sha256.iter().map(|entry| entry.pad).collect::<Vec<_>>(),
            vec![0, 2909, 263, 51]
        );
        assert_eq!(
            sha256[0].range,
            0..8,
            "EE's six bytes cross into Certificate"
        );
        assert_eq!(sha256[3].range, 300..301);

        let sha384 = plan_mirrored_records(317, &heads).expect("SHA-384 flight fits");
        assert_eq!(
            sha384
                .iter()
                .map(|entry| entry.range.len())
                .collect::<Vec<_>>(),
            vec![8, 307, 1, 1]
        );
    }
}
