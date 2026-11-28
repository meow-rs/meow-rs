//! REALITY server-side authentication, handshake and cover relay.
//!
//! The accepted stream reuses the REALITY record implementation with its keys
//! installed in the opposite directions.  This keeps one audited record-layer
//! implementation and gives the inbound the same independent raw-passthrough
//! switches as the outbound.

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use boring::mlkem::{Algorithm as MlKemAlgorithm, MlKemPublicKey};
use boring::pkey::{Id, PKey, Private};
use boring::sign::Signer;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::reality_hello::{EXT_KEY_SHARE, GROUP_X25519, GROUP_X25519_MLKEM768};
use crate::reality_tls::{
    finished_verify_data, hkdf_sha256, put_u16, put_u24, read_record, read_u24, take, take_u16,
    take_u8, verify_finished, wrap_plain_record_tls13, x25519, x25519_public_from_private,
    ApplicationKeys, CipherSuite, HandshakeKeys, HashAlg, RealityTlsStream, TranscriptHasher,
    HS_CERTIFICATE, HS_CERTIFICATE_VERIFY, HS_CLIENT_HELLO, HS_ENCRYPTED_EXTENSIONS, HS_FINISHED,
    HS_SERVER_HELLO, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
    TLS_RECORD_APPLICATION_DATA, TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE,
};
use crate::{Result, Stream, TransportError};

pub use crate::reality_mirror::{
    MirrorClientProfileError, MirrorCoverReason, MirrorTemplate, MirrorTemplateError,
    MirroredHandshakeCompletion, PreparedFlight, TargetFlightScanner, TargetScanState,
};

const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_RECORD_SIZE_LIMIT: u16 = 28;
const EXT_PRE_SHARED_KEY: u16 = 41;
const EXT_EARLY_DATA: u16 = 42;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const TLS13_VERSION: u16 = 0x0304;
const HYBRID_SHARE_LEN: usize = 1184 + 32;

const MAX_AUTHED_STREAM_BYTES: usize = 64 * 1024;
const MAX_AUTHED_STREAM_RECORDS: usize = 32;
const MAX_PLAINTEXT_RECORD: usize = 16 * 1024;
const REALITY_ACCEPT_TIMEOUT: Duration = Duration::from_secs(15);
const COVER_BUFFER: usize = 16 * 1024;
const COVER_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const COVER_MAX_LIFETIME: Duration = Duration::from_secs(600);
const COVER_LIMITER_GRANULARITY: Duration = Duration::from_millis(10);
const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

/// One bit for every possible u16 extension/group value.  Reusing the same
/// fixed bitmap for extension uniqueness and then key-share uniqueness keeps
/// duplicate detection out of attacker-sized hash maps.
struct DedupBitset([u64; 1024]);

impl DedupBitset {
    fn new() -> Self {
        Self([0; 1024])
    }

    fn clear(&mut self) {
        self.0.fill(0);
    }

    /// Returns true when the value had already been inserted.
    fn insert(&mut self, value: u16) -> bool {
        let word = usize::from(value / 64);
        let bit = 1u64 << (value % 64);
        let duplicate = self.0[word] & bit != 0;
        self.0[word] |= bit;
        duplicate
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct OfferedCipherSuites(u8);

impl OfferedCipherSuites {
    const AES128: u8 = 1;
    const AES256: u8 = 2;
    const CHACHA20: u8 = 4;

    pub(crate) fn insert(&mut self, value: u16) {
        self.0 |= match value {
            TLS_AES_128_GCM_SHA256 => Self::AES128,
            TLS_AES_256_GCM_SHA384 => Self::AES256,
            TLS_CHACHA20_POLY1305_SHA256 => Self::CHACHA20,
            _ => 0,
        };
    }

    pub(crate) fn contains(&self, value: u16) -> bool {
        self.0
            & match value {
                TLS_AES_128_GCM_SHA256 => Self::AES128,
                TLS_AES_256_GCM_SHA384 => Self::AES256,
                TLS_CHACHA20_POLY1305_SHA256 => Self::CHACHA20,
                _ => 0,
            }
            != 0
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SupportedGroups {
    x25519: bool,
    hybrid: bool,
    absent_or_empty: bool,
}

impl Default for SupportedGroups {
    fn default() -> Self {
        Self {
            x25519: false,
            hybrid: false,
            absent_or_empty: true,
        }
    }
}

impl SupportedGroups {
    pub(crate) fn insert(&mut self, group: u16) {
        match group {
            GROUP_X25519 => self.x25519 = true,
            GROUP_X25519_MLKEM768 => self.hybrid = true,
            _ => {}
        }
    }

    pub(crate) fn mark_nonempty(&mut self) {
        self.absent_or_empty = false;
    }

    pub(crate) fn declares(&self, group: u16) -> bool {
        match group {
            GROUP_X25519 => self.x25519,
            GROUP_X25519_MLKEM768 => self.hybrid,
            _ => false,
        }
    }

    fn allows_v1(&self, group: u16) -> bool {
        self.absent_or_empty || self.declares(group)
    }
}

#[derive(Clone)]
pub(crate) struct FixedServerName {
    len: u8,
    bytes: [u8; 253],
}

impl FixedServerName {
    fn from_wire(name: &str) -> Option<Self> {
        if name.len() > 253 {
            return None;
        }
        let mut out = Self {
            len: name.len() as u8,
            bytes: [0; 253],
        };
        for (dst, src) in out.bytes[..name.len()].iter_mut().zip(name.as_bytes()) {
            *dst = src.to_ascii_lowercase();
        }
        Some(out)
    }

    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..usize::from(self.len)])
            .expect("SNI was validated as UTF-8")
    }

    #[cfg(test)]
    pub(crate) fn from_test(name: &str) -> Option<Self> {
        Self::from_wire(name)
    }
}

#[derive(Clone)]
pub(crate) struct KeyShareSlot<const N: usize> {
    present: bool,
    wire_len: usize,
    valid_len: bool,
    bytes: [u8; N],
}

impl<const N: usize> Default for KeyShareSlot<N> {
    fn default() -> Self {
        Self {
            present: false,
            wire_len: 0,
            valid_len: false,
            bytes: [0; N],
        }
    }
}

impl<const N: usize> KeyShareSlot<N> {
    pub(crate) fn insert(&mut self, bytes: &[u8]) {
        self.present = true;
        self.wire_len = bytes.len();
        self.valid_len = bytes.len() == N;
        if self.valid_len {
            self.bytes.copy_from_slice(bytes);
        }
    }

    fn bytes(&self) -> Option<&[u8; N]> {
        self.valid_len.then_some(&self.bytes)
    }

    #[cfg(test)]
    pub(crate) fn retained_capacity(&self) -> usize {
        usize::from(self.valid_len) * N
    }
}

#[derive(Clone, Default)]
pub(crate) struct ClientKeyShares {
    x25519: KeyShareSlot<32>,
    hybrid: KeyShareSlot<HYBRID_SHARE_LEN>,
}

impl ClientKeyShares {
    pub(crate) fn insert(&mut self, group: u16, bytes: &[u8]) {
        match group {
            GROUP_X25519 => self.x25519.insert(bytes),
            GROUP_X25519_MLKEM768 => self.hybrid.insert(bytes),
            _ => {}
        }
    }

    pub(crate) fn present(&self, group: u16) -> bool {
        match group {
            GROUP_X25519 => self.x25519.present,
            GROUP_X25519_MLKEM768 => self.hybrid.present,
            _ => false,
        }
    }

    pub(crate) fn bytes(&self, group: u16) -> Option<&[u8]> {
        match group {
            GROUP_X25519 => self.x25519.bytes().map(|bytes| &bytes[..]),
            GROUP_X25519_MLKEM768 => self.hybrid.bytes().map(|bytes| &bytes[..]),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn retained_capacity(&self) -> usize {
        self.x25519.retained_capacity() + self.hybrid.retained_capacity()
    }
}

type HmacSha512 = Hmac<Sha512>;

/// REALITY private identity and admission policy.
pub struct RealityServerConfig {
    /// Base64-decoded 32-byte server X25519 private scalar.  Its public key
    /// is the public key distributed to clients.
    pub private_key: [u8; 32],
    /// Base64-decoded short identifiers, already zero-padded to eight bytes.
    pub short_ids: Vec<[u8; 8]>,
    /// Exact destination names the REALITY handshake admits.  A client whose
    /// SNI is absent or outside this set falls through to the cover relay.
    pub server_names: HashSet<String>,
    /// Accepted client timestamp skew.  `None` uses the REALITY default of
    /// 120 seconds; `Some(Duration::ZERO)` disables the check.
    pub max_time_difference: Option<Duration>,
    /// Test clock hook; production uses `None`.  Sub-second precision is
    /// significant to the freshness-window comparison.
    pub now: Option<fn() -> SystemTime>,
}

impl fmt::Debug for RealityServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityServerConfig")
            .field("private_key", &"<redacted>")
            .field("short_ids", &"<redacted>")
            .field(
                "server_names",
                &format_args!("[{} entries]", self.server_names.len()),
            )
            .field("max_time_difference", &self.max_time_difference)
            .finish_non_exhaustive()
    }
}

/// REALITY acceptor.  It owns no listener and never dials the cover target;
/// the inbound passes an already-connected target stream to [`CoverRelay::relay`].
#[derive(Clone)]
pub struct RealityServer {
    inner: Arc<RealityServerInner>,
}

struct RealityServerInner {
    instance: Arc<()>,
    // The only long-lived caller-owned copy of the static private key; the
    // config's own copy belongs to the caller and is outside this contract.
    private_key: Zeroizing<[u8; 32]>,
    short_ids: Vec<[u8; 8]>,
    server_names: HashSet<String>,
    max_time_difference: Duration,
    certificate: RealityCertificate,
    now: fn() -> SystemTime,
    #[cfg(test)]
    corrupt_certificate_verify: bool,
}

/// Result of accepting one TCP stream.
pub enum RealityServerAccept {
    /// Authenticated REALITY client.  The stream is post-handshake and clean.
    Authenticated(Box<dyn Stream>),
    /// Ordinary TLS or unauthenticated REALITY-looking traffic.  Relay the
    /// preserved bytes first, then both directions transparently.
    Cover(CoverRelay),
}

/// ClientHello pre-read and static REALITY authentication, split from the
/// server-flight completion so the listener can drive the next phase itself.
pub enum RealityClientHello {
    /// Statically authenticated REALITY ClientHello.  No response byte has
    /// been written and the client stream is unchanged after the exact
    /// pre-read prefix.
    Verified {
        stream: Box<dyn Stream>,
        hello: Box<VerifiedHello>,
    },
    /// Ordinary TLS or authentication failure; the relay owns the exact
    /// consumed wire prefix and the client stream.
    Cover(CoverRelay),
}

impl fmt::Debug for RealityClientHello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified { .. } => f.write_str("RealityClientHello::Verified(..)"),
            Self::Cover(_) => f.write_str("RealityClientHello::Cover(..)"),
        }
    }
}

/// Opaque result of a successful static REALITY authentication.
///
/// The type intentionally exposes wire bytes needed for upload/cover but no
/// AuthKey, private key, certificate identity, or constructor: production
/// callers can obtain it only by validating a real ClientHello against a
/// [`RealityServer`].
pub struct VerifiedHello {
    pub(crate) issuer: Arc<()>,
    pub(crate) hello: ClientHello,
    pub(crate) ch_wire: Vec<u8>,
    pub(crate) auth_key: Zeroizing<[u8; 32]>,
    pub(crate) local_cipher: CipherSuite,
    pub(crate) local_key_group: u16,
}

/// Small authenticated state needed by mirroring after the large logical
/// ClientHello allocation has been released.  Both transcript states are
/// advanced over the original logical CH exactly once.
pub struct AuthenticatedMirrorContext {
    pub(crate) issuer: Arc<()>,
    pub(crate) auth_key: Zeroizing<[u8; 32]>,
    pub(crate) session_id: [u8; 32],
    pub(crate) cipher_suites: OfferedCipherSuites,
    pub(crate) supported_groups: SupportedGroups,
    pub(crate) key_shares: ClientKeyShares,
    pub(crate) has_pre_shared_key: bool,
    pub(crate) has_early_data: bool,
    pub(crate) record_size_limit: Option<u16>,
    pub(crate) record_size_limit_malformed: bool,
    pub(crate) key_share_malformed: bool,
    pub(crate) transcript_sha256: TranscriptHasher,
    pub(crate) transcript_sha384: TranscriptHasher,
}

/// Consuming split of a verified ClientHello: the exact wire prefix can be
/// uploaded and then released while only the small mirror context remains.
pub struct MirrorHelloUpload {
    context: AuthenticatedMirrorContext,
    wire: Vec<u8>,
}

impl MirrorHelloUpload {
    pub fn context(&self) -> &AuthenticatedMirrorContext {
        &self.context
    }
    pub fn ch_wire(&self) -> &[u8] {
        &self.wire
    }
    pub fn finish_upload(self) -> (AuthenticatedMirrorContext, Vec<u8>) {
        (self.context, self.wire)
    }
}

impl AuthenticatedMirrorContext {
    /// Whether this authenticated context is eligible for v2 mirroring.
    pub fn mirror_profile(
        &self,
    ) -> std::result::Result<(), crate::reality_mirror::MirrorClientProfileError> {
        crate::reality_mirror::mirror_profile_context(self)
    }
}

impl fmt::Debug for VerifiedHello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedHello").finish_non_exhaustive()
    }
}

impl VerifiedHello {
    /// Split the authenticated token into a small mirror context plus the
    /// independently owned upload prefix.  The logical CH arena is dropped by
    /// this conversion rather than carried through target probing.
    pub fn into_mirror_upload(self) -> MirrorHelloUpload {
        let mut transcript_sha256 = TranscriptHasher::new(HashAlg::Sha256);
        let mut transcript_sha384 = TranscriptHasher::new(HashAlg::Sha384);
        transcript_sha256.update(&self.hello.raw);
        transcript_sha384.update(&self.hello.raw);
        let VerifiedHello {
            issuer,
            hello,
            ch_wire,
            auth_key,
            ..
        } = self;
        MirrorHelloUpload {
            context: AuthenticatedMirrorContext {
                issuer,
                auth_key,
                session_id: hello.session_id,
                cipher_suites: hello.cipher_suites,
                supported_groups: hello.supported_groups,
                key_shares: hello.key_shares,
                has_pre_shared_key: hello.has_pre_shared_key,
                has_early_data: hello.has_early_data,
                record_size_limit: hello.record_size_limit,
                record_size_limit_malformed: hello.record_size_limit_malformed,
                key_share_malformed: hello.key_share_malformed,
                transcript_sha256,
                transcript_sha384,
            },
            wire: ch_wire,
        }
    }

    /// Exact pre-read TCP prefix, including TLS record headers.  This is the
    /// only byte string a dial-first probe may upload or a cover relay may
    /// forward; it is never reconstructed from the parse tree.
    pub fn ch_wire(&self) -> &[u8] {
        &self.ch_wire
    }

    /// Convert an authenticated-but-not-locally-served ClientHello into the
    /// transparent cover branch without losing or duplicating the pre-read
    /// prefix.
    pub fn into_cover(self, stream: Box<dyn Stream>) -> CoverRelay {
        CoverRelay::new(stream, self.ch_wire)
    }
}

impl fmt::Debug for RealityServerAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticated(_) => f.write_str("RealityServerAccept::Authenticated(..)"),
            Self::Cover(_) => f.write_str("RealityServerAccept::Cover(..)"),
        }
    }
}

fn default_now() -> SystemTime {
    SystemTime::now()
}

impl RealityServer {
    pub fn new(config: &RealityServerConfig) -> Result<Self> {
        Self::with_certificate(config, RealityCertificate::generate)
    }

    fn with_certificate(
        config: &RealityServerConfig,
        certificate: impl FnOnce() -> Result<RealityCertificate>,
    ) -> Result<Self> {
        if config.short_ids.is_empty() || config.short_ids.len() > 64 {
            return Err(TransportError::Config(
                "REALITY server requires 1..64 short IDs".into(),
            ));
        }
        if config.server_names.is_empty() || config.server_names.len() > 64 {
            return Err(TransportError::Config(
                "REALITY server requires 1..64 destination server names".into(),
            ));
        }
        for name in &config.server_names {
            if !valid_server_name(name) {
                return Err(TransportError::Config(format!(
                    "REALITY server name is invalid: {name:?}"
                )));
            }
        }
        let max_time_difference = config
            .max_time_difference
            .unwrap_or(Duration::from_secs(120));
        Ok(Self {
            inner: Arc::new(RealityServerInner {
                instance: Arc::new(()),
                private_key: Zeroizing::new(config.private_key),
                short_ids: config.short_ids.clone(),
                server_names: config
                    .server_names
                    .iter()
                    .map(|name| name.to_ascii_lowercase())
                    .collect(),
                max_time_difference,
                certificate: certificate()?,
                now: config.now.unwrap_or(default_now),
                #[cfg(test)]
                corrupt_certificate_verify: false,
            }),
        })
    }

    #[cfg(test)]
    fn new_with_ed25519_private_der(
        config: &RealityServerConfig,
        private_key_der: &[u8],
    ) -> Result<Self> {
        Self::with_certificate(config, || {
            RealityCertificate::from_private_key_der(private_key_der)
        })
    }

    #[cfg(test)]
    fn new_corrupting_certificate_verify(config: &RealityServerConfig) -> Result<Self> {
        let mut server = Self::new(config)?;
        Arc::get_mut(&mut server.inner)
            .expect("fresh REALITY server is unique")
            .corrupt_certificate_verify = true;
        Ok(server)
    }

    /// Read through the complete ClientHello, classify it, and either finish
    /// the REALITY TLS handshake or hand back the preserved wire bytes for a
    /// cover relay.  No response byte is emitted before authentication succeeds.
    pub async fn accept(&self, inner: Box<dyn Stream>) -> Result<RealityServerAccept> {
        tokio::time::timeout(REALITY_ACCEPT_TIMEOUT, self.accept_inner(inner))
            .await
            .map_err(|_| TransportError::Timeout("REALITY accept exceeded 15 seconds".into()))?
    }

    async fn accept_inner(&self, inner: Box<dyn Stream>) -> Result<RealityServerAccept> {
        let classified = self.verify_client_hello(inner).await?;
        let (stream, hello) = match classified {
            RealityClientHello::Verified { stream, hello } => (stream, hello),
            RealityClientHello::Cover(relay) => return Ok(RealityServerAccept::Cover(relay)),
        };
        let stream = self
            .complete_handshake(stream, *hello)
            .await
            .inspect_err(|e| {
                tracing::debug!(error = %redact_error(e), "authenticated REALITY handshake failed");
            })?;
        Ok(RealityServerAccept::Authenticated(stream))
    }

    /// Read the bounded ClientHello prefix and statically authenticate it.
    ///
    /// This phase writes nothing.  The returned stream still owns every byte
    /// after the exact pre-read prefix, and `Cover` preserves that prefix for
    /// transparent relaying.  Completion is deliberately separate: callers
    /// either drive the v1 local flight with [`Self::complete_handshake`] or,
    /// in a later dial-first pipeline, prepare a mirrored flight.
    pub async fn verify_client_hello(&self, inner: Box<dyn Stream>) -> Result<RealityClientHello> {
        let (inner, preflight) = read_client_hello_preflight(inner).await?;
        let (hello, wire_prefix) = match preflight {
            Preflight::Cover(wire) => {
                return Ok(RealityClientHello::Cover(CoverRelay::new(inner, wire)))
            }
            Preflight::Candidate { hello, wire_prefix } => (*hello, wire_prefix),
        };

        let verified = match self.verify_hello(hello, wire_prefix) {
            Ok(verified) => verified,
            Err(wire_prefix) => {
                return Ok(RealityClientHello::Cover(CoverRelay::new(
                    inner,
                    wire_prefix,
                )))
            }
        };
        Ok(RealityClientHello::Verified {
            stream: inner,
            hello: Box::new(verified),
        })
    }

    /// Complete the v1 local REALITY server flight for an already verified
    /// ClientHello.  Authentication cannot be bypassed through this API
    /// because [`VerifiedHello`] has no public constructor.
    pub async fn complete_handshake(
        &self,
        inner: Box<dyn Stream>,
        hello: VerifiedHello,
    ) -> Result<Box<dyn Stream>> {
        if !Arc::ptr_eq(&hello.issuer, &self.inner.instance) {
            return Err(TransportError::Tls(
                "REALITY verified ClientHello belongs to a different server instance".into(),
            ));
        }
        let VerifiedHello {
            hello,
            auth_key,
            local_cipher,
            local_key_group,
            ..
        } = hello;
        let Some(key_share) = chosen_key_share_for(&hello, local_key_group) else {
            return Err(TransportError::Tls(
                "REALITY verified ClientHello lost its selected key share".into(),
            ));
        };
        let prepared = PreparedHandshake {
            raw_hello: hello.raw,
            session_id: hello.session_id.to_vec(),
            cipher: local_cipher,
            key_share,
            auth_key,
        };
        self.complete_prepared_handshake(inner, prepared).await
    }

    /// Prepare the v2 mirrored server flight for an authenticated ClientHello
    /// and a target template already validated against it.  Nothing is written
    /// by this method; the caller controls commit ordering and then drives the
    /// returned completion state.
    /// Test-only compatibility wrapper; production uses
    /// [`RealityServer::prepare_mirrored_upload`], which consumes the upload
    /// and drops the authenticated wire copy before the flight is built.
    #[cfg(test)]
    pub fn prepare_mirrored_flight(
        &self,
        hello: &VerifiedHello,
        template: MirrorTemplate,
    ) -> Result<PreparedFlight> {
        if !Arc::ptr_eq(&hello.issuer, &self.inner.instance) {
            return Err(TransportError::Tls(
                "REALITY verified ClientHello belongs to a different server instance".into(),
            ));
        }
        crate::reality_mirror::prepare_mirrored_flight(
            &self.inner.certificate,
            hello,
            template,
            None,
        )
    }

    /// Start the incremental target scan for the consuming upload/context
    /// split.  The scanner owns the W+1 target prefix arena until the caller
    /// either freezes a template or moves the same allocation into cover.
    pub fn target_flight_scanner<'a>(
        &self,
        context: &'a AuthenticatedMirrorContext,
    ) -> std::result::Result<
        crate::reality_mirror::TargetFlightScanner<'a>,
        crate::reality_mirror::MirrorClientProfileError,
    > {
        crate::reality_mirror::TargetFlightScanner::new(context, self.inner.certificate.der_len())
    }

    /// Prepare mirroring by consuming both the authenticated context and the
    /// frozen template.  The logical CH and upload wire are already gone at
    /// this point; a pre-commit rejection returns the template (and therefore
    /// the target prefix allocation) inside the error for cover.
    #[allow(clippy::needless_pass_by_value)] // consumption is the pre-commit ownership contract
    pub fn prepare_mirrored_upload(
        &self,
        context: AuthenticatedMirrorContext,
        template: MirrorTemplate,
    ) -> std::result::Result<PreparedFlight, Box<crate::reality_mirror::MirrorPrepareError>> {
        if !Arc::ptr_eq(&context.issuer, &self.inner.instance) {
            return Err(Box::new(
                crate::reality_mirror::MirrorPrepareError::cross_instance(template),
            ));
        }
        crate::reality_mirror::prepare_mirrored_flight_context(
            &self.inner.certificate,
            context,
            template,
        )
    }

    fn open_auth_plaintext(&self, hello: &mut ClientHello) -> Option<OpenedAuth> {
        let auth_share = hello.auth_share()?;
        let shared = x25519(&self.inner.private_key, &auth_share).ok()?;
        let auth_key = Zeroizing::new(
            <[u8; 32]>::try_from(
                &hkdf_sha256(&shared[..], &hello.random[..20], b"REALITY", 32)[..],
            )
            .expect("REALITY AuthKey length"),
        );

        let session_id = hello.session_id;
        hello.raw[39..71].fill(0);
        let plaintext = aes_gcm_open(
            &auth_key[..],
            &hello.random[20..32],
            &session_id[..16],
            &session_id[16..32],
            &hello.raw,
        );
        hello.raw[39..71].copy_from_slice(&session_id);
        let plaintext = plaintext?;
        if plaintext.len() != 16 {
            return None;
        }
        Some(OpenedAuth(auth_key, plaintext))
    }

    fn validate_hello(
        &self,
        hello: &mut ClientHello,
    ) -> Option<(Zeroizing<[u8; 32]>, CipherSuite, u16)> {
        if !hello.reality_session_id_layout
            || !hello.offers_tls13
            || hello.duplicate_extension
            || hello.sni_malformed
            || hello.key_share_malformed
        {
            return None;
        }
        let server_name = hello.server_name.as_ref()?.as_str();
        if !self.inner.server_names.contains(server_name) {
            return None;
        }
        let OpenedAuth(auth_key, plaintext) = self.open_auth_plaintext(hello)?;
        let (_version, _reserved, unix_seconds, short_id) = parse_auth_plaintext(&plaintext)?;
        // The wire timestamp is whole Unix seconds, but the comparison
        // happens in the Duration domain: truncating the window to whole
        // seconds would collapse a sub-second window to zero width.
        let client_time = Duration::from_secs(u64::from(unix_seconds));
        if self.inner.max_time_difference != Duration::ZERO {
            let now = (self.inner.now)()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            if now.abs_diff(client_time) > self.inner.max_time_difference {
                return None;
            }
        }
        let mut matched = subtle::Choice::from(0);
        for configured in &self.inner.short_ids {
            matched |= configured.ct_eq(&short_id);
        }
        if !bool::from(matched) {
            return None;
        }

        let cipher = select_cipher(&hello.cipher_suites)?;
        let key_group = select_key_group(hello)?;
        Some((auth_key, cipher, key_group))
    }

    fn verify_hello(
        &self,
        mut hello: ClientHello,
        ch_wire: Vec<u8>,
    ) -> std::result::Result<VerifiedHello, Vec<u8>> {
        match self.validate_hello(&mut hello) {
            Some((auth_key, local_cipher, local_key_group)) => Ok(VerifiedHello {
                issuer: Arc::clone(&self.inner.instance),
                hello,
                ch_wire,
                auth_key,
                local_cipher,
                local_key_group,
            }),
            None => Err(ch_wire),
        }
    }

    #[cfg(test)]
    fn classify(&self, hello: &mut ClientHello) -> Option<PreparedHandshake> {
        let (auth_key, cipher, key_group) = self.validate_hello(hello)?;
        let key_share = chosen_key_share_for(hello, key_group)?;
        Some(PreparedHandshake {
            raw_hello: hello.raw.clone(),
            session_id: hello.session_id.to_vec(),
            cipher,
            key_share,
            auth_key,
        })
    }

    async fn complete_prepared_handshake(
        &self,
        mut inner: Box<dyn Stream>,
        prepared: PreparedHandshake,
    ) -> Result<Box<dyn Stream>> {
        let hash = prepared.cipher.hash();
        let (server_key_exchange, shared_secret) = encapsulate_server_share(&prepared.key_share)?;
        let server_hello = build_server_hello(
            &prepared.session_id,
            prepared.cipher,
            &prepared.key_share.group,
            &server_key_exchange,
        );

        let mut transcript = prepared.raw_hello.clone();
        transcript.extend_from_slice(&server_hello);
        let mut hs = HandshakeKeys::derive(prepared.cipher, &shared_secret, &transcript);

        // EncryptedExtensions carries a two-byte extension-vector length even
        // when it is empty; a zero-length body is not a legal TLS 1.3 message.
        let ee = handshake_message(HS_ENCRYPTED_EXTENSIONS, &[0, 0]);
        transcript.extend_from_slice(&ee);
        let certificate_der = self.inner.certificate.for_auth_key(&prepared.auth_key);
        let certificate = certificate_message(&certificate_der);
        transcript.extend_from_slice(&certificate);

        let mut cv_body = Vec::with_capacity(2 + 2 + 64);
        put_u16(SIG_ED25519, &mut cv_body);
        put_u16(64, &mut cv_body);
        let signed = certificate_verify_input(&hash.digest(&transcript));
        let signature = self.inner.certificate.sign(&signed)?;
        #[cfg(test)]
        let mut signature = signature;
        #[cfg(test)]
        if self.inner.corrupt_certificate_verify {
            signature[0] ^= 1;
        }
        debug_assert_eq!(signature.len(), 64);
        cv_body.extend_from_slice(&signature);
        let certificate_verify = handshake_message(HS_CERTIFICATE_VERIFY, &cv_body);
        transcript.extend_from_slice(&certificate_verify);

        let finished_body = finished_verify_data(hash, &hs.server_secret, &transcript);
        let finished = handshake_message(HS_FINISHED, &finished_body);
        transcript.extend_from_slice(&finished);

        let mut encrypted_plain = Vec::with_capacity(
            ee.len() + certificate.len() + certificate_verify.len() + finished.len(),
        );
        encrypted_plain.extend_from_slice(&ee);
        encrypted_plain.extend_from_slice(&certificate);
        encrypted_plain.extend_from_slice(&certificate_verify);
        encrypted_plain.extend_from_slice(&finished);
        if encrypted_plain.len() > MAX_PLAINTEXT_RECORD {
            return Err(TransportError::Tls(
                "REALITY server flight exceeds one TLS plaintext record".into(),
            ));
        }
        let mut encrypted = hs.server.seal(TLS_RECORD_HANDSHAKE, &encrypted_plain)?;
        let mut out = wrap_plain_record_tls13(TLS_RECORD_HANDSHAKE, &server_hello)?;
        out.extend_from_slice(&wrap_plain_record_tls13(
            TLS_RECORD_CHANGE_CIPHER_SPEC,
            &[1],
        )?);
        out.append(&mut encrypted);
        inner.write_all(&out).await?;
        inner.flush().await?;

        let client_finished = read_client_finished(&mut inner, &mut hs).await?;
        verify_finished(hash, &hs.client_secret, &transcript, &client_finished)?;
        let app = ApplicationKeys::derive(prepared.cipher, &hs.master_secret, &transcript);
        Ok(Box::new(RealityTlsStream::new(
            inner, app.client, app.server,
        )))
    }
}

fn redact_error(e: &TransportError) -> String {
    match e {
        TransportError::Tls(_) | TransportError::Crypto(_) => "TLS cryptographic failure".into(),
        TransportError::Io(_) => "I/O failure".into(),
        other => other.to_string(),
    }
}

fn valid_server_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.contains('/')
        && !name.chars().any(char::is_whitespace)
}

pub(crate) const SIG_ED25519: u16 = 0x0807;

fn parse_auth_plaintext(plaintext: &[u8]) -> Option<([u8; 3], u8, u32, [u8; 8])> {
    if plaintext.len() != 16 {
        return None;
    }
    Some((
        plaintext[0..3].try_into().ok()?,
        plaintext[3],
        u32::from_be_bytes(plaintext[4..8].try_into().ok()?),
        plaintext[8..16].try_into().ok()?,
    ))
}

pub(crate) fn certificate_verify_input(transcript_hash: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(64 + 33 + 1 + transcript_hash.len());
    signed.extend_from_slice(&[0x20; 64]);
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed.push(0);
    signed.extend_from_slice(transcript_hash);
    signed
}

enum Preflight {
    Candidate {
        hello: Box<ClientHello>,
        wire_prefix: Vec<u8>,
    },
    Cover(Vec<u8>),
}

async fn read_client_hello_preflight(
    mut inner: Box<dyn Stream>,
) -> Result<(Box<dyn Stream>, Preflight)> {
    // The two CH arenas are explicit, bounded allocations: the exact wire
    // prefix and the reassembled logical handshake.  They briefly coexist
    // while records are read, then ownership of the logical allocation moves
    // into ClientHello without a third copy.
    let mut wire_prefix = Vec::with_capacity(MAX_AUTHED_STREAM_BYTES);
    let mut logical = Vec::with_capacity(MAX_AUTHED_STREAM_BYTES);
    for _ in 0..MAX_AUTHED_STREAM_RECORDS {
        let remaining_budget = MAX_AUTHED_STREAM_BYTES - wire_prefix.len();
        if remaining_budget < 5 {
            // A partial next header cannot prove overflow by itself.  Read the
            // first byte beyond the cap before deciding; EOF exactly at the
            // cap remains the historical I/O boundary.
            let needed = remaining_budget + 1;
            let mut probe = [0u8; 5];
            let mut pos = 0;
            while pos < needed {
                match inner.read(&mut probe[pos..needed]).await {
                    Ok(0) => {
                        return Err(TransportError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "early eof",
                        )));
                    }
                    Ok(n) => {
                        pos += n;
                        if wire_prefix.len() + pos > MAX_AUTHED_STREAM_BYTES {
                            return Err(TransportError::ResourceLimit(
                                "REALITY ClientHello pre-read exceeds 64 KiB".into(),
                            ));
                        }
                    }
                    Err(e) => return Err(TransportError::Io(e)),
                }
            }
        }
        let mut header = [0u8; 5];
        if let Err(e) = inner.read_exact(&mut header).await {
            return Err(TransportError::Io(e));
        }
        wire_prefix.extend_from_slice(&header);
        let record_version = u16::from_be_bytes([header[1], header[2]]);
        if header[0] != TLS_RECORD_HANDSHAKE || record_version >= 0x1000 {
            return Ok((inner, Preflight::Cover(wire_prefix)));
        }
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len > MAX_PLAINTEXT_RECORD || len == 0 {
            return Err(TransportError::ResourceLimit(
                "REALITY ClientHello pre-read record length out of range".into(),
            ));
        }
        if wire_prefix.len() + len > MAX_AUTHED_STREAM_BYTES {
            return Err(TransportError::ResourceLimit(
                "REALITY ClientHello pre-read exceeds 64 KiB".into(),
            ));
        }
        let body_start = wire_prefix.len();
        wire_prefix.resize(body_start + len, 0);
        if let Err(e) = inner
            .read_exact(&mut wire_prefix[body_start..body_start + len])
            .await
        {
            return Err(TransportError::Io(e));
        }
        logical.extend_from_slice(&wire_prefix[body_start..body_start + len]);
        if logical.len() >= 4 {
            if logical[0] != HS_CLIENT_HELLO {
                return Ok((inner, Preflight::Cover(wire_prefix)));
            }
            let message_len = read_u24(&logical[1..4]);
            let total = 4usize.saturating_add(message_len);
            if total > MAX_AUTHED_STREAM_BYTES {
                return Err(TransportError::ResourceLimit(
                    "REALITY ClientHello exceeds 64 KiB".into(),
                ));
            }
            if logical.len() == total {
                let raw = std::mem::take(&mut logical);
                return match parse_client_hello(raw) {
                    Ok(hello) => Ok((
                        inner,
                        Preflight::Candidate {
                            hello: Box::new(hello),
                            wire_prefix,
                        },
                    )),
                    Err(_) => Ok((inner, Preflight::Cover(wire_prefix))),
                };
            }
            if logical.len() > total {
                return Ok((inner, Preflight::Cover(wire_prefix)));
            }
        }
    }
    Err(TransportError::ResourceLimit(
        "REALITY ClientHello pre-read exceeded 32 records".into(),
    ))
}

pub(crate) struct ClientHello {
    pub(crate) raw: Vec<u8>,
    pub(crate) random: [u8; 32],
    pub(crate) session_id: [u8; 32],
    pub(crate) server_name: Option<FixedServerName>,
    pub(crate) cipher_suites: OfferedCipherSuites,
    pub(crate) supported_groups: SupportedGroups,
    pub(crate) key_shares: ClientKeyShares,
    pub(crate) offers_tls13: bool,
    pub(crate) reality_session_id_layout: bool,
    pub(crate) duplicate_extension: bool,
    pub(crate) sni_malformed: bool,
    pub(crate) key_share_malformed: bool,
    pub(crate) has_pre_shared_key: bool,
    pub(crate) has_early_data: bool,
    pub(crate) record_size_limit: Option<u16>,
    pub(crate) record_size_limit_malformed: bool,
    #[cfg(test)]
    pub(crate) parse_explicit_arena_bytes: usize,
}

impl ClientHello {
    fn auth_share(&self) -> Option<[u8; 32]> {
        if let Some(bytes) = self.key_shares.x25519.bytes() {
            return Some(*bytes);
        }
        let hybrid = self.key_shares.hybrid.bytes()?;
        Some(
            hybrid[HYBRID_SHARE_LEN - 32..]
                .try_into()
                .expect("32-byte suffix"),
        )
    }
}

#[cfg(test)]
impl ClientHello {
    pub(crate) fn test_empty() -> Self {
        Self {
            raw: Vec::new(),
            random: [0; 32],
            session_id: [0; 32],
            server_name: None,
            cipher_suites: OfferedCipherSuites::default(),
            supported_groups: SupportedGroups::default(),
            key_shares: ClientKeyShares::default(),
            offers_tls13: true,
            reality_session_id_layout: true,
            duplicate_extension: false,
            sni_malformed: false,
            key_share_malformed: false,
            has_pre_shared_key: false,
            has_early_data: false,
            record_size_limit: None,
            record_size_limit_malformed: false,
            parse_explicit_arena_bytes: 0,
        }
    }
}

fn parse_client_hello(raw: Vec<u8>) -> Result<ClientHello> {
    if raw.len() < 4 + 2 + 32 || raw[0] != HS_CLIENT_HELLO || read_u24(&raw[1..4]) + 4 != raw.len()
    {
        return Err(TransportError::Tls("malformed REALITY ClientHello".into()));
    }
    if raw.len() < 77 || raw[38] != 0x20 {
        return Err(TransportError::Tls("malformed REALITY session id".into()));
    }
    let mut pos = 4;
    if take(&raw, &mut pos, 2)? != [0x03, 0x03] {
        return Err(TransportError::Tls(
            "REALITY ClientHello legacy version".into(),
        ));
    }
    let random: [u8; 32] = take(&raw, &mut pos, 32)?.try_into().expect("32 bytes");
    let sid_len = take_u8(&raw, &mut pos)? as usize;
    let session_id: [u8; 32] = take(&raw, &mut pos, sid_len)?
        .try_into()
        .map_err(|_| TransportError::Tls("malformed REALITY session id".into()))?;
    let suites_len = take_u16(&raw, &mut pos)? as usize;
    if !suites_len.is_multiple_of(2) {
        return Err(TransportError::Tls("malformed cipher suites".into()));
    }
    let suites_bytes = take(&raw, &mut pos, suites_len)?;
    let mut cipher_suites = OfferedCipherSuites::default();
    for suite in suites_bytes.as_chunks::<2>().0 {
        cipher_suites.insert(u16::from_be_bytes(*suite));
    }
    let compression_len = take_u8(&raw, &mut pos)? as usize;
    let compression = take(&raw, &mut pos, compression_len)?;
    if compression != [0] {
        return Err(TransportError::Tls(
            "REALITY ClientHello compression methods are not exactly [0]".into(),
        ));
    }
    let extensions_len = take_u16(&raw, &mut pos)? as usize;
    let extensions = take(&raw, &mut pos, extensions_len)?;
    if pos != raw.len() {
        return Err(TransportError::Tls(
            "REALITY ClientHello trailing bytes".into(),
        ));
    }

    let mut server_name = None;
    let mut saw_host_name = false;
    let mut supported_groups = SupportedGroups::default();
    let mut key_shares = ClientKeyShares::default();
    let mut offers_tls13 = false;
    let mut duplicate_extension = false;
    let mut sni_malformed = false;
    let mut key_share_malformed = false;
    let mut has_pre_shared_key = false;
    let mut has_early_data = false;
    let mut record_size_limit = None;
    let mut record_size_limit_malformed = false;
    let mut key_share_data = None;

    let mut ep = 0;
    let mut dedup = DedupBitset::new();
    while ep < extensions.len() {
        let ext_type = take_u16(extensions, &mut ep)?;
        let ext_len = take_u16(extensions, &mut ep)? as usize;
        let data = take(extensions, &mut ep, ext_len)?;
        if dedup.insert(ext_type) {
            duplicate_extension = true;
        }
        match ext_type {
            EXT_SERVER_NAME => parse_server_name(
                data,
                &mut server_name,
                &mut saw_host_name,
                &mut sni_malformed,
            ),
            EXT_PRE_SHARED_KEY => has_pre_shared_key = true,
            EXT_EARLY_DATA => has_early_data = true,
            EXT_RECORD_SIZE_LIMIT => {
                if data.len() == 2 {
                    record_size_limit = Some(u16::from_be_bytes([data[0], data[1]]));
                } else {
                    record_size_limit_malformed = true;
                }
            }
            EXT_SUPPORTED_VERSIONS => {
                if data.is_empty()
                    || data[0] as usize + 1 != data.len()
                    || !data[0].is_multiple_of(2)
                {
                    return Err(TransportError::Tls("malformed supported_versions".into()));
                }
                offers_tls13 = data[1..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .any(|b| u16::from_be_bytes(*b) == TLS13_VERSION);
            }
            EXT_SUPPORTED_GROUPS => {
                if data.len() < 2 {
                    return Err(TransportError::Tls("malformed supported_groups".into()));
                }
                let len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if len + 2 != data.len() || !len.is_multiple_of(2) {
                    return Err(TransportError::Tls("malformed supported_groups".into()));
                }
                if len != 0 {
                    supported_groups.mark_nonempty();
                }
                for group in data[2..].as_chunks::<2>().0 {
                    supported_groups.insert(u16::from_be_bytes(*group));
                }
            }
            EXT_KEY_SHARE => key_share_data = Some(data),
            _ => {}
        }
    }
    if ep != extensions.len() {
        return Err(TransportError::Tls(
            "REALITY extension block truncated".into(),
        ));
    }

    // The same 8 KiB bitmap is reused for key-share group uniqueness.  Only
    // the two protocol groups are copied, and only when their length is exact.
    dedup.clear();
    if let Some(data) = key_share_data {
        parse_key_share(data, &mut key_shares, &mut key_share_malformed, &mut dedup);
    }
    #[cfg(test)]
    let parse_explicit_arena_bytes =
        raw.capacity() + std::mem::size_of::<DedupBitset>() + 5 + key_shares.retained_capacity();

    Ok(ClientHello {
        raw,
        random,
        session_id,
        server_name,
        cipher_suites,
        supported_groups,
        key_shares,
        offers_tls13,
        reality_session_id_layout: sid_len == 32,
        duplicate_extension,
        sni_malformed,
        key_share_malformed,
        has_pre_shared_key,
        has_early_data,
        record_size_limit,
        record_size_limit_malformed,
        #[cfg(test)]
        parse_explicit_arena_bytes,
    })
}

fn parse_server_name(
    data: &[u8],
    server_name: &mut Option<FixedServerName>,
    saw_host_name: &mut bool,
    malformed: &mut bool,
) {
    let mut pos = 0;
    let Ok(list_len) = take_u16(data, &mut pos) else {
        *malformed = true;
        return;
    };
    let Ok(list) = take(data, &mut pos, list_len as usize) else {
        *malformed = true;
        return;
    };
    if pos != data.len() || list.len() < 3 {
        *malformed = true;
        return;
    }
    let mut lp = 0;
    while lp < list.len() {
        let Ok(kind) = take_u8(list, &mut lp) else {
            *malformed = true;
            return;
        };
        let Ok(len) = take_u16(list, &mut lp) else {
            *malformed = true;
            return;
        };
        let Ok(name) = take(list, &mut lp, len as usize) else {
            *malformed = true;
            return;
        };
        if kind != 0 || name.is_empty() {
            *malformed = true;
            return;
        }
        let Ok(name) = std::str::from_utf8(name) else {
            *malformed = true;
            return;
        };
        if *saw_host_name {
            *malformed = true;
            return;
        }
        *saw_host_name = true;
        *server_name = FixedServerName::from_wire(name);
    }
    if lp != list.len() {
        *malformed = true;
    }
}

fn parse_key_share(
    data: &[u8],
    shares: &mut ClientKeyShares,
    malformed: &mut bool,
    seen: &mut DedupBitset,
) {
    let mut pos = 0;
    let Ok(list_len) = take_u16(data, &mut pos) else {
        *malformed = true;
        return;
    };
    let Ok(list) = take(data, &mut pos, list_len as usize) else {
        *malformed = true;
        return;
    };
    if pos != data.len() {
        *malformed = true;
        return;
    }
    let mut lp = 0;
    while lp < list.len() {
        let Ok(group) = take_u16(list, &mut lp) else {
            *malformed = true;
            return;
        };
        let Ok(len) = take_u16(list, &mut lp) else {
            *malformed = true;
            return;
        };
        let Ok(bytes) = take(list, &mut lp, len as usize) else {
            *malformed = true;
            return;
        };
        if seen.insert(group) {
            *malformed = true;
        } else {
            shares.insert(group, bytes);
        }
    }
    if lp != list.len() {
        *malformed = true;
    }
}

fn select_cipher(offered: &OfferedCipherSuites) -> Option<CipherSuite> {
    for suite in [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ] {
        if offered.contains(suite) {
            return CipherSuite::try_from(suite).ok();
        }
    }
    None
}

struct PreparedHandshake {
    raw_hello: Vec<u8>,
    session_id: Vec<u8>,
    cipher: CipherSuite,
    key_share: ChosenKeyShare,
    auth_key: Zeroizing<[u8; 32]>,
}

pub(crate) struct ChosenKeyShare {
    pub(crate) group: u16,
    pub(crate) client_share: Vec<u8>,
}

pub(crate) fn x25519_public_key_usable(bytes: &[u8]) -> bool {
    let Ok(public) = <[u8; 32]>::try_from(bytes) else {
        return false;
    };
    // Already-clamped form of scalar 9.  A fixed nonzero scalar is enough
    // for contributory validation: low-order inputs are precisely the ones
    // whose X25519 result is zero and therefore unusable for the handshake.
    let mut probe_private = [0u8; 32];
    probe_private[0] = 8;
    probe_private[31] = 64;
    x25519(&probe_private, &public).is_ok()
}

pub(crate) fn hybrid_key_share_usable(bytes: &[u8]) -> bool {
    if bytes.len() != HYBRID_SHARE_LEN {
        return false;
    }
    let (mlkem_public, x25519_public) = bytes.split_at(HYBRID_SHARE_LEN - 32);
    MlKemPublicKey::from_slice(MlKemAlgorithm::MlKem768, mlkem_public).is_ok()
        && x25519_public_key_usable(x25519_public)
}

fn select_key_group(hello: &ClientHello) -> Option<u16> {
    if hello.supported_groups.allows_v1(GROUP_X25519_MLKEM768) {
        if let Some(bytes) = hello.key_shares.bytes(GROUP_X25519_MLKEM768) {
            if hybrid_key_share_usable(bytes) {
                return Some(GROUP_X25519_MLKEM768);
            }
        }
    }
    if hello.supported_groups.allows_v1(GROUP_X25519) {
        if let Some(bytes) = hello.key_shares.bytes(GROUP_X25519) {
            if x25519_public_key_usable(bytes) {
                return Some(GROUP_X25519);
            }
        }
    }
    None
}

fn chosen_key_share_for(hello: &ClientHello, group: u16) -> Option<ChosenKeyShare> {
    Some(ChosenKeyShare {
        group,
        client_share: hello.key_shares.bytes(group)?.to_vec(),
    })
}

pub(crate) fn encapsulate_server_share_bytes(
    group: u16,
    client_share: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let mut x_private = Zeroizing::new(rand::random::<[u8; 32]>());
    crate::reality_tls::clamp_x25519_private(&mut x_private);
    let x_public = x25519_public_from_private(&x_private);
    if group == GROUP_X25519 {
        let client: [u8; 32] = client_share
            .try_into()
            .map_err(|_| TransportError::Tls("REALITY X25519 key share length".into()))?;
        return Ok((
            x_public.to_vec(),
            Zeroizing::new(x25519(&x_private, &client)?.to_vec()),
        ));
    }
    if group != GROUP_X25519_MLKEM768 || client_share.len() != HYBRID_SHARE_LEN {
        return Err(TransportError::Tls("unsupported REALITY key share".into()));
    }
    let mlkem_public_bytes = &client_share[..HYBRID_SHARE_LEN - 32];
    let client_x: [u8; 32] = client_share[HYBRID_SHARE_LEN - 32..]
        .try_into()
        .expect("32-byte suffix");
    let mlkem_public = MlKemPublicKey::from_slice(MlKemAlgorithm::MlKem768, mlkem_public_bytes)
        .map_err(|e| TransportError::Crypto(format!("REALITY ML-KEM client share: {e}")))?;
    let (ciphertext, mlkem_secret) = mlkem_public
        .encapsulate()
        .map_err(|e| TransportError::Crypto(format!("REALITY ML-KEM encapsulation: {e}")))?;
    let mlkem_secret = Zeroizing::new(mlkem_secret);
    if ciphertext.len() != 1088 {
        return Err(TransportError::Crypto(
            "REALITY ML-KEM ciphertext length".into(),
        ));
    }
    let x_secret = x25519(&x_private, &client_x)?;
    let mut server_share = ciphertext;
    server_share.reserve_exact(32);
    server_share.extend_from_slice(&x_public);
    let mut shared = Zeroizing::new(Vec::with_capacity(64));
    shared.extend_from_slice(&mlkem_secret[..]);
    shared.extend_from_slice(&x_secret[..]);
    Ok((server_share, shared))
}

pub(crate) fn encapsulate_server_share(
    chosen: &ChosenKeyShare,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    encapsulate_server_share_bytes(chosen.group, &chosen.client_share)
}

fn build_server_hello(
    session_id: &[u8],
    cipher: CipherSuite,
    group: &u16,
    share: &[u8],
) -> Vec<u8> {
    let random = rand::random::<[u8; 32]>();
    let cipher_value = match cipher {
        CipherSuite::Aes128GcmSha256 => TLS_AES_128_GCM_SHA256,
        CipherSuite::Aes256GcmSha384 => TLS_AES_256_GCM_SHA384,
        CipherSuite::ChaCha20Poly1305Sha256 => TLS_CHACHA20_POLY1305_SHA256,
    };

    let mut supported_versions_ext = Vec::new();
    put_u16(TLS13_VERSION, &mut supported_versions_ext);
    let mut key_share_ext = Vec::new();
    put_u16(*group, &mut key_share_ext);
    put_u16(share.len() as u16, &mut key_share_ext);
    key_share_ext.extend_from_slice(share);

    let mut extensions = Vec::new();
    put_u16(EXT_SUPPORTED_VERSIONS, &mut extensions);
    put_u16(supported_versions_ext.len() as u16, &mut extensions);
    extensions.extend_from_slice(&supported_versions_ext);
    put_u16(EXT_KEY_SHARE, &mut extensions);
    put_u16(key_share_ext.len() as u16, &mut extensions);
    extensions.extend_from_slice(&key_share_ext);

    let mut body = Vec::with_capacity(2 + 32 + 1 + session_id.len() + 2 + 1 + 2 + extensions.len());
    put_u16(0x0303, &mut body);
    body.extend_from_slice(&random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    put_u16(cipher_value, &mut body);
    body.push(0);
    put_u16(extensions.len() as u16, &mut body);
    body.extend_from_slice(&extensions);
    handshake_message(HS_SERVER_HELLO, &body)
}

pub(crate) fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(kind);
    put_u24(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

pub(crate) fn certificate_message(certificate_der: &[u8]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(3 + certificate_der.len() + 2);
    put_u24(certificate_der.len(), &mut entry);
    entry.extend_from_slice(certificate_der);
    put_u16(0, &mut entry);
    let mut list = Vec::with_capacity(3 + entry.len());
    put_u24(entry.len(), &mut list);
    list.extend_from_slice(&entry);
    let mut body = Vec::with_capacity(1 + list.len());
    body.push(0);
    body.extend_from_slice(&list);
    handshake_message(HS_CERTIFICATE, &body)
}

async fn read_client_finished(
    inner: &mut Box<dyn Stream>,
    hs: &mut HandshakeKeys,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut handshake_bytes = Zeroizing::new(Vec::new());
    for _ in 0..MAX_AUTHED_STREAM_RECORDS {
        let Some(record) = read_record(inner).await? else {
            return Err(TransportError::Tls(
                "EOF before REALITY client Finished".into(),
            ));
        };
        if record.typ == TLS_RECORD_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record.typ != TLS_RECORD_APPLICATION_DATA {
            return Err(TransportError::Tls(format!(
                "REALITY client Finished record type {}",
                record.typ
            )));
        }
        let mut payload = record.payload;
        let (inner_type, len) = hs.client.open_in_place(&record.header, &mut payload)?;
        payload.truncate(len);
        if inner_type != TLS_RECORD_HANDSHAKE {
            return Err(TransportError::Tls(format!(
                "REALITY pre-Finished inner record type {inner_type}"
            )));
        }
        handshake_bytes.extend_from_slice(&payload);
        if handshake_bytes.len() >= 4 {
            if handshake_bytes[0] != HS_FINISHED {
                return Err(TransportError::Tls(format!(
                    "REALITY expected client Finished, got handshake {}",
                    handshake_bytes[0]
                )));
            }
            let total = 4 + read_u24(&handshake_bytes[1..4]);
            if total > MAX_AUTHED_STREAM_BYTES {
                return Err(TransportError::ResourceLimit(
                    "REALITY client Finished exceeds 64 KiB".into(),
                ));
            }
            if handshake_bytes.len() > total {
                return Err(TransportError::Tls(
                    "REALITY unexpected bytes after client Finished".into(),
                ));
            }
            if handshake_bytes.len() == total {
                return Ok(Zeroizing::new(handshake_bytes[4..].to_vec()));
            }
        }
    }
    Err(TransportError::ResourceLimit(
        "REALITY client Finished exceeded record limit".into(),
    ))
}

/// REALITY session-id open result: the derived AuthKey and the sealed
/// 16-byte plaintext, both caller-owned secrets kept in erasing wrappers.
struct OpenedAuth(Zeroizing<[u8; 32]>, Zeroizing<Vec<u8>>);

fn aes_gcm_open(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    if key.len() != 32 || nonce.len() != 12 || ciphertext.len() != 16 || tag.len() != 16 {
        return None;
    }
    let ctx = boring::aead::AeadCtx::new_default_tag(&boring::aead::Algorithm::aes_256_gcm(), key)
        .ok()?;
    let mut data = Zeroizing::new(ciphertext.to_vec());
    let mut tag_buf = [0u8; 16];
    tag_buf.copy_from_slice(tag);
    let mut nonce_buf = [0u8; 12];
    nonce_buf.copy_from_slice(nonce);
    ctx.open_in_place(&nonce_buf, &mut data, &tag_buf, aad)
        .ok()?;
    Some(data)
}

pub(crate) struct RealityCertificate {
    key: PKey<Private>,
    template_der: Vec<u8>,
}

impl RealityCertificate {
    pub(crate) fn generate() -> Result<Self> {
        let key = PKey::generate(Id::ED25519)
            .map_err(|e| TransportError::Crypto(format!("REALITY Ed25519 identity: {e}")))?;
        Self::from_key(key)
    }

    #[cfg(test)]
    fn from_private_key_der(private_key_der: &[u8]) -> Result<Self> {
        let key = PKey::private_key_from_der(private_key_der)
            .map_err(|e| TransportError::Crypto(format!("REALITY Ed25519 test identity: {e}")))?;
        if key.id() != Id::ED25519 {
            return Err(TransportError::Crypto(
                "REALITY test identity is not Ed25519".into(),
            ));
        }
        Self::from_key(key)
    }

    fn from_key(key: PKey<Private>) -> Result<Self> {
        let mut public_key = [0u8; 32];
        let key_len = key
            .raw_public_key(&mut public_key)
            .map_err(|e| TransportError::Crypto(format!("REALITY Ed25519 public key: {e}")))?
            .len();
        if key_len != 32 {
            return Err(TransportError::Crypto(
                "REALITY Ed25519 public key length".into(),
            ));
        }
        let template_der = build_certificate_template(&public_key);
        Ok(Self { key, template_der })
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut signer = Signer::new_without_digest(&self.key).map_err(|e| {
            TransportError::Crypto(format!("REALITY CertificateVerify signer: {e}"))
        })?;
        signer
            .sign_oneshot_to_vec(message)
            .map_err(|e| TransportError::Crypto(format!("REALITY CertificateVerify sign: {e}")))
    }

    pub(crate) fn der_len(&self) -> usize {
        self.template_der.len()
    }

    pub(crate) fn for_auth_key(&self, auth_key: &[u8; 32]) -> Vec<u8> {
        let mut der = self.template_der.clone();
        let signature_start = der.len() - 64;
        let mut mac =
            <HmacSha512 as Mac>::new_from_slice(auth_key).expect("HMAC accepts any key length");
        let mut public_key = [0u8; 32];
        let public_key = self
            .key
            .raw_public_key(&mut public_key)
            .expect("Ed25519 public key");
        mac.update(public_key);
        let signature = mac.finalize().into_bytes();
        der[signature_start..].copy_from_slice(&signature);
        der
    }
}

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        put_u16(len as u16, out);
    }
}

fn der_wrap(tag: u8, body: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    der_len(body.len(), out);
    out.extend_from_slice(body);
}

fn build_certificate_template(public_key: &[u8; 32]) -> Vec<u8> {
    let serial = [0x02, 0x01, 0x01];
    let mut algorithm = Vec::new();
    algorithm.extend_from_slice(ED25519_OID);
    let mut algorithm_seq = Vec::new();
    der_wrap(0x30, &algorithm, &mut algorithm_seq);

    let mut issuer = Vec::new();
    der_wrap(0x30, &[], &mut issuer);

    let mut validity_inner = Vec::new();
    der_wrap(0x17, b"250101000000Z", &mut validity_inner);
    der_wrap(0x17, b"490101000000Z", &mut validity_inner);
    let mut validity = Vec::new();
    der_wrap(0x30, &validity_inner, &mut validity);

    let mut spki_alg = Vec::new();
    spki_alg.extend_from_slice(ED25519_OID);
    let mut spki_alg_seq = Vec::new();
    der_wrap(0x30, &spki_alg, &mut spki_alg_seq);
    let mut bitstring_body = vec![0];
    bitstring_body.extend_from_slice(public_key);
    let mut bitstring = Vec::new();
    der_wrap(0x03, &bitstring_body, &mut bitstring);
    let mut spki_inner = Vec::new();
    spki_inner.extend_from_slice(&spki_alg_seq);
    spki_inner.extend_from_slice(&bitstring);
    let mut spki = Vec::new();
    der_wrap(0x30, &spki_inner, &mut spki);

    let mut version_explicit_inner = Vec::new();
    der_wrap(0x02, &[2], &mut version_explicit_inner);
    let mut version_explicit = Vec::new();
    der_wrap(0xa0, &version_explicit_inner, &mut version_explicit);

    let mut tbs_inner = Vec::new();
    tbs_inner.extend_from_slice(&version_explicit);
    tbs_inner.extend_from_slice(&serial);
    tbs_inner.extend_from_slice(&algorithm_seq);
    tbs_inner.extend_from_slice(&issuer);
    tbs_inner.extend_from_slice(&validity);
    tbs_inner.extend_from_slice(&issuer);
    tbs_inner.extend_from_slice(&spki);
    let mut tbs = Vec::new();
    der_wrap(0x30, &tbs_inner, &mut tbs);

    let mut sig_bits_body = vec![0];
    sig_bits_body.extend_from_slice(&[0u8; 64]);
    let mut sig_bits = Vec::new();
    der_wrap(0x03, &sig_bits_body, &mut sig_bits);

    let mut cert_inner = Vec::new();
    cert_inner.extend_from_slice(&tbs);
    cert_inner.extend_from_slice(&algorithm_seq);
    cert_inner.extend_from_slice(&sig_bits);
    let mut cert = Vec::new();
    der_wrap(0x30, &cert_inner, &mut cert);
    cert
}

/// Directional cover bandwidth policy.  Rates are bytes/second after the
/// configured exemption; zero disables bandwidth shaping for that direction.
#[derive(Debug, Clone, Copy, Default)]
pub struct CoverBandwidthLimit {
    pub upload_bytes_per_second: u64,
    pub upload_exempt_bytes: u64,
    pub download_bytes_per_second: u64,
    pub download_exempt_bytes: u64,
    pub burst_bytes: u64,
}

/// Directional byte state for a cover relay over an already-connected target.
///
/// `upload` and `download` are exact byte prefixes that must be written once
/// before their direction's later socket bytes.  `uploaded` counts bytes the
/// caller already wrote to the target before relay ownership began; those
/// bytes consume the upload rate-limit exemption but are never replayed.
/// `download_eof` preserves a target EOF observed during probing: the relay
/// still writes the complete download prefix, then half-closes the client
/// write side without waiting for another target read.
#[derive(Default)]
pub struct CoverRelayPrefixes {
    pub upload: Vec<u8>,
    pub download: Vec<u8>,
    pub uploaded: u64,
    pub download_eof: bool,
}

impl fmt::Debug for CoverRelayPrefixes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoverRelayPrefixes")
            .field("upload_len", &self.upload.len())
            .field("download_len", &self.download.len())
            .field("uploaded", &self.uploaded)
            .field("download_eof", &self.download_eof)
            .finish()
    }
}

/// Run the shared shaped cover relay over an already-connected target with
/// explicit directional prefixes.  This is the same relay engine used by the
/// v1 [`CoverRelay`] path: 16 KiB direction buffers, independent half-close,
/// the 60-second idle watchdog and the 600-second lifetime cap.
pub async fn relay_cover_with_prefixes(
    client: Box<dyn Stream>,
    target: Box<dyn Stream>,
    prefixes: CoverRelayPrefixes,
    limit: CoverBandwidthLimit,
) -> Result<()> {
    let (client_read, client_write) = tokio::io::split(client);
    let (target_read, target_write) = tokio::io::split(target);
    let (activity_tx, activity_rx) = tokio::sync::watch::channel(());
    let upload_limit = DirectionalLimit::with_transferred(
        limit.upload_bytes_per_second,
        limit.upload_exempt_bytes,
        limit.burst_bytes,
        prefixes.uploaded,
    );
    let download_limit = DirectionalLimit::new(
        limit.download_bytes_per_second,
        limit.download_exempt_bytes,
        limit.burst_bytes,
    );
    let upload = relay_direction(
        client_read,
        target_write,
        prefixes.upload,
        upload_limit,
        activity_tx.clone(),
    );
    let download = relay_download_direction(
        target_read,
        client_write,
        prefixes.download,
        download_limit,
        activity_tx,
        prefixes.download_eof,
    );
    let watchdog = idle_watchdog(activity_rx);
    let main = drive_cover(upload, download, watchdog);
    tokio::time::timeout(COVER_MAX_LIFETIME, main)
        .await
        .map_err(|_| TransportError::Timeout("REALITY cover relay lifetime exceeded".into()))?
}

/// A cover connection with the ClientHello bytes already consumed from the
/// client.  Those bytes must reach the target unchanged before any relay.
pub struct CoverRelay {
    client: Box<dyn Stream>,
    wire_prefix: Vec<u8>,
}

impl fmt::Debug for CoverRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoverRelay")
            .field("wire_prefix_len", &self.wire_prefix.len())
            .finish_non_exhaustive()
    }
}

impl CoverRelay {
    fn new(client: Box<dyn Stream>, wire_prefix: Vec<u8>) -> Self {
        Self {
            client,
            wire_prefix,
        }
    }

    pub fn wire_prefix_len(&self) -> usize {
        self.wire_prefix.len()
    }

    pub fn into_parts(self) -> (Box<dyn Stream>, Vec<u8>) {
        (self.client, self.wire_prefix)
    }

    pub async fn relay(self, target: Box<dyn Stream>) -> Result<()> {
        self.relay_with_limit(target, CoverBandwidthLimit::default())
            .await
    }

    pub async fn relay_with_limit(
        self,
        target: Box<dyn Stream>,
        limit: CoverBandwidthLimit,
    ) -> Result<()> {
        let (client, prefix) = self.into_parts();
        relay_cover_with_prefixes(
            client,
            target,
            CoverRelayPrefixes {
                upload: prefix,
                ..CoverRelayPrefixes::default()
            },
            limit,
        )
        .await
    }
}

async fn drive_cover<U, D, W>(upload: U, download: D, watchdog: W) -> Result<()>
where
    U: std::future::Future<Output = Result<()>>,
    D: std::future::Future<Output = Result<()>>,
    W: std::future::Future<Output = Result<()>>,
{
    tokio::pin!(upload, download, watchdog);
    let mut upload_done = false;
    let mut download_done = false;
    loop {
        if upload_done && download_done {
            return Ok(());
        }
        tokio::select! {
            r = &mut upload, if !upload_done => {
                r?;
                upload_done = true;
            }
            r = &mut download, if !download_done => {
                r?;
                download_done = true;
            }
            r = &mut watchdog => {
                return r;
            }
        }
    }
}

async fn idle_watchdog(mut rx: tokio::sync::watch::Receiver<()>) -> Result<()> {
    loop {
        if tokio::time::timeout(COVER_IDLE_TIMEOUT, rx.changed())
            .await
            .is_err()
        {
            return Err(TransportError::Timeout(
                "REALITY cover relay idle timeout".into(),
            ));
        }
    }
}

struct DirectionalLimit {
    bytes_per_second: u64,
    exempt_bytes: u64,
    capacity: u64,
    tokens: u64,
    transferred: u64,
    refill_at: Instant,
}

impl DirectionalLimit {
    fn new(bytes_per_second: u64, exempt_bytes: u64, burst_bytes: u64) -> Self {
        Self::with_transferred(bytes_per_second, exempt_bytes, burst_bytes, 0)
    }

    fn with_transferred(
        bytes_per_second: u64,
        exempt_bytes: u64,
        burst_bytes: u64,
        transferred: u64,
    ) -> Self {
        let capacity = if bytes_per_second == 0 {
            0
        } else {
            burst_bytes.max(bytes_per_second).max(1)
        };
        Self {
            bytes_per_second,
            exempt_bytes,
            capacity,
            tokens: capacity,
            transferred,
            refill_at: Instant::now(),
        }
    }

    async fn wait_for_allowance(&mut self, bytes: usize) -> usize {
        if self.bytes_per_second == 0 {
            return bytes;
        }
        let mut remaining = bytes as u64;
        let mut granted = 0u64;
        if self.transferred < self.exempt_bytes {
            let exempt = remaining.min(self.exempt_bytes - self.transferred);
            self.transferred += exempt;
            remaining -= exempt;
            granted += exempt;
        }
        if remaining == 0 {
            return granted as usize;
        }
        loop {
            self.refill();
            if self.tokens > 0 {
                let limited = remaining.min(self.tokens);
                self.tokens -= limited;
                self.transferred = self.transferred.saturating_add(limited);
                granted += limited;
                return granted as usize;
            }
            if granted > 0 {
                return granted as usize;
            }
            let nanos_per_byte = 1_000_000_000u64.div_ceil(self.bytes_per_second.max(1));
            tokio::time::sleep(Duration::from_nanos(nanos_per_byte).max(COVER_LIMITER_GRANULARITY))
                .await;
        }
    }

    fn refill(&mut self) {
        const NANOS_PER_SECOND: u128 = 1_000_000_000;
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.refill_at);
        if elapsed.is_zero() {
            return;
        }
        if self.tokens >= self.capacity {
            // While the bucket is full every further token is discarded,
            // so the uncredited time is semantically a no-op; pinning the
            // baseline keeps it from going stale over a long idle.
            self.refill_at = now;
            return;
        }
        // Nanoseconds times a byte rate overflows u64 within minutes at
        // high rates, and even the u128 product can saturate for absurd
        // idle×rate combinations.  The credit is only ever meaningful up
        // to the room left in the bucket, so clamping the u128 value
        // before the u64 conversion — instead of truncating it with
        // `as` — loses nothing (issue #974).
        let earned = elapsed
            .as_nanos()
            .saturating_mul(u128::from(self.bytes_per_second))
            / NANOS_PER_SECOND;
        if earned == 0 {
            if elapsed.as_secs() >= 1 {
                self.refill_at = now;
            }
            return;
        }
        let room = u128::from(self.capacity - self.tokens);
        if earned >= room {
            // Tokens beyond the bucket's room are discarded, together with
            // the time that produced them; keeping that time as credit would
            // let one idle period fund several consecutive bursts.
            self.tokens = self.capacity;
            self.refill_at = now;
            return;
        }
        // Advance the baseline by the exact time the credited tokens take
        // to accrue, preserving the sub-token remainder.  The saturating
        // conversion only triggers on multi-century idles, where pinning to
        // any reachable instant is equivalent.
        let spent_nanos = earned * NANOS_PER_SECOND / u128::from(self.bytes_per_second);
        self.refill_at += Duration::from_nanos(u64::try_from(spent_nanos).unwrap_or(u64::MAX));
        // `earned < room` came from a u64 difference, so the conversion is
        // lossless and the sum never exceeds `capacity`.
        self.tokens += earned as u64;
    }
}

async fn write_shaped<W>(
    writer: &mut W,
    bytes: &[u8],
    limit: &mut DirectionalLimit,
    activity: &tokio::sync::watch::Sender<()>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut pos = 0;
    while pos < bytes.len() {
        let allowed = limit.wait_for_allowance(bytes.len() - pos).await;
        debug_assert!(allowed > 0, "a non-empty shaped write must make progress");
        let end = pos + allowed;
        while pos < end {
            let n = writer.write(&bytes[pos..end]).await?;
            if n == 0 {
                return Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "REALITY cover relay zero write",
                )));
            }
            pos += n;
            // Idle means no bytes are crossing the relay.  Refresh on every
            // accepted partial write, not only after a whole throttled segment
            // survives kernel backpressure.
            let _ = activity.send(());
        }
        writer.flush().await?;
    }
    Ok(())
}

async fn relay_download_direction<R, W>(
    reader: R,
    mut writer: W,
    initial: Vec<u8>,
    mut limit: DirectionalLimit,
    activity: tokio::sync::watch::Sender<()>,
    eof: bool,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if eof {
        drop(reader);
        if !initial.is_empty() {
            write_shaped(&mut writer, &initial, &mut limit, &activity).await?;
        }
        drop(initial);
        writer.shutdown().await?;
        return Ok(());
    }
    relay_direction(reader, writer, initial, limit, activity).await
}

async fn relay_direction<R, W>(
    mut reader: R,
    mut writer: W,
    initial: Vec<u8>,
    mut limit: DirectionalLimit,
    activity: tokio::sync::watch::Sender<()>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if !initial.is_empty() {
        write_shaped(&mut writer, &initial, &mut limit, &activity).await?;
    }
    // The preserved ClientHello can run to 64 KiB; holding it for the relay's
    // lifetime would keep that allocation pinned per cover connection long
    // after its only use.
    drop(initial);
    let mut buf = [0u8; COVER_BUFFER];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        write_shaped(&mut writer, &buf[..n], &mut limit, &activity).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality_tls::wrap_plain_record;
    use crate::reality_tls::{build_reality_client_hello, RealityTlsLayer};
    use crate::tls::TlsConfig;
    use crate::Transport;
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SERVER_NAME: &str = "www.example.com";
    const SHORT_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    /// Compile-time erasure contract: every caller-owned secret buffer keeps
    /// its `Zeroizing` wrapper.  These bindings fail to type-check the moment
    /// a field is unwrapped back to a plain array or Vec, which is the only
    /// meaningful mutation signal available — post-drop heap inspection would
    /// be undefined behavior, and zeroize's own Drop semantics are upstream's
    /// test burden.
    #[test]
    fn secret_buffers_keep_zeroizing_wrappers() {
        use zeroize::Zeroizing;
        let (private, _public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let _: &Zeroizing<[u8; 32]> = &server.inner.private_key;

        let hs = HandshakeKeys::derive(CipherSuite::Aes128GcmSha256, &[0x55; 32], b"transcript");
        let _: &Zeroizing<Vec<u8>> = &hs.client_secret;
        let _: &Zeroizing<Vec<u8>> = &hs.server_secret;
        let _: &Zeroizing<Vec<u8>> = &hs.master_secret;

        let shared =
            x25519(&[0x08; 32], &x25519_public_from_private(&[0x09; 32])).expect("test ECDH");
        let _: &Zeroizing<[u8; 32]> = &shared;

        let hello = verified_hello_for_zeroize_types();
        let _: &Zeroizing<[u8; 32]> = &hello.auth_key;
        let (context, _wire) = hello.into_mirror_upload().finish_upload();
        let _: &Zeroizing<[u8; 32]> = &context.auth_key;
    }

    #[test]
    fn server_config_debug_redacts_admission_policy_names() {
        let (private, _public) = keypair();
        let debug = format!("{:?}", server_config(private));
        assert!(
            !debug.contains(SERVER_NAME),
            "server name leaked into RealityServerConfig Debug: {debug}"
        );
        assert!(
            !debug.contains(&format!("{SHORT_ID:?}")),
            "short-id bytes leaked into RealityServerConfig Debug: {debug}"
        );
    }

    fn verified_hello_for_zeroize_types() -> VerifiedHello {
        VerifiedHello {
            issuer: Arc::new(()),
            hello: ClientHello::test_empty(),
            ch_wire: Vec::new(),
            auth_key: zeroize::Zeroizing::new([0x23; 32]),
            local_cipher: CipherSuite::Aes128GcmSha256,
            local_key_group: GROUP_X25519,
        }
    }

    fn fixed_unix() -> u64 {
        1_700_000_000
    }

    fn fixed_system_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(fixed_unix())
    }

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let mut private = rand::random::<[u8; 32]>();
        crate::reality_tls::clamp_x25519_private(&mut private);
        let public = x25519_public_from_private(&private);
        (private, public)
    }

    fn server_config(private: [u8; 32]) -> RealityServerConfig {
        RealityServerConfig {
            private_key: private,
            short_ids: vec![[0u8; 8], SHORT_ID, [0xff; 8]],
            server_names: HashSet::from([SERVER_NAME.to_string()]),
            max_time_difference: None,
            now: Some(fixed_system_time),
        }
    }

    fn client_config(public: [u8; 32], short_id: [u8; 8], hybrid: bool) -> TlsConfig {
        let mut config = TlsConfig::new(SERVER_NAME);
        config.fingerprint = Some("chrome".into());
        config.reality = Some(crate::tls::RealityConfig {
            public_key: public,
            short_id,
            support_x25519_mlkem768: hybrid,
            protocol_clock: Some(fixed_system_time),
        });
        config
    }

    async fn authenticated_roundtrip(hybrid: bool) {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });

        let layer =
            RealityTlsLayer::new(&client_config(public, SHORT_ID, hybrid)).expect("client layer");
        let mut client = layer
            .connect(Box::new(client_io))
            .await
            .expect("REALITY client handshake must complete");

        let accepted = accept_task.await.expect("accept task").expect("accept");
        let RealityServerAccept::Authenticated(mut server_stream) = accepted else {
            panic!("valid REALITY client must authenticate");
        };

        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0u8; 4];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server_stream.write_all(b"pong").await.unwrap();
        server_stream.flush().await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn authenticates_real_client_x25519_and_round_trips() {
        authenticated_roundtrip(false).await;
    }

    #[tokio::test]
    async fn authenticates_real_client_hybrid_and_round_trips() {
        authenticated_roundtrip(true).await;
    }

    #[tokio::test]
    async fn verified_hello_split_api_preserves_prefix_and_completes_independently() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let verify_task = tokio::spawn({
            let server = server.clone();
            async move { server.verify_client_hello(Box::new(server_io)).await }
        });

        let layer =
            RealityTlsLayer::new(&client_config(public, SHORT_ID, false)).expect("client layer");
        let client_task = tokio::spawn(async move { layer.connect(Box::new(client_io)).await });
        let classified = verify_task
            .await
            .expect("verify task")
            .expect("verify ClientHello");
        let RealityClientHello::Verified { stream, hello } = classified else {
            panic!("valid REALITY client must verify")
        };
        assert!(hello.ch_wire().len() > 5 + 71);
        assert_eq!(hello.ch_wire()[0], TLS_RECORD_HANDSHAKE);
        let server_task =
            tokio::spawn(async move { server.complete_handshake(stream, *hello).await });
        assert!(
            server_task.await.expect("completion task").is_ok(),
            "a statically verified ClientHello completes through the split v1 API"
        );
        assert!(client_task.await.expect("client task").is_ok());
    }

    /// End-to-end mirrored-flight integration with no cryptographic
    /// injection: a real hybrid client hello flows preflight -> verify ->
    /// consuming upload split -> incrementally fragmented target scanner ->
    /// freeze -> production prepare_mirrored_upload.  The emitted flight is
    /// fed to the real client implementation, whose successful handshake is
    /// the independent verification of the patched ServerHello, the real
    /// ML-KEM encapsulation, the certificate chain and the server Finished;
    /// the server-side completion then verifies the client Finished and the
    /// application seq=0 roundtrip runs in both directions.
    #[tokio::test]
    async fn mirrored_real_hybrid_end_to_end_no_injection() {
        use crate::reality_mirror::TargetScanState;

        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let verify_task = tokio::spawn({
            let server = server.clone();
            async move { server.verify_client_hello(Box::new(server_io)).await }
        });
        let layer = RealityTlsLayer::new(&client_config(public, SHORT_ID, true)).expect("layer");
        let client_task = tokio::spawn(async move { layer.connect(Box::new(client_io)).await });

        let classified = tokio::time::timeout(Duration::from_secs(2), verify_task)
            .await
            .expect("verify timed out")
            .expect("verify joined")
            .expect("verify io");
        let RealityClientHello::Verified { mut stream, hello } = classified else {
            panic!("real hybrid client must authenticate")
        };
        let ch_len = hello.ch_wire().len();
        let session_id = hello.hello.session_id;
        let upload = (*hello).into_mirror_upload();
        assert_eq!(
            upload.ch_wire().len(),
            ch_len,
            "upload owns the exact CH wire"
        );

        // Synthetic target flight shape: hybrid key-share group, a suite the
        // client offered, session-id echo, one compat CCS and the acceptance
        // record shape.  Share bytes are filler — prepare patches in the real
        // encapsulation.
        let mut sh_body = Vec::new();
        sh_body.extend_from_slice(&[0x03, 0x03]);
        sh_body.extend_from_slice(&[0x66; 32]);
        sh_body.push(32);
        sh_body.extend_from_slice(&session_id);
        sh_body.extend_from_slice(&0x1301u16.to_be_bytes());
        sh_body.push(0);
        let versions = extension_bytes(0x002b, &0x0304u16.to_be_bytes());
        let mut ks_body = Vec::new();
        ks_body.extend_from_slice(&0x11ecu16.to_be_bytes());
        ks_body.extend_from_slice(&1120u16.to_be_bytes());
        ks_body.resize(ks_body.len() + 1120, 0x5a);
        let key_share = extension_bytes(0x0033, &ks_body);
        let mut exts = Vec::new();
        exts.extend_from_slice(&versions);
        exts.extend_from_slice(&key_share);
        sh_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        sh_body.extend_from_slice(&exts);
        let mut sh = vec![0x02];
        sh.extend_from_slice(&(sh_body.len() as u32).to_be_bytes()[1..4]);
        sh.extend_from_slice(&sh_body);

        let mut flight = Vec::new();
        flight.extend_from_slice(&[0x16, 0x03, 0x03]);
        flight.extend_from_slice(&(sh.len() as u16).to_be_bytes());
        flight.extend_from_slice(&sh);
        flight.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        for len in [25u16, 3217, 281, 69] {
            flight.extend_from_slice(&[0x17, 0x03, 0x03]);
            flight.extend_from_slice(&len.to_be_bytes());
            flight.resize(flight.len() + usize::from(len), 0x5a);
        }

        // Fragmented feeding: 1-byte slices across the SH header, then a
        // slice crossing a record header boundary, then the remainder.
        let mut scanner = server
            .target_flight_scanner(upload.context())
            .expect("wire-authenticated context is mirrorable");
        for byte in &flight[..7] {
            assert_eq!(scanner.push(&[*byte]).unwrap(), TargetScanState::NeedBytes);
        }
        assert_eq!(
            scanner.push(&flight[7..40]).unwrap(),
            TargetScanState::NeedBytes
        );
        let mid = scanner.push(&flight[40..flight.len() - 100]).unwrap();
        assert!(
            matches!(
                mid,
                TargetScanState::NeedBytes | TargetScanState::CapacityTemporarilyInsufficient
            ),
            "mid-flight must not be freezable before record bodies complete: {mid:?}"
        );
        let final_state = scanner.push(&flight[flight.len() - 100..]).unwrap();
        assert_eq!(
            final_state,
            TargetScanState::Freezable,
            "complete acceptance-shape flight must be freezable"
        );

        let template = scanner.freeze().expect("freeze context");
        let (context, upload_wire) = upload.finish_upload();
        assert_eq!(
            upload_wire.len(),
            ch_len,
            "upload wire survives until release"
        );
        drop(upload_wire);
        let prepared = server
            .prepare_mirrored_upload(context, template)
            .expect("no-injection prepare");
        let (wire, completion) = prepared.commit().into_wire_and_completion();

        // The patched flight must carry a real hybrid server share: parse the
        // patched SH out of the emitted wire and check the share length.
        let sh_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
        let patched = &wire[5..5 + sh_len];
        let (group, share_len) = server_hello_key_share(patched);
        assert_eq!(
            group, GROUP_X25519_MLKEM768,
            "patched SH keeps hybrid group"
        );
        assert_eq!(share_len, 1120, "real ML-KEM ciphertext || X25519 share");

        stream
            .write_all(&wire)
            .await
            .expect("write mirrored flight");
        stream.flush().await.expect("flush flight");

        let finish_task = tokio::spawn(async move { completion.finish(stream).await });
        let client_connected = tokio::time::timeout(Duration::from_secs(5), client_task)
            .await
            .expect("client handshake timed out")
            .expect("client joined")
            .expect("real client must accept the no-injection mirrored flight");
        let mut server_stream = tokio::time::timeout(Duration::from_secs(5), finish_task)
            .await
            .expect("finish timed out")
            .expect("finish joined")
            .expect("client Finished must verify under the mirrored transcript");
        let mut client_stream = client_connected;

        client_stream
            .write_all(b"client-to-server seq0")
            .await
            .expect("client write");
        client_stream.flush().await.expect("client flush");
        let mut buf = vec![0u8; b"client-to-server seq0".len()];
        tokio::time::timeout(Duration::from_secs(2), server_stream.read_exact(&mut buf))
            .await
            .expect("server read timed out")
            .expect("server read");
        assert_eq!(buf, b"client-to-server seq0");
        server_stream
            .write_all(b"server-to-client seq0")
            .await
            .expect("server write");
        server_stream.flush().await.expect("server flush");
        let mut buf = vec![0u8; b"server-to-client seq0".len()];
        tokio::time::timeout(Duration::from_secs(2), client_stream.read_exact(&mut buf))
            .await
            .expect("client read timed out")
            .expect("client read");
        assert_eq!(buf, b"server-to-client seq0");
    }

    /// Real public-order probe peak reconciliation.  The CH is authenticated
    /// from real client wire, converted through the consuming upload split,
    /// written to the upload sink, and released before the scanner exists.
    /// The scanner then owns the near-W target prefix through freeze/prepare.
    #[tokio::test]
    async fn probe_prepare_arena_reconciles_with_spec_bprobe_in_real_public_order() {
        use crate::reality_mirror::{
            TargetScanState, TARGET_SCAN_PREFIX_CAPACITY, TARGET_SCAN_WIRE_LIMIT,
        };

        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let verify_task = tokio::spawn({
            let server = server.clone();
            async move { server.verify_client_hello(Box::new(server_io)).await }
        });
        let layer = RealityTlsLayer::new(&client_config(public, SHORT_ID, true)).expect("layer");
        let client_task = tokio::spawn(async move { layer.connect(Box::new(client_io)).await });
        let classified = tokio::time::timeout(Duration::from_secs(2), verify_task)
            .await
            .expect("verify timed out")
            .expect("verify joined")
            .expect("verify io");
        client_task.abort();
        let RealityClientHello::Verified { hello, .. } = classified else {
            panic!("real hybrid client must authenticate")
        };
        let session_id = hello.hello.session_id;
        let upload = (*hello).into_mirror_upload();

        // Upload/write the exact CH wire before target scanning.  The write
        // half owns no persistent copy here; `sink` models bytes leaving the
        // process, and `finish_upload` then releases the upload allocation.
        let mut sink = tokio::io::sink();
        sink.write_all(upload.ch_wire()).await.expect("upload sink");
        sink.flush().await.expect("upload flush");
        let (context, upload_wire) = upload.finish_upload();
        let retained_share_capacity = context.key_shares.retained_capacity();
        drop(upload_wire);

        // A valid hybrid SH followed by application records whose total wire
        // width is exactly W.  This is the real scanner input shape, not an
        // internal prepare-only artifact.
        let mut sh_body = Vec::new();
        sh_body.extend_from_slice(&[0x03, 0x03]);
        sh_body.extend_from_slice(&[0x66; 32]);
        sh_body.push(32);
        sh_body.extend_from_slice(&session_id);
        sh_body.extend_from_slice(&0x1301u16.to_be_bytes());
        sh_body.push(0);
        let versions = extension_bytes(0x002b, &0x0304u16.to_be_bytes());
        let mut ks_body = Vec::new();
        ks_body.extend_from_slice(&0x11ecu16.to_be_bytes());
        ks_body.extend_from_slice(&1120u16.to_be_bytes());
        ks_body.resize(ks_body.len() + 1120, 0x5a);
        let key_share = extension_bytes(0x0033, &ks_body);
        let mut exts = Vec::new();
        exts.extend_from_slice(&versions);
        exts.extend_from_slice(&key_share);
        sh_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        sh_body.extend_from_slice(&exts);
        let mut sh = vec![0x02];
        sh.extend_from_slice(&(sh_body.len() as u32).to_be_bytes()[1..4]);
        sh.extend_from_slice(&sh_body);
        let base = 5 + sh.len();
        let needed = TARGET_SCAN_WIRE_LIMIT - base;
        let mut lengths = vec![18usize; 4];
        let mut extra = needed - 4 * 23;
        for len in &mut lengths {
            let add = extra.min(16_401 - 18);
            *len += add;
            extra -= add;
        }
        assert_eq!(extra, 0, "four records represent the near-W width");
        let mut flight = Vec::new();
        flight.extend_from_slice(&[0x16, 0x03, 0x03]);
        flight.extend_from_slice(&(sh.len() as u16).to_be_bytes());
        flight.extend_from_slice(&sh);
        for len in lengths {
            flight.extend_from_slice(&[0x17, 0x03, 0x03]);
            flight.extend_from_slice(&(len as u16).to_be_bytes());
            flight.resize(flight.len() + len, 0x5a);
        }
        assert_eq!(flight.len(), TARGET_SCAN_WIRE_LIMIT);

        crate::test_alloc::start_measurement();
        let mut scanner = server
            .target_flight_scanner(&context)
            .expect("wire-authenticated context is mirrorable");
        assert_eq!(
            scanner.push(&flight).expect("within scanner window"),
            TargetScanState::Freezable
        );
        let template = scanner.freeze().expect("W-sized candidate freezes");
        assert_eq!(
            template.target_prefix.capacity(),
            TARGET_SCAN_PREFIX_CAPACITY,
            "the scanner's single W+1 allocation moves into the template"
        );
        let prepared = server
            .prepare_mirrored_upload(context, template)
            .expect("W-shaped template prepares");
        let (prepare_live, prepare_peak) = crate::test_alloc::measurement();
        assert!(
            prepare_live >= (TARGET_SCAN_PREFIX_CAPACITY + TARGET_SCAN_WIRE_LIMIT) as i64,
            "allocator witness must include the live target prefix and sealed wire: {prepare_live}"
        );
        let measured_peak = retained_share_capacity
            + usize::try_from(prepare_peak).expect("prepare peak is nonnegative");
        assert!(
            measured_peak <= 136_417,
            "allocator-measured real-order probe/prepare peak {measured_peak} exceeds Bprobe"
        );
        eprintln!(
            "bprobe-measured real-public-order: peak={measured_peak} raw_peak={prepare_peak} live_at_prepare_return={prepare_live} G={retained_share_capacity} Bprobe=136417"
        );
        let (wire, _completion) = prepared.commit().into_wire_and_completion();
        assert_eq!(wire.len(), TARGET_SCAN_WIRE_LIMIT);
    }

    /// The production mirror path enforces the same issuer binding as the
    /// legacy completion API: a context minted by one server instance must
    /// not prepare a flight on another.
    #[test]
    fn mirrored_upload_is_bound_to_issuing_server_instance() {
        use zeroize::Zeroizing;
        let (private, _public) = keypair();
        let issuer = RealityServer::new(&server_config(private)).expect("issuer");
        let other = RealityServer::new(&server_config(private)).expect("other");

        let mut cipher_suites = OfferedCipherSuites::default();
        cipher_suites.insert(0x1301);
        let mut supported_groups = SupportedGroups::default();
        supported_groups.insert(GROUP_X25519);
        let mut key_shares = ClientKeyShares::default();
        key_shares.insert(GROUP_X25519, &[0x11; 32]);
        let context = AuthenticatedMirrorContext {
            issuer: Arc::clone(&issuer.inner.instance),
            auth_key: Zeroizing::new([0x23; 32]),
            session_id: [0u8; 32],
            cipher_suites,
            supported_groups,
            key_shares,
            has_pre_shared_key: false,
            has_early_data: false,
            record_size_limit: None,
            record_size_limit_malformed: false,
            key_share_malformed: false,
            transcript_sha256: TranscriptHasher::new(HashAlg::Sha256),
            transcript_sha384: TranscriptHasher::new(HashAlg::Sha384),
        };

        let mut sh_body = Vec::new();
        sh_body.extend_from_slice(&[0x03, 0x03]);
        sh_body.extend_from_slice(&[0x66; 32]);
        sh_body.push(32);
        sh_body.extend_from_slice(&[0u8; 32]);
        sh_body.extend_from_slice(&0x1301u16.to_be_bytes());
        sh_body.push(0);
        let versions = extension_bytes(0x002b, &0x0304u16.to_be_bytes());
        let mut ks_body = Vec::new();
        ks_body.extend_from_slice(&0x001du16.to_be_bytes());
        ks_body.extend_from_slice(&32u16.to_be_bytes());
        ks_body.extend_from_slice(&[0x40; 32]);
        let key_share = extension_bytes(0x0033, &ks_body);
        let mut exts = Vec::new();
        exts.extend_from_slice(&versions);
        exts.extend_from_slice(&key_share);
        sh_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        sh_body.extend_from_slice(&exts);
        let mut sh = vec![0x02];
        sh.extend_from_slice(&(sh_body.len() as u32).to_be_bytes()[1..4]);
        sh.extend_from_slice(&sh_body);
        let mut flight = Vec::new();
        flight.extend_from_slice(&[0x16, 0x03, 0x03]);
        flight.extend_from_slice(&(sh.len() as u16).to_be_bytes());
        flight.extend_from_slice(&sh);
        for len in [25u16, 3217, 281, 69] {
            flight.extend_from_slice(&[0x17, 0x03, 0x03]);
            flight.extend_from_slice(&len.to_be_bytes());
            flight.resize(flight.len() + usize::from(len), 0x5a);
        }

        let mut scanner = issuer
            .target_flight_scanner(&context)
            .expect("controlled context is mirrorable");
        scanner.push(&flight).unwrap();
        let template = scanner
            .freeze()
            .expect("synthetic flight must freeze for the controlled context");

        let error = other
            .prepare_mirrored_upload(context, template)
            .expect_err("foreign instance must reject the upload context before any output");
        assert_eq!(
            error.into_target_prefix(),
            flight,
            "even an issuer rejection returns the original target prefix for cover"
        );
    }

    fn extension_bytes(typ: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + data.len());
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    #[tokio::test]
    async fn verified_hello_is_bound_to_issuing_server_instance() {
        let (private, public) = keypair();
        let server_a = RealityServer::new(&server_config(private)).expect("server A");
        let server_b = RealityServer::new(&server_config(private)).expect("server B");
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let verify_task =
            tokio::spawn(async move { server_a.verify_client_hello(Box::new(server_io)).await });
        let hello = manual_valid_hello(public, rand::random::<[u8; 32]>());
        client_io
            .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, &hello).unwrap())
            .await
            .unwrap();
        client_io.flush().await.unwrap();
        let classified = verify_task.await.expect("verify task").expect("verify");
        let RealityClientHello::Verified { stream, hello } = classified else {
            panic!("valid ClientHello must verify")
        };
        assert!(
            server_b.complete_handshake(stream, *hello).await.is_err(),
            "a different RealityServer instance must reject the token before output"
        );
        let mut byte = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(5), client_io.read_exact(&mut byte)).await
        {
            Err(_) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("cross-instance rejection emitted {n} handshake bytes"),
        }
    }

    async fn rejected_client_goes_to_cover(client_config: TlsConfig, server: RealityServer) {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let layer = RealityTlsLayer::new(&client_config).expect("client layer");
        let client_task = tokio::spawn(async move { layer.connect(Box::new(client_io)).await });
        let accepted = accept_task.await.expect("accept task").expect("accept");
        let RealityServerAccept::Cover(relay) = accepted else {
            panic!("invalid REALITY client must fall through to cover");
        };
        assert!(relay.wire_prefix_len() > 71);
        drop(relay);
        let client_result = client_task.await.expect("client task");
        assert!(
            client_result.is_err(),
            "unauthenticated client must not complete"
        );
    }

    #[tokio::test]
    async fn wrong_short_id_goes_to_cover_without_response() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        rejected_client_goes_to_cover(client_config(public, [9u8; 8], false), server).await;
    }

    #[tokio::test]
    async fn wrong_server_public_key_goes_to_cover_without_response() {
        let (private, _public) = keypair();
        let (_other_private, wrong_public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        rejected_client_goes_to_cover(client_config(wrong_public, SHORT_ID, false), server).await;
    }

    #[tokio::test]
    async fn wrong_sni_goes_to_cover_without_response() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let mut config = client_config(public, SHORT_ID, false);
        config.sni = Some("other.example.com".into());
        rejected_client_goes_to_cover(config, server).await;
    }

    async fn expect_authenticated(client_config: TlsConfig, server: RealityServer) {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let layer = RealityTlsLayer::new(&client_config).expect("client layer");
        let client_task = tokio::spawn(async move { layer.connect(Box::new(client_io)).await });
        let accepted = accept_task.await.expect("accept task").expect("accept");
        assert!(
            matches!(accepted, RealityServerAccept::Authenticated(_)),
            "in-window REALITY client must authenticate"
        );
        assert!(client_task.await.expect("client task").is_ok());
    }

    #[tokio::test]
    async fn expired_timestamp_goes_to_cover_but_zero_window_disables_check() {
        fn ancient_system_time() -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(1_000)
        }
        let (private, public) = keypair();
        let mut config = client_config(public, SHORT_ID, false);
        config.reality.as_mut().unwrap().protocol_clock = Some(ancient_system_time);

        let server = RealityServer::new(&server_config(private)).expect("server");
        rejected_client_goes_to_cover(config.clone(), server).await;

        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::ZERO);
        let server = RealityServer::new(&sc).expect("server");
        expect_authenticated(config, server).await;
    }

    #[tokio::test]
    async fn sub_second_window_accepts_client_ahead_across_second_boundary() {
        // The client truncates its clock to whole wire seconds, so a client
        // 100 ms ahead of the server can seal the *next* second.  A 500 ms
        // window must still accept it: the diff is 100 ms, not one second.
        fn server_now() -> SystemTime {
            UNIX_EPOCH + Duration::from_millis(1_700_000_000_900)
        }
        fn client_now() -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(1_700_000_001)
        }
        let (private, public) = keypair();
        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::from_millis(500));
        sc.now = Some(server_now);
        let server = RealityServer::new(&sc).expect("server");
        let mut config = client_config(public, SHORT_ID, false);
        config.reality.as_mut().unwrap().protocol_clock = Some(client_now);
        expect_authenticated(config, server).await;
    }

    #[tokio::test]
    async fn sub_second_window_rejects_outside_window_in_both_directions() {
        fn server_now_late() -> SystemTime {
            UNIX_EPOCH + Duration::from_millis(1_700_000_000_900)
        }
        fn server_now_early() -> SystemTime {
            UNIX_EPOCH + Duration::from_millis(1_700_000_000_200)
        }
        fn client_now_ahead() -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(1_700_000_001)
        }
        let (private, public) = keypair();

        // Client behind: seals second T against a server at T+900ms → 900 ms
        // skew exceeds the 500 ms window.
        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::from_millis(500));
        sc.now = Some(server_now_late);
        let server = RealityServer::new(&sc).expect("server");
        rejected_client_goes_to_cover(client_config(public, SHORT_ID, false), server).await;

        // Client ahead: seals T+1 against a server at T+200ms → 800 ms skew.
        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::from_millis(500));
        sc.now = Some(server_now_early);
        let server = RealityServer::new(&sc).expect("server");
        let mut config = client_config(public, SHORT_ID, false);
        config.reality.as_mut().unwrap().protocol_clock = Some(client_now_ahead);
        rejected_client_goes_to_cover(config, server).await;
    }

    #[tokio::test]
    async fn window_boundary_is_inclusive() {
        fn server_now_exact() -> SystemTime {
            UNIX_EPOCH + Duration::from_millis(1_700_000_000_500)
        }
        fn server_now_beyond() -> SystemTime {
            UNIX_EPOCH + Duration::from_millis(1_700_000_000_500) + Duration::from_micros(1)
        }
        let (private, public) = keypair();

        // Skew exactly equal to the 500 ms window is accepted …
        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::from_millis(500));
        sc.now = Some(server_now_exact);
        let server = RealityServer::new(&sc).expect("server");
        expect_authenticated(client_config(public, SHORT_ID, false), server).await;

        // … and one microsecond beyond it is rejected.
        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::from_millis(500));
        sc.now = Some(server_now_beyond);
        let server = RealityServer::new(&sc).expect("server");
        rejected_client_goes_to_cover(client_config(public, SHORT_ID, false), server).await;
    }

    #[tokio::test]
    async fn huge_window_accepts_distant_timestamp_without_overflow() {
        fn ancient_system_time() -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(1_000)
        }
        let (private, public) = keypair();
        let mut sc = server_config(private);
        sc.max_time_difference = Some(Duration::from_micros(u64::MAX));
        let server = RealityServer::new(&sc).expect("server");
        let mut config = client_config(public, SHORT_ID, false);
        config.reality.as_mut().unwrap().protocol_clock = Some(ancient_system_time);
        expect_authenticated(config, server).await;
    }

    #[tokio::test]
    async fn corrupt_certificate_verify_is_rejected_by_real_client() {
        let (private, public) = keypair();
        let server = RealityServer::new_corrupting_certificate_verify(&server_config(private))
            .expect("server");
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let layer =
            RealityTlsLayer::new(&client_config(public, SHORT_ID, false)).expect("client layer");
        let client_result = layer.connect(Box::new(client_io)).await;
        assert!(
            client_result.is_err(),
            "bad CertificateVerify must fail the client"
        );
        assert!(accept_task.await.expect("accept task").is_err());
    }

    fn manual_valid_hello(public: [u8; 32], random: [u8; 32]) -> Vec<u8> {
        let mut client_private = rand::random::<[u8; 32]>();
        crate::reality_tls::clamp_x25519_private(&mut client_private);
        let client_public = x25519_public_from_private(&client_private);
        let shared = x25519(&client_private, &public).unwrap();
        let reality = crate::tls::RealityConfig {
            public_key: public,
            short_id: SHORT_ID,
            support_x25519_mlkem768: false,
            protocol_clock: Some(fixed_system_time),
        };
        build_reality_client_hello(
            SERVER_NAME,
            &[],
            &random,
            &client_public,
            None,
            &shared,
            &reality,
            crate::reality_hello::HelloProfile::Chrome,
        )
        .expect("manual hello")
        .0
    }

    fn manual_valid_hybrid_hello(public: [u8; 32]) -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let mut client_private = rand::random::<[u8; 32]>();
        crate::reality_tls::clamp_x25519_private(&mut client_private);
        let client_public = x25519_public_from_private(&client_private);
        let shared = x25519(&client_private, &public).unwrap();
        let (pq_public, _pq_private) =
            boring::mlkem::MlKemPrivateKey::generate(boring::mlkem::Algorithm::MlKem768)
                .expect("ML-KEM keygen");
        let mut hybrid_x_private = rand::random::<[u8; 32]>();
        crate::reality_tls::clamp_x25519_private(&mut hybrid_x_private);
        let hybrid_x_public = x25519_public_from_private(&hybrid_x_private);
        let random = rand::random::<[u8; 32]>();
        let reality = crate::tls::RealityConfig {
            public_key: public,
            short_id: SHORT_ID,
            support_x25519_mlkem768: true,
            protocol_clock: Some(fixed_system_time),
        };
        let (hello, auth_key) = build_reality_client_hello(
            SERVER_NAME,
            &[],
            &random,
            &client_public,
            Some((pq_public.as_bytes(), &hybrid_x_public)),
            &shared,
            &reality,
            crate::reality_hello::HelloProfile::Chrome,
        )
        .expect("manual hybrid hello");
        (hello, random, *auth_key)
    }

    fn key_share_data_range(hello: &[u8], wanted_group: u16) -> Option<std::ops::Range<usize>> {
        let mut pos = 4 + 2 + 32;
        let sid_len = *hello.get(pos)? as usize;
        pos += 1 + sid_len;
        let suites_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
        pos += 2 + suites_len;
        let compression_len = *hello.get(pos)? as usize;
        pos += 1 + compression_len;
        let extensions_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
        pos += 2;
        let extensions_end = pos.checked_add(extensions_len)?;
        while pos + 4 <= extensions_end {
            let typ = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
            let len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
            pos += 4;
            let data_end = pos.checked_add(len)?;
            if data_end > extensions_end || data_end > hello.len() {
                return None;
            }
            if typ == EXT_KEY_SHARE {
                let data = &hello[pos..data_end];
                if data.len() < 2 {
                    return None;
                }
                let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if list_len + 2 != data.len() {
                    return None;
                }
                let mut share_pos = 2;
                while share_pos + 4 <= data.len() {
                    let group = u16::from_be_bytes([data[share_pos], data[share_pos + 1]]);
                    let share_len =
                        u16::from_be_bytes([data[share_pos + 2], data[share_pos + 3]]) as usize;
                    share_pos += 4;
                    let share_end = share_pos.checked_add(share_len)?;
                    if share_end > data.len() {
                        return None;
                    }
                    if group == wanted_group {
                        return Some(pos + share_pos..pos + share_end);
                    }
                    share_pos = share_end;
                }
                return None;
            }
            pos = data_end;
        }
        None
    }

    fn reseal_reality_session_id(hello: &mut Vec<u8>, random: &[u8; 32], auth_key: &[u8; 32]) {
        hello[39..71].fill(0);
        let mut plaintext = Vec::with_capacity(16);
        plaintext.extend_from_slice(&[0, 0, 0, 0]);
        plaintext.extend_from_slice(&(fixed_unix() as u32).to_be_bytes());
        plaintext.extend_from_slice(&SHORT_ID);
        assert_eq!(plaintext.len(), 16);
        let cipher = Aes256Gcm::new_from_slice(auth_key).expect("AES-256-GCM key");
        let nonce = Nonce::from_slice(&random[20..32]);
        let tag = cipher
            .encrypt_in_place_detached(nonce, hello.as_slice(), &mut plaintext)
            .expect("re-seal REALITY session id");
        plaintext.extend_from_slice(&tag);
        hello[39..71].copy_from_slice(&plaintext);
    }

    fn server_hello_key_share(message: &[u8]) -> (u16, usize) {
        assert_eq!(message[0], HS_SERVER_HELLO);
        assert_eq!(message.len(), 4 + read_u24(&message[1..4]));
        let mut pos = 4 + 2 + 32;
        let sid_len = message[pos] as usize;
        pos += 1 + sid_len + 2 + 1;
        let extensions_len = u16::from_be_bytes([message[pos], message[pos + 1]]) as usize;
        pos += 2;
        let extensions_end = pos + extensions_len;
        while pos + 4 <= extensions_end {
            let typ = u16::from_be_bytes([message[pos], message[pos + 1]]);
            let len = u16::from_be_bytes([message[pos + 2], message[pos + 3]]) as usize;
            pos += 4;
            if typ == EXT_KEY_SHARE {
                assert!(len >= 4, "ServerHello key_share carries group and length");
                let share_len = u16::from_be_bytes([message[pos + 2], message[pos + 3]]) as usize;
                assert_eq!(share_len + 4, len, "ServerHello key_share is exact");
                return (
                    u16::from_be_bytes([message[pos], message[pos + 1]]),
                    share_len,
                );
            }
            pos += len;
        }
        panic!("ServerHello key_share extension missing")
    }

    fn server_hello_group(message: &[u8]) -> u16 {
        server_hello_key_share(message).0
    }

    /// Selection itself must treat a correctly sized but unparsable ML-KEM
    /// encapsulation key as unavailable and move on to the usable classical
    /// share instead of committing to a handshake that cannot be built.
    #[test]
    fn unusable_hybrid_key_share_falls_back_to_classical_in_selection() {
        assert!(!x25519_public_key_usable(&[0u8; 32]));
        let mut probe_private = rand::random::<[u8; 32]>();
        crate::reality_tls::clamp_x25519_private(&mut probe_private);
        assert!(x25519_public_key_usable(&x25519_public_from_private(
            &probe_private
        )));

        let mut hybrid = vec![0xff; HYBRID_SHARE_LEN - 32];
        hybrid.extend_from_slice(&[7u8; 32]);
        assert!(
            MlKemPublicKey::from_slice(MlKemAlgorithm::MlKem768, &hybrid[..HYBRID_SHARE_LEN - 32],)
                .is_err(),
            "the test mutation must produce an unusable ML-KEM public key"
        );
        let classical = vec![9u8; 32];
        let mut hello = ClientHello::test_empty();
        hello.supported_groups.mark_nonempty();
        hello.supported_groups.insert(GROUP_X25519_MLKEM768);
        hello.supported_groups.insert(GROUP_X25519);
        hello.key_shares.insert(GROUP_X25519_MLKEM768, &hybrid);
        hello.key_shares.insert(GROUP_X25519, &classical);

        let key_group = select_key_group(&hello).expect("classical fallback remains usable");
        let chosen = chosen_key_share_for(&hello, key_group).expect("classical share copy");
        assert_eq!(chosen.group, GROUP_X25519);
        assert_eq!(chosen.client_share, classical);

        let (pq_public, _pq_private) =
            boring::mlkem::MlKemPrivateKey::generate(boring::mlkem::Algorithm::MlKem768)
                .expect("ML-KEM keygen");
        let mut usable_hybrid = pq_public.as_bytes().to_vec();
        usable_hybrid.extend_from_slice(&x25519_public_from_private(&probe_private));
        hello
            .key_shares
            .insert(GROUP_X25519_MLKEM768, &usable_hybrid);
        hello.key_shares.insert(GROUP_X25519, &classical);
        let key_group = select_key_group(&hello).expect("usable hybrid remains selectable");
        let chosen = chosen_key_share_for(&hello, key_group).expect("hybrid share copy");
        assert_eq!(chosen.group, GROUP_X25519_MLKEM768);
        assert_eq!(chosen.client_share, usable_hybrid);
    }

    /// The same fallback must hold after REALITY authentication: a valid
    /// session-id proof made with the standalone X25519 share is not thrown
    /// away merely because the preferred hybrid share cannot encapsulate.
    #[tokio::test]
    async fn authenticated_unusable_hybrid_share_falls_back_to_classical_server_share() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });

        let (mut hello, random, auth_key) = manual_valid_hybrid_hello(public);
        let share_range = key_share_data_range(&hello, GROUP_X25519_MLKEM768)
            .expect("hybrid ClientHello carries a hybrid share");
        assert_eq!(share_range.end - share_range.start, HYBRID_SHARE_LEN);
        let mlkem_range = share_range.start..share_range.end - 32;
        hello[mlkem_range.clone()].fill(0xff);
        assert!(
            MlKemPublicKey::from_slice(MlKemAlgorithm::MlKem768, &hello[mlkem_range],).is_err(),
            "the wire mutation must be an unusable ML-KEM public key"
        );
        reseal_reality_session_id(&mut hello, &random, &auth_key);

        client_io
            .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, &hello).unwrap())
            .await
            .unwrap();
        client_io.flush().await.unwrap();
        let server_hello =
            tokio::time::timeout(Duration::from_secs(2), read_record(&mut client_io))
                .await
                .expect("authenticated fallback must emit a server flight")
                .expect("server flight record read")
                .expect("server flight must start with plaintext ServerHello");
        assert_eq!(server_hello.typ, TLS_RECORD_HANDSHAKE);
        assert_eq!(
            server_hello_group(&server_hello.payload),
            GROUP_X25519,
            "the unusable hybrid share must fall back to classical X25519"
        );

        drop(client_io);
        let _ = tokio::time::timeout(Duration::from_secs(1), accept_task).await;
    }

    #[tokio::test]
    async fn fragmented_client_hello_across_records_authenticates() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let hello = manual_valid_hello(public, rand::random::<[u8; 32]>());
        let split = 11;
        client_io
            .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, &hello[..split]).unwrap())
            .await
            .unwrap();
        client_io
            .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, &hello[split..]).unwrap())
            .await
            .unwrap();
        client_io.flush().await.unwrap();

        let mut header = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(2), client_io.read_exact(&mut header))
            .await
            .expect("valid fragmented hello must produce a server flight")
            .unwrap();
        assert_eq!(header[0], TLS_RECORD_HANDSHAKE);
        drop(client_io);
        assert!(accept_task.await.expect("accept task").is_err());
    }

    #[tokio::test]
    async fn non_client_hello_goes_to_cover_and_relay_is_byte_transparent() {
        let (private, _public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (mut client_peer, server_io) = tokio::io::duplex(128 * 1024);
        let (target_io, mut cover_peer) = tokio::io::duplex(128 * 1024);

        let original = wrap_plain_record(TLS_RECORD_HANDSHAKE, &[2, 0, 0, 1, 0]).unwrap();
        client_peer.write_all(&original).await.unwrap();
        client_peer.flush().await.unwrap();
        let accepted = server.accept(Box::new(server_io)).await.expect("accept");
        let RealityServerAccept::Cover(relay) = accepted else {
            panic!("non-ClientHello must go to cover");
        };
        assert_eq!(relay.wire_prefix_len(), original.len());
        let relay_task = tokio::spawn(async move { relay.relay(Box::new(target_io)).await });

        let mut got = vec![0u8; original.len()];
        cover_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(
            got, original,
            "preserved wire prefix must be byte-identical"
        );
        cover_peer.write_all(b"cover-response").await.unwrap();
        cover_peer.flush().await.unwrap();
        let mut response = vec![0u8; b"cover-response".len()];
        client_peer.read_exact(&mut response).await.unwrap();
        assert_eq!(response, b"cover-response");

        drop(client_peer);
        drop(cover_peer);
        let _ = relay_task.await;
    }

    fn expect_preflight_cover(
        preflight: Result<(Box<dyn Stream>, Preflight)>,
    ) -> (Box<dyn Stream>, Vec<u8>) {
        let (inner, preflight) = preflight.expect("preflight itself must not fail");
        match preflight {
            Preflight::Cover(prefix) => (inner, prefix),
            Preflight::Candidate { .. } => {
                panic!("implausible record header must not be a candidate")
            }
        }
    }

    /// A record type that cannot carry a ClientHello is already decisive
    /// after the five-byte header; preflight must not wait for its body.
    #[tokio::test]
    async fn non_handshake_record_header_goes_to_cover_without_waiting_for_body() {
        let header = [TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0, 4];
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(&header).await.unwrap();
        writer.flush().await.unwrap();

        let preflight = tokio::time::timeout(
            Duration::from_millis(200),
            read_client_hello_preflight(Box::new(reader)),
        )
        .await
        .expect("the decisive header must classify before the accept timeout");
        let (_inner, prefix) = expect_preflight_cover(preflight);
        assert_eq!(prefix, header);
        drop(writer);
    }

    /// The impossible-type/version verdict also precedes the resource
    /// limits: those limits exist for real TLS candidates, not for input
    /// already known to belong on the cover path.
    #[tokio::test]
    async fn implausible_record_header_goes_to_cover_before_length_resource_check() {
        for header in [
            [TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0x40, 1],
            [TLS_RECORD_HANDSHAKE, 0xff, 0xff, 0x40, 1],
        ] {
            let (mut writer, reader) = tokio::io::duplex(64);
            writer.write_all(&header).await.unwrap();
            writer.flush().await.unwrap();

            let preflight = tokio::time::timeout(
                Duration::from_millis(200),
                read_client_hello_preflight(Box::new(reader)),
            )
            .await
            .expect("the decisive header must classify promptly");
            let (_inner, prefix) = expect_preflight_cover(preflight);
            assert_eq!(prefix, header);
            drop(writer);
        }
    }

    /// Only the bytes actually consumed for the decisive header belong in
    /// the cover prefix; the unread record body stays on the stream and is
    /// relayed after that prefix, exactly once and in order.
    #[tokio::test]
    async fn cover_after_decisive_header_leaves_record_body_on_stream() {
        let header = [TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0, 4];
        let body = b"abcd";
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(&header).await.unwrap();
        writer.write_all(body).await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);

        let preflight = read_client_hello_preflight(Box::new(reader)).await;
        let (mut inner, prefix) = expect_preflight_cover(preflight);
        assert_eq!(prefix, header);
        let mut preserved = [0u8; 4];
        inner.read_exact(&mut preserved).await.unwrap();
        assert_eq!(&preserved, body);
    }

    fn padding_data_offset(hello: &[u8]) -> Option<usize> {
        let mut pos = 4 + 2 + 32;
        let sid_len = *hello.get(pos)? as usize;
        pos += 1 + sid_len;
        let suites_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
        pos += 2 + suites_len;
        let comp_len = *hello.get(pos)? as usize;
        pos += 1 + comp_len;
        let ext_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
        pos += 2;
        let end = pos.checked_add(ext_len)?;
        while pos + 4 <= end {
            let typ = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
            let len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
            pos += 4;
            if typ == 0xfe0d && len >= 144 {
                return Some(pos + len - 1);
            }
            pos = pos.checked_add(len)?;
        }
        None
    }

    #[tokio::test]
    async fn tampered_aad_goes_to_cover() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let mut hello = manual_valid_hello(public, rand::random::<[u8; 32]>());
        let grease_ech = padding_data_offset(&hello).expect("Chrome hello carries GREASE ECH");
        hello[grease_ech] ^= 1;
        client_io
            .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, &hello).unwrap())
            .await
            .unwrap();
        client_io.flush().await.unwrap();
        let accepted = accept_task.await.expect("accept task").expect("accept");
        assert!(
            matches!(accepted, RealityServerAccept::Cover(_)),
            "AAD tamper must not authenticate"
        );
    }

    struct CorruptSecondWrite<S> {
        inner: S,
        writes: usize,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for CorruptSecondWrite<S> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for CorruptSecondWrite<S> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if !data.is_empty() {
                this.writes += 1;
                if this.writes == 2 {
                    let mut corrupted = data.to_vec();
                    let last = corrupted.len() - 1;
                    corrupted[last] ^= 1;
                    return std::pin::Pin::new(&mut this.inner).poll_write(cx, &corrupted);
                }
            }
            std::pin::Pin::new(&mut this.inner).poll_write(cx, data)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn authenticated_branch_with_corrupt_client_finished_fails_closed() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let layer =
            RealityTlsLayer::new(&client_config(public, SHORT_ID, false)).expect("client layer");
        let corrupted = CorruptSecondWrite {
            inner: client_io,
            writes: 0,
        };
        let client_task = tokio::spawn(async move { layer.connect(Box::new(corrupted)).await });
        let accept_result = accept_task.await.expect("accept task");
        assert!(
            accept_result.is_err(),
            "corrupt client Finished must close the authenticated branch"
        );
        let _ = client_task.await.expect("client task");
    }

    // ─── ClientHello pre-read wire cap, compression shape, token bucket ──────

    fn stress_extension(typ: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + data.len());
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn sni_extension_body(entries: &[&[u8]]) -> Vec<u8> {
        let list_len: usize = entries.iter().map(|name| 3 + name.len()).sum();
        let mut body = Vec::new();
        body.extend_from_slice(&(list_len as u16).to_be_bytes());
        for name in entries {
            body.push(0);
            body.extend_from_slice(&(name.len() as u16).to_be_bytes());
            body.extend_from_slice(name);
        }
        body
    }

    fn stress_valid_client_hello(
        server_public: [u8; 32],
        padding_len: usize,
        unknown_share_count: usize,
        unknown_group_count: usize,
        duplicate_x25519: bool,
    ) -> Vec<u8> {
        let sni_body = sni_extension_body(&[SERVER_NAME.as_bytes()]);
        stress_valid_client_hello_with_sni(
            server_public,
            padding_len,
            unknown_share_count,
            unknown_group_count,
            duplicate_x25519,
            &sni_body,
        )
    }

    fn stress_valid_client_hello_with_sni(
        server_public: [u8; 32],
        padding_len: usize,
        unknown_share_count: usize,
        unknown_group_count: usize,
        duplicate_x25519: bool,
        sni_body: &[u8],
    ) -> Vec<u8> {
        let mut client_private = rand::random::<[u8; 32]>();
        crate::reality_tls::clamp_x25519_private(&mut client_private);
        let client_public = x25519_public_from_private(&client_private);
        let shared = x25519(&client_private, &server_public).unwrap();
        let random = rand::random::<[u8; 32]>();

        let mut groups = Vec::new();
        groups.extend_from_slice(&GROUP_X25519.to_be_bytes());
        groups.extend_from_slice(&GROUP_X25519_MLKEM768.to_be_bytes());
        for index in 0..unknown_group_count {
            let group = 0x4000u16 + index as u16;
            if group != GROUP_X25519 && group != GROUP_X25519_MLKEM768 {
                groups.extend_from_slice(&group.to_be_bytes());
            }
        }
        let mut groups_body = Vec::new();
        groups_body.extend_from_slice(&(groups.len() as u16).to_be_bytes());
        groups_body.extend_from_slice(&groups);

        let mut shares = Vec::new();
        let mut push_share = |group: u16, bytes: &[u8]| {
            shares.extend_from_slice(&group.to_be_bytes());
            shares.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            shares.extend_from_slice(bytes);
        };
        push_share(GROUP_X25519, &client_public);
        let hybrid = vec![0x5a; HYBRID_SHARE_LEN];
        push_share(GROUP_X25519_MLKEM768, &hybrid);
        for index in 0..unknown_share_count {
            let group = 0x5000u16 + index as u16;
            push_share(group, &[0x66; 7]);
        }
        if duplicate_x25519 {
            push_share(GROUP_X25519, &client_public);
        }
        let mut shares_body = Vec::new();
        shares_body.extend_from_slice(&(shares.len() as u16).to_be_bytes());
        shares_body.extend_from_slice(&shares);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&stress_extension(EXT_SERVER_NAME, sni_body));
        extensions.extend_from_slice(&stress_extension(EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]));
        extensions.extend_from_slice(&stress_extension(EXT_SUPPORTED_GROUPS, &groups_body));
        extensions.extend_from_slice(&stress_extension(EXT_KEY_SHARE, &shares_body));
        extensions.extend_from_slice(&stress_extension(21, &vec![0u8; padding_len]));

        let mut hello = Vec::new();
        hello.push(HS_CLIENT_HELLO);
        hello.extend_from_slice(&[0, 0, 0]);
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&random);
        hello.push(32);
        hello.extend_from_slice(&[0u8; 32]);
        hello.extend_from_slice(&(2u16).to_be_bytes());
        hello.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
        let body_len = hello.len() - 4;
        hello[1..4].copy_from_slice(&(body_len as u32).to_be_bytes()[1..4]);

        let auth_key = hkdf_sha256(&shared[..], &random[..20], b"REALITY", 32);
        let mut plaintext = Vec::with_capacity(16);
        plaintext.extend_from_slice(&[0, 0, 0, 0]);
        plaintext.extend_from_slice(&(fixed_unix() as u32).to_be_bytes());
        plaintext.extend_from_slice(&SHORT_ID);
        let cipher = Aes256Gcm::new_from_slice(&auth_key).expect("AES-256-GCM key");
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&random[20..32]), &hello, &mut plaintext)
            .expect("seal stress REALITY session id");
        plaintext.extend_from_slice(&tag);
        hello[39..71].copy_from_slice(&plaintext);
        hello
    }

    fn frame_stress_hello(hello: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        for chunk in hello.chunks(MAX_PLAINTEXT_RECORD) {
            wire.extend_from_slice(&[TLS_RECORD_HANDSHAKE, 0x03, 0x03]);
            wire.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            wire.extend_from_slice(chunk);
        }
        wire
    }

    fn near_cap_stress_input(
        server_public: [u8; 32],
        unknown_share_count: usize,
        unknown_group_count: usize,
        duplicate_x25519: bool,
    ) -> (Vec<u8>, Vec<u8>) {
        let target_wire = MAX_AUTHED_STREAM_BYTES - 8;
        let mut padding = 0usize;
        let mut hello = Vec::new();
        let mut wire = Vec::new();
        for _ in 0..64 {
            hello = stress_valid_client_hello(
                server_public,
                padding,
                unknown_share_count,
                unknown_group_count,
                duplicate_x25519,
            );
            wire = frame_stress_hello(&hello);
            if wire.len() <= target_wire && wire.len() >= MAX_AUTHED_STREAM_BYTES - 32 {
                break;
            }
            if wire.len() > target_wire {
                padding = padding.saturating_sub(wire.len() - target_wire);
            } else {
                padding += target_wire - wire.len();
            }
        }
        assert!(
            wire.len() >= MAX_AUTHED_STREAM_BYTES - 32,
            "stress input must be near the wire cap, got {}",
            wire.len()
        );
        assert!(wire.len() <= MAX_AUTHED_STREAM_BYTES);
        (hello, wire)
    }

    #[tokio::test]
    async fn client_hello_arena_accounts_for_near_cap_padding_and_group_stress() {
        let (private, public) = keypair();
        let server = RealityServer::new(&server_config(private)).expect("server");
        let (_logical, wire) = near_cap_stress_input(public, 384, 512, false);
        let expected_wire = wire.clone();
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let verify_task =
            tokio::spawn(async move { server.verify_client_hello(Box::new(server_io)).await });
        client_io.write_all(&wire).await.unwrap();
        client_io.flush().await.unwrap();
        let classified = verify_task
            .await
            .expect("verify task")
            .expect("near-cap stress ClientHello preflight");
        let RealityClientHello::Verified { hello, .. } = classified else {
            panic!("near-cap stress ClientHello must authenticate")
        };
        assert_eq!(hello.ch_wire(), expected_wire);
        let measured_peak = hello.ch_wire.capacity() + hello.hello.parse_explicit_arena_bytes;
        assert_eq!(
            measured_peak, 140_517,
            "wire, logical/AAD, bitset, header and both candidate shares exactly fill Bch"
        );
        let (context, upload_wire) = hello.into_mirror_upload().finish_upload();
        let upload_peak = upload_wire.capacity() + context.key_shares.retained_capacity();
        assert_eq!(
            upload_peak, 66_784,
            "after the consuming split only W bytes of CH wire plus G candidate bytes remain"
        );
    }

    #[test]
    fn client_hello_group_stress_keeps_only_fixed_candidates() {
        let (_private, public) = keypair();
        let (logical, _wire) = near_cap_stress_input(public, 384, 512, true);
        let logical_capacity = logical.capacity();
        let parsed = parse_client_hello(logical).expect("stress ClientHello parses");
        assert!(
            parsed.key_share_malformed,
            "duplicate group is still classified malformed"
        );
        assert_eq!(
            parsed.parse_explicit_arena_bytes,
            logical_capacity + std::mem::size_of::<DedupBitset>() + 5 + 32 + HYBRID_SHARE_LEN,
            "duplicate/unknown groups leave only the two fixed candidates in the parse arena"
        );
    }

    #[tokio::test]
    async fn overlong_first_sni_still_makes_a_second_hostname_duplicate_on_wire() {
        async fn classify_hello(server: RealityServer, hello: &[u8]) -> RealityClientHello {
            let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
            let verify_task =
                tokio::spawn(async move { server.verify_client_hello(Box::new(server_io)).await });
            client_io
                .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, hello).unwrap())
                .await
                .unwrap();
            client_io.flush().await.unwrap();
            verify_task.await.expect("verify task").expect("verify io")
        }

        let (private, public) = keypair();
        let control_server = RealityServer::new(&server_config(private)).expect("control server");
        let control = stress_valid_client_hello(public, 0, 0, 0, false);
        assert!(
            matches!(
                classify_hello(control_server, &control).await,
                RealityClientHello::Verified { .. }
            ),
            "control: the same cryptographic inputs authenticate with one valid SNI"
        );

        let long_name = vec![b'a'; 254];
        let sni = sni_extension_body(&[&long_name, SERVER_NAME.as_bytes()]);
        let mutated = stress_valid_client_hello_with_sni(public, 0, 0, 0, false, &sni);
        let server = RealityServer::new(&server_config(private)).expect("server");
        assert!(
            matches!(
                classify_hello(server, &mutated).await,
                RealityClientHello::Cover(_)
            ),
            "v1 semantics: an overlong first host_name is still a host_name, so the second entry is a duplicate"
        );
    }

    /// C4: the pre-read cap is 64 KiB of *wire* bytes — record headers
    /// included — not 64 KiB plus one header.  Drives the boundary: an
    /// accumulation of exactly 64 KiB must pass the size check (and fail
    /// later only because the peer hangs up), one byte more must be
    /// rejected as a resource limit.
    #[tokio::test]
    async fn preflight_wire_cap_counts_record_headers() {
        // The ClientHello claim is sized to never complete inside the
        // cap: message_len 65532 → total 65536, accepted by the inner
        // message-length check, so the wire byte cap is the only limit
        // that can fire.  Three full records then a fourth sized to land
        // exactly on, or one byte past, the 64 KiB wire total:
        // 3 × (5 + 16384) = 49167, the fourth header adds 5, so the
        // payload hitting exactly 65536 is 65536 − 49172 = 16364.
        fn wire_input(last_payload_len: usize) -> Vec<u8> {
            let mut input = Vec::new();
            let mut first_payload = vec![0u8; MAX_PLAINTEXT_RECORD];
            first_payload[..4].copy_from_slice(&[HS_CLIENT_HELLO, 0x00, 0xFF, 0xFC]);
            for payload in [
                first_payload,
                vec![0u8; MAX_PLAINTEXT_RECORD],
                vec![0u8; MAX_PLAINTEXT_RECORD],
                vec![0u8; last_payload_len],
            ] {
                input.extend_from_slice(&[TLS_RECORD_HANDSHAKE, 0x03, 0x03]);
                input.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                input.extend_from_slice(&payload);
            }
            input
        }

        // Exactly at the cap: no resource error — the pre-read fails only
        // because the peer's EOF arrives with the hello still incomplete.
        let (mut writer, reader) = tokio::io::duplex(128 * 1024);
        writer.write_all(&wire_input(16364)).await.unwrap();
        drop(writer);
        match read_client_hello_preflight(Box::new(reader)).await {
            Err(TransportError::Io(_)) => {}
            Err(err) => panic!("exactly 64 KiB of wire passes the size cap, got: {err:?}"),
            Ok(_) => panic!("incomplete hello at exactly 64 KiB wire must not classify"),
        }

        // One byte past the cap: the wire limit itself must fire.  Before
        // the fix the +5 header slack let this through to the same EOF.
        let (mut writer, reader) = tokio::io::duplex(128 * 1024);
        writer.write_all(&wire_input(16365)).await.unwrap();
        drop(writer);
        match read_client_hello_preflight(Box::new(reader)).await {
            Err(TransportError::ResourceLimit(_)) => {}
            Err(err) => panic!("64 KiB + 1 of wire hits the resource limit, got: {err:?}"),
            Ok(_) => panic!("one byte past 64 KiB wire must be rejected"),
        }

        // A decisive non-TLS header cannot be used to carry the preserved
        // prefix past the same cap once the incomplete hello already fills it.
        let mut input = wire_input(16364);
        input.extend_from_slice(&[TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0, 4]);
        let (mut writer, reader) = tokio::io::duplex(128 * 1024);
        writer.write_all(&input).await.unwrap();
        drop(writer);
        match read_client_hello_preflight(Box::new(reader)).await {
            Err(TransportError::ResourceLimit(_)) => {}
            Err(err) => {
                panic!("a header beyond the 64 KiB cap hits the resource limit, got: {err:?}")
            }
            Ok(_) => panic!("a header beyond 64 KiB wire must not become cover prefix"),
        }

        // Even a fragment of the next header is decisive once it is the first
        // byte beyond the cap; truncation after it must not demote the error.
        let mut input = wire_input(16364);
        input.push(TLS_RECORD_APPLICATION_DATA);
        let (mut writer, reader) = tokio::io::duplex(128 * 1024);
        writer.write_all(&input).await.unwrap();
        drop(writer);
        match read_client_hello_preflight(Box::new(reader)).await {
            Err(TransportError::ResourceLimit(_)) => {}
            Err(err) => {
                panic!("one byte beyond the 64 KiB cap hits the resource limit, got: {err:?}")
            }
            Ok(_) => panic!("one byte beyond 64 KiB wire must be rejected"),
        }
    }

    /// C6: TLS 1.3 admits exactly one compression method, zero — a REALITY
    /// candidate carrying anything else is not parsed as a candidate.
    #[test]
    fn client_hello_compression_must_be_exactly_null() {
        fn synthetic_client_hello(compression: &[u8]) -> Vec<u8> {
            let mut body = vec![0x03, 0x03];
            body.extend_from_slice(&[0xAA; 32]);
            body.push(0x20);
            body.extend_from_slice(&[0xBB; 32]);
            body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
            body.push(compression.len() as u8);
            body.extend_from_slice(compression);
            body.extend_from_slice(&[0, 0]); // empty extension vector
            let mut hello = vec![HS_CLIENT_HELLO];
            put_u24(body.len(), &mut hello);
            hello.extend_from_slice(&body);
            hello
        }

        parse_client_hello(synthetic_client_hello(&[0])).expect("exactly [0] parses");
        for bad in [&[][..], &[1][..], &[0, 0][..], &[1, 0][..], &[0, 1][..]] {
            assert!(
                parse_client_hello(synthetic_client_hello(bad)).is_err(),
                "compression {bad:?} must be rejected"
            );
        }
    }

    /// C3: token accrual saturates at the bucket's room instead of
    /// truncating the u128 intermediate — before the fix an idle×rate
    /// product of exactly 2^65 wrapped the `as u64` credit to zero.
    #[test]
    fn refill_saturates_instead_of_truncating() {
        // 2^63 B/s for 4 s earns exactly 2^65 tokens — beyond u64 — so
        // any wrap in the conversion chain is visible as a missing or
        // under-counted credit.
        let mut limit = DirectionalLimit::new(1u64 << 63, 0, 0);
        assert_eq!(limit.capacity, 1u64 << 63);
        limit.tokens = 0;
        limit.refill_at = Instant::now() - Duration::from_secs(4);
        limit.refill();
        assert_eq!(
            limit.tokens, limit.capacity,
            "the credit saturates the bucket instead of wrapping"
        );
        assert!(
            limit.refill_at <= Instant::now(),
            "the refill baseline must never pass the present"
        );
    }

    /// Once accrued credit saturates the bucket, the excess idle time is
    /// discarded rather than remaining available to fund another burst.
    #[test]
    fn saturated_refill_discards_excess_idle_time() {
        let mut limit = DirectionalLimit::new(1000, 0, 0);
        limit.tokens = 0;
        limit.refill_at = Instant::now() - Duration::from_secs(3);
        let before_refill = Instant::now();
        limit.refill();
        assert_eq!(limit.tokens, limit.capacity);
        assert!(
            limit.refill_at >= before_refill,
            "the saturated refill baseline must be pinned to the refill, not left in the past"
        );
    }

    /// A full bucket earns nothing further, and once room exists the
    /// normal-rate accrual still credits whole tokens — the saturation
    /// clamp must not eat ordinary refills.
    #[test]
    fn refill_still_accrues_at_normal_rates() {
        let mut limit = DirectionalLimit::new(1000, 0, 0);
        assert_eq!(limit.capacity, 1000);

        // Full bucket: refill pins the baseline without changing tokens.
        limit.refill();
        assert_eq!(limit.tokens, 1000);
        assert!(limit.refill_at <= Instant::now());

        // Half-drained bucket after 400+ ms idle at 1000 B/s: the credit
        // is hundreds of tokens, bounded by the rate and the elapsed
        // floor of 400 ms.
        limit.tokens = 500;
        limit.refill_at = Instant::now() - Duration::from_millis(400);
        limit.refill();
        assert!(
            limit.tokens >= 900,
            "400 ms at 1000 B/s restores at least 400 tokens, got {}",
            limit.tokens
        );
        assert!(limit.tokens <= 1000, "never beyond capacity");
    }

    struct RecordingWriter {
        writes: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl AsyncWrite for RecordingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.writes.lock().unwrap().push(buf.to_vec());
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    struct OneByteThenPendingWriter {
        writes: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl AsyncWrite for OneByteThenPendingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.writes.lock().unwrap().is_empty() {
                self.writes.lock().unwrap().push(buf[..1].to_vec());
                return std::task::Poll::Ready(Ok(1));
            }
            std::task::Poll::Pending
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A writer that accepts one byte and then applies backpressure has still
    /// relayed data: even that partial progress must refresh the idle watchdog.
    #[tokio::test]
    async fn shaped_write_reports_partial_write_progress_as_activity() {
        let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (activity_tx, mut activity_rx) = tokio::sync::watch::channel(());
        activity_rx.borrow_and_update();
        let task = tokio::spawn({
            let writes = std::sync::Arc::clone(&writes);
            async move {
                let mut writer = OneByteThenPendingWriter { writes };
                let mut limit = DirectionalLimit::new(0, 0, 0);
                write_shaped(&mut writer, b"abc", &mut limit, &activity_tx).await
            }
        });

        let first_write = tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                if !writes.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(first_write.is_ok(), "the one-byte write must be accepted");
        assert!(
            activity_rx.has_changed().expect("activity sender is alive"),
            "the accepted byte must refresh cover activity before the segment completes"
        );
        task.abort();
    }

    fn spawn_recorded_shaped_prefix(
        len: usize,
        writes: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    ) -> tokio::task::JoinHandle<Result<()>> {
        let (activity_tx, _activity_rx) = tokio::sync::watch::channel(());
        tokio::spawn(relay_direction(
            tokio::io::empty(),
            RecordingWriter { writes },
            vec![0x5a; len],
            DirectionalLimit::new(1000, 0, 0),
            activity_tx,
        ))
    }

    /// A throttled prefix must make wire progress with the tokens already
    /// in the bucket instead of waiting for the whole multi-second block.
    #[tokio::test]
    async fn shaped_prefix_progresses_before_whole_prefix_is_throttled() {
        let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let relay = spawn_recorded_shaped_prefix(3000, std::sync::Arc::clone(&writes));

        let first_write = tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                if !writes.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            first_write.is_ok(),
            "the first bucket-sized segment must reach the writer promptly"
        );
        relay.abort();
    }

    /// Rate accounting may span a block larger than the bucket, but the
    /// wire write must still be segmented at the configured burst size.
    #[tokio::test]
    async fn shaped_prefix_never_writes_more_than_bucket_capacity_in_one_burst() {
        let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let relay = spawn_recorded_shaped_prefix(1001, std::sync::Arc::clone(&writes));

        let completed = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if writes.lock().unwrap().iter().map(Vec::len).sum::<usize>() >= 1001 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(completed.is_ok(), "the small shaped prefix must complete");
        let chunks = writes.lock().unwrap().clone();
        assert!(
            chunks.iter().all(|chunk| chunk.len() <= 1000),
            "no write may exceed the 1000-byte bucket capacity: {:?}",
            chunks.iter().map(Vec::len).collect::<Vec<_>>()
        );
        assert!(
            chunks.len() > 1,
            "an over-capacity block must be split, got {:?}",
            chunks.iter().map(Vec::len).collect::<Vec<_>>()
        );
        assert_eq!(chunks.concat(), vec![0x5a; 1001]);
        relay.abort();
    }

    #[tokio::test]
    async fn prefixed_cover_relay_writes_both_prefixes_once_and_preserves_half_close() {
        let (mut client_peer, client_inner) = tokio::io::duplex(8192);
        let (mut target_peer, target_inner) = tokio::io::duplex(8192);
        let relay = tokio::spawn(relay_cover_with_prefixes(
            Box::new(client_inner),
            Box::new(target_inner),
            CoverRelayPrefixes {
                upload: b"up-prefix".to_vec(),
                download: b"down-prefix".to_vec(),
                uploaded: 0,
                download_eof: false,
            },
            CoverBandwidthLimit::default(),
        ));

        let mut up = [0u8; 9];
        target_peer
            .read_exact(&mut up)
            .await
            .expect("upload prefix");
        assert_eq!(&up, b"up-prefix");
        let mut down = [0u8; 11];
        client_peer
            .read_exact(&mut down)
            .await
            .expect("download prefix");
        assert_eq!(&down, b"down-prefix");

        target_peer
            .write_all(b"target-suffix")
            .await
            .expect("target suffix write");
        let mut suffix = [0u8; 13];
        client_peer
            .read_exact(&mut suffix)
            .await
            .expect("target suffix relay");
        assert_eq!(&suffix, b"target-suffix");

        target_peer
            .shutdown()
            .await
            .expect("target write half-close");
        let mut eof = [0u8; 1];
        assert_eq!(
            client_peer.read(&mut eof).await.expect("client EOF read"),
            0,
            "target EOF half-closes the client write side after the prefixes"
        );

        client_peer
            .write_all(b"late-upload")
            .await
            .expect("upload after target EOF");
        let mut late = [0u8; 11];
        target_peer
            .read_exact(&mut late)
            .await
            .expect("independent upload side continues");
        assert_eq!(&late, b"late-upload");
        client_peer.shutdown().await.expect("client half-close");
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("relay completion timeout")
            .expect("relay task")
            .expect("relay result");
    }

    #[tokio::test]
    async fn prefixed_cover_relay_download_eof_delivers_prefix_then_half_closes() {
        let (mut client_peer, client_inner) = tokio::io::duplex(8192);
        let (mut target_peer, target_inner) = tokio::io::duplex(8192);
        let relay = tokio::spawn(relay_cover_with_prefixes(
            Box::new(client_inner),
            Box::new(target_inner),
            CoverRelayPrefixes {
                upload: Vec::new(),
                download: b"eof-prefix".to_vec(),
                uploaded: 0,
                download_eof: true,
            },
            CoverBandwidthLimit::default(),
        ));

        let mut down = [0u8; 10];
        client_peer
            .read_exact(&mut down)
            .await
            .expect("EOF download prefix");
        assert_eq!(&down, b"eof-prefix");
        let mut byte = [0u8; 1];
        assert_eq!(
            client_peer.read(&mut byte).await.expect("EOF after prefix"),
            0,
            "the preserved target EOF shuts down client writing even though the target peer is open"
        );

        client_peer
            .write_all(b"still-uploads")
            .await
            .expect("upload remains independent");
        let mut up = [0u8; 13];
        target_peer
            .read_exact(&mut up)
            .await
            .expect("upload reaches target");
        assert_eq!(&up, b"still-uploads");
        client_peer.shutdown().await.expect("client half-close");
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("relay completion timeout")
            .expect("relay task")
            .expect("relay result");
    }

    #[tokio::test]
    async fn uploaded_bytes_consume_the_cover_upload_exemption() {
        let mut limit = DirectionalLimit::with_transferred(1, 100, 1, 60);
        let granted = limit.wait_for_allowance(50).await;
        assert_eq!(
            granted, 41,
            "40 exemption bytes remain after 60 uploaded bytes, and one token is available"
        );
    }

    #[tokio::test]
    async fn v1_cover_relay_shape_is_unchanged_with_empty_probe_prefix_state() {
        let (mut client_peer, client_inner) = tokio::io::duplex(8192);
        let (mut target_peer, target_inner) = tokio::io::duplex(8192);
        let relay = CoverRelay::new(Box::new(client_inner), b"v1-hello".to_vec());
        let task = tokio::spawn(
            relay.relay_with_limit(Box::new(target_inner), CoverBandwidthLimit::default()),
        );

        let mut hello = [0u8; 8];
        target_peer
            .read_exact(&mut hello)
            .await
            .expect("v1 upload prefix");
        assert_eq!(&hello, b"v1-hello");
        target_peer
            .write_all(b"v1-download")
            .await
            .expect("v1 target bytes");
        let mut download = [0u8; 11];
        client_peer
            .read_exact(&mut download)
            .await
            .expect("v1 download relay");
        assert_eq!(&download, b"v1-download");
        client_peer
            .write_all(b"v1-suffix")
            .await
            .expect("v1 client suffix");
        let mut suffix = [0u8; 9];
        target_peer
            .read_exact(&mut suffix)
            .await
            .expect("v1 suffix relay");
        assert_eq!(&suffix, b"v1-suffix");

        client_peer.shutdown().await.expect("client half-close");
        target_peer.shutdown().await.expect("target half-close");
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("v1 relay completion timeout")
            .expect("v1 relay task")
            .expect("v1 relay result");
    }
}

#[cfg(test)]
mod independent_wire_vectors {
    use super::*;
    use std::collections::HashSet;

    use aes_gcm::aead::{Aead, AeadInPlace, KeyInit};
    use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
    use boring::sign::Verifier;
    use hmac::Mac;
    use sha2::{Digest, Sha256};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::DuplexStream;

    use crate::reality_mirror::{prepare_mirrored_flight_context_fixed, MirrorCryptoInput};
    use crate::reality_tls::RecordKey;

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/reality_independent_vectors.rs"
    ));

    type IndependentHmacSha256 = hmac::Hmac<Sha256>;
    type IndependentHmacSha512 = hmac::Hmac<sha2::Sha512>;

    fn hex_bytes(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex input must have even length");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("generated hex"))
            .collect()
    }

    fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
        hex_bytes(hex)
            .try_into()
            .expect("generated hex constant length")
    }

    struct DecodedVector {
        client_hello: Vec<u8>,
        aad: Vec<u8>,
        sid: Vec<u8>,
        shared: Vec<u8>,
        auth_key: Vec<u8>,
        plaintext: Vec<u8>,
    }

    fn decode_vector(vector: &FrozenHelloVector) -> DecodedVector {
        DecodedVector {
            client_hello: hex_bytes(vector.client_hello_hex),
            aad: hex_bytes(vector.aad_hex),
            sid: hex_bytes(vector.sid_hex),
            shared: hex_bytes(vector.shared_hex),
            auth_key: hex_bytes(vector.auth_key_hex),
            plaintext: hex_bytes(vector.plaintext_hex),
        }
    }

    fn vector_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(UNIX_SECONDS)
    }

    fn vector_config() -> RealityServerConfig {
        RealityServerConfig {
            private_key: hex_array(SERVER_STATIC_PRIVATE_HEX),
            short_ids: vec![hex_array(SHORT_ID_HEX)],
            server_names: HashSet::from([SERVER_NAME.to_string()]),
            max_time_difference: None,
            now: Some(vector_now),
        }
    }

    fn vector_server() -> RealityServer {
        RealityServer::new_with_ed25519_private_der(
            &vector_config(),
            &hex_bytes(ED25519_PRIVATE_DER_HEX),
        )
        .expect("fixed-vector REALITY server")
    }

    fn plaintext_record(payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() <= u16::MAX as usize);
        let mut out = Vec::with_capacity(payload.len() + 5);
        out.extend_from_slice(&[TLS_RECORD_HANDSHAKE, 0x03, 0x03]);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn independent_handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + body.len());
        out.push(kind);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        out.extend_from_slice(body);
        out
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut mac = <IndependentHmacSha256 as Mac>::new_from_slice(key)
            .expect("HMAC-SHA256 accepts any key length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().to_vec()
    }

    fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut mac = <IndependentHmacSha512 as Mac>::new_from_slice(key)
            .expect("HMAC-SHA512 accepts any key length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().to_vec()
    }

    fn hkdf_extract_independent(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        hmac_sha256(salt, &[ikm])
    }

    fn hkdf_expand_independent(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut okm = Vec::new();
        let mut previous = Vec::new();
        let mut counter = 1u8;
        while okm.len() < len {
            previous = hmac_sha256(prk, &[&previous, info, &[counter]]);
            okm.extend_from_slice(&previous);
            counter += 1;
        }
        okm.truncate(len);
        okm
    }

    fn hkdf_expand_label_independent(
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Vec<u8> {
        let mut info = Vec::new();
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push((6 + label.len()) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        hkdf_expand_independent(secret, &info, len)
    }

    fn derive_secret_independent(secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        hkdf_expand_label_independent(secret, label, transcript_hash, 32)
    }

    struct IndependentHandshakeSecrets {
        client_secret: Vec<u8>,
        server_secret: Vec<u8>,
        master_secret: Vec<u8>,
    }

    fn derive_handshake_secrets(
        shared_secret: &[u8],
        transcript: &[u8],
    ) -> IndependentHandshakeSecrets {
        let zero = [0u8; 32];
        let empty_hash = sha256(&[]);
        let early_secret = hkdf_extract_independent(&zero, &zero);
        let derived = derive_secret_independent(&early_secret, b"derived", &empty_hash);
        let handshake_secret = hkdf_extract_independent(&derived, shared_secret);
        let transcript_hash = sha256(transcript);
        let client_secret =
            derive_secret_independent(&handshake_secret, b"c hs traffic", &transcript_hash);
        let server_secret =
            derive_secret_independent(&handshake_secret, b"s hs traffic", &transcript_hash);
        let derived = derive_secret_independent(&handshake_secret, b"derived", &empty_hash);
        let master_secret = hkdf_extract_independent(&derived, &zero);
        IndependentHandshakeSecrets {
            client_secret,
            server_secret,
            master_secret,
        }
    }

    fn independent_finished_verify_data(secret: &[u8], transcript: &[u8]) -> Vec<u8> {
        let finished_key = hkdf_expand_label_independent(secret, b"finished", &[], 32);
        hmac_sha256(&finished_key, &[&sha256(transcript)])
    }

    type IndependentHmacSha384 = hmac::Hmac<sha2::Sha384>;

    fn hmac_sha384(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut mac = <IndependentHmacSha384 as Mac>::new_from_slice(key)
            .expect("HMAC-SHA384 accepts any key length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().to_vec()
    }

    /// Suite-parameterized transcript hash for the mirror oracle: TLS 1.3
    /// binds the hash to the cipher suite (SHA-384 only under
    /// TLS_AES_256_GCM_SHA384), so the independent recomputation must follow
    /// the suite instead of hardcoding SHA-256.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum OracleHash {
        Sha256,
        Sha384,
    }

    impl OracleHash {
        fn for_cipher(cipher: u16) -> Self {
            if cipher == TLS_AES_256_GCM_SHA384 {
                Self::Sha384
            } else {
                Self::Sha256
            }
        }

        fn len(self) -> usize {
            match self {
                Self::Sha256 => 32,
                Self::Sha384 => 48,
            }
        }

        fn digest(self, data: &[u8]) -> Vec<u8> {
            match self {
                Self::Sha256 => Sha256::digest(data).to_vec(),
                Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            }
        }

        fn hmac(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            match self {
                Self::Sha256 => hmac_sha256(key, parts),
                Self::Sha384 => hmac_sha384(key, parts),
            }
        }

        fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
            self.hmac(salt, &[ikm])
        }

        fn expand(self, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
            let mut okm = Vec::new();
            let mut previous = Vec::new();
            let mut counter = 1u8;
            while okm.len() < len {
                previous = self.hmac(prk, &[&previous, info, &[counter]]);
                okm.extend_from_slice(&previous);
                counter += 1;
            }
            okm.truncate(len);
            okm
        }

        fn expand_label(self, secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
            let mut info = Vec::new();
            info.extend_from_slice(&(len as u16).to_be_bytes());
            info.push((6 + label.len()) as u8);
            info.extend_from_slice(b"tls13 ");
            info.extend_from_slice(label);
            info.push(context.len() as u8);
            info.extend_from_slice(context);
            self.expand(secret, &info, len)
        }

        fn derive_secret(self, secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
            self.expand_label(secret, label, transcript_hash, self.len())
        }
    }

    struct IndependentRecordKey {
        cipher: Aes128Gcm,
        iv: [u8; 12],
        seq: u64,
    }

    impl IndependentRecordKey {
        fn new(secret: &[u8]) -> Self {
            let key = hkdf_expand_label_independent(secret, b"key", &[], 16);
            let iv = hkdf_expand_label_independent(secret, b"iv", &[], 12);
            Self {
                cipher: Aes128Gcm::new_from_slice(&key).expect("AES-128 key length"),
                iv: iv.try_into().expect("TLS IV length"),
                seq: 0,
            }
        }

        fn next_nonce(&mut self) -> [u8; 12] {
            assert_ne!(self.seq, u64::MAX, "test nonce sequence must not wrap");
            let mut nonce = self.iv;
            for (dst, src) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
                *dst ^= src;
            }
            self.seq += 1;
            nonce
        }

        fn seal(&mut self, inner_type: u8, plaintext: &[u8]) -> Vec<u8> {
            let body_len = plaintext.len() + 1;
            let record_len = body_len + 16;
            let mut header = [TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0, 0];
            header[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
            let nonce = self.next_nonce();
            let mut body = plaintext.to_vec();
            body.push(inner_type);
            let tag = self
                .cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), &header, &mut body)
                .expect("independent TLS record seal");
            body.extend_from_slice(&tag);
            let mut out = header.to_vec();
            out.extend_from_slice(&body);
            out
        }

        fn open(&mut self, header: &[u8; 5], payload: &[u8]) -> (u8, Vec<u8>) {
            let split = payload
                .len()
                .checked_sub(16)
                .expect("TLS ciphertext carries a tag");
            let (data, tag) = payload.split_at(split);
            let nonce = self.next_nonce();
            let mut body = data.to_vec();
            self.cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    header,
                    &mut body,
                    Tag::from_slice(tag),
                )
                .expect("independent TLS record open");
            let type_pos = body
                .iter()
                .rposition(|byte| *byte != 0)
                .expect("TLS inner plaintext type");
            let inner_type = body[type_pos];
            body.truncate(type_pos);
            (inner_type, body)
        }
    }

    fn independent_take<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> &'a [u8] {
        let end = pos.checked_add(len).expect("parser offset overflow");
        let out = input.get(*pos..end).expect("parser input truncated");
        *pos = end;
        out
    }

    fn independent_u16(input: &[u8], pos: &mut usize) -> u16 {
        let bytes = independent_take(input, pos, 2);
        u16::from_be_bytes([bytes[0], bytes[1]])
    }

    fn independent_u24(input: &[u8], pos: &mut usize) -> usize {
        let bytes = independent_take(input, pos, 3);
        ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
    }

    struct IndependentServerHello {
        cipher_suite: u16,
        session_id: Vec<u8>,
        group: u16,
        share: Vec<u8>,
    }

    fn parse_server_hello_independent(raw: &[u8]) -> IndependentServerHello {
        assert_eq!(raw[0], HS_SERVER_HELLO);
        let mut pos = 1;
        let body_len = independent_u24(raw, &mut pos);
        assert_eq!(pos + body_len, raw.len(), "one exact ServerHello message");
        assert_eq!(independent_take(raw, &mut pos, 2), &[0x03, 0x03]);
        independent_take(raw, &mut pos, 32);
        let sid_len = independent_take(raw, &mut pos, 1)[0] as usize;
        let session_id = independent_take(raw, &mut pos, sid_len).to_vec();
        let cipher_suite = independent_u16(raw, &mut pos);
        assert_eq!(independent_take(raw, &mut pos, 1), &[0]);
        let extensions_len = independent_u16(raw, &mut pos) as usize;
        let extensions_end = pos + extensions_len;
        let mut key_share = None;
        while pos < extensions_end {
            let ext_type = independent_u16(raw, &mut pos);
            let ext_len = independent_u16(raw, &mut pos) as usize;
            let data = independent_take(raw, &mut pos, ext_len);
            match ext_type {
                EXT_SUPPORTED_VERSIONS => assert_eq!(data, &[0x03, 0x04]),
                EXT_KEY_SHARE => {
                    let mut kp = 0;
                    let group = independent_u16(data, &mut kp);
                    let share_len = independent_u16(data, &mut kp) as usize;
                    let share = independent_take(data, &mut kp, share_len).to_vec();
                    assert_eq!(kp, data.len(), "ServerHello key_share exact length");
                    key_share = Some((group, share));
                }
                _ => panic!("unexpected ServerHello extension {ext_type:#x}"),
            }
        }
        assert_eq!(pos, extensions_end);
        let (group, share) = key_share.expect("ServerHello key_share");
        IndependentServerHello {
            cipher_suite,
            session_id,
            group,
            share,
        }
    }

    struct IndependentHandshakeMessage {
        kind: u8,
        raw: Vec<u8>,
        body: Vec<u8>,
    }

    fn split_handshake_messages(plaintext: &[u8]) -> Vec<IndependentHandshakeMessage> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < plaintext.len() {
            let kind = independent_take(plaintext, &mut pos, 1)[0];
            let len = independent_u24(plaintext, &mut pos);
            let start = pos - 4;
            let body = independent_take(plaintext, &mut pos, len).to_vec();
            out.push(IndependentHandshakeMessage {
                kind,
                raw: plaintext[start..pos].to_vec(),
                body,
            });
        }
        out
    }

    fn extract_certificate_der(message: &IndependentHandshakeMessage) -> Vec<u8> {
        assert_eq!(message.kind, HS_CERTIFICATE);
        let body = &message.body;
        assert_eq!(body[0], 0, "empty certificate request context");
        let mut pos = 1;
        let list_len = independent_u24(body, &mut pos);
        assert_eq!(pos + list_len, body.len(), "single exact certificate list");
        let der_len = independent_u24(body, &mut pos);
        let der = independent_take(body, &mut pos, der_len).to_vec();
        let extensions_len = independent_u16(body, &mut pos) as usize;
        assert_eq!(extensions_len, 0, "no leaf extensions in the server vector");
        assert_eq!(pos, body.len(), "exactly one certificate entry");
        der
    }

    fn extract_certificate_verify(message: &IndependentHandshakeMessage) -> Vec<u8> {
        assert_eq!(message.kind, HS_CERTIFICATE_VERIFY);
        assert_eq!(&message.body[..2], &SIG_ED25519.to_be_bytes());
        assert_eq!(&message.body[2..4], &64u16.to_be_bytes());
        assert_eq!(message.body.len(), 4 + 64);
        message.body[4..].to_vec()
    }

    fn verify_ed25519_signature(signature: &[u8], input: &[u8]) {
        let key = PKey::public_key_from_der(&hex_bytes(ED25519_SPKI_DER_HEX))
            .expect("fixed Ed25519 SPKI");
        let mut verifier = Verifier::new_without_digest(&key).expect("Ed25519 verifier");
        assert!(
            verifier
                .verify_oneshot(signature, input)
                .expect("Ed25519 verification"),
            "CertificateVerify signature must verify over the independent transcript input"
        );
    }

    fn expected_leaf_for_auth_key(auth_key: &[u8]) -> Vec<u8> {
        let mut der = hex_bytes(LEAF_DER_HEX);
        let mac = hmac_sha512(auth_key, &[&hex_bytes(ED25519_PUBLIC_HEX)]);
        assert_eq!(mac.len(), 64);
        let signature_start = der.len() - 64;
        der[signature_start..].copy_from_slice(&mac);
        der
    }

    fn independent_shared_secret(
        server_hello: &IndependentServerHello,
        client_x25519_private: &[u8; 32],
        hybrid_x25519_private: &[u8; 32],
        mlkem_seed: &[u8; 64],
    ) -> Vec<u8> {
        if server_hello.group == GROUP_X25519 {
            assert_eq!(server_hello.share.len(), 32);
            let server_public: [u8; 32] = server_hello
                .share
                .as_slice()
                .try_into()
                .expect("X25519 server share length");
            let secret = x25519_dalek::x25519(*client_x25519_private, server_public);
            assert_ne!(secret, [0u8; 32], "low-order TLS ECDH must be rejected");
            return secret.to_vec();
        }
        assert_eq!(server_hello.group, GROUP_X25519_MLKEM768);
        assert_eq!(server_hello.share.len(), 1088 + 32);
        let mlkem = boring::mlkem::MlKemPrivateKey::from_seed(
            boring::mlkem::Algorithm::MlKem768,
            mlkem_seed,
        )
        .expect("fixed ML-KEM seed");
        let mlkem_secret = mlkem
            .decapsulate(&server_hello.share[..1088])
            .expect("server ML-KEM ciphertext decapsulates");
        let server_x: [u8; 32] = server_hello.share[1088..]
            .try_into()
            .expect("hybrid X25519 server share length");
        let x_secret = x25519_dalek::x25519(*hybrid_x25519_private, server_x);
        assert_ne!(x_secret, [0u8; 32], "low-order hybrid TLS ECDH");
        let mut shared = mlkem_secret.to_vec();
        shared.extend_from_slice(&x_secret);
        shared
    }

    async fn read_required_record(
        io: &mut DuplexStream,
        what: &str,
    ) -> crate::reality_tls::TlsRecord {
        tokio::time::timeout(Duration::from_secs(2), read_record(io))
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .unwrap_or_else(|e| panic!("failed to read {what}: {e}"))
            .unwrap_or_else(|| panic!("EOF before {what}"))
    }

    #[derive(Clone, Copy, Debug)]
    enum HelloFraming {
        SingleRecord,
        ByteWiseTcp,
        SplitRecords(&'static [usize]),
    }

    async fn write_client_hello(io: &mut DuplexStream, hello: &[u8], framing: HelloFraming) {
        match framing {
            HelloFraming::SingleRecord => {
                io.write_all(&plaintext_record(hello)).await.unwrap();
            }
            HelloFraming::ByteWiseTcp => {
                for byte in plaintext_record(hello).chunks(1) {
                    io.write_all(byte).await.unwrap();
                    io.flush().await.unwrap();
                }
            }
            HelloFraming::SplitRecords(pattern) => {
                assert!(pattern.iter().all(|len| *len != 0));
                let mut pos = 0;
                let mut index = 0;
                while pos < hello.len() {
                    let len = pattern[index % pattern.len()].min(hello.len() - pos);
                    io.write_all(&plaintext_record(&hello[pos..pos + len]))
                        .await
                        .unwrap();
                    pos += len;
                    index += 1;
                }
            }
        }
        io.flush().await.unwrap();
    }

    struct CompletedVectorHandshake {
        server_stream: Box<dyn Stream>,
        client_io: DuplexStream,
        client_app: IndependentRecordKey,
        server_app: IndependentRecordKey,
        client_finished_record: Vec<u8>,
        certificate_der: Vec<u8>,
        selected_group: u16,
    }

    async fn perform_vector_handshake(
        server: RealityServer,
        vector: &FrozenHelloVector,
        framing: HelloFraming,
    ) -> CompletedVectorHandshake {
        let decoded = decode_vector(vector);
        perform_independent_client_handshake(
            server,
            &decoded.client_hello,
            &decoded.auth_key,
            framing,
        )
        .await
    }

    async fn perform_independent_client_handshake(
        server: RealityServer,
        client_hello: &[u8],
        auth_key: &[u8],
        framing: HelloFraming,
    ) -> CompletedVectorHandshake {
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        write_client_hello(&mut client_io, client_hello, framing).await;

        let server_hello_record = read_required_record(&mut client_io, "ServerHello").await;
        assert_eq!(server_hello_record.typ, TLS_RECORD_HANDSHAKE);
        let server_hello = parse_server_hello_independent(&server_hello_record.payload);
        assert_eq!(server_hello.cipher_suite, TLS_AES_128_GCM_SHA256);
        assert_eq!(
            server_hello.session_id,
            client_hello[39..71],
            "ServerHello must echo the encrypted REALITY session id"
        );
        let ccs = read_required_record(&mut client_io, "compatibility CCS").await;
        assert_eq!(ccs.typ, TLS_RECORD_CHANGE_CIPHER_SPEC);
        assert_eq!(ccs.payload, [1]);
        let encrypted_flight =
            read_required_record(&mut client_io, "encrypted server flight").await;
        assert_eq!(encrypted_flight.typ, TLS_RECORD_APPLICATION_DATA);

        let mut transcript = client_hello.to_vec();
        transcript.extend_from_slice(&server_hello_record.payload);
        let shared = independent_shared_secret(
            &server_hello,
            &hex_array(CLIENT_X25519_PRIVATE_HEX),
            &hex_array(HYBRID_X25519_PRIVATE_HEX),
            &hex_array(MLKEM768_SEED_HEX),
        );
        let secrets = derive_handshake_secrets(&shared, &transcript);
        let mut client_hs = IndependentRecordKey::new(&secrets.client_secret);
        let mut server_hs = IndependentRecordKey::new(&secrets.server_secret);
        let (inner_type, flight_plaintext) =
            server_hs.open(&encrypted_flight.header, &encrypted_flight.payload);
        assert_eq!(inner_type, TLS_RECORD_HANDSHAKE);
        let messages = split_handshake_messages(&flight_plaintext);
        assert_eq!(
            messages
                .iter()
                .map(|message| message.kind)
                .collect::<Vec<_>>(),
            vec![
                HS_ENCRYPTED_EXTENSIONS,
                HS_CERTIFICATE,
                HS_CERTIFICATE_VERIFY,
                HS_FINISHED
            ],
            "server flight message order"
        );
        assert_eq!(messages[0].body, [0, 0], "empty EncryptedExtensions vector");
        let certificate_der = extract_certificate_der(&messages[1]);
        assert_eq!(
            certificate_der,
            expected_leaf_for_auth_key(auth_key),
            "certificate HMAC must match the independent AuthKey/public-key vector"
        );
        let cv_signature = extract_certificate_verify(&messages[2]);

        let mut transcript_through_certificate = transcript.clone();
        transcript_through_certificate.extend_from_slice(&messages[0].raw);
        transcript_through_certificate.extend_from_slice(&messages[1].raw);
        let mut cv_input = vec![0x20; 64];
        cv_input.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        cv_input.push(0);
        cv_input.extend_from_slice(&sha256(&transcript_through_certificate));
        verify_ed25519_signature(&cv_signature, &cv_input);

        let mut transcript_through_cv = transcript_through_certificate.clone();
        transcript_through_cv.extend_from_slice(&messages[2].raw);
        assert_eq!(
            messages[3].body,
            independent_finished_verify_data(&secrets.server_secret, &transcript_through_cv),
            "server Finished verify_data must match the independent TLS key schedule"
        );
        let mut transcript_with_server_finished = transcript_through_cv.clone();
        transcript_with_server_finished.extend_from_slice(&messages[3].raw);

        let client_verify = independent_finished_verify_data(
            &secrets.client_secret,
            &transcript_with_server_finished,
        );
        let client_finished = independent_handshake_message(HS_FINISHED, &client_verify);
        let client_finished_record = client_hs.seal(TLS_RECORD_HANDSHAKE, &client_finished);
        client_io.write_all(&client_finished_record).await.unwrap();
        client_io.flush().await.unwrap();

        let accepted = tokio::time::timeout(Duration::from_secs(2), accept_task)
            .await
            .expect("REALITY accept timed out")
            .expect("REALITY accept task joined")
            .expect("independent vector Finished must be accepted");
        let RealityServerAccept::Authenticated(server_stream) = accepted else {
            panic!("valid frozen vector must select the authenticated branch");
        };

        let client_app_secret = hkdf_expand_label_independent(
            &secrets.master_secret,
            b"c ap traffic",
            &sha256(&transcript_with_server_finished),
            32,
        );
        let server_app_secret = hkdf_expand_label_independent(
            &secrets.master_secret,
            b"s ap traffic",
            &sha256(&transcript_with_server_finished),
            32,
        );
        CompletedVectorHandshake {
            server_stream,
            client_io,
            client_app: IndependentRecordKey::new(&client_app_secret),
            server_app: IndependentRecordKey::new(&server_app_secret),
            client_finished_record,
            certificate_der,
            selected_group: server_hello.group,
        }
    }

    async fn assert_vector_roundtrip(completed: &mut CompletedVectorHandshake) {
        let ping = completed
            .client_app
            .seal(TLS_RECORD_APPLICATION_DATA, b"ping");
        completed.client_io.write_all(&ping).await.unwrap();
        completed.client_io.flush().await.unwrap();
        let mut buf = [0u8; 4];
        completed.server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        completed.server_stream.write_all(b"pong").await.unwrap();
        completed.server_stream.flush().await.unwrap();
        let record = read_required_record(&mut completed.client_io, "application pong").await;
        assert_eq!(record.typ, TLS_RECORD_APPLICATION_DATA);
        let (inner_type, plaintext) = completed.server_app.open(&record.header, &record.payload);
        assert_eq!(inner_type, TLS_RECORD_APPLICATION_DATA);
        assert_eq!(plaintext, b"pong");
    }

    async fn accept_cover_for_bytes(
        server: RealityServer,
        hello: &[u8],
        trailing: &[u8],
    ) -> (CoverRelay, DuplexStream) {
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        let mut input = plaintext_record(hello);
        input.extend_from_slice(trailing);
        client_io.write_all(&input).await.unwrap();
        client_io.flush().await.unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(2), accept_task)
            .await
            .expect("cover accept timed out")
            .expect("cover accept task joined")
            .expect("cover classification must not be an I/O error");
        let RealityServerAccept::Cover(relay) = accepted else {
            panic!("negative vector must fall through to cover");
        };
        (relay, client_io)
    }

    async fn assert_no_response_bytes(client_io: &mut DuplexStream) {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(5), client_io.read(&mut byte)).await {
            Err(_) => {}
            Ok(Ok(0)) => panic!("cover branch closed before any cover-target relay"),
            Ok(Ok(n)) => panic!("unauthenticated candidate received {n} response bytes"),
            Ok(Err(e)) => panic!("failed while checking for cover-branch response bytes: {e}"),
        }
    }

    #[test]
    fn frozen_positive_vector_matches_independent_oracle_byte_for_byte() {
        let decoded = decode_vector(&POSITIVE_X25519);
        assert_eq!(decoded.client_hello.len(), 204);
        assert_eq!(decoded.client_hello[0], HS_CLIENT_HELLO);
        assert_eq!(decoded.client_hello[38], 0x20);
        assert_eq!(decoded.client_hello[39..71], decoded.sid[..]);
        let mut reconstructed_aad = decoded.client_hello.clone();
        reconstructed_aad[39..71].fill(0);
        assert_eq!(reconstructed_aad, decoded.aad);
        assert_eq!(decoded.plaintext.len(), 16);

        let server_private = hex_array::<32>(SERVER_STATIC_PRIVATE_HEX);
        let client_public = hex_array::<32>(CLIENT_X25519_PUBLIC_HEX);
        let shared = x25519(&server_private, &client_public).expect("vector ECDH");
        assert_eq!(shared.as_slice(), decoded.shared.as_slice());
        let auth_key = hkdf_sha256(&shared[..], &decoded.client_hello[6..26], b"REALITY", 32);
        assert_eq!(auth_key[..], decoded.auth_key);

        let mut parsed = parse_client_hello(decoded.client_hello.clone()).expect("vector parses");
        let server = vector_server();
        let OpenedAuth(opened_key, plaintext) = server
            .open_auth_plaintext(&mut parsed)
            .expect("positive frozen vector must authenticate cryptographically");
        assert_eq!(opened_key.as_slice(), decoded.auth_key.as_slice());
        assert_eq!(plaintext[..], decoded.plaintext);
        let (version, reserved, unix_seconds, short_id) =
            parse_auth_plaintext(&plaintext).expect("16-byte auth plaintext parses");
        assert_eq!(version.as_slice(), hex_bytes(VERSION_HEX));
        assert_eq!(reserved, 0);
        assert_eq!(unix_seconds, UNIX_SECONDS as u32);
        assert_eq!(short_id.as_slice(), hex_bytes(SHORT_ID_HEX));
        assert!(
            server.classify(&mut parsed).is_some(),
            "positive vector also satisfies the frozen time window and Short ID"
        );
    }

    #[test]
    fn frozen_vector_key_material_is_bound_to_wire_bytes() {
        let positive = hex_bytes(POSITIVE_X25519.client_hello_hex);
        assert_eq!(&positive[6..38], &hex_bytes(RANDOM32_HEX));
        assert_eq!(
            x25519_public_from_private(&hex_array(SERVER_STATIC_PRIVATE_HEX)),
            hex_array::<32>(SERVER_STATIC_PUBLIC_HEX)
        );
        assert_eq!(
            x25519_public_from_private(&hex_array(CLIENT_X25519_PRIVATE_HEX)),
            hex_array::<32>(CLIENT_X25519_PUBLIC_HEX)
        );
        assert_eq!(
            x25519_public_from_private(&hex_array(HYBRID_X25519_PRIVATE_HEX)),
            hex_array::<32>(HYBRID_X25519_PUBLIC_HEX)
        );
        assert_eq!(
            x25519_public_from_private(&hex_array(WRONG_X25519_PRIVATE_HEX)),
            hex_array::<32>(WRONG_X25519_PUBLIC_HEX)
        );

        let mut hybrid_share = hex_bytes(MLKEM768_PUBLIC_HEX);
        hybrid_share.extend_from_slice(&hex_bytes(HYBRID_X25519_PUBLIC_HEX));
        for vector in [&POSITIVE_HYBRID, &DUAL_SHARE, &LOW_ORDER] {
            let hello = hex_bytes(vector.client_hello_hex);
            assert!(
                hello
                    .windows(hybrid_share.len())
                    .any(|window| window == hybrid_share),
                "{} must carry the frozen ML-KEM public key followed by the hybrid X25519 share",
                vector.name
            );
        }
        let duplicate = hex_bytes(DUPLICATE_KEY_SHARE.client_hello_hex);
        assert!(
            duplicate
                .windows(32)
                .any(|window| window == hex_bytes(WRONG_X25519_PUBLIC_HEX)),
            "the duplicate key_share vector carries the wrong second share as its negative control"
        );
    }

    #[test]
    fn fixed_leaf_hmac_and_certificate_verify_match_python_oracle() {
        let certificate =
            RealityCertificate::from_private_key_der(&hex_bytes(ED25519_PRIVATE_DER_HEX))
                .expect("fixed Ed25519 key");
        let auth_key = hex_array::<32>(POSITIVE_X25519.auth_key_hex);
        let leaf = certificate.for_auth_key(&auth_key);
        assert_eq!(leaf, hex_bytes(LEAF_DER_HEX));
        assert_eq!(
            &leaf[leaf.len() - 64..],
            &hex_bytes(CERTIFICATE_HMAC_HEX),
            "X.509 signatureValue content is exactly HMAC-SHA512(AuthKey, raw Ed25519 public key)"
        );

        let cv_input = certificate_verify_input(&hex_bytes(CV_TRANSCRIPT_HASH_HEX));
        assert_eq!(cv_input, hex_bytes(CV_INPUT_HEX));
        let cv_signature = certificate.sign(&cv_input).expect("sign fixed CV input");
        assert_eq!(
            cv_signature,
            hex_bytes(CV_SIGNATURE_HEX),
            "Ed25519 is deterministic; the signature must equal the Python cryptography oracle"
        );
        verify_ed25519_signature(&cv_signature, &cv_input);
    }

    #[tokio::test]
    async fn frozen_x25519_vector_completes_full_handshake_and_round_trips() {
        let mut completed = perform_vector_handshake(
            vector_server(),
            &POSITIVE_X25519,
            HelloFraming::SingleRecord,
        )
        .await;
        assert_eq!(completed.selected_group, GROUP_X25519);
        assert_eq!(completed.certificate_der, hex_bytes(LEAF_DER_HEX));
        assert_vector_roundtrip(&mut completed).await;
    }

    #[tokio::test]
    async fn hybrid_only_vector_uses_final_32_bytes_and_completes() {
        let mut completed = perform_vector_handshake(
            vector_server(),
            &POSITIVE_HYBRID,
            HelloFraming::SingleRecord,
        )
        .await;
        assert_eq!(completed.selected_group, GROUP_X25519_MLKEM768);
        assert_vector_roundtrip(&mut completed).await;
    }

    #[tokio::test]
    async fn dual_share_authentication_prefers_independent_x25519() {
        assert_eq!(DUAL_SHARE.shared_hex, POSITIVE_X25519.shared_hex);
        assert_ne!(DUAL_SHARE.shared_hex, POSITIVE_HYBRID.shared_hex);
        let mut completed =
            perform_vector_handshake(vector_server(), &DUAL_SHARE, HelloFraming::SingleRecord)
                .await;
        assert_eq!(
            completed.selected_group, GROUP_X25519_MLKEM768,
            "the TLS key exchange still prefers the offered hybrid share"
        );
        assert_vector_roundtrip(&mut completed).await;
    }

    #[tokio::test]
    async fn single_bit_tampering_of_aad_ciphertext_or_tag_goes_to_cover() {
        let base = decode_vector(&POSITIVE_X25519).client_hello;
        for position in [
            6,                      // client_random[0]: HKDF salt and AAD
            PADDING_PAYLOAD_OFFSET, // ignored padding payload byte: pure AAD
            39,                     // first ciphertext byte
            54,                     // last ciphertext byte
            55,                     // first GCM tag byte
            70,                     // last GCM tag byte
        ] {
            let mut tampered = base.clone();
            tampered[position] ^= 1;
            let (relay, mut client_io) =
                accept_cover_for_bytes(vector_server(), &tampered, &[]).await;
            assert_eq!(
                relay.wire_prefix_len(),
                plaintext_record(&tampered).len(),
                "position {position}: cover receives exactly the consumed CH record"
            );
            assert_no_response_bytes(&mut client_io).await;
        }
    }

    #[tokio::test]
    async fn low_order_x25519_auth_share_is_rejected_without_panic() {
        assert_eq!(hex_bytes(LOW_ORDER.shared_hex), vec![0u8; 32]);
        let decoded = decode_vector(&LOW_ORDER);
        let (relay, mut client_io) =
            accept_cover_for_bytes(vector_server(), &decoded.client_hello, &[]).await;
        assert_eq!(
            relay.wire_prefix_len(),
            plaintext_record(&decoded.client_hello).len()
        );
        assert_no_response_bytes(&mut client_io).await;
    }

    #[tokio::test]
    async fn duplicate_key_share_and_supported_versions_are_rejected() {
        // Implementation semantics pinned here: a duplicate extension is
        // rejected outright.  The two key_share orders rule out both
        // first-wins and last-wins fallback interpretation.
        for vector in [
            &DUPLICATE_KEY_SHARE,
            &DUPLICATE_KEY_SHARE_REVERSED,
            &DUPLICATE_SUPPORTED_VERSIONS,
        ] {
            let decoded = decode_vector(vector);
            let (relay, mut client_io) =
                accept_cover_for_bytes(vector_server(), &decoded.client_hello, &[]).await;
            assert_eq!(
                relay.wire_prefix_len(),
                plaintext_record(&decoded.client_hello).len(),
                "{} duplicate extension must preserve exactly the CH wire prefix",
                vector.name
            );
            assert_no_response_bytes(&mut client_io).await;
        }
    }

    #[tokio::test]
    async fn byte_by_byte_tcp_fragmentation_has_the_same_authentication_result() {
        let mut completed =
            perform_vector_handshake(vector_server(), &POSITIVE_X25519, HelloFraming::ByteWiseTcp)
                .await;
        assert_eq!(completed.selected_group, GROUP_X25519);
        assert_vector_roundtrip(&mut completed).await;
    }

    #[tokio::test]
    async fn pseudo_random_record_fragmentation_has_the_same_authentication_result() {
        const PATTERN: &[usize] = &[1, 2, 7, 3, 31, 5, 11, 13];
        let mut completed = perform_vector_handshake(
            vector_server(),
            &POSITIVE_X25519,
            HelloFraming::SplitRecords(PATTERN),
        )
        .await;
        assert_eq!(completed.selected_group, GROUP_X25519);
        assert_vector_roundtrip(&mut completed).await;
    }

    #[tokio::test]
    async fn valid_client_hello_preflight_stops_exactly_before_trailing_bytes() {
        let hello = decode_vector(&POSITIVE_X25519).client_hello;
        let expected_prefix = plaintext_record(&hello);
        let trailing = b"already-readable trailing bytes";
        let mut batch = expected_prefix.clone();
        batch.extend_from_slice(trailing);
        let (mut writer, reader) = tokio::io::duplex(128 * 1024);
        writer.write_all(&batch).await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);

        let (mut inner, preflight) = read_client_hello_preflight(Box::new(reader))
            .await
            .expect("valid vector preflight");
        let Preflight::Candidate { wire_prefix, .. } = preflight else {
            panic!("valid frozen vector must remain a REALITY candidate");
        };
        assert_eq!(wire_prefix, expected_prefix);
        let mut got = vec![0u8; trailing.len()];
        inner.read_exact(&mut got).await.unwrap();
        assert_eq!(got, trailing);
    }

    #[tokio::test]
    async fn trailing_bytes_in_same_write_are_not_consumed_from_cover_stream() {
        let mut tampered = decode_vector(&POSITIVE_X25519).client_hello;
        tampered[70] ^= 1;
        let trailing = b"trailing bytes in the same write batch";
        let expected_prefix = plaintext_record(&tampered);
        let (relay, client_io) = accept_cover_for_bytes(vector_server(), &tampered, trailing).await;
        assert_eq!(relay.wire_prefix_len(), expected_prefix.len());
        let (target_io, mut target_peer) = tokio::io::duplex(128 * 1024);
        let relay_task = tokio::spawn(async move { relay.relay(Box::new(target_io)).await });

        let mut got = vec![0u8; expected_prefix.len() + trailing.len()];
        target_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..expected_prefix.len()], &expected_prefix[..]);
        assert_eq!(&got[expected_prefix.len()..], trailing);
        drop(client_io);
        drop(target_peer);
        relay_task.abort();
    }

    #[tokio::test]
    async fn replayed_client_hello_is_accepted_but_replayed_old_finished_fails() {
        // REALITY deliberately has no nonce replay cache in the freshness
        // window: the same authenticated CH may open a new TLS transcript.
        // A replayed Finished is cryptographically bound to the old random
        // ServerHello/ephemeral share and must not validate on the new one.
        let server = vector_server();
        let first =
            perform_vector_handshake(server.clone(), &POSITIVE_X25519, HelloFraming::SingleRecord)
                .await;
        let old_finished = first.client_finished_record.clone();
        drop(first);

        let second =
            perform_vector_handshake(server.clone(), &POSITIVE_X25519, HelloFraming::SingleRecord)
                .await;
        assert_eq!(second.selected_group, GROUP_X25519);
        drop(second);

        let hello = decode_vector(&POSITIVE_X25519).client_hello;
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let accept_task = tokio::spawn(async move { server.accept(Box::new(server_io)).await });
        client_io
            .write_all(&plaintext_record(&hello))
            .await
            .unwrap();
        client_io.write_all(&old_finished).await.unwrap();
        client_io.flush().await.unwrap();
        let accept_result = tokio::time::timeout(Duration::from_secs(2), accept_task)
            .await
            .expect("old-Finished accept timed out")
            .expect("old-Finished accept task joined");
        assert!(
            accept_result.is_err(),
            "a Finished replayed from the first transcript must fail on the second"
        );
    }

    #[tokio::test]
    async fn authenticated_reality_does_not_depend_on_cover_target_availability() {
        // The acceptor API has no cover dialer at all on the authenticated
        // branch.  Completing this handshake without any target object is the
        // transport-level proof that a down target cannot affect REALITY auth.
        let mut completed = perform_vector_handshake(
            vector_server(),
            &POSITIVE_X25519,
            HelloFraming::SingleRecord,
        )
        .await;
        assert_vector_roundtrip(&mut completed).await;
    }

    #[tokio::test]
    async fn cover_drop_after_simulated_target_dial_failure_closes_client_cleanly() {
        // Ownership of dialing belongs to the inbound listener; the transport
        // contract exercised here is the failure path after that dial returns
        // error: drop the relay exactly once, with no background task or write.
        let mut tampered = decode_vector(&POSITIVE_X25519).client_hello;
        tampered[70] ^= 1;
        let (relay, mut client_io) = accept_cover_for_bytes(vector_server(), &tampered, &[]).await;
        drop(relay);
        let mut byte = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), client_io.read(&mut byte))
            .await
            .expect("client close timed out")
            .expect("client close read");
        assert_eq!(
            n, 0,
            "dropping a never-dialed cover must close the client side"
        );
    }

    const MIRROR_RECORD_LENGTHS: [u16; 4] = [25, 3217, 281, 69];

    struct MirrorVectorSession {
        client_io: DuplexStream,
        stream: Box<dyn Stream>,
        completion: crate::reality_mirror::MirroredHandshakeCompletion,
    }

    fn mirror_target_prefix(vector: &FrozenMirrorVector) -> Vec<u8> {
        let mut prefix = plaintext_record(&hex_bytes(vector.target_sh_hex));
        prefix.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        for len in MIRROR_RECORD_LENGTHS {
            prefix.extend_from_slice(&[0x17, 0x03, 0x03]);
            prefix.extend_from_slice(&len.to_be_bytes());
            prefix.resize(prefix.len() + usize::from(len), 0);
        }
        prefix
    }

    fn mirror_fixed_crypto(vector: &FrozenMirrorVector) -> MirrorCryptoInput {
        MirrorCryptoInput {
            server_random: hex_array(vector.server_random_hex),
            x25519_private: Zeroizing::new(hex_array(vector.server_x25519_private_hex)),
            mlkem_ciphertext: (!vector.mlkem_ciphertext_hex.is_empty())
                .then(|| hex_bytes(vector.mlkem_ciphertext_hex)),
            mlkem_secret: (!vector.mlkem_secret_hex.is_empty())
                .then(|| Zeroizing::new(hex_bytes(vector.mlkem_secret_hex))),
        }
    }

    async fn open_mirror_vector_session(vector: &FrozenMirrorVector) -> MirrorVectorSession {
        open_mirror_vector_session_with_crypto(vector, mirror_fixed_crypto(vector), true).await
    }

    async fn open_mirror_vector_session_with_crypto(
        vector: &FrozenMirrorVector,
        crypto: MirrorCryptoInput,
        expect_frozen_wire: bool,
    ) -> MirrorVectorSession {
        open_mirror_vector_session_framed(
            vector,
            crypto,
            expect_frozen_wire,
            HelloFraming::SingleRecord,
        )
        .await
    }

    async fn open_mirror_vector_session_framed(
        vector: &FrozenMirrorVector,
        crypto: MirrorCryptoInput,
        expect_frozen_wire: bool,
        framing: HelloFraming,
    ) -> MirrorVectorSession {
        let server = vector_server();
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let classify_server = server.clone();
        let classify_task = tokio::spawn(async move {
            classify_server
                .verify_client_hello(Box::new(server_io))
                .await
        });
        let single_record = matches!(framing, HelloFraming::SingleRecord);
        write_client_hello(&mut client_io, &hex_bytes(vector.ch_message_hex), framing).await;
        let classified = tokio::time::timeout(Duration::from_secs(2), classify_task)
            .await
            .expect("mirror classification timed out")
            .expect("mirror classification joined")
            .expect("mirror classification io");
        let RealityClientHello::Verified { stream, hello } = classified else {
            panic!("{}: frozen mirror CH must authenticate", vector.name);
        };
        // ch_wire is the exact upload prefix as received on the wire, so it
        // is deliberately framing-dependent; only the single-record control
        // reproduces the frozen wire.  Framing invariance of the logical
        // transcript is proven by the frozen-flight comparison downstream.
        if single_record {
            assert_eq!(hello.ch_wire(), hex_bytes(vector.ch_wire_hex));
        }
        let prefix = mirror_target_prefix(vector);
        let upload = (*hello).into_mirror_upload();
        let mut scanner = server
            .target_flight_scanner(upload.context())
            .expect("wire-authenticated context is mirrorable");
        let scan_state = scanner
            .push(&prefix)
            .unwrap_or_else(|error| panic!("{}: scan push failed: {error}", vector.name));
        assert_eq!(
            scan_state,
            crate::reality_mirror::TargetScanState::Freezable,
            "{}: vector target shape must freeze through the production scanner",
            vector.name
        );
        let template = scanner
            .freeze()
            .unwrap_or_else(|error| panic!("{}: scanner freeze failed: {:?}", vector.name, error));
        let (context, upload_wire) = upload.finish_upload();
        if single_record {
            assert_eq!(upload_wire, hex_bytes(vector.ch_wire_hex));
        }
        drop(upload_wire);
        let prepared = prepare_mirrored_flight_context_fixed(
            &server.inner.certificate,
            context,
            template,
            Some(&crypto),
        )
        .unwrap_or_else(|error| panic!("{}: prepare failed: {error}", vector.name));
        let (wire, completion) = prepared.commit().into_wire_and_completion();
        if expect_frozen_wire {
            assert_eq!(
                wire,
                hex_bytes(vector.server_flight_wire_hex),
                "{}: complete mirrored server flight",
                vector.name
            );
            let sh_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
            assert_eq!(
                &wire[5..5 + sh_len],
                &hex_bytes(vector.patched_sh_hex),
                "{}: patched ServerHello",
                vector.name
            );
        }
        MirrorVectorSession {
            client_io,
            stream,
            completion,
        }
    }

    fn cipher_suite_from_vector(vector: &FrozenMirrorVector) -> CipherSuite {
        match vector.cipher {
            TLS_AES_128_GCM_SHA256 => CipherSuite::Aes128GcmSha256,
            TLS_AES_256_GCM_SHA384 => CipherSuite::Aes256GcmSha384,
            TLS_CHACHA20_POLY1305_SHA256 => CipherSuite::ChaCha20Poly1305Sha256,
            other => panic!("unsupported frozen cipher {other:#x}"),
        }
    }

    fn open_vector_record(
        vector: &FrozenMirrorVector,
        key_hex: &str,
        iv_hex: &str,
        record_hex: &str,
    ) -> (u8, Vec<u8>) {
        let record = hex_bytes(record_hex);
        let header: [u8; 5] = record[..5].try_into().unwrap();
        let mut key = RecordKey::from_key_iv(
            cipher_suite_from_vector(vector),
            &hex_bytes(key_hex),
            &hex_array::<12>(iv_hex),
        );
        key.open(&header, &record[5..])
            .expect("frozen vector record must decrypt")
    }

    // --- Independent oracle recomputation of the mirrored flight ----------
    //
    // Every intermediate below is recomputed in the test from the base inputs
    // (frozen private keys, seeds, the logical ClientHello and the target
    // ServerHello) with hmac/sha2/x25519-dalek/boring called directly, then
    // compared byte-for-byte against the frozen Python-oracle fields.  None of
    // it flows through the implementation's key-schedule or patching code.

    /// REALITY authentication is always HKDF-SHA256/AES-256-GCM regardless of
    /// the negotiated TLS suite: AuthKey = HKDF(shared, random[..20],
    /// "REALITY") with the static server key and the client's independent
    /// X25519 share.
    fn oracle_auth_key(ch_message: &[u8]) -> Vec<u8> {
        let server_private = hex_array::<32>(SERVER_STATIC_PRIVATE_HEX);
        let client_public = hex_array::<32>(CLIENT_X25519_PUBLIC_HEX);
        let shared = x25519_dalek::x25519(server_private, client_public);
        let prk = OracleHash::Sha256.extract(&ch_message[6..26], &shared);
        OracleHash::Sha256.expand(&prk, b"REALITY", 32)
    }

    /// Rebuild the patched ServerHello and the TLS ECDH input from the target
    /// SH, the fixed server random and the ephemeral/KEM material alone.
    fn oracle_patched_sh_and_tls_dh(vector: &FrozenMirrorVector) -> (Vec<u8>, Vec<u8>) {
        let target_sh = hex_bytes(vector.target_sh_hex);
        let target = parse_server_hello_independent(&target_sh);
        assert_eq!(target.group, vector.group);
        let server_x_private = hex_array::<32>(vector.server_x25519_private_hex);
        let server_x_public =
            x25519_dalek::x25519(server_x_private, x25519_dalek::X25519_BASEPOINT_BYTES);
        let (server_share, tls_dh) = if vector.group == GROUP_X25519 {
            assert_eq!(target.share.len(), 32);
            let secret =
                x25519_dalek::x25519(server_x_private, hex_array::<32>(CLIENT_X25519_PUBLIC_HEX));
            assert_ne!(secret, [0u8; 32], "low-order oracle ECDH");
            (server_x_public.to_vec(), secret.to_vec())
        } else {
            assert_eq!(vector.group, GROUP_X25519_MLKEM768);
            assert_eq!(target.share.len(), 1088 + 32);
            let mlkem = boring::mlkem::MlKemPrivateKey::from_seed(
                boring::mlkem::Algorithm::MlKem768,
                &hex_array::<64>(MLKEM768_SEED_HEX),
            )
            .expect("fixed ML-KEM seed");
            let mlkem_ciphertext = hex_bytes(vector.mlkem_ciphertext_hex);
            let mlkem_secret = mlkem
                .decapsulate(&mlkem_ciphertext)
                .expect("oracle ML-KEM ciphertext decapsulates");
            assert_eq!(
                mlkem_secret[..],
                hex_bytes(vector.mlkem_secret_hex)[..],
                "{}: ML-KEM secret byte-exact from independent decapsulation",
                vector.name
            );
            let x_secret =
                x25519_dalek::x25519(server_x_private, hex_array::<32>(HYBRID_X25519_PUBLIC_HEX));
            assert_ne!(x_secret, [0u8; 32], "low-order oracle hybrid ECDH");
            let mut share = mlkem_ciphertext;
            share.extend_from_slice(&server_x_public);
            let mut dh = mlkem_secret.to_vec();
            dh.extend_from_slice(&x_secret);
            (share, dh)
        };

        let mut patched = target_sh;
        patched[6..38].copy_from_slice(&hex_bytes(vector.server_random_hex));
        let share_pos = patched
            .windows(target.share.len())
            .position(|window| window == target.share.as_slice())
            .expect("target share occurs exactly in the target SH");
        patched[share_pos..share_pos + target.share.len()].copy_from_slice(&server_share);
        (patched, tls_dh)
    }

    fn oracle_sign_ed25519(message: &[u8]) -> Vec<u8> {
        let key = PKey::private_key_from_der(&hex_bytes(ED25519_PRIVATE_DER_HEX))
            .expect("fixed Ed25519 private key");
        let mut signer = Signer::new_without_digest(&key).expect("Ed25519 oracle signer");
        signer
            .sign_oneshot_to_vec(message)
            .expect("Ed25519 oracle sign")
    }

    fn oracle_certificate_message(leaf: &[u8]) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(&(leaf.len() as u32).to_be_bytes()[1..4]);
        entry.extend_from_slice(leaf);
        entry.extend_from_slice(&[0, 0]);
        let mut body = vec![0];
        body.extend_from_slice(&(entry.len() as u32).to_be_bytes()[1..4]);
        body.extend_from_slice(&entry);
        independent_handshake_message(HS_CERTIFICATE, &body)
    }

    struct OracleMirrorCrypto {
        leaf_der: Vec<u8>,
        ee: Vec<u8>,
        certificate: Vec<u8>,
        cv: Vec<u8>,
        server_finished_message: Vec<u8>,
        server_finished_body: Vec<u8>,
        client_finished_body: Vec<u8>,
        flight_plaintext: Vec<u8>,
        t0: Vec<u8>,
        t1: Vec<u8>,
        t2: Vec<u8>,
        t3: Vec<u8>,
        client_hs_secret: Vec<u8>,
        client_hs_key: Vec<u8>,
        client_hs_iv: Vec<u8>,
        server_hs_key: Vec<u8>,
        server_hs_iv: Vec<u8>,
        client_ap_key: Vec<u8>,
        client_ap_iv: Vec<u8>,
        server_ap_key: Vec<u8>,
        server_ap_iv: Vec<u8>,
    }

    /// Full TLS 1.3 key schedule and server-flight reconstruction, given the
    /// exact transcript inputs.  `transcript_ch`/`transcript_sh` are
    /// parameters rather than hardwired vector fields so negative tests can
    /// measure how a mutated transcript input diverges.
    fn oracle_flight_crypto(
        vector: &FrozenMirrorVector,
        transcript_ch: &[u8],
        transcript_sh: &[u8],
        tls_dh: &[u8],
        auth_key: &[u8],
    ) -> OracleMirrorCrypto {
        let hash = OracleHash::for_cipher(vector.cipher);
        let mut transcript = transcript_ch.to_vec();
        transcript.extend_from_slice(transcript_sh);
        let t0 = hash.digest(&transcript);

        let zero = vec![0u8; hash.len()];
        let empty_hash = hash.digest(&[]);
        let early = hash.extract(&zero, &zero);
        let handshake_secret = {
            let derived = hash.derive_secret(&early, b"derived", &empty_hash);
            hash.extract(&derived, tls_dh)
        };
        let client_hs_secret = hash.derive_secret(&handshake_secret, b"c hs traffic", &t0);
        let server_hs_secret = hash.derive_secret(&handshake_secret, b"s hs traffic", &t0);
        let master_secret = {
            let derived = hash.derive_secret(&handshake_secret, b"derived", &empty_hash);
            hash.extract(&derived, &zero)
        };

        let ee = independent_handshake_message(HS_ENCRYPTED_EXTENSIONS, &[0, 0]);
        let mut leaf_der = hex_bytes(LEAF_DER_HEX);
        let mac = hmac_sha512(auth_key, &[&hex_bytes(ED25519_PUBLIC_HEX)]);
        let leaf_mac_start = leaf_der.len() - 64;
        leaf_der[leaf_mac_start..].copy_from_slice(&mac);
        let certificate = oracle_certificate_message(&leaf_der);
        transcript.extend_from_slice(&ee);
        transcript.extend_from_slice(&certificate);
        let t1 = hash.digest(&transcript);

        let mut cv_input = vec![0x20; 64];
        cv_input.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        cv_input.push(0);
        cv_input.extend_from_slice(&t1);
        let signature = oracle_sign_ed25519(&cv_input);
        assert_eq!(signature.len(), 64, "Ed25519 signature length");
        let mut cv_body = Vec::new();
        cv_body.extend_from_slice(&SIG_ED25519.to_be_bytes());
        cv_body.extend_from_slice(&64u16.to_be_bytes());
        cv_body.extend_from_slice(&signature);
        let cv = independent_handshake_message(HS_CERTIFICATE_VERIFY, &cv_body);
        transcript.extend_from_slice(&cv);
        let t2 = hash.digest(&transcript);

        let server_finished_key =
            hash.expand_label(&server_hs_secret, b"finished", &[], hash.len());
        let server_finished_body = hash.hmac(&server_finished_key, &[&t2]);
        let server_finished_message =
            independent_handshake_message(HS_FINISHED, &server_finished_body);
        transcript.extend_from_slice(&server_finished_message);
        let t3 = hash.digest(&transcript);

        let client_finished_key =
            hash.expand_label(&client_hs_secret, b"finished", &[], hash.len());
        let client_finished_body = hash.hmac(&client_finished_key, &[&t3]);

        let key_len = if vector.cipher == TLS_AES_128_GCM_SHA256 {
            16
        } else {
            32
        };
        let traffic = |secret: &[u8]| {
            (
                hash.expand_label(secret, b"key", &[], key_len),
                hash.expand_label(secret, b"iv", &[], 12),
            )
        };
        let (client_hs_key, client_hs_iv) = traffic(&client_hs_secret);
        let (server_hs_key, server_hs_iv) = traffic(&server_hs_secret);
        let client_ap_secret = hash.derive_secret(&master_secret, b"c ap traffic", &t3);
        let server_ap_secret = hash.derive_secret(&master_secret, b"s ap traffic", &t3);
        let (client_ap_key, client_ap_iv) = traffic(&client_ap_secret);
        let (server_ap_key, server_ap_iv) = traffic(&server_ap_secret);

        let mut flight_plaintext = ee.clone();
        flight_plaintext.extend_from_slice(&certificate);
        flight_plaintext.extend_from_slice(&cv);
        flight_plaintext.extend_from_slice(&server_finished_message);

        OracleMirrorCrypto {
            leaf_der,
            ee,
            certificate,
            cv,
            server_finished_message,
            server_finished_body,
            client_finished_body,
            flight_plaintext,
            t0,
            t1,
            t2,
            t3,
            client_hs_secret,
            client_hs_key,
            client_hs_iv,
            server_hs_key,
            server_hs_iv,
            client_ap_key,
            client_ap_iv,
            server_ap_key,
            server_ap_iv,
        }
    }

    /// Recompute every frozen intermediate of one mirror vector from the base
    /// inputs and compare byte-for-byte.  A single flipped hex digit in any
    /// covered field must turn this red.
    fn assert_mirror_vector_oracle_recompute(vector: &FrozenMirrorVector) {
        let ch_message = hex_bytes(vector.ch_message_hex);

        let mut aad = ch_message.clone();
        aad[39..71].fill(0);
        assert_eq!(
            aad,
            hex_bytes(vector.aad_hex),
            "{}: AAD is the logical CH with a zeroed session-id window",
            vector.name
        );

        let auth_key = oracle_auth_key(&ch_message);
        assert_eq!(
            auth_key,
            hex_bytes(vector.auth_key_hex),
            "{}: AuthKey byte-exact",
            vector.name
        );
        let mut auth_plaintext = hex_bytes(VERSION_HEX);
        auth_plaintext.push(0);
        auth_plaintext.extend_from_slice(&(UNIX_SECONDS as u32).to_be_bytes());
        auth_plaintext.extend_from_slice(&hex_bytes(SHORT_ID_HEX));
        let auth_box = Aes256Gcm::new_from_slice(&auth_key).expect("AES-256 AuthKey");
        let sid = auth_box
            .encrypt(
                Nonce::from_slice(&ch_message[26..38]),
                aes_gcm::aead::Payload {
                    msg: &auth_plaintext,
                    aad: &aad,
                },
            )
            .expect("oracle AuthKey seal");
        assert_eq!(
            sid,
            ch_message[39..71],
            "{}: session id re-seals byte-exact under the recomputed AuthKey/AAD/nonce",
            vector.name
        );

        let (patched_sh, tls_dh) = oracle_patched_sh_and_tls_dh(vector);
        assert_eq!(
            patched_sh,
            hex_bytes(vector.patched_sh_hex),
            "{}: patched ServerHello byte-exact",
            vector.name
        );
        assert_eq!(
            tls_dh,
            hex_bytes(vector.tls_dh_hex),
            "{}: tls_dh byte-exact",
            vector.name
        );

        let oracle = oracle_flight_crypto(vector, &ch_message, &patched_sh, &tls_dh, &auth_key);
        let byte_exact = |label: &str, recomputed: &[u8], frozen_hex: &str| {
            assert_eq!(
                recomputed,
                hex_bytes(frozen_hex),
                "{}: {label} byte-exact",
                vector.name
            );
        };
        byte_exact("T0 transcript hash", &oracle.t0, vector.t0_hex);
        byte_exact("T1 transcript hash", &oracle.t1, vector.t1_hex);
        byte_exact("T2 transcript hash", &oracle.t2, vector.t2_hex);
        byte_exact("T3 transcript hash", &oracle.t3, vector.t3_hex);
        byte_exact(
            "leaf certificate DER",
            &oracle.leaf_der,
            vector.leaf_der_hex,
        );
        byte_exact("CertificateVerify message", &oracle.cv, vector.cv_hex);
        byte_exact(
            "server Finished body",
            &oracle.server_finished_body,
            vector.server_finished_hex,
        );
        byte_exact(
            "client Finished body",
            &oracle.client_finished_body,
            vector.client_finished_hex,
        );
        byte_exact(
            "client handshake key",
            &oracle.client_hs_key,
            vector.client_hs_key_hex,
        );
        byte_exact(
            "client handshake iv",
            &oracle.client_hs_iv,
            vector.client_hs_iv_hex,
        );
        byte_exact(
            "server handshake key",
            &oracle.server_hs_key,
            vector.server_hs_key_hex,
        );
        byte_exact(
            "server handshake iv",
            &oracle.server_hs_iv,
            vector.server_hs_iv_hex,
        );
        byte_exact(
            "client application key",
            &oracle.client_ap_key,
            vector.client_ap_key_hex,
        );
        byte_exact(
            "client application iv",
            &oracle.client_ap_iv,
            vector.client_ap_iv_hex,
        );
        byte_exact(
            "server application key",
            &oracle.server_ap_key,
            vector.server_ap_key_hex,
        );
        byte_exact(
            "server application iv",
            &oracle.server_ap_iv,
            vector.server_ap_iv_hex,
        );
        byte_exact(
            "flight plaintext",
            &oracle.flight_plaintext,
            vector.flight_plaintext_hex,
        );

        let cv_input_t1 = {
            let mut input = vec![0x20; 64];
            input.extend_from_slice(b"TLS 1.3, server CertificateVerify");
            input.push(0);
            input.extend_from_slice(&oracle.t1);
            input
        };
        verify_ed25519_signature(&oracle.cv[8..], &cv_input_t1);
    }

    fn assert_mirror_vector_intermediates(vector: &FrozenMirrorVector) {
        assert_mirror_vector_oracle_recompute(vector);
        let hash_len = if vector.cipher == TLS_AES_256_GCM_SHA384 {
            48
        } else {
            32
        };
        assert_eq!(
            vector.group == 0x11ec,
            !vector.mlkem_ciphertext_hex.is_empty()
        );
        assert!(hex_bytes(vector.ch_wire_hex).ends_with(&hex_bytes(vector.ch_message_hex)));
        assert_eq!(hex_bytes(vector.aad_hex)[39..71], [0u8; 32]);
        assert_eq!(
            hex_bytes(vector.tls_dh_hex).len(),
            if vector.group == 0x11ec { 64 } else { 32 }
        );
        assert_eq!(hex_bytes(vector.auth_key_hex).len(), 32);
        for hash_hex in [vector.t0_hex, vector.t1_hex, vector.t2_hex, vector.t3_hex] {
            assert_eq!(hex_bytes(hash_hex).len(), hash_len);
        }
        assert_eq!(hex_bytes(vector.server_finished_hex).len(), hash_len);
        assert_eq!(hex_bytes(vector.client_finished_hex).len(), hash_len);
        let flight = hex_bytes(vector.flight_plaintext_hex);
        let cv = hex_bytes(vector.cv_hex);
        assert!(flight.windows(cv.len()).any(|window| window == cv));
        assert!(flight.ends_with(&hex_bytes(vector.server_finished_hex)));

        let mut offset = 0usize;
        let mut server_hs = RecordKey::from_key_iv(
            cipher_suite_from_vector(vector),
            &hex_bytes(vector.server_hs_key_hex),
            &hex_array::<12>(vector.server_hs_iv_hex),
        );
        for record_hex in [
            vector.record0_hex,
            vector.record1_hex,
            vector.record2_hex,
            vector.record3_hex,
        ] {
            let record = hex_bytes(record_hex);
            let header: [u8; 5] = record[..5].try_into().unwrap();
            let (inner_type, plaintext) = server_hs
                .open(&header, &record[5..])
                .expect("frozen mirrored record must decrypt");
            assert_eq!(inner_type, TLS_RECORD_HANDSHAKE);
            assert_eq!(
                plaintext,
                flight[offset..offset + plaintext.len()],
                "{}: mirrored bucket plaintext slice",
                vector.name
            );
            offset += plaintext.len();
        }
        assert_eq!(
            offset,
            flight.len(),
            "{}: all mirrored plaintext consumed",
            vector.name
        );

        let (inner_type, finished_plaintext) = open_vector_record(
            vector,
            vector.client_hs_key_hex,
            vector.client_hs_iv_hex,
            vector.client_finished_record_hex,
        );
        assert_eq!(inner_type, TLS_RECORD_HANDSHAKE);
        assert_eq!(finished_plaintext[0], HS_FINISHED);
        assert_eq!(
            &finished_plaintext[4..],
            &hex_bytes(vector.client_finished_hex)
        );

        let (inner_type, client_plaintext) = open_vector_record(
            vector,
            vector.client_ap_key_hex,
            vector.client_ap_iv_hex,
            vector.client_app_record_hex,
        );
        assert_eq!(inner_type, TLS_RECORD_APPLICATION_DATA);
        assert_eq!(client_plaintext, hex_bytes(vector.app_plaintext_hex));
        let mut server_app = RecordKey::from_key_iv(
            cipher_suite_from_vector(vector),
            &hex_bytes(vector.server_ap_key_hex),
            &hex_array::<12>(vector.server_ap_iv_hex),
        );
        assert_eq!(
            server_app
                .seal(
                    TLS_RECORD_APPLICATION_DATA,
                    &hex_bytes(vector.app_plaintext_hex)
                )
                .unwrap(),
            hex_bytes(vector.server_app_record_hex),
            "{}: frozen server application record",
            vector.name
        );
    }

    #[tokio::test]
    async fn mirror_independent_vectors_are_byte_exact_and_roundtrip() {
        for vector in [
            &MIRROR_X25519_AES128,
            &MIRROR_X25519_AES256,
            &MIRROR_X25519_CHACHA,
            &MIRROR_HYBRID_AES256,
        ] {
            assert_mirror_vector_intermediates(vector);
            let mut session = open_mirror_vector_session(vector).await;
            session
                .client_io
                .write_all(&hex_bytes(vector.client_finished_record_hex))
                .await
                .unwrap();
            session.client_io.flush().await.unwrap();
            let mut stream = tokio::time::timeout(
                Duration::from_secs(2),
                session.completion.finish(session.stream),
            )
            .await
            .expect("mirrored Finished timed out")
            .unwrap_or_else(|error| panic!("{}: finish failed: {error}", vector.name));

            session
                .client_io
                .write_all(&hex_bytes(vector.client_app_record_hex))
                .await
                .unwrap();
            session.client_io.flush().await.unwrap();
            let app = hex_bytes(vector.app_plaintext_hex);
            let mut got = vec![0u8; app.len()];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, app, "{}: client application plaintext", vector.name);

            stream.write_all(&app).await.unwrap();
            stream.flush().await.unwrap();
            let expected_record = hex_bytes(vector.server_app_record_hex);
            let mut encrypted = vec![0u8; expected_record.len()];
            session.client_io.read_exact(&mut encrypted).await.unwrap();
            assert_eq!(
                encrypted, expected_record,
                "{}: server application record seq=0",
                vector.name
            );
            assert!(!hex_bytes(vector.leaf_der_hex).is_empty());
        }
    }

    #[tokio::test]
    async fn mirrored_finished_refragments_across_records_and_rejects_bad_sequence() {
        let vector = &MIRROR_X25519_AES128;
        let finished_body = hex_bytes(vector.client_finished_hex);
        let mut finished = Vec::new();
        finished.push(HS_FINISHED);
        finished.extend_from_slice(&(finished_body.len() as u32).to_be_bytes()[1..4]);
        finished.extend_from_slice(&finished_body);
        let split = 2;
        let key = hex_bytes(vector.client_hs_key_hex);
        let iv = hex_array::<12>(vector.client_hs_iv_hex);
        let cipher = cipher_suite_from_vector(vector);
        let mut key0 = RecordKey::from_key_iv(cipher, &key, &iv);
        let first = key0.seal(TLS_RECORD_HANDSHAKE, &finished[..split]).unwrap();
        let second = key0.seal(TLS_RECORD_HANDSHAKE, &finished[split..]).unwrap();

        let mut session = open_mirror_vector_session(vector).await;
        session.client_io.write_all(&first).await.unwrap();
        session.client_io.write_all(&second).await.unwrap();
        session.client_io.flush().await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            session.completion.finish(session.stream),
        )
        .await
        .expect("refragmented Finished timed out")
        .expect("refragmented valid Finished must pass");

        let mut session = open_mirror_vector_session(vector).await;
        session.client_io.write_all(&second).await.unwrap();
        session.client_io.write_all(&first).await.unwrap();
        session.client_io.flush().await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            session.completion.finish(session.stream),
        )
        .await
        .expect("reordered Finished timed out");
        assert!(
            result.is_err(),
            "records encrypted under reversed sequence order must fail"
        );
    }

    #[tokio::test]
    async fn mirrored_finished_rejects_bit_tampered_or_replayed_foreign_records() {
        let vector = &MIRROR_X25519_AES128;
        for mutation in ["tag", "foreign"] {
            let mut session = open_mirror_vector_session(vector).await;
            let mut record = hex_bytes(vector.client_finished_record_hex);
            if mutation == "tag" {
                let last = record.len() - 1;
                record[last] ^= 1;
            } else {
                record = hex_bytes(MIRROR_X25519_AES256.client_finished_record_hex);
            }
            session.client_io.write_all(&record).await.unwrap();
            session.client_io.flush().await.unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                session.completion.finish(session.stream),
            )
            .await
            .expect("tampered Finished timed out");
            assert!(result.is_err(), "{mutation} Finished must be rejected");
        }
    }

    // --- Discrete negative discriminators for the mirrored Finished --------
    //
    // Every test below isolates one mechanism: the record always opens under
    // the keys the server actually uses unless the tested mechanism itself is
    // the key schedule, so the rejection cause is never ambiguous.

    fn oracle_inputs(vector: &FrozenMirrorVector) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let ch_message = hex_bytes(vector.ch_message_hex);
        let auth_key = oracle_auth_key(&ch_message);
        let (patched_sh, tls_dh) = oracle_patched_sh_and_tls_dh(vector);
        (ch_message, patched_sh, tls_dh, auth_key)
    }

    fn seal_vector_finished(
        vector: &FrozenMirrorVector,
        key_bytes: &[u8],
        iv_bytes: &[u8],
        verify_data: &[u8],
    ) -> Vec<u8> {
        let mut message = Vec::new();
        message.push(HS_FINISHED);
        message.extend_from_slice(&(verify_data.len() as u32).to_be_bytes()[1..4]);
        message.extend_from_slice(verify_data);
        let iv: [u8; 12] = iv_bytes.try_into().expect("twelve-byte record iv");
        let mut key = RecordKey::from_key_iv(cipher_suite_from_vector(vector), key_bytes, &iv);
        key.seal(TLS_RECORD_HANDSHAKE, &message)
            .expect("test Finished record seal")
    }

    async fn finish_error_after_record(
        mut session: MirrorVectorSession,
        record: &[u8],
    ) -> TransportError {
        session.client_io.write_all(record).await.unwrap();
        session.client_io.flush().await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            session.completion.finish(session.stream),
        )
        .await
        .expect("mirrored Finished timed out")
        .err()
        .expect("negative Finished must be rejected")
    }

    /// Seal a first (sequence-zero) record whose AEAD tag is valid for the
    /// transmitted header, even when that header violates the strict shape
    /// the mirrored Finished reader admits.  The rejection then cannot be an
    /// AEAD failure: it is the header policy alone.
    fn seal_aes128_record_with_header_and_aad(
        key_bytes: &[u8],
        iv: &[u8; 12],
        typ: u8,
        version: [u8; 2],
        aad: [u8; 5],
        inner_type: u8,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let cipher = Aes128Gcm::new_from_slice(key_bytes).expect("AES-128 test key");
        let mut body = plaintext.to_vec();
        body.push(inner_type);
        let record_len = body.len() + 16;
        let mut header = [typ, version[0], version[1], 0, 0];
        header[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(iv), &aad, &mut body)
            .expect("test header-mutation seal");
        body.extend_from_slice(&tag);
        let mut out = header.to_vec();
        out.extend_from_slice(&body);
        out
    }

    fn seal_aes128_record_with_header(
        key_bytes: &[u8],
        iv: &[u8; 12],
        typ: u8,
        version: [u8; 2],
        inner_type: u8,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mut body = plaintext.to_vec();
        body.push(inner_type);
        let record_len = body.len() + 16;
        let mut aad = [typ, version[0], version[1], 0, 0];
        aad[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
        seal_aes128_record_with_header_and_aad(
            key_bytes, iv, typ, version, aad, inner_type, plaintext,
        )
    }

    #[tokio::test]
    async fn mirrored_finished_replayed_from_same_suite_different_session_is_rejected() {
        // The existing foreign-record case proves rejection across cipher
        // suites; that failure is explained by the AEAD suite alone.  Here
        // session B is the frozen session with one ServerHello-random bit
        // flipped: same suite, same client, same ephemeral key — only the
        // session keys differ, so rejecting the original session's Finished
        // is same-suite cross-session discrimination.
        let vector = &MIRROR_X25519_AES128;
        let mut crypto_b = mirror_fixed_crypto(vector);
        crypto_b.server_random[0] ^= 1;
        let session = open_mirror_vector_session_with_crypto(vector, crypto_b.clone(), false).await;
        let record = hex_bytes(vector.client_finished_record_hex);
        finish_error_after_record(session, &record).await;

        // Control: the honestly recomputed Finished for session B is accepted,
        // so the rejection above is keyed to the session, not a broken path.
        let (ch_message, patched_sh, tls_dh, auth_key) = oracle_inputs(vector);
        let mut patched_b = patched_sh.clone();
        patched_b[6] ^= 1;
        let oracle_b = oracle_flight_crypto(vector, &ch_message, &patched_b, &tls_dh, &auth_key);
        assert_ne!(
            oracle_b.client_hs_key,
            hex_bytes(vector.client_hs_key_hex),
            "one random bit must rekey the session"
        );
        let valid_b = seal_vector_finished(
            vector,
            &oracle_b.client_hs_key,
            &oracle_b.client_hs_iv,
            &oracle_b.client_finished_body,
        );
        let mut session = open_mirror_vector_session_with_crypto(vector, crypto_b, false).await;
        session.client_io.write_all(&valid_b).await.unwrap();
        session.client_io.flush().await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            session.completion.finish(session.stream),
        )
        .await
        .expect("session-B Finished timed out")
        .expect("session-B honest Finished must be accepted");
    }

    #[tokio::test]
    async fn mirrored_finished_with_wrong_verify_data_under_correct_keys_is_rejected() {
        // Sealed under the exact keys of the current session, so the AEAD
        // open succeeds and the rejection is isolated at the verify_data
        // comparison rather than any decryption failure.
        let vector = &MIRROR_X25519_AES128;
        let (ch_message, patched_sh, tls_dh, auth_key) = oracle_inputs(vector);
        let oracle = oracle_flight_crypto(vector, &ch_message, &patched_sh, &tls_dh, &auth_key);
        assert_eq!(
            oracle.client_hs_key,
            hex_bytes(vector.client_hs_key_hex),
            "oracle keys must be the current session keys for this isolation"
        );
        let mut wrong_verify = oracle.client_finished_body.clone();
        wrong_verify[0] ^= 1;
        let record = seal_vector_finished(
            vector,
            &oracle.client_hs_key,
            &oracle.client_hs_iv,
            &wrong_verify,
        );
        let session = open_mirror_vector_session(vector).await;
        let error = finish_error_after_record(session, &record).await;
        assert!(
            error.to_string().contains("verify_data mismatch"),
            "correct-key wrong-verify_data rejection must reach the comparison: {error}"
        );
    }

    #[tokio::test]
    async fn mirrored_finished_record_with_noncanonical_header_is_rejected_despite_valid_aead() {
        let vector = &MIRROR_X25519_AES128;
        assert_eq!(vector.cipher, TLS_AES_128_GCM_SHA256);
        let (ch_message, patched_sh, tls_dh, auth_key) = oracle_inputs(vector);
        let oracle = oracle_flight_crypto(vector, &ch_message, &patched_sh, &tls_dh, &auth_key);
        let iv: [u8; 12] = oracle
            .client_hs_iv
            .as_slice()
            .try_into()
            .expect("twelve-byte iv");
        let mut finished = Vec::new();
        finished.push(HS_FINISHED);
        finished.extend_from_slice(&(oracle.client_finished_body.len() as u32).to_be_bytes()[1..4]);
        finished.extend_from_slice(&oracle.client_finished_body);
        for (typ, version, expected) in [
            (TLS_RECORD_HANDSHAKE, [0x03, 0x03], "record type"),
            (TLS_RECORD_APPLICATION_DATA, [0x03, 0x01], "record version"),
        ] {
            let record = seal_aes128_record_with_header(
                &oracle.client_hs_key,
                &iv,
                typ,
                version,
                TLS_RECORD_HANDSHAKE,
                &finished,
            );
            let session = open_mirror_vector_session(vector).await;
            let error = finish_error_after_record(session, &record).await;
            assert!(
                error.to_string().contains(expected),
                "AEAD-valid record with mutated header must be rejected at admission ({expected}): {error}"
            );
        }
    }

    #[tokio::test]
    async fn mirrored_finished_with_canonical_header_but_wrong_aad_tag_is_aead_rejected() {
        let vector = &MIRROR_X25519_AES128;
        assert_eq!(vector.cipher, TLS_AES_128_GCM_SHA256);
        let (ch_message, patched_sh, tls_dh, auth_key) = oracle_inputs(vector);
        let oracle = oracle_flight_crypto(vector, &ch_message, &patched_sh, &tls_dh, &auth_key);
        let iv: [u8; 12] = oracle
            .client_hs_iv
            .as_slice()
            .try_into()
            .expect("twelve-byte iv");
        let mut finished = Vec::new();
        finished.push(HS_FINISHED);
        finished.extend_from_slice(&(oracle.client_finished_body.len() as u32).to_be_bytes()[1..4]);
        finished.extend_from_slice(&oracle.client_finished_body);
        let plaintext_len = finished.len() + 1;
        let record_len = plaintext_len + 16;
        // The transmitted header is canonical and passes header admission.
        // The tag is instead computed for a wrong-AAD input under the same
        // key and sequence-zero nonce, so rejection must occur in AEAD open.
        let mut wrong_aad = [TLS_RECORD_APPLICATION_DATA, 0x03, 0x01, 0, 0];
        wrong_aad[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
        let record = seal_aes128_record_with_header_and_aad(
            &oracle.client_hs_key,
            &iv,
            TLS_RECORD_APPLICATION_DATA,
            [0x03, 0x03],
            wrong_aad,
            TLS_RECORD_HANDSHAKE,
            &finished,
        );
        let session = open_mirror_vector_session(vector).await;
        let error = finish_error_after_record(session, &record).await;
        assert!(
            error.to_string().contains("decrypt"),
            "wrong-AAD input must fail AEAD open after header admission: {error}"
        );
        assert!(
            !error.to_string().contains("record type")
                && !error.to_string().contains("record version"),
            "wrong-AAD case must not be confused with header admission: {error}"
        );
    }

    /// correct keys seal the record, but the verify_data is computed over a
    /// transcript whose CH/SH segment is mutated — the comparison must fail
    /// even though every other input is honest.
    async fn assert_verify_data_over_mutated_transcript_is_rejected(
        vector: &FrozenMirrorVector,
        transcript_ch: &[u8],
        transcript_sh: &[u8],
        label: &str,
    ) {
        let (ch_message, patched_sh, tls_dh, auth_key) = oracle_inputs(vector);
        let oracle = oracle_flight_crypto(vector, &ch_message, &patched_sh, &tls_dh, &auth_key);
        let hash = OracleHash::for_cipher(vector.cipher);
        let mut mutated = transcript_ch.to_vec();
        mutated.extend_from_slice(transcript_sh);
        mutated.extend_from_slice(&oracle.ee);
        mutated.extend_from_slice(&oracle.certificate);
        mutated.extend_from_slice(&oracle.cv);
        mutated.extend_from_slice(&oracle.server_finished_message);
        let mutated_t3 = hash.digest(&mutated);
        let finished_key =
            hash.expand_label(&oracle.client_hs_secret, b"finished", &[], hash.len());
        let mutated_verify = hash.hmac(&finished_key, &[&mutated_t3]);
        assert_ne!(
            mutated_verify, oracle.client_finished_body,
            "{label}: the mutated transcript must actually change verify_data"
        );
        let record = seal_vector_finished(
            vector,
            &oracle.client_hs_key,
            &oracle.client_hs_iv,
            &mutated_verify,
        );
        let session = open_mirror_vector_session(vector).await;
        let error = finish_error_after_record(session, &record).await;
        assert!(
            error.to_string().contains("verify_data mismatch"),
            "{label}: rejection must be the verify_data comparison, not AEAD: {error}"
        );
    }

    #[tokio::test]
    async fn verify_data_over_zeroed_session_id_transcript_is_rejected() {
        // The transcript binds the encrypted-SID logical CH.  Hashing the
        // zeroed-SID (AAD) form instead — the confusion the mirror design
        // rules out — must not produce an acceptable Finished.
        let vector = &MIRROR_X25519_AES128;
        let mut zeroed = hex_bytes(vector.ch_message_hex);
        zeroed[39..71].fill(0);
        let patched_sh = hex_bytes(vector.patched_sh_hex);
        assert_verify_data_over_mutated_transcript_is_rejected(
            vector,
            &zeroed,
            &patched_sh,
            "zeroed-session-id CH transcript",
        )
        .await;
    }

    #[tokio::test]
    async fn verify_data_over_unpatched_target_sh_transcript_is_rejected() {
        // The transcript binds the patched ServerHello, not the target's
        // original bytes: an implementation hashing the unpatched SH must not
        // interoperate with a correct peer.
        let vector = &MIRROR_X25519_AES128;
        let ch_message = hex_bytes(vector.ch_message_hex);
        let target_sh = hex_bytes(vector.target_sh_hex);
        assert_eq!(
            target_sh.len(),
            hex_bytes(vector.patched_sh_hex).len(),
            "patching preserves length, so this mutation isolates content"
        );
        assert_verify_data_over_mutated_transcript_is_rejected(
            vector,
            &ch_message,
            &target_sh,
            "unpatched target SH transcript",
        )
        .await;
    }

    #[tokio::test]
    async fn hybrid_secret_with_reversed_halves_cannot_complete_mirrored_handshake() {
        // tls_dh is ML-KEM secret ∥ X25519 secret.  A consistently reversed
        // client derives a coherent-but-different key schedule; since the
        // server concatenates in the correct order, the Finished record must
        // already fail at AEAD open.
        let vector = &MIRROR_HYBRID_AES256;
        let (ch_message, patched_sh, tls_dh, auth_key) = oracle_inputs(vector);
        assert_eq!(tls_dh.len(), 64, "hybrid tls_dh carries two halves");
        let mut reversed = tls_dh[32..].to_vec();
        reversed.extend_from_slice(&tls_dh[..32]);
        assert_ne!(reversed, tls_dh, "halves must actually differ");
        let oracle = oracle_flight_crypto(vector, &ch_message, &patched_sh, &reversed, &auth_key);
        assert_ne!(
            oracle.client_hs_key,
            hex_bytes(vector.client_hs_key_hex),
            "reversing the secret halves must rekey the client"
        );
        let record = seal_vector_finished(
            vector,
            &oracle.client_hs_key,
            &oracle.client_hs_iv,
            &oracle.client_finished_body,
        );
        let session = open_mirror_vector_session(vector).await;
        finish_error_after_record(session, &record).await;
    }

    #[tokio::test]
    async fn hybrid_finished_from_unreplaced_kem_ciphertext_cannot_complete_mirrored_handshake() {
        // If the patcher replaced only the hybrid share's X25519 suffix and
        // left the target's ML-KEM ciphertext in place, the honest client
        // would decapsulate that target ciphertext.  Its secret then diverges
        // from the mirror server's no matter what the server does, so the
        // Finished must fail — the positive handshake genuinely depends on
        // the ciphertext half being replaced.
        let vector = &MIRROR_HYBRID_AES256;
        let (ch_message, patched_sh, tls_dh, auth_key) = oracle_inputs(vector);
        let target_sh = hex_bytes(vector.target_sh_hex);
        let target = parse_server_hello_independent(&target_sh);
        let mlkem = boring::mlkem::MlKemPrivateKey::from_seed(
            boring::mlkem::Algorithm::MlKem768,
            &hex_array::<64>(MLKEM768_SEED_HEX),
        )
        .expect("fixed ML-KEM seed");
        let target_secret = mlkem
            .decapsulate(&target.share[..1088])
            .expect("ML-KEM decapsulation is total");
        let correct_secret = mlkem
            .decapsulate(&hex_bytes(vector.mlkem_ciphertext_hex))
            .expect("correct ciphertext decapsulates");
        assert_ne!(
            target_secret[..],
            correct_secret[..],
            "the target ciphertext must yield a different secret, or this test proves nothing"
        );
        // The suffix half was patched in this scenario, so the client keeps
        // the correct X25519 secret and only the KEM half diverges.
        let mut mutated_dh = target_secret.to_vec();
        mutated_dh.extend_from_slice(&tls_dh[32..]);
        let oracle = oracle_flight_crypto(vector, &ch_message, &patched_sh, &mutated_dh, &auth_key);
        assert_ne!(
            oracle.client_hs_key,
            hex_bytes(vector.client_hs_key_hex),
            "decapsulating the target ciphertext must rekey the client"
        );
        let record = seal_vector_finished(
            vector,
            &oracle.client_hs_key,
            &oracle.client_hs_iv,
            &oracle.client_finished_body,
        );
        let session = open_mirror_vector_session(vector).await;
        finish_error_after_record(session, &record).await;
    }

    // --- Wire-level off-vs-mirror dual-path evidence (P2-4) -----------------

    /// Insert one extra extension into the frozen positive ClientHello and
    /// re-seal the session id.  The AAD covers the whole logical CH, so any
    /// extension change rekeys nothing but rewrites the ciphertext; the
    /// AuthKey itself is unchanged because the random and the key shares are
    /// untouched.
    fn resealed_hello_with_extra_extension(
        base: &[u8],
        ext_type: u16,
        ext_data: &[u8],
        auth_key: &[u8],
    ) -> Vec<u8> {
        let mut pos = 4 + 2 + 32;
        let sid_len = base[pos] as usize;
        pos += 1 + sid_len;
        let cs_len = usize::from(u16::from_be_bytes([base[pos], base[pos + 1]]));
        pos += 2 + cs_len;
        let comp_len = base[pos] as usize;
        pos += 1 + comp_len;
        let ext_len = usize::from(u16::from_be_bytes([base[pos], base[pos + 1]]));
        pos += 2;
        assert_eq!(pos + ext_len, base.len(), "base CH extensions end exactly");

        let mut new_exts = base[pos..pos + ext_len].to_vec();
        new_exts.extend_from_slice(&ext_type.to_be_bytes());
        new_exts.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        new_exts.extend_from_slice(ext_data);

        let mut hello = base[..pos - 2].to_vec();
        hello.extend_from_slice(&(new_exts.len() as u16).to_be_bytes());
        hello.extend_from_slice(&new_exts);
        let body_len = hello.len() - 4;
        hello[1..4].copy_from_slice(&(body_len as u32).to_be_bytes()[1..4]);
        hello[39..71].fill(0);

        let mut auth_plaintext = hex_bytes(VERSION_HEX);
        auth_plaintext.push(0);
        auth_plaintext.extend_from_slice(&(UNIX_SECONDS as u32).to_be_bytes());
        auth_plaintext.extend_from_slice(&hex_bytes(SHORT_ID_HEX));
        let auth_box = Aes256Gcm::new_from_slice(auth_key).expect("AES-256 AuthKey");
        let nonce: [u8; 12] = hello[26..38].try_into().expect("REALITY nonce window");
        let sid = auth_box
            .encrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: &auth_plaintext,
                    aad: &hello,
                },
            )
            .expect("re-seal mutated CH");
        hello[39..71].copy_from_slice(&sid);
        hello
    }

    /// Minimal valid mirror target prefix bound to one session id: SH record
    /// (x25519, TLS_AES_128, both mandatory extensions) plus canonical CCS
    /// and the four standard application records.
    fn target_prefix_for_session(session_id: &[u8]) -> Vec<u8> {
        let share = hex_bytes(CLIENT_X25519_PUBLIC_HEX);
        let mut key_share_body = Vec::new();
        key_share_body.extend_from_slice(&GROUP_X25519.to_be_bytes());
        key_share_body.extend_from_slice(&(share.len() as u16).to_be_bytes());
        key_share_body.extend_from_slice(&share);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        extensions.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        extensions.extend_from_slice(&(key_share_body.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&key_share_body);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x77; 32]);
        body.push(32);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut sh = vec![0x02];
        sh.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        sh.extend_from_slice(&body);

        let mut prefix = plaintext_record(&sh);
        prefix.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        for len in MIRROR_RECORD_LENGTHS {
            prefix.extend_from_slice(&[0x17, 0x03, 0x03]);
            prefix.extend_from_slice(&len.to_be_bytes());
            prefix.resize(prefix.len() + usize::from(len), 0);
        }
        prefix
    }

    async fn verify_wire_hello(server: RealityServer, hello: &[u8]) -> RealityClientHello {
        let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
        let classify_task =
            tokio::spawn(async move { server.verify_client_hello(Box::new(server_io)).await });
        client_io.write_all(&plaintext_record(hello)).await.unwrap();
        client_io.flush().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), classify_task)
            .await
            .expect("wire-verify timed out")
            .expect("wire-verify joined")
            .expect("wire-verify io")
    }

    #[tokio::test]
    async fn mirror_profile_restrictions_do_not_leak_into_v1_accept_path() {
        // Every CH below passes through the real preflight parser and REALITY
        // authentication as wire bytes; nothing constructs a VerifiedHello by
        // hand.  The v1/off path must treat them exactly like the positive
        // baseline (authenticate and complete), while the mirror profile
        // judgment rejects them with the typed profile error.
        let positive = decode_vector(&POSITIVE_X25519);
        let psk_body = {
            // well-formed minimal pre_shared_key: one identity, one binder
            let mut body = Vec::new();
            body.extend_from_slice(&7u16.to_be_bytes());
            body.extend_from_slice(&1u16.to_be_bytes());
            body.push(0x58);
            body.extend_from_slice(&0u32.to_be_bytes());
            body.extend_from_slice(&33u16.to_be_bytes());
            body.push(32);
            body.extend_from_slice(&[0xaa; 32]);
            body
        };
        for (ext_type, ext_data, profile_error, name) in [
            (
                EXT_RECORD_SIZE_LIMIT,
                16384u16.to_be_bytes().to_vec(),
                MirrorClientProfileError::RecordSizeLimit,
                "shrunk record_size_limit",
            ),
            (
                EXT_PRE_SHARED_KEY,
                psk_body,
                MirrorClientProfileError::PreSharedKey,
                "pre_shared_key",
            ),
            (
                EXT_EARLY_DATA,
                Vec::new(),
                MirrorClientProfileError::EarlyData,
                "early_data",
            ),
        ] {
            let hello = resealed_hello_with_extra_extension(
                &positive.client_hello,
                ext_type,
                &ext_data,
                &positive.auth_key,
            );
            assert_ne!(
                hello[39..71],
                positive.client_hello[39..71],
                "{name}: the extended AAD must re-seal the session id"
            );

            let classified = verify_wire_hello(vector_server(), &hello).await;
            let RealityClientHello::Verified {
                hello: verified, ..
            } = classified
            else {
                panic!(
                    "{name}: the v1/off path must authenticate this CH; mirror restrictions must not leak into it"
                );
            };
            assert_eq!(
                verified.mirror_profile(),
                Err(profile_error),
                "{name}: mirror profile judgment on the wire-parsed CH"
            );
            let prefix = target_prefix_for_session(&hello[39..71]);
            assert_eq!(
                MirrorTemplate::parse(&verified, &prefix),
                Err(MirrorTemplateError::ClientProfile(profile_error)),
                "{name}: template parse must surface the profile rejection before any SH check"
            );
            let upload = verified.into_mirror_upload();
            assert_eq!(
                upload.context().mirror_profile(),
                Err(profile_error),
                "{name}: the consuming context must carry the same profile facts"
            );

            let mut completed = perform_independent_client_handshake(
                vector_server(),
                &hello,
                &positive.auth_key,
                HelloFraming::SingleRecord,
            )
            .await;
            assert_vector_roundtrip(&mut completed).await;
        }
    }

    #[tokio::test]
    async fn mirror_profile_accepts_default_and_exact_record_size_limit_on_wire() {
        // Controls for the dual-path evidence: the unmodified positive CH and
        // a CH carrying the exact record_size_limit 16385 both authenticate
        // AND satisfy the mirror profile, so the rejections above are caused
        // by the specific extension semantics rather than the harness.
        let positive = decode_vector(&POSITIVE_X25519);
        for (hello, name) in [
            (positive.client_hello.clone(), "baseline positive CH"),
            (
                resealed_hello_with_extra_extension(
                    &positive.client_hello,
                    EXT_RECORD_SIZE_LIMIT,
                    &16385u16.to_be_bytes(),
                    &positive.auth_key,
                ),
                "exact record_size_limit 16385",
            ),
        ] {
            let classified = verify_wire_hello(vector_server(), &hello).await;
            let RealityClientHello::Verified {
                hello: verified, ..
            } = classified
            else {
                panic!("{name}: must authenticate");
            };
            assert_eq!(verified.mirror_profile(), Ok(()), "{name}");
            let prefix = target_prefix_for_session(&hello[39..71]);
            assert!(
                MirrorTemplate::parse(&verified, &prefix).is_ok(),
                "{name}: template must parse when the profile is clean"
            );
        }
    }

    #[tokio::test]
    async fn mirrored_flight_is_invariant_under_client_hello_reframing() {
        // The logical transcript is the assembled CH message, never its
        // record or TCP framing: the same authenticated CH split across many
        // TLS records, dribbled byte-wise over one record, or sent whole must
        // reproduce the frozen logical CH byte-for-byte and therefore the
        // byte-identical frozen mirrored flight.
        for vector in [&MIRROR_X25519_AES128, &MIRROR_HYBRID_AES256] {
            for framing in [
                HelloFraming::SingleRecord,
                HelloFraming::ByteWiseTcp,
                HelloFraming::SplitRecords(&[113, 64, 7]),
            ] {
                let session = open_mirror_vector_session_framed(
                    vector,
                    mirror_fixed_crypto(vector),
                    true,
                    framing,
                )
                .await;
                let MirrorVectorSession {
                    mut client_io,
                    stream,
                    completion,
                } = session;
                client_io
                    .write_all(&hex_bytes(vector.client_finished_record_hex))
                    .await
                    .unwrap();
                client_io.flush().await.unwrap();
                tokio::time::timeout(Duration::from_secs(2), completion.finish(stream))
                    .await
                    .expect("reframed mirrored Finished timed out")
                    .unwrap_or_else(|error| {
                        panic!(
                            "{}: reframed {:?} Finished failed: {error}",
                            vector.name, framing
                        )
                    });
            }
        }
    }
    #[tokio::test]
    async fn staged_bcover_capacity_measurement_counts_moved_prefix_and_direction_buffers() {
        let (client_end, _client_peer) = tokio::io::duplex(1024);
        let (target_end, _target_peer) = tokio::io::duplex(1024);
        let download = Vec::with_capacity(65_537);
        let upload = Vec::new();
        let future = relay_cover_with_prefixes(
            Box::new(client_end),
            Box::new(target_end),
            CoverRelayPrefixes {
                upload,
                download,
                ..CoverRelayPrefixes::default()
            },
            CoverBandwidthLimit::default(),
        );
        let future_state_size = std::mem::size_of_val(&future);
        let accounted = 65_537 + 2 * COVER_BUFFER;
        assert_eq!(accounted, 98_305, "Bcover arithmetic");
        eprintln!(
            "bcover-measured moved_prefix_capacity=65537 direction_buffers=32768 accounted={accounted} Bcover=98305 cover_future_state_size={future_state_size}"
        );
        drop(future);
    }
}
