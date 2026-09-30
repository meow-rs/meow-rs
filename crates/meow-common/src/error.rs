use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MeowError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Config error: {0}")]
    Config(String),
    #[error("DNS error: {0}")]
    Dns(String),
    #[error("Proxy error: {0}")]
    Proxy(String),
    #[error("Not supported: {0}")]
    NotSupported(String),
    #[error("proxy authentication failed")]
    ProxyAuthFailed,
    #[error("HTTP CONNECT failed with status {0}")]
    HttpConnectFailed(u16),
    #[error("SOCKS5 connect failed with reply code {0:#04x}")]
    Socks5ConnectFailed(u8),
    #[error("SOCKS5: no acceptable authentication method")]
    NoAcceptableMethod,
    #[error("no proxy available")]
    NoProxyAvailable,
    #[error("relay chain failed at hop {hop}: {source}")]
    RelayHopFailed { hop: usize, source: Box<MeowError> },
    #[error("UDP not supported by this relay chain")]
    UdpNotSupported,
    #[error("{0}")]
    Other(String),
}

impl MeowError {
    /// True when the failure describes member *capability*, not member
    /// health: `NotSupported`/`UdpNotSupported` at any [`RelayHopFailed`]
    /// depth, or an `Unsupported` io error a front's refusal was mapped to
    /// at the dialer io boundary ([`Self::into_io_error`]). A UDP-less
    /// front or a relay hop that cannot carry the protocol is a permanent
    /// property of the member — dead-marking cannot fix it and only
    /// blackholes the group until the next probe.
    ///
    /// [`RelayHopFailed`]: MeowError::RelayHopFailed
    pub fn is_capability_error(&self) -> bool {
        match self {
            Self::NotSupported(_) | Self::UdpNotSupported => true,
            Self::Io(e) => e.kind() == io::ErrorKind::Unsupported,
            Self::RelayHopFailed { source, .. } => source.is_capability_error(),
            _ => false,
        }
    }

    /// True when the failure is *local* resource exhaustion — this process,
    /// not the remote member, ran out: fd-table, socket-buffer, or memory
    /// pressure (`EMFILE`/`ENFILE`/`ENOBUFS`/`ENOMEM`, or the WSA
    /// equivalents) at any [`RelayHopFailed`] depth. Dead-marking the
    /// member punishes a healthy node for a local condition; for a
    /// load-balance group it escalates to `NoProxyAvailable` until the
    /// next probe sweep (issue #668).
    ///
    /// [`RelayHopFailed`]: MeowError::RelayHopFailed
    pub fn is_local_resource_error(&self) -> bool {
        match self {
            Self::Io(e) => is_local_resource_io_error(e),
            Self::RelayHopFailed { source, .. } => source.is_local_resource_error(),
            _ => false,
        }
    }

    /// Whether an `io::Error` carries a preservable payload — a raw
    /// errno, or an errno-less `OutOfMemory` allocation failure — that
    /// classification must not lose to a later context-only error.
    pub fn io_errno_backed(e: &io::Error) -> bool {
        e.raw_os_error().is_some() || e.kind() == io::ErrorKind::OutOfMemory
    }

    /// True when the error still carries a preservable io payload (a
    /// live OS errno or an errno-less `OutOfMemory`) at any
    /// [`RelayHopFailed`] depth. Multi-candidate dial loops use this to
    /// keep a concrete socket failure (e.g. EMFILE on an early
    /// candidate's `socket()`) from being masked by a later candidate's
    /// context-only error — the errno is the classification dead-marking
    /// reads (issue #668).
    ///
    /// [`RelayHopFailed`]: MeowError::RelayHopFailed
    pub fn is_errno_backed(&self) -> bool {
        match self {
            Self::Io(e) => Self::io_errno_backed(e),
            Self::RelayHopFailed { source, .. } => source.is_errno_backed(),
            _ => false,
        }
    }

    /// Accumulator for multi-candidate dial loops: keeps `prev` when it
    /// is errno-backed and `next` is not — a concrete socket error
    /// outranks a context-only failure. Errno-vs-errno and
    /// context-vs-context keep last-wins.
    pub fn prefer_errno(prev: Option<Self>, next: Self) -> Option<Self> {
        if prev.as_ref().is_some_and(Self::is_errno_backed) && !next.is_errno_backed() {
            prev
        } else {
            Some(next)
        }
    }

    /// `io::Error`-level counterpart of [`Self::prefer_errno`] for dial
    /// loops that accumulate `Option<io::Error>` directly.
    pub fn prefer_errno_io(prev: Option<io::Error>, next: io::Error) -> Option<io::Error> {
        if prev.as_ref().is_some_and(Self::io_errno_backed) && !Self::io_errno_backed(&next) {
            prev
        } else {
            Some(next)
        }
    }

    /// Flatten for an `io::Result` boundary (e.g. `ProxyDialer` under a
    /// transport stack) while preserving the classification the inner
    /// error carried:
    ///
    /// - Capability refusals become `ErrorKind::Unsupported` so the caller
    ///   side of the boundary can reconstitute them ([`Self::is_capability_error`]
    ///   recognizes the kind).
    /// - A chain whose innermost error is `Io` passes that io error through
    ///   verbatim — `raw_os_error()` and `kind()` survive, which is what
    ///   dead-marking reads to tell local resource exhaustion from member
    ///   health (issue #668). The `context` prefix is dropped for these:
    ///   std io errors cannot carry context without discarding the errno.
    /// - Anything else collapses to `Other` with a `{context}: {error}`
    ///   message, matching the historical `io::Error::other` flattening.
    pub fn into_io_error(self, context: &str) -> io::Error {
        if self.is_capability_error() {
            return io::Error::new(io::ErrorKind::Unsupported, format!("{context}: {self}"));
        }
        match self.innermost_io() {
            Ok(e) => e,
            Err(e) => io::Error::other(format!("{context}: {e}")),
        }
    }

    /// Wrap a transport-layer `io::Error` at an adapter boundary (e.g.
    /// `ss tcp connect: {e}`). An error carrying a preservable io
    /// payload (`raw_os_error` or errno-less `OutOfMemory`), or one
    /// carrying the `Unsupported` capability class, passes through as
    /// `Io` verbatim — `Proxy`/`Other` stringification would erase the
    /// classification dead-marking reads to tell local resource
    /// exhaustion and capability refusals from member health (issues
    /// #663/#668), and the OS message is self-descriptive. Other
    /// synthesized io errors keep the historical `{context}: {e}`
    /// `Proxy` shape.
    pub fn io_with(context: &str, e: io::Error) -> Self {
        if Self::io_errno_backed(&e) || e.kind() == io::ErrorKind::Unsupported {
            Self::Io(e)
        } else {
            Self::Proxy(format!("{context}: {e}"))
        }
    }

    /// Unwrap [`RelayHopFailed`] layers down to the innermost `Io` error,
    /// rebuilding the wrapper when the chain bottoms in a non-io leaf so
    /// the caller keeps the full hop context.
    ///
    /// [`RelayHopFailed`]: MeowError::RelayHopFailed
    fn innermost_io(self) -> std::result::Result<io::Error, Self> {
        match self {
            Self::Io(e) => Ok(e),
            Self::RelayHopFailed { hop, source } => match source.innermost_io() {
                Ok(e) => Ok(e),
                Err(source) => Err(Self::RelayHopFailed {
                    hop,
                    source: Box::new(source),
                }),
            },
            e => Err(e),
        }
    }
}

/// `raw_os_error` values that mean the *local* process is out of
/// resources: `EMFILE`/`ENFILE` (fd table), `ENOBUFS` (socket buffers),
/// `ENOMEM`. The set stays tight — `EAGAIN`/`EADDRNOTAVAIL` are transient
/// or config-shaped and are already bounded by dial timeouts.
#[cfg(unix)]
fn is_local_resource_io_error(e: &io::Error) -> bool {
    // `OutOfMemory` covers errno-less synthesized allocation failures.
    e.kind() == io::ErrorKind::OutOfMemory
        || matches!(
            e.raw_os_error(),
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
        )
}

/// Winsock equivalents of the unix set: `WSAEMFILE` (10024),
/// `WSAENOBUFS` (10055), `ERROR_NOT_ENOUGH_MEMORY` (8) and
/// `ERROR_OUTOFMEMORY` (14), which socket/allocation failures surface as
/// raw os errors.
#[cfg(windows)]
fn is_local_resource_io_error(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::OutOfMemory
        || matches!(e.raw_os_error(), Some(10024 | 10055 | 8 | 14))
}

#[cfg(not(any(unix, windows)))]
fn is_local_resource_io_error(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::OutOfMemory
}

pub type Result<T> = std::result::Result<T, MeowError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_errors_are_detected_at_any_hop_depth() {
        assert!(MeowError::NotSupported("udp".into()).is_capability_error());
        assert!(MeowError::UdpNotSupported.is_capability_error());
        let nested = MeowError::RelayHopFailed {
            hop: 2,
            source: Box::new(MeowError::NotSupported("udp".into())),
        };
        assert!(nested.is_capability_error());
        // io-boundary reconstitution: a front's refusal mapped to
        // `ErrorKind::Unsupported` and re-wrapped as `MeowError::Io`.
        let io = MeowError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "dialer-proxy udp: refused",
        ));
        assert!(io.is_capability_error());
        assert!(!MeowError::Proxy("boom".into()).is_capability_error());
        assert!(!MeowError::Io(io::Error::other("x")).is_capability_error());
    }

    #[cfg(unix)]
    #[test]
    fn local_resource_errnos_are_detected_at_any_hop_depth() {
        let emfile = MeowError::Io(io::Error::from_raw_os_error(libc::EMFILE));
        assert!(emfile.is_local_resource_error());
        let nested = MeowError::RelayHopFailed {
            hop: 0,
            source: Box::new(MeowError::Io(io::Error::from_raw_os_error(libc::ENFILE))),
        };
        assert!(nested.is_local_resource_error());
        // Ordinary dial failures are NOT local resource errors.
        let refused = MeowError::Io(io::Error::from_raw_os_error(libc::ECONNREFUSED));
        assert!(!refused.is_local_resource_error());
        let timeout = MeowError::Io(io::Error::new(io::ErrorKind::TimedOut, "x"));
        assert!(!timeout.is_local_resource_error());
        assert!(!MeowError::Proxy("boom".into()).is_local_resource_error());
    }

    #[test]
    fn into_io_error_preserves_the_capability_class() {
        let e = MeowError::RelayHopFailed {
            hop: 1,
            source: Box::new(MeowError::UdpNotSupported),
        };
        let io_err = e.into_io_error("dialer-proxy");
        assert_eq!(io_err.kind(), io::ErrorKind::Unsupported);
        assert!(io_err.to_string().contains("dialer-proxy"));
    }

    #[cfg(unix)]
    #[test]
    fn into_io_error_passes_errno_through_hop_wrappers() {
        let e = MeowError::RelayHopFailed {
            hop: 1,
            source: Box::new(MeowError::Io(io::Error::from_raw_os_error(libc::EMFILE))),
        };
        let io_err = e.into_io_error("dialer-proxy");
        assert_eq!(io_err.raw_os_error(), Some(libc::EMFILE));
    }

    #[test]
    fn into_io_error_keeps_context_on_non_io_chains() {
        let e = MeowError::RelayHopFailed {
            hop: 3,
            source: Box::new(MeowError::Proxy("down".into())),
        };
        let io_err = e.into_io_error("dialer-proxy");
        assert_eq!(io_err.kind(), io::ErrorKind::Other);
        let msg = io_err.to_string();
        assert!(msg.contains("dialer-proxy"), "{msg}");
        assert!(msg.contains("hop 3"), "{msg}");
    }

    #[test]
    fn synthesized_out_of_memory_counts_as_local_resource() {
        // `TryReserveError`-style failures arrive errno-less — the kind
        // arm still classifies them as local exhaustion on every platform.
        let e = MeowError::Io(io::Error::new(io::ErrorKind::OutOfMemory, "reserve"));
        assert!(e.is_local_resource_error());
    }

    #[test]
    fn into_io_error_round_trips_capability_through_hop_wrappers() {
        // `RelayHopFailed{Io(Unsupported)}` — the io-boundary shape a
        // front's refusal takes when `dial_udp_conn` already mapped it —
        // must re-emit `Unsupported`, not collapse to `Other`.
        let e = MeowError::RelayHopFailed {
            hop: 2,
            source: Box::new(MeowError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "front refused udp",
            ))),
        };
        assert_eq!(
            e.into_io_error("dialer-proxy").kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[cfg(unix)]
    #[test]
    fn classification_survives_deep_relay_chains() {
        // Bounded in production by MAX_DIALER_CHAIN_DEPTH (16); exercise
        // depth 3 to pin the recursive walk.
        let mut e = MeowError::Io(io::Error::from_raw_os_error(libc::ENOBUFS));
        for hop in [2, 1, 0] {
            e = MeowError::RelayHopFailed {
                hop,
                source: Box::new(e),
            };
        }
        assert!(e.is_local_resource_error());
        assert_eq!(
            e.into_io_error("dialer-proxy").raw_os_error(),
            Some(libc::ENOBUFS)
        );

        let mut e = MeowError::NotSupported("udp".into());
        for hop in [2, 1, 0] {
            e = MeowError::RelayHopFailed {
                hop,
                source: Box::new(e),
            };
        }
        assert!(e.is_capability_error());
    }

    #[test]
    fn io_with_keeps_errno_backed_errors_as_io() {
        let e = io::Error::from_raw_os_error(1); // EPERM — errno present, not
                                                 // in the local-resource set.
        let wrapped = MeowError::io_with("ctx", e);
        match wrapped {
            MeowError::Io(e) => assert_eq!(e.raw_os_error(), Some(1)),
            other => panic!("expected Io, got {other}"),
        }
    }

    #[test]
    fn io_with_keeps_the_capability_kind_as_io() {
        // Synthesized `Unsupported` (no errno) is still a capability
        // refusal — flattening to `Proxy` would let it dead-mark members.
        let e = io::Error::new(io::ErrorKind::Unsupported, "front: no udp");
        let wrapped = MeowError::io_with("ctx", e);
        match wrapped {
            MeowError::Io(e) => {
                assert_eq!(e.kind(), io::ErrorKind::Unsupported);
                assert!(MeowError::Io(e).is_capability_error());
            }
            other => panic!("expected Io, got {other}"),
        }
    }

    #[test]
    fn io_with_stringifies_context_only_errors() {
        // Synthesized errors without errno or a capability kind keep the
        // historical `Proxy("{ctx}: {e}")` shape.
        let e = io::Error::other("handshake torn");
        let wrapped = MeowError::io_with("ctx", e);
        match wrapped {
            MeowError::Proxy(msg) => assert_eq!(msg, "ctx: handshake torn"),
            other => panic!("expected Proxy, got {other}"),
        }
    }

    #[test]
    fn prefer_errno_keeps_errno_backed_over_context_only() {
        let emfile = || MeowError::RelayHopFailed {
            hop: 0,
            source: Box::new(MeowError::Io(io::Error::from_raw_os_error(1))),
        };
        let ctx = || MeowError::Proxy("session config".into());
        // errno prev survives a context-only next…
        let acc = MeowError::prefer_errno(Some(emfile()), ctx());
        assert!(acc.as_ref().is_some_and(MeowError::is_errno_backed));
        // …and errno next replaces a context-only prev.
        let acc = MeowError::prefer_errno(Some(ctx()), emfile());
        assert!(acc.as_ref().is_some_and(MeowError::is_errno_backed));
        // Two context-only errors: last wins.
        let acc = MeowError::prefer_errno(Some(ctx()), MeowError::Proxy("later".into()));
        assert!(matches!(acc, Some(MeowError::Proxy(ref s)) if s == "later"));
        // An `Io` without errno does not claim precedence.
        let acc = MeowError::prefer_errno(Some(MeowError::Io(io::Error::other("synth"))), ctx());
        assert!(matches!(acc, Some(MeowError::Proxy(_))));
    }

    #[test]
    fn prefer_errno_io_keeps_errno_backed_over_context_only() {
        let errno = || io::Error::from_raw_os_error(1);
        let context = || io::Error::other("candidate failed");

        // errno prev survives a context-only next; errno next always
        // replaces; errno-less Io claims no precedence; OOM-kind io
        // counts as payload-bearing.
        let prev = MeowError::prefer_errno_io(Some(errno()), context());
        assert_eq!(prev.as_ref().and_then(io::Error::raw_os_error), Some(1));
        let prev = MeowError::prefer_errno_io(Some(context()), errno());
        assert_eq!(prev.as_ref().and_then(io::Error::raw_os_error), Some(1));
        let prev = MeowError::prefer_errno_io(None, context());
        assert_eq!(prev.as_ref().and_then(io::Error::raw_os_error), None);
        let oom = || io::Error::new(io::ErrorKind::OutOfMemory, "reserve");
        let prev = MeowError::prefer_errno_io(Some(oom()), context());
        assert_eq!(
            prev.as_ref().map(io::Error::kind),
            Some(io::ErrorKind::OutOfMemory)
        );
    }

    #[test]
    fn io_with_passes_errno_less_out_of_memory_verbatim() {
        // Matches `is_local_resource_io_error`'s kind arm: a synthesized
        // OOM io error must not be flattened to `Proxy` at adapter
        // boundaries — `Io` is what the exemption reads.
        let e = MeowError::io_with("ctx", io::Error::new(io::ErrorKind::OutOfMemory, "reserve"));
        match e {
            MeowError::Io(ref inner) => assert_eq!(inner.kind(), io::ErrorKind::OutOfMemory),
            ref other => panic!("expected Io passthrough, got {other:?}"),
        }
        assert!(e.is_local_resource_error());
    }

    #[cfg(windows)]
    #[test]
    fn windows_resource_errnos_are_detected() {
        // WSAEMFILE / WSAENOBUFS / ERROR_NOT_ENOUGH_MEMORY /
        // ERROR_OUTOFMEMORY — socket and allocation failures surface as
        // raw os errors on Windows.
        for code in [10024, 10055, 8, 14] {
            let e = MeowError::Io(io::Error::from_raw_os_error(code));
            assert!(e.is_local_resource_error(), "errno {code}");
        }
        let refused = MeowError::Io(io::Error::from_raw_os_error(10061)); // WSAECONNREFUSED
        assert!(!refused.is_local_resource_error());
    }
}
