use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;

use hickory_proto::op::ResponseCode;

/// A parsed nameserver URL in one of the supported transport forms.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameServerUrl {
    Udp {
        addr: HostOrIp,
        port: u16,
    },
    Tcp {
        addr: HostOrIp,
        port: u16,
    },
    Tls {
        addr: HostOrIp,
        port: u16,
        sni: String,
    },
    Https {
        addr: HostOrIp,
        port: u16,
        path: String,
        sni: String,
        /// HTTP/3 policy for this entry: mihomo `prefer-h3` (global) and the
        /// per-entry `?h3=` parameter both land here.
        h3: H3Policy,
    },
    /// DNS over QUIC (RFC 9250) — `quic://host[:port][#sni]`.
    Quic {
        addr: HostOrIp,
        port: u16,
        sni: String,
    },
    RCode {
        code: ResponseCode,
        label: String,
    },
}

/// How a `https://` nameserver uses HTTP/3.
///
/// mihomo spells this two ways: the global `dns.prefer-h3` flag ("allow HTTP/3
/// alongside HTTP/2 and HTTP/1.1") and the per-entry `&h3=true` parameter
/// ("HTTP/3 only"). meow-rs keeps both meanings apart, and adds the explicit
/// `?h3=prefer` spelling so a config can opt one entry into the preference
/// without the global flag:
///
/// | YAML | policy |
/// | --- | --- |
/// | (nothing) | [`H3Policy::Off`] |
/// | `dns.prefer-h3: true` | [`H3Policy::Prefer`] on every `https://` entry |
/// | `?h3=prefer` | [`H3Policy::Prefer`] on that entry |
/// | `?h3=true` (mihomo spelling) | [`H3Policy::Force`], like mihomo |
///
/// `?h3=false` turns the entry back off, overriding `dns.prefer-h3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum H3Policy {
    /// Never attempt HTTP/3 (the default).
    #[default]
    Off,
    /// Try HTTP/3 first and fall back to HTTP/2 / HTTP/1.1 when the QUIC
    /// exchange fails. This is what mihomo's `prefer-h3` asks for.
    Prefer,
    /// HTTP/3 only, no fallback — mihomo's per-entry `&h3=true`.
    Force,
}

impl H3Policy {
    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// Either a resolved IP address or a hostname that requires bootstrap resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostOrIp {
    Ip(IpAddr),
    Host(String),
}

impl fmt::Display for HostOrIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostOrIp::Ip(ip) => write!(f, "{ip}"),
            HostOrIp::Host(h) => write!(f, "{h}"),
        }
    }
}

impl fmt::Display for NameServerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameServerUrl::Udp { addr, port } => write!(f, "udp://{addr}:{port}"),
            NameServerUrl::Tcp { addr, port } => write!(f, "tcp://{addr}:{port}"),
            NameServerUrl::Tls { addr, port, sni } => write!(f, "tls://{addr}:{port}#{sni}"),
            NameServerUrl::Https {
                addr,
                port,
                path,
                sni,
                h3,
            } => {
                let param = match h3 {
                    H3Policy::Off => "",
                    H3Policy::Prefer => "h3=prefer",
                    H3Policy::Force => "h3=true",
                };
                if param.is_empty() {
                    write!(f, "https://{addr}:{port}{path}#{sni}")
                } else {
                    let separator = h3_parameter_separator(path);
                    write!(f, "https://{addr}:{port}{path}{separator}{param}#{sni}")
                }
            }
            NameServerUrl::Quic { addr, port, sni } => write!(f, "quic://{addr}:{port}#{sni}"),
            NameServerUrl::RCode { label, .. } => write!(f, "rcode://{label}"),
        }
    }
}

/// A nameserver entry — a [`NameServerUrl`] plus an optional proxy tag
/// telling the resolver to tunnel queries through the named proxy.
///
/// See [ADR-0012](../../../../docs/adr/0012-dns-via-proxy.md) for the
/// design (issue #67 phase 2). Plain `Udp` / `Tcp` forms take the proxy
/// name in the `#PROXY` fragment; `Tls` / `Https` forms already use `#`
/// for SNI, so they take it in the `?proxy=NAME` parameter section
/// instead. Both spellings land in this same `proxy` slot.
///
/// `?` parameter-section rule [canonical — every doc/test must state it
/// the same way]:
///
/// **A `?` parameter section is only legal on `tls://` / `https://`
/// entries. Using the entry's *last* `?` as the boundary: when any
/// `&`-separated segment of the tail is a `proxy=` key, that `?` section
/// is a parameter section — an `&`-separated `k=v` list whose only
/// currently-legal key is `proxy`. Key detection trims whitespace around
/// the key and is ASCII case-insensitive, so `? proxy=P`, `?proxy =P`
/// and `?Proxy=P` also mark a parameter section — then fail validation
/// as non-canonical spellings rather than riding inside the request
/// path. The `proxy` value is trimmed like the `#PROXY` slot and must
/// then be non-empty and contain no `#`/`?`/`&`; any other key is a hard
/// [`NameServerParseError::InvalidParams`], so `?a=b&proxy=P` errors
/// rather than silently dropping the proxy tag. When no `&`-separated
/// segment is a `proxy=` key, the `?` section is not a parameter section
/// and stays in the URL (path) verbatim — whitespace *inside* a key
/// (`?p roxy=P`) and percent-spellings (`?%20proxy=`) stay path
/// material — and if any earlier `?` section still carries a `proxy=`
/// key (the `?proxy=P?x=1` double-`?` typo), parse fails: a stranded
/// `proxy=` key would travel inside the request path and leak the proxy
/// name to the upstream. A path that legitimately needs the key
/// percent-spells it (`?%70roxy=`).**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameServerEntry {
    pub url: NameServerUrl,
    pub proxy: Option<String>,
}

impl NameServerEntry {
    pub fn plain(url: NameServerUrl) -> Self {
        Self { url, proxy: None }
    }

    /// Parse a nameserver string, returning the parsed `NameServerUrl` plus
    /// the optional proxy name carried by a plain-form `#PROXY` fragment or
    /// an encrypted-form `?proxy=NAME` parameter section. The latter decodes
    /// percent escapes once; encode a literal percent as `%25`. Parameter keys,
    /// the DoH request path and plain-form fragments are not decoded here.
    pub fn parse(s: &str) -> Result<Self, NameServerParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(NameServerParseError::EmptyInput);
        }

        // Only encrypted entries (`tls://`, `https://`, `quic://`) may carry
        // a `?` parameter section; strip it here so the `#` fragment dispatch
        // below — and `NameServerUrl::parse`'s hostname/path consumption —
        // sees the remainder untouched. On plain forms any `?` at all is a
        // config bug (previously it was silently swallowed into the
        // hostname).
        let is_encrypted_form =
            s.starts_with("tls://") || s.starts_with("https://") || s.starts_with("quic://");
        let mut head: Cow<'_, str> = Cow::Borrowed(s);
        let mut query_proxy: Option<String> = None;
        let mut query_h3: Option<H3Policy> = None;
        if is_encrypted_form {
            if let Some(qidx) = s.rfind('?') {
                // mihomo writes parameters into the `#` fragment, meow-rs
                // writes them into a `?` section — a URL can therefore carry
                // its SNI *after* the parameters (`?h3=true#dns.google`).
                // Split the fragment off the section before validating keys,
                // then re-attach it ahead of the `?` so the fragment rules
                // below see it as SNI.
                let after = &s[qidx + 1..];
                let (tail, trailing_frag) = match after.find('#') {
                    Some(idx) => (&after[..idx], Some(&after[idx..])),
                    None => (after, None),
                };
                // The tail is a parameter section when ANY `&`-separated
                // segment is a known parameter key — `?a=b&proxy=P` must
                // hard-error on the unknown `a` key below, not silently
                // lose the proxy tag inside the path (r15 review I1). The
                // shared key predicate trims whitespace and is ASCII
                // case-insensitive, so `? proxy=P` / `?Proxy=P` mark the
                // section too — and then fail validation below as
                // non-canonical spellings.
                if tail.split('&').any(is_param_key_segment) {
                    // The tail is a parameter section: an `&`-separated
                    // `k=v` list of `proxy` and `h3`.
                    let mut proxy_value: Option<&str> = None;
                    for kv in tail.split('&') {
                        let (key, val) = kv.split_once('=').unwrap_or((kv, ""));
                        if key.eq_ignore_ascii_case("proxy") {
                            // Case-variant keys reached this section through
                            // the case-insensitive detection above — name the
                            // canonical spelling instead of reporting `Proxy`
                            // as just another unknown key.
                            if key != "proxy" {
                                return Err(NameServerParseError::InvalidParams(format!(
                                    "nameserver parameter '{key}' must be spelled \
                                     lowercase 'proxy' in '{s}'"
                                )));
                            }
                            if proxy_value.is_some() {
                                return Err(NameServerParseError::InvalidParams(format!(
                                    "duplicate 'proxy' parameter in '{s}'"
                                )));
                            }
                            // Same trim as the `#PROXY` slot below:
                            // `?proxy= P` means the proxy named `P`.
                            let val = val.trim();
                            if val.is_empty() || val.contains('#') {
                                return Err(NameServerParseError::InvalidParams(format!(
                                    "invalid proxy name '{val}' in '{s}'"
                                )));
                            }
                            proxy_value = Some(val);
                            continue;
                        }
                        if key.eq_ignore_ascii_case("h3") {
                            if key != "h3" {
                                return Err(NameServerParseError::InvalidParams(format!(
                                    "nameserver parameter '{key}' must be spelled \
                                     lowercase 'h3' in '{s}'"
                                )));
                            }
                            if !s.starts_with("https://") {
                                return Err(NameServerParseError::InvalidParams(format!(
                                    "'h3' is only valid on https:// nameserver entries \
                                     (it selects HTTP/3 for DoH), got '{s}'"
                                )));
                            }
                            if query_h3.is_some() {
                                return Err(NameServerParseError::InvalidParams(format!(
                                    "duplicate 'h3' parameter in '{s}'"
                                )));
                            }
                            query_h3 = Some(match val.trim() {
                                // mihomo spells the per-entry form `&h3=true`
                                // and means "HTTP/3 only".
                                "true" => H3Policy::Force,
                                "false" => H3Policy::Off,
                                // meow-rs addition: prefer without forcing, so
                                // one entry can opt into the global behaviour.
                                "prefer" => H3Policy::Prefer,
                                other => {
                                    return Err(NameServerParseError::InvalidParams(format!(
                                        "invalid 'h3' value '{other}' in '{s}' (expected \
                                         'true', 'false' or 'prefer')"
                                    )));
                                }
                            });
                            continue;
                        }
                        // Whitespace-padded known keys marked this a parameter
                        // section above; give the key its own hint — the
                        // generic arm would print `' proxy'` with the defect
                        // invisible.
                        if key.trim().eq_ignore_ascii_case("proxy")
                            || key.trim().eq_ignore_ascii_case("h3")
                        {
                            return Err(NameServerParseError::InvalidParams(format!(
                                "whitespace is not allowed in the '{key}' parameter \
                                 name in '{s}' — spell it exactly '{stripped}'",
                                stripped = key.trim()
                            )));
                        }
                        return Err(NameServerParseError::InvalidParams(format!(
                            "unknown nameserver parameter '{key}' in '{s}' \
                             (only 'proxy' and 'h3' are supported)"
                        )));
                    }
                    query_proxy = proxy_value.map(decode_proxy_name).transpose()?;
                    head = match trailing_frag {
                        Some(frag) => Cow::Owned(format!("{}{frag}", &s[..qidx])),
                        None => Cow::Borrowed(&s[..qidx]),
                    };
                }
            }
            // Every `?` section still standing (post-strip on either
            // branch — `head` is final here) must be parameter-key-free: a
            // `proxy=` key stranded in an earlier `?` section — the
            // `?proxy=P?x=1` double-`?` typo, or `?proxy=A?proxy=B`
            // where the last `?` still tagged — would travel inside the
            // request path and leak the proxy name to the upstream.
            // Key-level per `?`-section, `skip(1)` so `&` inside the
            // path (`/p&proxy=P?x=1`) stays path material.
            if head
                .as_ref()
                .split('?')
                .skip(1)
                .flat_map(|sec| sec.split('&'))
                .any(is_param_key_segment)
            {
                return Err(NameServerParseError::InvalidParams(format!(
                    "the parameter section must be the last '?' section in '{s}'"
                )));
            }
            // The fragment that survives `?`-section stripping must be
            // clean SNI material: leftover `&`/`?` is the classic mihomo
            // `#sni&proxy=P` migration typo — under our `#`=SNI
            // divergence it is a garbage SNI that would only fail at
            // handshake time, so refuse it at parse time instead.
            if let Some(hidx) = head.as_ref().find('#') {
                let frag = &head.as_ref()[hidx + 1..];
                if frag.contains('&') || frag.contains('?') {
                    return Err(NameServerParseError::InvalidParams(format!(
                        "invalid SNI fragment '#{frag}' in '{s}'"
                    )));
                }
                // A DNS name never contains '=', so a fragment that does is
                // the mihomo spelling of a per-entry parameter (`#h3=true`).
                // `#` is SNI in meow-rs: say so instead of failing the TLS
                // handshake on a nonsense server name later.
                if frag.contains('=') {
                    return Err(NameServerParseError::InvalidParams(format!(
                        "invalid SNI fragment '#{frag}' in '{s}' — '#' is SNI on \
                         tls://, https:// and quic:// entries; parameters go in the \
                         '?' section (e.g. '?h3=true')"
                    )));
                }
                // `#P?proxy=Q` would be read by a mihomo migrant as a
                // second proxy tag; in meow-rs `#` is SNI, so the pair is
                // unresolvable — a bare fragment (no `.`, proxy-name
                // shaped) next to an explicit `?proxy=` is refused loudly.
                // `#dns.google?proxy=P` is the intended SNI+proxy form.
                if query_proxy.is_some() && !frag.contains('.') {
                    return Err(NameServerParseError::InvalidParams(format!(
                        "'#{frag}' next to '?proxy=' is ambiguous — '#' on a \
                         tls:///https:// entry is SNI in meow-rs, so a bare \
                         fragment reads as a second proxy tag (a config bug). \
                         Use a dotted SNI, e.g. '#dns.google?proxy=NAME'"
                    )));
                }
            }
        } else if s.contains('?') {
            return Err(NameServerParseError::InvalidParams(format!(
                "'?' parameters are only valid on tls:// / https:// / quic:// \
                 nameserver entries, got '{s}'"
            )));
        }

        // Only plain forms (no scheme, `udp://`, `tcp://`) treat the `#`
        // fragment as a proxy name. For `tls://` / `https://` the
        // fragment is SNI — leave it intact and let NameServerUrl::parse
        // consume it normally.
        if !is_encrypted_form {
            if let Some(idx) = head.as_ref().find('#') {
                let proxy = head.as_ref()[idx + 1..].trim();
                if proxy.is_empty() {
                    return Err(NameServerParseError::InvalidHost(s.to_string()));
                }
                let url = NameServerUrl::parse(&head.as_ref()[..idx])?;
                return Ok(Self {
                    url,
                    proxy: Some(proxy.to_string()),
                });
            }
        }
        let url = NameServerUrl::parse(head.as_ref())?;
        // `?h3=` only reaches here on `https://` (validated above); apply it
        // to the parsed entry. `None` leaves the entry at `H3Policy::Off` —
        // `dns.prefer-h3` is applied later, by the config layer, so an
        // explicit `?h3=false` keeps overriding it.
        let url = match query_h3 {
            None => url,
            Some(h3) => match url {
                NameServerUrl::Https {
                    addr,
                    port,
                    path,
                    sni,
                    ..
                } => NameServerUrl::Https {
                    addr,
                    port,
                    path,
                    sni,
                    h3,
                },
                other => {
                    return Err(NameServerParseError::InvalidParams(format!(
                        "'h3' is only valid on https:// nameserver entries, got '{other}'"
                    )));
                }
            },
        };
        Ok(Self {
            url,
            proxy: query_proxy,
        })
    }
}

// Decode only an already-isolated proxy value. Decoding before splitting the
// URL would turn escaped group-name delimiters into path/SNI/parameter syntax.
// A plus is literal (these are config URLs, not HTML form submissions).
fn decode_proxy_name(encoded: &str) -> Result<String, NameServerParseError> {
    let invalid =
        || NameServerParseError::InvalidParams("invalid percent-encoded proxy name".into());
    let mut bytes = Vec::with_capacity(encoded.len());
    let mut input = encoded.bytes();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let hi = input.next().and_then(|b| (b as char).to_digit(16));
            let lo = input.next().and_then(|b| (b as char).to_digit(16));
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return Err(invalid());
            };
            bytes.push((hi * 16 + lo) as u8);
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes)
        .ok()
        .filter(|name| !name.trim().is_empty() && !name.chars().any(char::is_control))
        .ok_or_else(invalid)
}

impl From<NameServerUrl> for NameServerEntry {
    fn from(url: NameServerUrl) -> Self {
        Self::plain(url)
    }
}

impl NameServerUrl {
    /// Returns `Some(hostname)` if this entry needs bootstrap DNS resolution,
    /// `None` if the address is already an IP literal.
    pub fn needs_bootstrap(&self) -> Option<&str> {
        let addr = match self {
            NameServerUrl::Udp { addr, .. }
            | NameServerUrl::Tcp { addr, .. }
            | NameServerUrl::Tls { addr, .. }
            | NameServerUrl::Https { addr, .. }
            | NameServerUrl::Quic { addr, .. } => addr,
            NameServerUrl::RCode { .. } => return None,
        };
        match addr {
            HostOrIp::Host(h) => Some(h.as_str()),
            HostOrIp::Ip(_) => None,
        }
    }

    /// Returns true if this is a plain (non-encrypted) nameserver.
    pub fn is_plain(&self) -> bool {
        matches!(
            self,
            NameServerUrl::Udp { .. } | NameServerUrl::Tcp { .. } | NameServerUrl::RCode { .. }
        )
    }

    /// Parse a nameserver string into a `NameServerUrl`.
    ///
    /// Accepted forms:
    /// - `8.8.8.8` / `8.8.8.8:53`  — plain UDP
    /// - `dns.google` / `dns.google:53`  — plain UDP with hostname
    /// - `udp://host[:port]`
    /// - `tcp://host[:port]`
    /// - `tls://host[:port][#sni]`
    /// - `https://host[:port][/path][#sni]`
    /// - `quic://host[:port][#sni]`
    pub fn parse(s: &str) -> Result<Self, NameServerParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(NameServerParseError::EmptyInput);
        }

        // Split off #fragment before any URL parsing — the fragment is NOT a
        // standard URL anchor in this context; it carries the SNI override.
        let (s_no_frag, fragment) = match s.find('#') {
            Some(idx) => (&s[..idx], Some(&s[idx + 1..])),
            None => (s, None),
        };

        // Dispatch on scheme
        if let Some(rest) = s_no_frag.strip_prefix("tls://") {
            return Self::parse_tls(rest, fragment);
        }
        if let Some(rest) = s_no_frag.strip_prefix("https://") {
            return Self::parse_https(rest, fragment);
        }
        if let Some(rest) = s_no_frag.strip_prefix("udp://") {
            let (addr, port) = parse_host_port(rest, 53)?;
            return Ok(NameServerUrl::Udp { addr, port });
        }
        if let Some(rest) = s_no_frag.strip_prefix("tcp://") {
            let (addr, port) = parse_host_port(rest, 53)?;
            return Ok(NameServerUrl::Tcp { addr, port });
        }
        if let Some(rest) = s_no_frag.strip_prefix("quic://") {
            return Self::parse_quic(rest, fragment);
        }
        if let Some(rest) = s_no_frag.strip_prefix("rcode://") {
            return parse_rcode(rest);
        }
        // Any other explicit scheme → unsupported
        if let Some(colon) = s_no_frag.find("://") {
            let scheme = &s_no_frag[..colon];
            // Make sure it's actually a scheme (letters only, reasonable length)
            if scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
                && colon <= 20
            {
                return Err(NameServerParseError::UnsupportedScheme(scheme.to_string()));
            }
        }

        // No scheme — bare IP or hostname, defaults to UDP port 53
        let (addr, port) = parse_host_port(s_no_frag, 53)?;
        Ok(NameServerUrl::Udp { addr, port })
    }

    #[cfg(feature = "encrypted")]
    fn parse_tls(rest: &str, fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        let (addr, port) = parse_host_port(rest, 853)?;
        let sni = match fragment {
            Some(f) if !f.is_empty() => f.to_string(),
            // Default SNI = the host string (IP or hostname)
            _ => addr.to_string(),
        };
        Ok(NameServerUrl::Tls { addr, port, sni })
    }

    #[cfg(not(feature = "encrypted"))]
    fn parse_tls(_rest: &str, _fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        Err(NameServerParseError::EncryptedFeatureDisabled)
    }

    #[cfg(feature = "encrypted")]
    fn parse_https(rest: &str, fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        // Split path off the host[:port] portion. Path starts at first '/' after host.
        let (hostport, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], rest[idx..].to_string()),
            None => (rest, "/dns-query".to_string()),
        };
        // Ensure path starts with /
        let path = if path.is_empty() {
            "/dns-query".to_string()
        } else {
            path
        };

        let (addr, port) = parse_host_port(hostport, 443)?;
        let sni = match fragment {
            Some(f) if !f.is_empty() => f.to_string(),
            _ => addr.to_string(),
        };
        Ok(NameServerUrl::Https {
            addr,
            port,
            path,
            sni,
            // `?h3=` / `dns.prefer-h3` are applied by `NameServerEntry::parse`
            // and the config layer; a bare `https://` entry is HTTP/2 / HTTP/1.1 DoH.
            h3: H3Policy::Off,
        })
    }

    #[cfg(not(feature = "encrypted"))]
    fn parse_https(_rest: &str, _fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        Err(NameServerParseError::EncryptedFeatureDisabled)
    }

    #[cfg(feature = "quic-dns")]
    fn parse_quic(rest: &str, fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        // RFC 9250 does not fix a port; 853 is the DoQ default the ecosystem
        // uses (and mihomo's `quic://` default).
        let (addr, port) = parse_host_port(rest, 853)?;
        let sni = match fragment {
            Some(f) if !f.is_empty() => f.to_string(),
            _ => addr.to_string(),
        };
        Ok(NameServerUrl::Quic { addr, port, sni })
    }

    #[cfg(not(feature = "quic-dns"))]
    fn parse_quic(_rest: &str, _fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        Err(NameServerParseError::QuicNotSupported)
    }
}

/// Which separator appends an `h3=` parameter to `path` without changing what
/// the path means.
///
/// The parser reads the entry's **last** `?` section as the parameter section,
/// and only when one of its segments is a known key. So a DoH path that
/// already carries a query string (`/dns-query?x=1`) needs a *new* `?`
/// section — `&` would fold `x=1` into the parameter list, where it is an
/// unknown key and a hard parse error.
pub(crate) fn h3_parameter_separator(path: &str) -> &'static str {
    match path.rsplit_once('?').map(|(_, tail)| tail) {
        Some(tail) if tail.split('&').any(is_param_key_segment) => "&",
        _ => "?",
    }
}

/// A `k=v` segment names a *known* nameserver parameter when its key trims to
/// `proxy` or `h3` in any ASCII case. Used to decide whether the `?` tail is a
/// parameter section at all; validation of the exact spelling happens after
/// the decision (so `? proxy=P` is reported as a padded `proxy` key rather
/// than as an unknown one).
fn is_param_key_segment(kv: &str) -> bool {
    kv.split_once('=')
        .is_some_and(|(k, _)| is_param_name(k.trim()))
}

fn is_param_name(key: &str) -> bool {
    key.eq_ignore_ascii_case("proxy") || key.eq_ignore_ascii_case("h3")
}

fn parse_rcode(s: &str) -> Result<NameServerUrl, NameServerParseError> {
    let label = s.trim();
    let code = match label {
        "success" => ResponseCode::NoError,
        "format_error" => ResponseCode::FormErr,
        "server_failure" => ResponseCode::ServFail,
        "name_error" => ResponseCode::NXDomain,
        "not_implemented" => ResponseCode::NotImp,
        "refused" => ResponseCode::Refused,
        _ => return Err(NameServerParseError::UnsupportedRCode(label.to_string())),
    };
    Ok(NameServerUrl::RCode {
        code,
        label: label.to_string(),
    })
}

/// Parse `host:port` or `[ipv6]:port` or bare `host`, returning `(HostOrIp, port)`.
/// `default_port` is used when no port is present.
fn parse_host_port(s: &str, default_port: u16) -> Result<(HostOrIp, u16), NameServerParseError> {
    // IPv6 bracketed form: [::1]:853 or [::1]
    if s.starts_with('[') {
        let close = s
            .find(']')
            .ok_or_else(|| NameServerParseError::InvalidHost(s.to_string()))?;
        let ipv6_str = &s[1..close];
        let ip: IpAddr = ipv6_str
            .parse()
            .map_err(|_| NameServerParseError::InvalidHost(s.to_string()))?;
        let port = if close + 1 < s.len() {
            let port_str = s[close + 1..]
                .strip_prefix(':')
                .ok_or_else(|| NameServerParseError::InvalidHost(s.to_string()))?;
            parse_port(port_str)?
        } else {
            default_port
        };
        return Ok((HostOrIp::Ip(ip), port));
    }

    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((HostOrIp::Ip(ip), default_port));
    }

    if let Some(idx) = s.rfind(':') {
        let maybe_port = &s[idx + 1..];
        if maybe_port.chars().all(|c| c.is_ascii_digit()) {
            let port = parse_port(maybe_port)?;
            let host_str = &s[..idx];
            let addr = parse_host_or_ip(host_str)?;
            return Ok((addr, port));
        }
    }

    // No port — use default
    let addr = parse_host_or_ip(s)?;
    Ok((addr, default_port))
}

fn parse_host_or_ip(s: &str) -> Result<HostOrIp, NameServerParseError> {
    if s.is_empty() {
        return Err(NameServerParseError::InvalidHost(s.to_string()));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(HostOrIp::Ip(ip));
    }
    // Validate it looks like a hostname (not arbitrary junk). `?` and `&`
    // must never reach the hostname slot: a `?proxy=` tail that was not
    // stripped (e.g. `tls://h?x`, or `?x` on a scheme that does not take
    // parameters) would otherwise be swallowed into the host silently.
    if s.contains('/') || s.contains(' ') || s.contains('?') || s.contains('&') {
        return Err(NameServerParseError::InvalidHost(s.to_string()));
    }
    Ok(HostOrIp::Host(s.to_string()))
}

fn parse_port(s: &str) -> Result<u16, NameServerParseError> {
    s.parse::<u32>()
        .ok()
        .filter(|&p| p > 0 && p <= 65535)
        .map(|p| p as u16)
        .ok_or_else(|| NameServerParseError::InvalidPort(s.to_string()))
}

/// Parse error for `NameServerUrl::parse`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameServerParseError {
    #[error("nameserver string is empty")]
    EmptyInput,
    #[error(
        "nameserver uses the 'quic' scheme which requires the 'quic-dns' Cargo feature; rebuild with --features quic-dns (or use 'tls://' / 'https://')"
    )]
    QuicNotSupported,
    #[error("nameserver uses unsupported scheme '{0}'")]
    UnsupportedScheme(String),
    #[error("invalid host in nameserver: '{0}'")]
    InvalidHost(String),
    #[error("invalid port in nameserver: '{0}'")]
    InvalidPort(String),
    #[error(
        "encrypted DNS (tls:// / https://) requires the 'encrypted' Cargo feature to be enabled"
    )]
    EncryptedFeatureDisabled,
    #[error("unsupported rcode nameserver type '{0}'")]
    UnsupportedRCode(String),
    #[error("invalid nameserver parameters: {0}")]
    InvalidParams(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> HostOrIp {
        HostOrIp::Ip(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }
    fn host(s: &str) -> HostOrIp {
        HostOrIp::Host(s.to_string())
    }

    // A1
    #[test]
    fn parse_plain_bare_ip() {
        let url = NameServerUrl::parse("8.8.8.8").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: ip4(8, 8, 8, 8),
                port: 53
            }
        );
    }

    #[test]
    fn parse_plain_bare_ipv6_preserves_address_and_default_port() {
        for literal in [
            "2402:4e00::",
            "::1",
            "2001:db8::8888",
            "2001:db8::abcd",
            "2001:db8::1:853",
            "::ffff:192.0.2.1",
        ] {
            let addr = HostOrIp::Ip(literal.parse().unwrap());
            for prefix in ["", "udp://", "tcp://"] {
                let input = format!("{prefix}{literal}");
                let expected = if prefix == "tcp://" {
                    NameServerUrl::Tcp {
                        addr: addr.clone(),
                        port: 53,
                    }
                } else {
                    NameServerUrl::Udp {
                        addr: addr.clone(),
                        port: 53,
                    }
                };
                assert_eq!(NameServerUrl::parse(&input).unwrap(), expected, "{input}");
            }
        }
    }

    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_encrypted_bare_ipv6_uses_transport_default_port() {
        for literal in ["2402:4e00::", "::1", "2001:db8::1:853"] {
            let addr = HostOrIp::Ip(literal.parse().unwrap());
            let sni = addr.to_string();
            assert_eq!(
                NameServerUrl::parse(&format!("tls://{literal}")).unwrap(),
                NameServerUrl::Tls {
                    addr: addr.clone(),
                    port: 853,
                    sni: sni.clone()
                },
            );
            assert_eq!(
                NameServerUrl::parse(&format!("https://{literal}/dns-query")).unwrap(),
                NameServerUrl::Https {
                    addr,
                    port: 443,
                    path: "/dns-query".into(),
                    sni,
                    h3: H3Policy::Off,
                },
            );
        }
    }

    #[test]
    fn parse_bracketed_ipv6_keeps_explicit_ports() {
        let addr = HostOrIp::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        for prefix in ["", "udp://", "tcp://"] {
            let input = format!("{prefix}[::1]:5353");
            let expected = if prefix == "tcp://" {
                NameServerUrl::Tcp {
                    addr: addr.clone(),
                    port: 5353,
                }
            } else {
                NameServerUrl::Udp {
                    addr: addr.clone(),
                    port: 5353,
                }
            };
            assert_eq!(NameServerUrl::parse(&input).unwrap(), expected, "{input}");
        }
        for port in ["0", "65536", "invalid"] {
            assert!(matches!(
                NameServerUrl::parse(&format!("[::1]:{port}")),
                Err(NameServerParseError::InvalidPort(_)),
            ));
        }
    }

    // A2
    #[test]
    fn parse_plain_bare_ip_with_port() {
        let url = NameServerUrl::parse("8.8.8.8:5353").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: ip4(8, 8, 8, 8),
                port: 5353
            }
        );
    }

    // A3
    #[test]
    fn parse_udp_scheme() {
        let url = NameServerUrl::parse("udp://1.1.1.1").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: ip4(1, 1, 1, 1),
                port: 53
            }
        );
    }

    // A4
    #[test]
    fn parse_udp_scheme_with_port() {
        let url = NameServerUrl::parse("udp://1.1.1.1:5353").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: ip4(1, 1, 1, 1),
                port: 5353
            }
        );
    }

    // A5
    #[test]
    fn parse_tcp_scheme() {
        let url = NameServerUrl::parse("tcp://1.1.1.1:53").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Tcp {
                addr: ip4(1, 1, 1, 1),
                port: 53
            }
        );
    }

    // A6
    // Upstream: component/resolver/parser.go::parseNameServer case "tls" — defaults port to DoTPort (853) and uses host as SNI.
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_tls_default_port_and_sni() {
        let url = NameServerUrl::parse("tls://dns.google").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Tls {
                addr: host("dns.google"),
                port: 853,
                sni: "dns.google".to_string()
            }
        );
    }

    // A7
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_tls_explicit_port() {
        let url = NameServerUrl::parse("tls://dns.google:8853").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Tls {
                addr: host("dns.google"),
                port: 8853,
                sni: "dns.google".to_string()
            }
        );
    }

    // A8
    // Upstream: same function, u.Fragment branch.
    // NOT: the '#' fragment is not a standard URL anchor; extracted manually.
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_tls_explicit_sni() {
        let url = NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Tls {
                addr: ip4(8, 8, 8, 8),
                port: 853,
                sni: "dns.google".to_string()
            }
        );
    }

    // A9
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_tls_ip_literal_no_sni_uses_ip_string() {
        let url = NameServerUrl::parse("tls://8.8.8.8:853").unwrap();
        match &url {
            NameServerUrl::Tls { addr, sni, .. } => {
                assert_eq!(addr, &ip4(8, 8, 8, 8));
                assert!(!sni.is_empty());
            }
            _ => panic!("expected Tls"),
        }
        assert_eq!(url.needs_bootstrap(), None);
    }

    // A10
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_default_path_and_port() {
        let url = NameServerUrl::parse("https://cloudflare-dns.com").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Https {
                addr: host("cloudflare-dns.com"),
                port: 443,
                path: "/dns-query".to_string(),
                sni: "cloudflare-dns.com".to_string(),
                h3: H3Policy::Off,
            }
        );
    }

    // A11
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_explicit_path() {
        let url = NameServerUrl::parse("https://dns.quad9.net/dns-query").unwrap();
        match &url {
            NameServerUrl::Https { path, .. } => assert_eq!(path, "/dns-query"),
            _ => panic!("expected Https"),
        }
    }

    // A12
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_explicit_port_and_path() {
        let url = NameServerUrl::parse("https://1.1.1.1:8443/custom-path").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Https {
                addr: ip4(1, 1, 1, 1),
                port: 8443,
                path: "/custom-path".to_string(),
                sni: "1.1.1.1".to_string(),
                h3: H3Policy::Off,
            }
        );
    }

    // A13
    // Upstream: same u.Fragment branch for DoH.
    // NOT: sni must override cert validation even when dial target is the IP.
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_explicit_sni_on_ip() {
        let url = NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Https {
                addr: ip4(1, 1, 1, 1),
                port: 443,
                path: "/dns-query".to_string(),
                sni: "cloudflare-dns.com".to_string(),
                h3: H3Policy::Off,
            }
        );
    }

    // A14
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_hostname_sni_override() {
        let url = NameServerUrl::parse("https://dns.google/dns-query#override.example").unwrap();
        match &url {
            NameServerUrl::Https { addr, sni, .. } => {
                assert_eq!(addr, &host("dns.google"));
                assert_eq!(sni, "override.example");
            }
            _ => panic!("expected Https"),
        }
    }

    // A15 — IPv6 trip-wire: a naive split(':') parser breaks here.
    // Upstream: uses net.SplitHostPort which handles brackets. NOT a split-on-colon path.
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_ipv6_bracketed() {
        let url = NameServerUrl::parse("https://[2606:4700:4700::1111]/dns-query").unwrap();
        match &url {
            NameServerUrl::Https { addr, .. } => {
                let expected: IpAddr = "2606:4700:4700::1111".parse().unwrap();
                assert_eq!(addr, &HostOrIp::Ip(expected));
            }
            _ => panic!("expected Https"),
        }
    }

    // A16
    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_https_ipv6_with_port_bracketed() {
        let url = NameServerUrl::parse("https://[::1]:853/dns-query").unwrap();
        match &url {
            NameServerUrl::Https { addr, port, .. } => {
                assert_eq!(addr, &HostOrIp::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
                assert_eq!(*port, 853);
            }
            _ => panic!("expected Https"),
        }
    }

    // A17 — DoQ (RFC 9250) is supported behind the `quic-dns` feature.
    #[test]
    #[cfg(feature = "quic-dns")]
    fn parse_quic() {
        assert_eq!(
            NameServerUrl::parse("quic://dns.adguard.com").unwrap(),
            NameServerUrl::Quic {
                addr: host("dns.adguard.com"),
                port: 853,
                sni: "dns.adguard.com".to_string(),
            }
        );
        // Explicit port + SNI override, mirroring the DoT/DoH spelling.
        assert_eq!(
            NameServerUrl::parse("quic://[::1]:8853#dns.adguard.com").unwrap(),
            NameServerUrl::Quic {
                addr: HostOrIp::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                port: 8853,
                sni: "dns.adguard.com".to_string(),
            }
        );
    }

    /// `?h3=` — mihomo's per-entry spelling (`true`) plus meow-rs's
    /// `prefer`/`false`, which let one entry override `dns.prefer-h3`.
    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_h3_parameter_forms() {
        let h3_of = |s: &str| match NameServerEntry::parse(s) {
            Ok(entry) => match entry.url {
                NameServerUrl::Https { h3, .. } => h3,
                other => panic!("{s} parsed as {other:?}, expected Https"),
            },
            Err(e) => panic!("{s} failed to parse: {e}"),
        };
        assert_eq!(
            h3_of("https://dns.google/dns-query?h3=true"),
            H3Policy::Force
        );
        assert_eq!(
            h3_of("https://dns.google/dns-query?h3=prefer"),
            H3Policy::Prefer
        );
        assert_eq!(
            h3_of("https://dns.google/dns-query?h3=false"),
            H3Policy::Off
        );
        // No parameter section at all → no policy of its own.
        assert_eq!(h3_of("https://dns.google/dns-query"), H3Policy::Off);
        // `proxy` and `h3` coexist in one section, in either order.
        let entry =
            NameServerEntry::parse("https://dns.google/dns-query?h3=true&proxy=JP").unwrap();
        assert_eq!(entry.proxy.as_deref(), Some("JP"));
        assert!(matches!(
            entry.url,
            NameServerUrl::Https {
                h3: H3Policy::Force,
                ..
            }
        ));
        let entry =
            NameServerEntry::parse("https://dns.google/dns-query?proxy=JP&h3=prefer").unwrap();
        assert_eq!(entry.proxy.as_deref(), Some("JP"));
        assert!(matches!(
            entry.url,
            NameServerUrl::Https {
                h3: H3Policy::Prefer,
                ..
            }
        ));
    }

    /// `h3` only names an HTTP/3 preference, so it is refused where there is
    /// no HTTP: `tls://` / `quic://` entries and bad values.
    #[test]
    #[cfg(feature = "quic-dns")]
    fn entry_h3_parameter_rejected_off_https() {
        for s in [
            "tls://8.8.8.8?h3=true",
            "quic://dns.adguard.com?h3=true",
            "https://dns.google/dns-query?h3=maybe",
            "https://dns.google/dns-query?h3=true&h3=false",
            "https://dns.google/dns-query?h3 =true",
        ] {
            match NameServerEntry::parse(s) {
                Err(NameServerParseError::InvalidParams(msg)) => {
                    assert!(
                        msg.contains("h3") || msg.contains("parameter"),
                        "{s}: message must name the offending parameter; got {msg}"
                    );
                }
                other => panic!("{s} must be InvalidParams, got {other:?}"),
            }
        }
    }

    /// `#h3=true` is the mihomo spelling of a per-entry parameter; `#` is SNI
    /// here, so the fragment is refused with the fix spelled out.
    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_h3_in_fragment_is_refused() {
        match NameServerEntry::parse("https://dns.google/dns-query#h3=true") {
            Err(NameServerParseError::InvalidParams(msg)) => {
                assert!(msg.contains("'?' section"), "got: {msg}");
            }
            other => panic!("must be InvalidParams, got {other:?}"),
        }
    }

    /// `quic://` carries the same proxy tag and SNI slot as the other
    /// encrypted forms.
    #[test]
    #[cfg(feature = "quic-dns")]
    fn entry_quic_proxy_and_sni() {
        let entry = NameServerEntry::parse("quic://dns.adguard.com?proxy=JP").unwrap();
        assert_eq!(entry.proxy.as_deref(), Some("JP"));
        assert_eq!(
            entry.url,
            NameServerUrl::Quic {
                addr: host("dns.adguard.com"),
                port: 853,
                sni: "dns.adguard.com".to_string(),
            }
        );
        let entry = NameServerEntry::parse("quic://1.1.1.1:8853#cloudflare-dns.com").unwrap();
        assert_eq!(entry.proxy, None);
        assert_eq!(
            entry.url.to_string(),
            "quic://1.1.1.1:8853#cloudflare-dns.com"
        );
    }

    /// Display renders the h3 policy, so labels and API output keep it.
    #[test]
    #[cfg(feature = "encrypted")]
    fn display_renders_h3_policy() {
        for (raw, shown) in [
            (
                "https://1.1.1.1/dns-query?h3=true#cloudflare-dns.com",
                "https://1.1.1.1:443/dns-query?h3=true#cloudflare-dns.com",
            ),
            (
                "https://1.1.1.1/dns-query?h3=prefer",
                "https://1.1.1.1:443/dns-query?h3=prefer#1.1.1.1",
            ),
            (
                "https://1.1.1.1/dns-query",
                "https://1.1.1.1:443/dns-query#1.1.1.1",
            ),
            // A DoH path that carries its own query string needs a *new* `?`
            // section — the parser reads the last `?` tail as the parameter
            // section, and `&` would fold `x=1` into it as an unknown key.
            (
                "https://1.1.1.1/dns-query?x=1?h3=prefer",
                "https://1.1.1.1:443/dns-query?x=1?h3=prefer#1.1.1.1",
            ),
        ] {
            let url = NameServerEntry::parse(raw).unwrap().url;
            assert_eq!(url.to_string(), shown, "{raw}");
            // Display is what warning messages and the API report, so it must
            // re-parse to the same entry.
            assert_eq!(
                NameServerEntry::parse(&url.to_string()).unwrap().url,
                url,
                "Display must round-trip: {raw}"
            );
        }
    }

    /// Without the feature the scheme stays a hard config error (never a
    /// silent drop): the message names the feature to rebuild with.
    #[test]
    #[cfg(not(feature = "quic-dns"))]
    fn parse_quic_rejected_without_feature() {
        let err = NameServerUrl::parse("quic://dns.adguard.com").unwrap_err();
        assert!(matches!(err, NameServerParseError::QuicNotSupported));
        assert!(
            err.to_string().contains("quic-dns"),
            "error message must name the Cargo feature"
        );
    }

    // A18 — Class A per ADR-0002: silent-drop bug in upstream.
    // Upstream: parseNameServer logs warn and drops entry. NOT a warn.
    #[test]
    fn parse_unknown_scheme() {
        let err = NameServerUrl::parse("sdns://something").unwrap_err();
        assert!(matches!(err, NameServerParseError::UnsupportedScheme(ref s) if s == "sdns"));
    }

    #[test]
    fn parse_rcode_success() {
        let url = NameServerUrl::parse("rcode://success").unwrap();
        assert_eq!(
            url,
            NameServerUrl::RCode {
                code: ResponseCode::NoError,
                label: "success".to_string(),
            }
        );
        assert_eq!(url.to_string(), "rcode://success");
        assert_eq!(url.needs_bootstrap(), None);
    }

    #[test]
    fn parse_rcode_unknown_errors() {
        let err = NameServerUrl::parse("rcode://unknown").unwrap_err();
        assert!(matches!(err, NameServerParseError::UnsupportedRCode(ref s) if s == "unknown"));
    }

    // A19
    #[test]
    fn parse_empty_string_errors() {
        assert!(matches!(
            NameServerUrl::parse("").unwrap_err(),
            NameServerParseError::EmptyInput
        ));
    }

    // A20
    #[test]
    fn parse_invalid_port_errors() {
        assert!(matches!(
            NameServerUrl::parse("1.1.1.1:99999").unwrap_err(),
            NameServerParseError::InvalidPort(_)
        ));
    }

    // A21
    // Upstream: parseNameServer defaults bare entries to UDP. We match.
    #[test]
    fn parse_bare_hostname_no_scheme() {
        let url = NameServerUrl::parse("dns.google").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: host("dns.google"),
                port: 53
            }
        );
        assert_eq!(url.needs_bootstrap(), Some("dns.google"));
    }

    // A22
    #[test]
    fn needs_bootstrap_ip_literal_returns_none() {
        let udp = NameServerUrl::parse("8.8.8.8").unwrap();
        assert_eq!(udp.needs_bootstrap(), None);
        #[cfg(feature = "encrypted")]
        {
            let tls = NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap();
            assert_eq!(tls.needs_bootstrap(), None);
            let https =
                NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap();
            assert_eq!(https.needs_bootstrap(), None);
        }
    }

    // A23
    #[cfg(feature = "encrypted")]
    #[test]
    fn needs_bootstrap_hostname_returns_some() {
        let tls = NameServerUrl::parse("tls://dns.google").unwrap();
        assert_eq!(tls.needs_bootstrap(), Some("dns.google"));
        let https = NameServerUrl::parse("https://cloudflare-dns.com").unwrap();
        assert_eq!(https.needs_bootstrap(), Some("cloudflare-dns.com"));
    }

    // G1
    #[test]
    fn all_url_forms_display_contains_host() {
        let cases: &[&str] = if cfg!(feature = "encrypted") {
            &[
                "udp://8.8.8.8:53",
                "tcp://8.8.8.8:53",
                "tls://dns.google:853#dns.google",
                "https://cloudflare-dns.com:443/dns-query#cloudflare-dns.com",
            ]
        } else {
            &["udp://8.8.8.8:53", "tcp://8.8.8.8:53"]
        };
        for s in cases {
            let url = NameServerUrl::parse(s).unwrap();
            let display = url.to_string();
            assert!(!display.is_empty(), "display must not be empty for {s}");
        }
    }

    // G2
    #[test]
    fn parse_error_is_non_exhaustive_match() {
        let err = NameServerUrl::parse("").unwrap_err();
        // This match must compile — the wildcard arm ensures #[non_exhaustive] is respected.
        let _msg = match err {
            NameServerParseError::EmptyInput => "empty",
            NameServerParseError::QuicNotSupported => "quic",
            NameServerParseError::UnsupportedScheme(_) => "unsupported",
            NameServerParseError::InvalidHost(_) => "invalid host",
            NameServerParseError::InvalidPort(_) => "invalid port",
            NameServerParseError::UnsupportedRCode(_) => "rcode",
            _ => "other",
        };
    }

    // D4: without the `encrypted` feature, tls:// must hard-error mentioning the feature name.
    #[cfg(not(feature = "encrypted"))]
    #[test]
    fn parse_tls_without_encrypted_feature_hard_errors() {
        let result = NameServerUrl::parse("tls://8.8.8.8");
        assert!(
            result.is_err(),
            "tls:// without encrypted feature must error"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("encrypted"),
            "error message must mention the 'encrypted' feature, got: {msg}"
        );
    }

    // ─── #PROXY suffix parsing (issue #67 phase 2, ADR-0012) ──────────────

    #[test]
    fn entry_no_proxy_default() {
        let e = NameServerEntry::parse("8.8.8.8").unwrap();
        assert!(e.proxy.is_none());
        assert_eq!(
            e.url,
            NameServerUrl::Udp {
                addr: ip4(8, 8, 8, 8),
                port: 53,
            }
        );
    }

    #[test]
    fn entry_plain_udp_with_proxy_tag() {
        let e = NameServerEntry::parse("1.1.1.1#PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert_eq!(
            e.url,
            NameServerUrl::Udp {
                addr: ip4(1, 1, 1, 1),
                port: 53,
            }
        );
    }

    #[test]
    fn entry_tcp_scheme_with_proxy_tag() {
        let e = NameServerEntry::parse("tcp://1.1.1.1:53#PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert!(matches!(e.url, NameServerUrl::Tcp { .. }));
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_tls_fragment_is_sni_not_proxy() {
        // For tls:// the `#` is SNI per the existing parser; the
        // NameServerEntry layer must NOT steal that fragment as a proxy
        // name — the proxy slot for encrypted entries is the implemented
        // `?proxy=NAME` parameter section (ADR-0012).
        let e = NameServerEntry::parse("tls://1.1.1.1:853#dns.google").unwrap();
        assert!(e.proxy.is_none());
        assert!(matches!(e.url, NameServerUrl::Tls { .. }));
    }

    #[test]
    fn entry_empty_proxy_tag_errors() {
        // `1.1.1.1#` with nothing after the # is a typo, not "no proxy."
        let err = NameServerEntry::parse("1.1.1.1#").unwrap_err();
        assert!(matches!(err, NameServerParseError::InvalidHost(_)));
    }

    // ─── `?proxy=` parameter section (ADR-0012, issue #67 phase 2) ──────
    //
    // Canonical rule: a `?` parameter section is only legal on `tls://` /
    // `https://` entries. Using the entry's *last* `?` as the boundary:
    // when any `&`-separated segment of the tail is a `proxy=` key, that
    // `?` section is a parameter section — an `&`-separated `k=v` list
    // whose only currently-legal key is `proxy`. The `proxy` value must
    // be non-empty and must not contain `#`/`?`/`&`; any other key is a
    // hard `InvalidParams`. When no `&`-separated segment is a `proxy=`
    // key, the `?` section is not a parameter section and stays in the
    // URL (path) verbatim. Detection of the `proxy=` key is ASCII
    // case-insensitive; only exact lowercase `proxy` is legal —
    // `?Proxy=`/`?PROXY=` are hard `InvalidParams`, never path params.

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_tls_query_proxy_with_sni() {
        let e = NameServerEntry::parse("tls://8.8.8.8#dns.google?proxy=PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert_eq!(
            e.url,
            NameServerUrl::Tls {
                addr: ip4(8, 8, 8, 8),
                port: 853,
                sni: "dns.google".to_string(),
            }
        );
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_tls_query_proxy_default_sni() {
        let e = NameServerEntry::parse("tls://8.8.8.8?proxy=PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert_eq!(
            e.url,
            NameServerUrl::Tls {
                addr: ip4(8, 8, 8, 8),
                port: 853,
                sni: "8.8.8.8".to_string(),
            }
        );
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_tls_hostname_upstream_with_proxy() {
        // The flagship form: the hostname is left to the proxy for remote
        // resolution — the entry itself parses to Host + proxy tag.
        let e = NameServerEntry::parse("tls://dns.google?proxy=PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert_eq!(
            e.url,
            NameServerUrl::Tls {
                addr: host("dns.google"),
                port: 853,
                sni: "dns.google".to_string(),
            }
        );
        assert_eq!(e.url.needs_bootstrap(), Some("dns.google"));
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_https_sni_path_and_proxy() {
        let e =
            NameServerEntry::parse("https://1.1.1.1/dns-query#cloudflare-dns.com?proxy=PROXY-JP")
                .unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert_eq!(
            e.url,
            NameServerUrl::Https {
                addr: ip4(1, 1, 1, 1),
                port: 443,
                path: "/dns-query".to_string(),
                sni: "cloudflare-dns.com".to_string(),
                h3: H3Policy::Off,
            }
        );
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_https_path_and_proxy() {
        let e = NameServerEntry::parse("https://1.1.1.1/dns-query?proxy=PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert_eq!(
            e.url,
            NameServerUrl::Https {
                addr: ip4(1, 1, 1, 1),
                port: 443,
                path: "/dns-query".to_string(),
                sni: "1.1.1.1".to_string(),
                h3: H3Policy::Off,
            }
        );
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_https_non_proxy_query_stays_in_path() {
        // `?x=1` carries no `proxy=` key — the `?` section is part of the
        // DoH path and must pass through verbatim.
        let e = NameServerEntry::parse("https://h/dns-query?x=1").unwrap();
        assert!(e.proxy.is_none());
        assert_eq!(
            e.url,
            NameServerUrl::Https {
                addr: host("h"),
                port: 443,
                path: "/dns-query?x=1".to_string(),
                sni: "h".to_string(),
                h3: H3Policy::Off,
            }
        );
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_query_proxy_in_later_key_is_params_section() {
        // A `proxy=` key anywhere in the `&`-separated tail marks the `?`
        // section as a parameter section — `?a=b&proxy=P` must hard-error
        // on the unknown `a` key, not silently keep the whole tail in the
        // path and lose the proxy intent (r15 review I1).
        for s in [
            "https://h/dns-query?a=b&proxy=P",
            "https://h/dns-query?a=b&proxy=P&c=d",
            "tls://h?x=1&proxy=P",
            "tls://h?x&proxy=P",
        ] {
            assert!(
                matches!(
                    NameServerEntry::parse(s),
                    Err(NameServerParseError::InvalidParams(_))
                ),
                "{s} must be InvalidParams"
            );
        }
        // `proxy` is still the only legal key — including in first place.
        for s in ["https://h/p?proxy=P&x=1", "https://h/p?x=1&proxy="] {
            assert!(
                matches!(
                    NameServerEntry::parse(s),
                    Err(NameServerParseError::InvalidParams(_))
                ),
                "{s} must be InvalidParams"
            );
        }
        // Non-`proxy=` tails — including look-alikes — still stay in the
        // path verbatim.
        for s in ["https://h/p?proxi=P", "https://h/p?x=a=proxy=P"] {
            let e = NameServerEntry::parse(s).unwrap();
            assert!(e.proxy.is_none(), "{s} must not tag a proxy");
        }
        let e = NameServerEntry::parse("https://h/p?proxi=P").unwrap();
        match e.url {
            NameServerUrl::Https { path, .. } => assert_eq!(path, "/p?proxi=P"),
            _ => panic!("expected Https"),
        }
    }

    #[test]
    fn entry_plain_with_query_params_errors() {
        // `?` on a plain entry used to be silently folded into the
        // hostname — now a hard `InvalidParams`.
        for s in [
            "8.8.8.8?proxy=P",
            "8.8.8.8?x=1",
            "udp://1.1.1.1?proxy=P",
            // Any `?` on a plain entry is a hard error regardless of
            // case — the `proxy=`-key case distinction is an
            // encrypted-forms-only concept.
            "udp://1.1.1.1?Proxy=P",
            "udp://1.1.1.1?proxy=P?x=1",
            // A padded key is still a `?` on a plain entry — same arm.
            "udp://1.1.1.1? proxy=P",
        ] {
            assert!(
                matches!(
                    NameServerEntry::parse(s),
                    Err(NameServerParseError::InvalidParams(_))
                ),
                "{s} must be InvalidParams"
            );
        }
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_tls_fragment_and_query_proxy_conflict_errors() {
        // `#P` next to `?proxy=` is a bare fragment — under `#`=SNI
        // semantics it is indistinguishable from a second proxy tag, so
        // it is a config bug, not an SNI.
        for s in [
            "tls://8.8.8.8#P?proxy=Q",
            "tls://8.8.8.8#PROXY?proxy=Q",
            "https://1.1.1.1/dns-query#P?proxy=Q",
        ] {
            assert!(
                matches!(
                    NameServerEntry::parse(s),
                    Err(NameServerParseError::InvalidParams(_))
                ),
                "{s} must be InvalidParams"
            );
        }
        // A dotted SNI is unambiguous — stays legal.
        let e = NameServerEntry::parse("tls://8.8.8.8#dns.google?proxy=Q").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("Q"));
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_query_proxy_hard_errors() {
        for s in [
            "tls://8.8.8.8?proxy=",            // empty proxy name
            "tls://8.8.8.8?proxy=P&h3=true",   // unknown key
            "tls://8.8.8.8?proxy=P&proxy=Q",   // duplicate key
            "tls://8.8.8.8?proxy=P#sni&x",     // & residue in fragment
            "tls://8.8.8.8#sni&proxy=P",       // mihomo-style params in fragment
            "https://h/p?proxy=P&ecs=1.2.3.4", // reserved-but-unimplemented key
        ] {
            assert!(
                matches!(
                    NameServerEntry::parse(s),
                    Err(NameServerParseError::InvalidParams(_))
                ),
                "{s} must be InvalidParams"
            );
        }
    }

    /// Case hardening on the `?proxy=` key: detection of a `proxy=` segment
    /// is ASCII case-insensitive (closing the leak where `?Proxy=P` survived
    /// into the stored DoH request path), while validation stays exact —
    /// only the lowercase `proxy` spelling is legal, so a case-variant key
    /// is a hard `InvalidParams` that names the canonical spelling.
    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_query_proxy_case_variant_hard_errors() {
        // Variants that hit the canonical-spelling hint — the case-variant
        // key is the first failure the validation loop sees.
        for s in [
            "tls://8.8.8.8?Proxy=P",
            "tls://8.8.8.8?PROXY=P",
            "tls://8.8.8.8?pRoXy=P",
            "https://h/dns-query?Proxy=P", // was the silent path leak
            "tls://8.8.8.8#dns.google?Proxy=P", // SNI + variant
            "https://h?Proxy=P",           // pins the InvalidHost → InvalidParams flip
        ] {
            match NameServerEntry::parse(s) {
                Err(NameServerParseError::InvalidParams(msg)) => assert!(
                    msg.contains("lowercase 'proxy'"),
                    "{s} must hint the canonical spelling; got: {msg}"
                ),
                other => panic!("{s} must be InvalidParams, got {other:?}"),
            }
        }
        // A case-variant segment in a non-first `&` position still marks
        // the section — it errors as InvalidParams (here on the unknown
        // `x` key first; either way the proxy name never reaches a path).
        let s = "https://h/dns-query?x=1&PROXY=P";
        assert!(
            matches!(
                NameServerEntry::parse(s),
                Err(NameServerParseError::InvalidParams(_))
            ),
            "{s} must be InvalidParams"
        );
        // Look-alikes stay unchanged: `?Proxy` bare (no `=`, so nothing
        // leakable) keeps the whole `?` section in the path, as do the
        // `proxi=` / `x=a=proxy=` near-misses covered above.
        for s in [
            "https://h/p?Proxy",
            "https://h/p?proxi=P",
            "https://h/p?x=a=proxy=P",
        ] {
            let e = NameServerEntry::parse(s).unwrap();
            assert!(e.proxy.is_none(), "{s} must not tag a proxy");
        }
        let e = NameServerEntry::parse("https://h/p?Proxy").unwrap();
        match e.url {
            NameServerUrl::Https { path, .. } => assert_eq!(path, "/p?Proxy"),
            _ => panic!("expected Https"),
        }
        // A case-variant segment stranded by a *later* `?` section is
        // caught by the post-strip `?`-section scan too — the stranded
        // `proxy=` key hard-errors regardless of position or spelling.
        assert!(matches!(
            NameServerEntry::parse("https://h/p?Proxy=P?x=1"),
            Err(NameServerParseError::InvalidParams(_))
        ));
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_question_mark_in_hostname_errors() {
        // A non-`proxy=` `?` tail stays in the URL — for tls:// there is
        // no path to hold it, so it lands in the hostname, which must
        // hard-error rather than silently accept `h?x` / `h&x` as hosts.
        for s in ["tls://h?x", "tls://h&x", "tls://h?x&proxy=P"] {
            assert!(NameServerEntry::parse(s).is_err(), "{s} must error");
        }
        assert!(matches!(
            NameServerEntry::parse("tls://h?x"),
            Err(NameServerParseError::InvalidHost(_))
        ));
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_tls_fragment_sni_without_proxy_unchanged() {
        // `#dns.google` alone keeps its SNI meaning — the divergence from
        // mihomo (which reads it as a proxy name) is documented, not
        // silently flipped.
        let e = NameServerEntry::parse("tls://8.8.8.8#PROXY").unwrap();
        assert!(e.proxy.is_none());
        assert_eq!(
            e.url,
            NameServerUrl::Tls {
                addr: ip4(8, 8, 8, 8),
                port: 853,
                sni: "PROXY".to_string(),
            }
        );
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_query_proxy_value_is_trimmed() {
        // Same contract as the `#PROXY` slot (`head[idx + 1..].trim()`):
        // `?proxy= P` tags the proxy named `P`, not ` P `.
        let e = NameServerEntry::parse("tls://8.8.8.8?proxy= P ").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("P"));
        // All-whitespace is still an empty (invalid) name.
        assert!(matches!(
            NameServerEntry::parse("tls://8.8.8.8?proxy= "),
            Err(NameServerParseError::InvalidParams(_))
        ));
    }

    /// Whitespace-padded `proxy=` keys are the same typo/leak class as
    /// the canonical spelling: detection trims the key (the full
    /// White_Space set — NBSP included) and is ASCII case-insensitive,
    /// so a padded or miscased key marks the `?` section a parameter
    /// section, then validation refuses the non-canonical spelling. A
    /// padded key gets a `whitespace` hint — the generic unknown-key
    /// message would print `' proxy'` with the defect invisible.
    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_query_proxy_whitespace_key_errors() {
        for s in [
            "tls://8.8.8.8? proxy=P", // was InvalidHost — padded key slipped detection
            "tls://8.8.8.8?proxy =P", // trailing-ws key — the same typo class
            "tls://8.8.8.8? proxy =P",
            "tls://8.8.8.8?\tproxy\t=P",
            "https://h/dns-query? proxy=P", // the leak row: key rode inside the path
            "https://h/dns-query?proxy =P",
            "https://h/dns-query?\u{a0}proxy=P", // NBSP is White_Space
            "https://h/p?proxy=Q& proxy=P",      // ws arm on a later `&` segment
            "tls://8.8.8.8?Proxy =P",            // case+ws: ws is the visible defect
        ] {
            match NameServerEntry::parse(s) {
                Err(NameServerParseError::InvalidParams(msg)) => assert!(
                    msg.contains("whitespace"),
                    "{s} must fail with the whitespace hint, got: {msg}"
                ),
                other => panic!("{s} must be InvalidParams, got {other:?}"),
            }
        }
        // Case pin: a case-flipped key also marks the section, then fails
        // with the lowercase hint rather than the whitespace one.
        match NameServerEntry::parse("tls://8.8.8.8?PROXY=P") {
            Err(NameServerParseError::InvalidParams(msg)) => assert!(
                msg.contains("lowercase 'proxy'"),
                "?PROXY=P must fail with the lowercase hint, got: {msg}"
            ),
            other => panic!("?PROXY=P must be InvalidParams, got {other:?}"),
        }
    }

    /// A `proxy=` key stranded in a non-last `?` section — any ASCII
    /// case, at a `?`- or `&`-segment start — is a hard `InvalidParams`,
    /// not a warn: the segment would travel inside the request path and
    /// leak the proxy name to the DoH upstream on every query (audit §2
    /// residual #1; `?proxy=A?proxy=B` covers r-b2's INFO-3 silent leak).
    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_stranded_proxy_segment_errors() {
        for s in [
            "https://h/dns-query?proxy=P?x=1", // the leak row
            "https://h/p?x=1&proxy=P?y=2",     // median &-segment
            "https://h/p?a=b?proxy=P?c=d",     // proxy= in a 2nd+ `?` section
            "https://h/p?proxy=A?proxy=B",     // INFO-3 silent leak
            "https://h/p?Proxy=P?x=1",         // case-insensitive median
            "https://h/p?PROXY=P?x=1",
            "https://h/p? proxy=P?x=1", // whitespace-padded median
            "https://h/p?proxy =P?x=1",
            "https://h/p?x=1&proxy =P?y=2",
            "tls://8.8.8.8?proxy=P?x=1",
            // the median arm fires before the fragment check
            "tls://8.8.8.8#dns.google?proxy=P?x=1",
        ] {
            match NameServerEntry::parse(s) {
                Err(NameServerParseError::InvalidParams(msg)) => assert!(
                    msg.contains("last '?' section"),
                    "{s} error must name the fix; got: {msg}"
                ),
                other => panic!("{s} must be InvalidParams, got {other:?}"),
            }
        }
    }

    /// The negative side of the scan: a `proxy=` *value*, a look-alike
    /// key, a bare `Proxy` segment with no `=`, a `&` before the first
    /// `?`, or a proxy-free double-`?` all stay in the path verbatim
    /// and tag no proxy — `skip(1)` plus the key-level predicate never
    /// reaches them.
    #[test]
    #[cfg(feature = "encrypted")]
    fn entry_stranded_scan_leaves_non_key_segments() {
        for s in [
            "https://h/p?x=proxy=P?y=1", // `proxy=` is a VALUE; the key is x
            "https://h/p?proxyx=P?y=1",
            "https://h/p?aproxy=P?y=1",
            "https://h/p?a=b?c=d",
            "https://h/p?Proxy?x=1",
            "https://h/p? proxy?x=1", // bare padded key, no `=` — no key shape
            "https://h/p?p roxy=P?x=1", // internal ws is never collapsed
            "https://h/p?%20proxy=P?x=1", // percent-spelling is literal
            "https://h/p?x= proxy=P", // ws lives in the VALUE; the key is x
            "https://h/p?proxyý?x=1", // non-ASCII look-alike key
            "https://h/p&proxy=P?x=1",
        ] {
            let e = NameServerEntry::parse(s)
                .unwrap_or_else(|err| panic!("{s} must stay in the path, got {err}"));
            assert!(e.proxy.is_none(), "{s} must not tag a proxy");
        }
        for (s, want) in [
            ("https://h/p?a=b?c=d", "/p?a=b?c=d"),
            ("https://h/p?x= proxy=P", "/p?x= proxy=P"),
            ("https://h/p?proxyý?x=1", "/p?proxyý?x=1"),
            ("https://h/p&proxy=P?x=1", "/p&proxy=P?x=1"),
        ] {
            match NameServerEntry::parse(s).unwrap().url {
                NameServerUrl::Https { path, .. } => assert_eq!(path, want, "{s}"),
                _ => panic!("expected Https"),
            }
        }
    }
}

#[cfg(all(test, feature = "encrypted"))]
mod proxy_encoding_tests {
    use super::*;

    #[test]
    fn encrypted_proxy_parameter_decodes_values_once() {
        for scheme in ["https", "tls", "quic"] {
            if scheme == "quic" && !cfg!(feature = "quic-dns") {
                continue;
            }
            for (encoded, expected) in [
                ("group%20%2F%20one", "group / one"),
                ("%E9%A6%99%E6%B8%AF", "香港"),
                ("a%26b%23c%3Fd%3De", "a&b#c?d=e"),
                ("a+b", "a+b"),
                ("%41", "A"),
                ("literal%2520", "literal%20"),
                ("literal%2525", "literal%25"),
            ] {
                let path = if scheme == "https" { "/dns-query" } else { "" };
                let entry = NameServerEntry::parse(&format!(
                    "{scheme}://192.0.2.1{path}?proxy={encoded}#dns.example"
                ))
                .unwrap();
                assert_eq!(entry.proxy.as_deref(), Some(expected));
                match entry.url {
                    NameServerUrl::Https { sni, path, .. } => {
                        assert_eq!(sni, "dns.example");
                        assert_eq!(path, "/dns-query");
                    }
                    NameServerUrl::Tls { sni, .. } | NameServerUrl::Quic { sni, .. } => {
                        assert_eq!(sni, "dns.example");
                    }
                    _ => panic!("unexpected scheme"),
                }
            }
        }
        // The plain-form fragment is a literal group name, not a query value.
        assert_eq!(
            NameServerEntry::parse("1.1.1.1#literal%20")
                .unwrap()
                .proxy
                .as_deref(),
            Some("literal%20")
        );
    }

    #[test]
    fn encrypted_proxy_parameter_rejects_bad_escapes_and_controls() {
        for value in [
            "%", "%0", "%xx", "%FF", "%C0%AF", "%00", "%0A", "%7f", "%7F", "%20",
        ] {
            assert!(
                NameServerEntry::parse(&format!(
                    "https://192.0.2.1/dns-query?proxy={value}#dns.example"
                ))
                .is_err(),
                "accepted malformed proxy value {value}"
            );
        }
    }
}
