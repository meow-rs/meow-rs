//! Request-header policy for the CONNECT streams.
//!
//! Two jobs, both about what the endpoint operator — or anyone watching the
//! TLS-wrapped stream — can tell this client apart by:
//!
//! 1. The spec-shaped `user-agent`. [PROTOCOL.md] asks for
//!    `<platform> <app_name>` on a TCP CONNECT (§5.1), `<platform> _udp2`
//!    (§6.1) and `<platform> _icmp` (§7.1) on the multiplexers, and a bare
//!    `<platform>` on `_check` (§8.2). The suffix varying per stream type is
//!    part of what an endpoint sees, so one fixed string across all four is
//!    itself a distinguishing mark.
//! 2. Operator-supplied extra headers, whose values may carry
//!    `<random-string(N)>` / `<random-string(MIN-MAX)>` placeholders. Every
//!    placeholder is re-rolled per CONNECT, which is the whole point: a
//!    padding header with a constant value is just a constant to match on.
//!
//! [PROTOCOL.md]: https://github.com/TrustTunnel/TrustTunnel/blob/master/PROTOCOL.md

use http::HeaderName;
use rand::RngCore as _;

/// URL-safe alphabet. Exactly 64 characters, so masking a random byte to its
/// low 6 bits selects uniformly — no rejection sampling, no modulo bias.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Largest random run one placeholder may ask for.
pub const MAX_RANDOM_BYTES: usize = 4096;
/// Largest value one rendered header may occupy.
pub const MAX_VALUE_BYTES: usize = 8192;
/// Largest number of placeholders in one value.
const MAX_PLACEHOLDERS: usize = 8;
/// Largest `platform` / `app-name` token.
const MAX_TOKEN_BYTES: usize = 64;

const OPEN: &str = "<random-string(";
const CLOSE: &str = ")>";

/// SP and HTAB: the only whitespace the field-value grammar admits.
const WHITESPACE: [char; 2] = [' ', '\t'];

/// Header names this adapter owns. Letting a config overwrite them would
/// either break authentication or put the credential somewhere it was never
/// meant to go; `user-agent` is deliberately *not* here, because overriding
/// it wholesale is the point of the knob.
const RESERVED: &[&str] = &["proxy-authorization"];

/// Header names no HTTP/2 or HTTP/3 request may carry.
///
/// Both versions removed the connection-specific headers (RFC 9113 §8.2.2,
/// RFC 9114 §4.2): a receiver treats a request carrying one as malformed and
/// resets the stream, which this client reports as a dial failure and
/// `DialFailureTracker` eventually dead-marks the node over. `connection:
/// keep-alive` is exactly what someone adds to "look like a browser", and
/// neither h2 nor the HTTP/3 encoder strips it for us — so the name is
/// refused at config load, where the mistake is still visible.
///
/// `te` is listed even though `te: trailers` is the one legal form, because a
/// CONNECT tunnel has no trailers to ask for; `host` and `content-length`
/// describe a message body a CONNECT does not have.
const UNSENDABLE: &[&str] = &[
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-connection",
    "te",
    "transfer-encoding",
    "upgrade",
];

/// Random bytes drawn at a time while rendering a placeholder. One stack
/// buffer, so the rendered `String` stays the only allocation per CONNECT.
const RANDOM_CHUNK: usize = 64;

/// One header value, split into its literal and random runs.
///
/// Parsed once at config load so a defect is reported against the node that
/// declared it, and so rendering on the dial path cannot fail.
#[derive(Debug, Clone)]
pub struct Template {
    parts: Vec<Part>,
    /// Longest value this template can render, checked at parse time.
    widest: usize,
}

#[derive(Debug, Clone)]
enum Part {
    Literal(Box<str>),
    /// `min` plus up to `span` extra characters, inclusive.
    Random {
        min: usize,
        span: usize,
    },
}

impl Template {
    /// Parse one configured value. Rejects a malformed or unbounded
    /// placeholder rather than passing the text through as a literal: a
    /// typo'd `<random-string(32>` that silently became padding-shaped
    /// *literal* text would defeat the reason the knob exists.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut parts = Vec::new();
        let mut widest = 0usize;
        let mut placeholders = 0usize;
        let mut rest = raw;
        while let Some(at) = rest.find(OPEN) {
            let (literal, tail) = rest.split_at(at);
            if !literal.is_empty() {
                validate_literal(literal)?;
                widest += literal.len();
                parts.push(Part::Literal(literal.into()));
            }
            let body = &tail[OPEN.len()..];
            let end = body
                .find(CLOSE)
                .ok_or_else(|| format!("unterminated '{OPEN}' placeholder; expected '{CLOSE}'"))?;
            let (min, max) = parse_range(&body[..end])?;
            placeholders += 1;
            if placeholders > MAX_PLACEHOLDERS {
                return Err(format!(
                    "more than {MAX_PLACEHOLDERS} '{OPEN}' placeholders in one value"
                ));
            }
            widest += max;
            parts.push(Part::Random {
                min,
                span: max - min,
            });
            rest = &body[end + CLOSE.len()..];
        }
        if !rest.is_empty() {
            validate_literal(rest)?;
            widest += rest.len();
            parts.push(Part::Literal(rest.into()));
        }
        if parts.is_empty() {
            return Err("header value is empty".into());
        }
        // RFC 9110 §5.5 excludes leading and trailing whitespace from a field
        // value, and RFC 9113 §8.2.1 has the receiver treat a value that
        // starts or ends with SP/HTAB as malformed: the stream is reset, and
        // the dial counts against a node that is fine.
        if can_render_edge_whitespace(parts.iter(), |text| text.starts_with(WHITESPACE)) {
            return Err("header value cannot start with a space or tab".into());
        }
        if can_render_edge_whitespace(parts.iter().rev(), |text| text.ends_with(WHITESPACE)) {
            return Err("header value cannot end with a space or tab".into());
        }
        if widest > MAX_VALUE_BYTES {
            return Err(format!(
                "header value can render {widest} bytes (max {MAX_VALUE_BYTES})"
            ));
        }
        Ok(Self { parts, widest })
    }

    /// Render one value, re-rolling every placeholder.
    ///
    /// Infallible by construction: literals were checked against the header
    /// grammar at parse time and the random alphabet is visible ASCII.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(self.widest);
        for part in &self.parts {
            match part {
                Part::Literal(text) => out.push_str(text),
                Part::Random { min, span } => {
                    let length = if *span == 0 {
                        *min
                    } else {
                        min + rand::rng().next_u32() as usize % (span + 1)
                    };
                    let start = out.len();
                    // The alphabet index is the low 6 bits of each random
                    // byte, so one pass of entropy is enough — drawn a
                    // stack buffer at a time rather than into a throwaway
                    // `Vec` per placeholder per request.
                    let mut chunk = [0u8; RANDOM_CHUNK];
                    let mut remaining = length;
                    while remaining > 0 {
                        let bytes = &mut chunk[..remaining.min(RANDOM_CHUNK)];
                        rand::rng().fill_bytes(bytes);
                        for byte in &*bytes {
                            out.push(ALPHABET[(byte & 0x3f) as usize] as char);
                        }
                        remaining -= bytes.len();
                    }
                    debug_assert_eq!(out.len() - start, length);
                }
            }
        }
        out
    }
}

/// `N` or `MIN-MAX`, as Surge writes it.
fn parse_range(body: &str) -> Result<(usize, usize), String> {
    let number = |text: &str| -> Result<usize, String> {
        let text = text.trim();
        text.parse::<usize>()
            .map_err(|_| format!("'{text}' is not a random-string length"))
    };
    let (min, max) = match body.split_once('-') {
        Some((min, max)) => (number(min)?, number(max)?),
        None => {
            let exact = number(body)?;
            (exact, exact)
        }
    };
    if min > max {
        return Err(format!("random-string range {min}-{max} is inverted"));
    }
    if max == 0 {
        return Err("random-string length is zero".into());
    }
    if max > MAX_RANDOM_BYTES {
        return Err(format!(
            "random-string length {max} exceeds {MAX_RANDOM_BYTES}"
        ));
    }
    Ok((min, max))
}

/// Whether some rendering of `parts`, walked inward from one edge, puts
/// whitespace at that edge. A random run never renders whitespace — the
/// alphabet has none — so it settles the question, unless its minimum is zero:
/// then it can render empty and expose the part behind it.
fn can_render_edge_whitespace<'a>(
    mut parts: impl Iterator<Item = &'a Part>,
    at_edge: impl Fn(&str) -> bool,
) -> bool {
    parts
        .find_map(|part| match part {
            Part::Literal(text) => Some(at_edge(text)),
            Part::Random { min: 0, .. } => None,
            Part::Random { .. } => Some(false),
        })
        .unwrap_or(false)
}

/// The `http` crate's header-value grammar: visible ASCII, plus space and
/// horizontal tab. Checked here so [`Template::render`] cannot fail; the
/// placement of that whitespace is [`Template::parse`]'s concern.
fn validate_literal(text: &str) -> Result<(), String> {
    match text
        .bytes()
        .find(|byte| !(matches!(byte, 0x20..=0x7e | b'\t')))
    {
        Some(byte) => Err(format!(
            "header value contains byte 0x{byte:02x}, which cannot be sent"
        )),
        None => Ok(()),
    }
}

/// The operator's extra CONNECT headers, in declaration order.
#[derive(Debug, Clone, Default)]
pub struct ExtraHeaders {
    entries: Vec<(HeaderName, Template)>,
    overrides_user_agent: bool,
}

impl ExtraHeaders {
    /// Validate a configured header map.
    ///
    /// `limit` bounds the entry count. The values are re-serialized into
    /// *every* CONNECT request, so a provider-supplied map is attacker-chosen
    /// process memory on a hot path — the same reason xhttp/http-upgrade cap
    /// theirs (issue #648).
    pub fn new(raw: &[(String, String)], limit: usize) -> Result<Self, String> {
        if raw.len() > limit {
            return Err(format!("headers has {} entries (max {limit})", raw.len()));
        }
        let mut entries = Vec::with_capacity(raw.len());
        let mut overrides_user_agent = false;
        for (name, value) in raw {
            // Pseudo-headers (`:method`, `:authority`, …) fail here on their
            // leading colon, which is the right answer: this adapter owns
            // them and a config cannot be allowed to contradict the method.
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("'{name}' is not a header name"))?;
            if RESERVED.contains(&name.as_str()) {
                return Err(format!("header '{name}' is set by the adapter itself"));
            }
            if UNSENDABLE.contains(&name.as_str()) {
                return Err(format!(
                    "header '{name}' cannot be sent on an HTTP/2 or HTTP/3 request; \
                     the endpoint would treat the CONNECT as malformed"
                ));
            }
            // `HeaderName` is case-insensitive, so `User-Agent` and
            // `user-agent` are one header — declaring both would send it
            // twice, which is itself a thing to match on.
            if entries.iter().any(|(seen, _)| *seen == name) {
                return Err(format!("header '{name}' is declared twice"));
            }
            let template = Template::parse(value).map_err(|e| format!("header '{name}': {e}"))?;
            overrides_user_agent |= name == http::header::USER_AGENT;
            entries.push((name, template));
        }
        Ok(Self {
            entries,
            overrides_user_agent,
        })
    }

    /// Whether the config supplies its own `user-agent`, in which case the
    /// spec-shaped one is not emitted and the per-stream-type distinction
    /// disappears with it.
    pub fn overrides_user_agent(&self) -> bool {
        self.overrides_user_agent
    }

    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &Template)> {
        self.entries.iter().map(|(name, value)| (name, value))
    }
}

/// The spec's `user-agent` for one CONNECT target.
///
/// `_check` carries the platform alone, the multiplexers name themselves, and
/// everything else is a TCP tunnel carrying the application name.
pub fn user_agent(platform: &str, app_name: &str, authority: &str) -> String {
    match authority {
        "_check" => platform.to_owned(),
        "_udp2" | "_icmp" => format!("{platform} {authority}"),
        _ => format!("{platform} {app_name}"),
    }
}

/// The `<platform>` token for this host.
///
/// The specification shows the field without defining its vocabulary, so
/// these are the conventional short names; `platform:` overrides them for an
/// operator who wants the session to look like some other client.
pub fn default_platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "mac",
        other => other,
    }
}

/// Validate a `platform` / `app-name` token.
///
/// `platform` is the first whitespace-delimited field of every user-agent, so
/// a space inside it would make the endpoint read the next field as the
/// application name. `app_name` is last and may contain spaces, but not at
/// either end: a trailing one would end the whole `user-agent` value in
/// whitespace, which RFC 9113 §8.2.1 makes malformed.
pub fn validate_token(label: &str, token: &str, spaces: bool) -> Result<(), String> {
    if token.is_empty() {
        return Err(format!("{label} is empty"));
    }
    if token.len() > MAX_TOKEN_BYTES {
        return Err(format!(
            "{label} is {} bytes (max {MAX_TOKEN_BYTES})",
            token.len()
        ));
    }
    validate_literal(token).map_err(|e| format!("{label}: {e}"))?;
    if !spaces && token.contains(WHITESPACE) {
        return Err(format!("{label} cannot contain whitespace"));
    }
    if token.starts_with(WHITESPACE) || token.ends_with(WHITESPACE) {
        return Err(format!("{label} cannot start or end with whitespace"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_follows_the_specs_per_stream_shape() {
        assert_eq!(user_agent("ios", "AdGuard", "_check"), "ios");
        assert_eq!(user_agent("ios", "AdGuard", "_udp2"), "ios _udp2");
        assert_eq!(user_agent("ios", "AdGuard", "_icmp"), "ios _icmp");
        assert_eq!(
            user_agent("ios", "AdGuard", "example.test:443"),
            "ios AdGuard"
        );
    }

    #[test]
    fn a_literal_value_renders_itself() {
        let template = Template::parse("keep-alive").unwrap();
        assert_eq!(template.render(), "keep-alive");
        assert_eq!(template.render(), "keep-alive");
    }

    #[test]
    fn a_fixed_length_placeholder_rerolls_every_render() {
        let template = Template::parse("<random-string(24)>").unwrap();
        let first = template.render();
        let second = template.render();
        assert_eq!(first.len(), 24);
        assert_eq!(second.len(), 24);
        // A constant padding value is just a constant to fingerprint, so the
        // re-roll is the feature, not an implementation detail.
        assert_ne!(first, second, "24 random characters collided twice");
        assert!(
            first.bytes().all(|b| ALPHABET.contains(&b)),
            "{first} left the URL-safe alphabet"
        );
    }

    /// Rendering draws entropy a stack buffer at a time, so a run longer than
    /// one draw has to come out exactly as long — and still inside the
    /// alphabet.
    #[test]
    fn a_placeholder_longer_than_one_random_draw_renders_exactly() {
        let length = RANDOM_CHUNK * 3 + 7;
        let template = Template::parse(&format!("<random-string({length})>")).unwrap();
        let rendered = template.render();
        assert_eq!(rendered.len(), length);
        assert!(
            rendered.bytes().all(|b| ALPHABET.contains(&b)),
            "{rendered}"
        );
        assert_ne!(rendered, template.render());
    }

    #[test]
    fn a_range_placeholder_stays_inside_its_range() {
        let template = Template::parse("p=<random-string(4-9)>;q").unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let rendered = template.render();
            let body = rendered
                .strip_prefix("p=")
                .and_then(|rest| rest.strip_suffix(";q"))
                .expect(&rendered);
            assert!((4..=9).contains(&body.len()), "{rendered}");
            seen.insert(body.len());
        }
        assert!(seen.len() > 1, "the length never varied: {seen:?}");
    }

    #[test]
    fn several_placeholders_in_one_value_are_independent() {
        // Separated by a character the alphabet cannot produce: `-` and `_`
        // are both URL-safe, so splitting on either would land inside a run
        // roughly two renders in five.
        let template = Template::parse("<random-string(16)>.<random-string(16)>").unwrap();
        let rendered = template.render();
        let (left, right) = rendered.split_once('.').unwrap();
        assert_eq!((left.len(), right.len()), (16, 16));
        assert_ne!(left, right);
    }

    #[test]
    fn malformed_placeholders_are_rejected_not_passed_through() {
        for broken in [
            "<random-string(32>",
            "<random-string()>",
            "<random-string(0)>",
            "<random-string(9-4)>",
            "<random-string(abc)>",
            "<random-string(4097)>",
            "",
        ] {
            assert!(
                Template::parse(broken).is_err(),
                "'{broken}' must not parse"
            );
        }
        // Eight is the cap, nine is one too many.
        let nine = "<random-string(1)>".repeat(9);
        assert!(Template::parse(&nine).is_err());
        assert!(Template::parse(&"<random-string(1)>".repeat(8)).is_ok());
    }

    #[test]
    fn a_value_that_cannot_be_sent_is_rejected_at_parse_time() {
        assert!(Template::parse("line\r\nInjected: yes").is_err());
        assert!(Template::parse("nul\0byte").is_err());
        // Two 4 KiB runs plus literals exceed the per-value budget.
        assert!(Template::parse("<random-string(4096)><random-string(4096)>x").is_err());
    }

    #[test]
    fn reserved_and_malformed_names_are_rejected() {
        let set = |name: &str| {
            ExtraHeaders::new(&[(name.to_string(), "value".to_string())], 8)
                .err()
                .unwrap_or_default()
        };
        assert!(set("proxy-authorization").contains("set by the adapter itself"));
        assert!(set(":method").contains("is not a header name"));
        assert!(set("bad header").contains("is not a header name"));
        assert!(ExtraHeaders::new(&[], 8).unwrap().iter().next().is_none());
    }

    /// `headers: {connection: keep-alive}` is exactly what an operator adds
    /// to look like a browser — and exactly what makes an HTTP/2 or HTTP/3
    /// receiver treat the CONNECT as malformed and reset the stream, which
    /// this client would report as a dial failure against a working node. The
    /// name has to be refused where the operator can still see it.
    #[test]
    fn headers_that_no_h2_or_h3_request_may_carry_are_rejected() {
        for name in UNSENDABLE {
            let error = ExtraHeaders::new(&[((*name).to_string(), "x".to_string())], 8)
                .err()
                .unwrap_or_else(|| panic!("'{name}' must not be accepted"));
            assert!(error.contains("malformed"), "{name}: {error}");
        }
        // Case is irrelevant — `HeaderName` normalises before the check.
        assert!(ExtraHeaders::new(&[("Connection".into(), "close".into())], 8).is_err());
        // Nothing adjacent got caught in the net.
        assert!(ExtraHeaders::new(&[("accept-encoding".into(), "gzip".into())], 8).is_ok());
    }

    /// Two spellings of one header name would be sent twice, which is its own
    /// distinguishing mark — and for `user-agent` it would also fight the
    /// override the knob exists to allow.
    #[test]
    fn a_header_declared_twice_is_rejected() {
        let error = ExtraHeaders::new(
            &[
                ("User-Agent".into(), "first".into()),
                ("user-agent".into(), "second".into()),
            ],
            8,
        )
        .unwrap_err();
        assert!(error.contains("declared twice"), "{error}");
    }

    #[test]
    fn the_entry_count_is_bounded() {
        let many: Vec<_> = (0..5)
            .map(|i| (format!("x-{i}"), "v".to_string()))
            .collect();
        assert!(ExtraHeaders::new(&many, 5).is_ok());
        assert!(ExtraHeaders::new(&many, 4).err().unwrap().contains("max 4"));
    }

    #[test]
    fn a_configured_user_agent_is_recorded_as_an_override() {
        let plain =
            ExtraHeaders::new(&[("x-padding".into(), "<random-string(8)>".into())], 8).unwrap();
        assert!(!plain.overrides_user_agent());
        let overridden =
            ExtraHeaders::new(&[("User-Agent".into(), "ios AdGuard/2.0".into())], 8).unwrap();
        assert!(overridden.overrides_user_agent());
        // Header names normalize to lowercase, so the wire form is stable
        // whatever case the YAML used.
        assert_eq!(overridden.iter().next().unwrap().0.as_str(), "user-agent");
    }

    #[test]
    fn tokens_are_validated_for_the_field_they_land_in() {
        assert!(validate_token("platform", "ios", false).is_ok());
        assert!(validate_token("platform", "i os", false).is_err());
        assert!(validate_token("app-name", "AdGuard VPN", true).is_ok());
        assert!(validate_token("app-name", "", true).is_err());
        assert!(validate_token("app-name", &"x".repeat(65), true).is_err());
        assert!(validate_token("app-name", "bad\nname", true).is_err());
        assert!(validate_token("platform", "\tios", false).is_err());
    }

    /// RFC 9113 §8.2.1: a value that starts or ends with SP/HTAB is malformed,
    /// so the endpoint would reset the CONNECT. `app-name` ends the
    /// `user-agent`, so its edges are the value's edge.
    #[test]
    fn app_name_whitespace_is_inner_only() {
        for padded in ["AdGuard ", " AdGuard", "AdGuard\t", "\tAdGuard"] {
            let error = validate_token("app-name", padded, true).unwrap_err();
            assert!(
                error.contains("cannot start or end with whitespace"),
                "{padded:?} -> {error}"
            );
        }
        assert!(validate_token("app-name", "Ad\tGuard VPN", true).is_ok());
    }

    #[test]
    fn header_values_cannot_render_edge_whitespace() {
        for (raw, edge) in [
            (" abc", "start"),
            ("\tabc", "start"),
            ("abc ", "end"),
            ("abc\t", "end"),
            (" ", "start"),
            // A placeholder that may render empty exposes its literal
            // neighbour — and two of them in a row expose the next one.
            ("<random-string(0-4)> abc", "start"),
            ("abc <random-string(0-4)>", "end"),
            ("<random-string(0-2)><random-string(0-2)>\tabc", "start"),
        ] {
            let error = Template::parse(raw).unwrap_err();
            assert!(
                error.contains(&format!("cannot {edge} with a space or tab")),
                "{raw:?} -> {error}"
            );
        }
        // Inner whitespace is fine, and so is an edge literal shielded by a
        // run that always renders at least one character.
        for raw in [
            "a b",
            "a\tb",
            "abc <random-string(1-4)>",
            "<random-string(2)> abc",
            "<random-string(0-4)>",
        ] {
            let template = Template::parse(raw).unwrap_or_else(|e| panic!("{raw:?}: {e}"));
            let rendered = template.render();
            assert!(!rendered.starts_with(WHITESPACE), "{rendered:?}");
            assert!(!rendered.ends_with(WHITESPACE), "{rendered:?}");
        }
    }
}
