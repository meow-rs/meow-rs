//! AnyTLS `padding-scheme` syntax validation, shared between the config
//! parser (which must not link the whole AnyTLS crate just to check a
//! string) and `anytls_rs::PaddingFactory`, whose `new` runs this same
//! contract before building its size table. MD5 stays out of scope —
//! the factory computes it over the raw bytes itself.
//!
//! Wire contract (upstream `transport/anytls/padding`): lines of
//! `key=value` trimmed like `StringMap::from_bytes` (last duplicate
//! wins); `stop` must be a `u32`; every *numeric* key maps a packet
//! index to a comma-separated spec of `min-max` ranges (each endpoint a
//! `u16` in `1..=65535`, reversed accepted) and `c` checkpoints.
//! Non-numeric keys are ignored like the factory does.

/// Authentication and Waste frames encode lengths as `u16`. Bound the
/// aggregate too: a short peer-supplied scheme must not expand one write
/// without limit (mirrors `PaddingFactory::MAX_PACKET_PADDING`).
const MAX_PACKET_PADDING: usize = 1024 * 1024;

/// AnyTLS frame header size (`cmd u8 | stream id u32 | len u16`) — every
/// declared size may additionally emit one Waste frame of this overhead.
const FRAME_OVERHEAD: usize = 7;

/// The whole scheme travels as ONE `UpdatePaddingScheme` frame payload —
/// the u16 length field is the protocol's hard ceiling. A scheme that
/// validates here must remain sendable, so the cap lives in the shared
/// contract rather than in either caller.
const MAX_SCHEME_BYTES: usize = u16::MAX as usize;

/// Validate `raw_scheme` exactly as `anytls_rs::PaddingFactory::new`
/// accepts it. Returns `Err` with a human-readable message on any
/// malformed `stop`, bad range endpoint, a packet whose total potential
/// padding exceeds the protocol bound, or a scheme too long to ever
/// ride the update frame.
pub fn validate_scheme(raw_scheme: &[u8]) -> Result<(), String> {
    if raw_scheme.len() > MAX_SCHEME_BYTES {
        return Err(format!(
            "padding scheme exceeds {MAX_SCHEME_BYTES} bytes — it must fit one frame"
        ));
    }
    let text = String::from_utf8_lossy(raw_scheme);

    // `StringMap::from_bytes` parity: `k=v` halves are taken VERBATIM
    // (no trimming — upstream `StringMapFromBytes` does not trim), last
    // duplicate key winning.
    let mut entries: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match entries.iter_mut().find(|(k, _)| k == key) {
                Some(slot) => slot.1 = value.to_string(),
                None => entries.push((key.to_string(), value.to_string())),
            }
        }
    }

    // `stop` tolerates whitespace around key and value — the pre-unify
    // config parser trimmed both, and tightening it would reject node
    // configs meow already accepted (N06). Numeric padding keys stay
    // verbatim: a padded " 0" is a non-numeric key, ignored like
    // upstream's StringMap.
    match entries.iter().find(|(k, _)| k.trim() == "stop") {
        Some((_, stop)) => {
            stop.trim()
                .parse::<u32>()
                .map_err(|_| "invalid 'stop' value".to_string())?;
        }
        None => return Err("missing 'stop' in padding scheme".to_string()),
    }

    for (key, spec) in &entries {
        if key.parse::<u32>().is_err() {
            continue;
        }
        let mut total = 0usize;
        for part in spec.split(',').map(str::trim) {
            if part == "c" {
                continue;
            }
            let (min, max) = part
                .split_once('-')
                .ok_or_else(|| "invalid padding range".to_string())?;
            let parse_size = |value: &str| {
                value
                    .trim()
                    .parse::<u16>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| "padding size must be between 1 and 65535".to_string())
            };
            let max = parse_size(min)?.max(parse_size(max)?);
            total += usize::from(max) + FRAME_OVERHEAD;
            if total > MAX_PACKET_PADDING {
                return Err("padding for one packet exceeds 1 MiB".to_string());
            }
        }
    }

    Ok(())
}
