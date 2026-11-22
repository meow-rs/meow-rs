//! TCP Brutal bandwidth negotiation — sing-mux v0.3.12 `brutal.go`.
//!
//! On each *new carrier session* a brutal-enabled client opens a mux
//! stream to the reserved destination [`BRUTAL_EXCHANGE_DOMAIN`]`:0`,
//! writes its configured receive rate (`down`) as a u64 BE, and reads
//! the server's reply — `[ok u8]` then `u64 BE serverReceiveBPS` on
//! success or a uvarint-length-prefixed message on failure. The applied
//! send rate is `min(up, serverReceiveBPS)`, programmed onto the
//! carrier's *physical* socket by [`meow_common::BrutalCarrier`] — the
//! pieces here are only the config-side rate parser and the reply codec.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Reserved stream destination carrying the negotiation — sing-mux
/// `BrutalExchangeDomain`. The port is always 0.
pub const BRUTAL_EXCHANGE_DOMAIN: &str = "_BrutalBwExchange";

/// The two negotiated rates in **bytes per second**, mihomo's
/// `BrutalOption` after `utils.StringToBps`: `send_bps` is `up` (the cap
/// this node applies to its own send socket), `receive_bps` is `down`
/// (sent to the server so it caps *its* send). A `Some(brutal)` in
/// [`MuxOptions`](super::client::MuxOptions) already implies
/// `enabled: true` — the parser drops `enabled: false` to `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxBrutal {
    pub send_bps: u64,
    pub receive_bps: u64,
}

/// mihomo `common/utils/mbps.go` `StringToBps`, exact semantics:
///
/// * `""` → 0;
/// * a pure `strconv.Atoi`-parseable integer (`007`, `+50` count;
///   `-5` recurses to `"-5 Mbps"` which the regex then rejects) → `N`
///   Mbps — so `"50"` is 50 M**b**ps = 6,250,000 B/s, not 50 MB/s;
/// * otherwise the anchored `^(\d+)\s*([KMGT]?)([Bb])ps$` — K/M/G/T are
///   decimal 1e3/1e6/1e9/1e12 (Go `\s` is `[\t\n\f\r ]` only), and a
///   lowercase `b` divides by 8 (bits → bytes) while `B` keeps bytes;
/// * a digits run past `u64` keeps Go's `ParseUint` saturation value
///   `u64::MAX` — the error is ignored upstream — and the multiply
///   wraps (`99999999999999999999 Mbps` → a wrapped nonzero, not 0);
/// * anything unparseable is silently 0, never an error.
pub fn string_to_bps(s: &str) -> u64 {
    if s.is_empty() {
        return 0;
    }
    // `strconv.Atoi` == `i64::from_str` on this input: optional ASCII
    // sign + digits, int64 range, no whitespace/underscore/radix forms.
    if let Ok(v) = s.parse::<i64>() {
        // Upstream recurses on `format!("{} Mbps", v)` — the ` Mbps`
        // suffix can never re-enter this arm, so it always terminates.
        return string_to_bps(&format!("{v} Mbps"));
    }
    let Some(m) = match_bps(s) else {
        return 0;
    };
    // `ParseUint` returns the max value on range error, which upstream
    // ignores — the wrapped product is the faithful result.
    let v = m.digits.parse::<u64>().unwrap_or(u64::MAX);
    let n = m.unit.wrapping_mul(v);
    if m.bits {
        n / 8
    } else {
        n
    }
}

/// The match arm of [`string_to_bps`]'s regex — the digits run, its unit
/// multiplier (1 when no K/M/G/T), and whether the `b` is lowercase.
struct BpsMatch<'a> {
    unit: u64,
    bits: bool,
    digits: &'a str,
}

/// `^(\d+)\s*([KMGT]?)([Bb])ps$` hand-rolled byte-exact — Go regexp `\d`
/// is ASCII `[0-9]` and `\s` is `[\t\n\f\r ]` (no vertical tab), so a
/// manual scan is both cheaper and closer to the original than
/// `char::is_whitespace` would be.
fn match_bps(s: &str) -> Option<BpsMatch<'_>> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    let digits = &s[..i];
    while i < b.len() && matches!(b[i], b'\t' | b'\n' | 0x0C | b'\r' | b' ') {
        i += 1;
    }
    let unit = match b.get(i) {
        Some(b'K') => {
            i += 1;
            1_000
        }
        Some(b'M') => {
            i += 1;
            1_000_000
        }
        Some(b'G') => {
            i += 1;
            1_000_000_000
        }
        Some(b'T') => {
            i += 1;
            1_000_000_000_000
        }
        _ => 1,
    };
    let bits = match b.get(i) {
        Some(b'b') => {
            i += 1;
            true
        }
        Some(b'B') => {
            i += 1;
            false
        }
        _ => return None,
    };
    match &b[i..] == b"ps" {
        true => Some(BpsMatch { unit, bits, digits }),
        false => None,
    }
}

/// sing's `rw.ReadVString`: a uvarint (LEB128) byte length followed by
/// the message — the `!ok` half of the `ReadBrutalResponse` wire shape.
/// The declared length is remote-controlled: an honest error message is
/// never large, so anything past the cap or beyond u64 varints is
/// `InvalidData` instead of an allocation.
pub(crate) async fn read_vstring<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<String> {
    const MAX_VSTRING: u64 = 64 * 1024;
    let mut len: u64 = 0;
    // Go's binary.Uvarint: at most 10 bytes, and the tenth may carry a
    // single bit (2^63). Anything more is an overflow, same verdict.
    for i in 0..10u32 {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        if i == 9 && byte[0] > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mux: brutal vstring length varint overflows u64",
            ));
        }
        len |= u64::from(byte[0] & 0x7f) << (7 * i);
        if byte[0] & 0x80 == 0 {
            if len > MAX_VSTRING {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("mux: brutal vstring length {len} exceeds {MAX_VSTRING}"),
                ));
            }
            let mut buf = vec![0u8; len as usize];
            stream.read_exact(&mut buf).await?;
            return String::from_utf8(buf).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mux: brutal vstring is not UTF-8",
                )
            });
        }
    }
    // Ten bytes all carrying the continuation bit can't happen — the
    // tenth already failed the `> 1` check — but keep the exit explicit.
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "mux: brutal vstring length varint unterminated",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The upstream table — every row verified against mihomo
    /// `common/utils/mbps.go` run under Go (including the surprising
    /// halves: bare integers are *megaBITS*, and a saturating
    /// `ParseUint` yields a wrapped nonzero, not 0).
    #[test]
    fn string_to_bps_matches_upstream() {
        for (input, want) in [
            ("", 0),
            ("abc", 0),
            ("0", 0),
            ("50", 6_250_000),       // 50 Mbps = 50e6/8
            ("007", 875_000),        // Atoi accepts leading zeros
            ("+50", 6_250_000),      // Atoi accepts a leading +
            ("-5", 0),               // "-5 Mbps" fails the regex
            ("50.5", 0),             // no floats
            ("50 Mbps", 6_250_000),  // bits → /8
            ("50Mbps", 6_250_000),   // \s* may be empty
            ("50 mbps", 0),          // units are case-sensitive
            ("50 MBps", 50_000_000), // B = bytes, no /8
            ("1 Gbps", 125_000_000),
            ("2gbps", 0),
            ("100 kbps", 0),
            ("100KBps", 100_000),
            ("3 Tbps", 375_000_000_000),
            ("10 bps", 1),
            ("10 Bps", 10),
            ("8 bps", 1),    // 8 bits = 1 byte
            (" 50 Mbps", 0), // no trim — the anchor rejects the space
            ("50 Mbps ", 0),
            ("1.5 Gbps", 0),
            ("0 Mbps", 0),
            ("5 Pbps", 0), // beyond T is not a unit
            ("5 Ebps", 0),
            ("50 mb", 0),
            ("50 Mbpsx", 0),
            // u64-range overflow saturates (upstream ignores the error)
            // and the multiply wraps — nonzero garbage, never 0.
            ("99999999999999999999 Mbps", 2_305_843_009_213_568_952),
            ("18446744073709551615 Mbps", 2_305_843_009_213_568_952),
            ("18446744073709551616 Mbps", 2_305_843_009_213_568_952),
            ("99999999999999999999", 0), // pure int overflow is just unparseable
            ("18446744073709551615 Gbps", 2_305_843_009_088_693_952),
            // Go `\s` set: tab/CR/LF/FF count, vertical tab does not.
            ("50\tMbps", 6_250_000),
            ("50\x0BMbps", 0),
        ] {
            assert_eq!(string_to_bps(input), want, "{input:?}");
        }
    }

    #[tokio::test]
    async fn read_vstring_roundtrip_and_bounds() {
        // uvarint len + bytes; 300 needs two varint bytes (0xAC 0x02).
        let msg = "x".repeat(300);
        let mut wire = vec![0xAC, 0x02];
        wire.extend_from_slice(msg.as_bytes());
        let mut cur: &[u8] = &wire;
        assert_eq!(read_vstring(&mut cur).await.unwrap(), msg);

        // A declared length past the cap errors instead of allocating.
        let mut cur: &[u8] = &[0xFF, 0xFF, 0xFF, 0x0F];
        assert!(read_vstring(&mut cur).await.is_err());

        // Truncated message and unterminated varint error too.
        let mut cur: &[u8] = &[0x05, b'a', b'b'];
        assert!(read_vstring(&mut cur).await.is_err());
        let mut cur: &[u8] = &[0x80; 10];
        assert!(read_vstring(&mut cur).await.is_err());
        // Non-UTF-8 payloads error.
        let mut cur: &[u8] = &[0x02, 0xFF, 0xFE];
        assert!(read_vstring(&mut cur).await.is_err());
    }
}
