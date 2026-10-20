//! Diagnostic-only ID parsing. Never returns arbitrary header values.
fn valid_probe_id(value: &[u8]) -> Option<&str> {
    if !(21..=30).contains(&value.len())
        || &value[..3] != b"tp-"
        || value[19] != b'-'
        || !value[3..19]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return None;
    }
    let decimal = &value[20..];
    if decimal[0] == b'0' || !decimal.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let text = std::str::from_utf8(value).ok()?;
    let id: u32 = text[20..].parse().ok()?;
    (id <= 1_000_000_000).then_some(text)
}

pub(crate) fn extract_probe_id<'a>(
    headers: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Option<&'a str> {
    let mut result = None;
    let mut seen = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case(b"X-TinyPaws-Probe") {
            if seen {
                return None;
            }
            seen = true;
            let start = value
                .iter()
                .position(|b| !matches!(b, b' ' | b'\t'))
                .unwrap_or(value.len());
            let end = value
                .iter()
                .rposition(|b| !matches!(b, b' ' | b'\t'))
                .map_or(start, |i| i + 1);
            result = valid_probe_id(&value[start..end]);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_bounded_numeric_request_id_and_lowercase_run_hex() {
        for id in ["tp-0123456789abcdef-1", "tp-0123456789abcdef-1000000000"] {
            assert_eq!(valid_probe_id(id.as_bytes()), Some(id));
        }
        for id in [
            "",
            "tp-0123456789abcdef-0",
            "tp-0123456789abcdef-01",
            "tp-0123456789abcdef-1000000001",
            "tp-0123456789abcdeF-1",
            "tp-0123456789abcdef-1\r\nAuthorization: secret",
            "tp-0123456789abcdef-password",
            "tp-0123456789abcdef-99999999999",
        ] {
            assert_eq!(valid_probe_id(id.as_bytes()), None);
        }
    }
    #[test]
    fn ignores_sensitive_headers_and_rejects_duplicate_probe_headers() {
        let probe = b" \ttp-0123456789abcdef-7\t ".as_slice();
        let headers = [
            (b"Authorization".as_slice(), b"Bearer secret".as_slice()),
            (b"x-tinypaws-probe".as_slice(), probe),
        ];
        assert_eq!(extract_probe_id(headers), Some("tp-0123456789abcdef-7"));
        assert_eq!(
            extract_probe_id([
                (b"X-TinyPaws-Probe".as_slice(), probe),
                (b"X-TinyPaws-Probe".as_slice(), probe)
            ]),
            None
        );
        assert_eq!(
            extract_probe_id([(b"Authorization".as_slice(), b"secret".as_slice())]),
            None
        );
    }
}
