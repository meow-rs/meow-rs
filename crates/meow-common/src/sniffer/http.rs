use smol_str::SmolStr;

/// Parse the HTTP `Host:` header from the first request bytes.
///
/// Returns `None` if the buffer does not look like HTTP/1.x or has no Host header.
/// `httparse::Status::Partial` is treated as success — as long as we've seen
/// the Host line we don't need the full request.
///
/// Returns `SmolStr` so typical hostnames (≤ 23 bytes) are inlined without
/// a heap allocation per sniffed request.
pub fn sniff_http(buf: &[u8]) -> Option<SmolStr> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    // Both Complete and Partial are fine; an Err means the buffer isn't HTTP.
    req.parse(buf).ok()?;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("host") {
            let s = std::str::from_utf8(h.value).ok()?.trim();
            // Strip optional `:port` suffix while preserving bracketed IPv6.
            // RFC 7230 §5.4: `Host = uri-host [":" port]` where uri-host may
            // be an `IP-literal` in `[...]`. Naive split(':') mangles `[::1]:8080`.
            let host = if let Some(rest) = s.strip_prefix('[') {
                let end = rest.find(']')?;
                &rest[..end]
            } else {
                s.split(':').next()?
            };
            // `a@evil.com`, `evil.com/x`, ... would steer the rules by a
            // name the peer parses differently (issue #734).
            if host.is_empty() || !crate::is_valid_host(host) {
                return None;
            }
            // Hostnames are usually already lowercase — only pay for a
            // char-mapped rebuild when one actually contains uppercase.
            return Some(if host.bytes().any(|b| b.is_ascii_uppercase()) {
                host.chars().map(|c| c.to_ascii_lowercase()).collect()
            } else {
                SmolStr::new(host)
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_http_basic_host_header() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(sniff_http(buf).as_deref(), Some("example.com"));
    }

    #[test]
    fn sniff_http_host_with_port_stripped() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(sniff_http(buf).as_deref(), Some("example.com"));
    }

    #[test]
    fn sniff_http_case_insensitive_header_name() {
        let buf = b"GET / HTTP/1.1\r\nHOST: example.com\r\n\r\n";
        assert_eq!(sniff_http(buf).as_deref(), Some("example.com"));
    }

    #[test]
    fn sniff_http_partial_request_ok() {
        // No trailing \r\n\r\n — httparse returns Partial, which we treat as success.
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert_eq!(sniff_http(buf).as_deref(), Some("example.com"));
    }

    #[test]
    fn sniff_http_binary_garbage_none() {
        let buf = b"\x00\x01\x02\x03\x04\x05";
        assert_eq!(sniff_http(buf), None);
    }

    #[test]
    fn sniff_http_no_host_header_none() {
        let buf = b"GET / HTTP/1.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(sniff_http(buf), None);
    }

    #[test]
    fn sniff_http_ipv6_host_brackets_stripped() {
        let buf = b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
        assert_eq!(sniff_http(buf).as_deref(), Some("::1"));
    }

    #[test]
    fn sniff_http_ipv6_host_no_port() {
        // Bracketed IPv6 host without a `:port` suffix is still recognised.
        let buf = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n";
        assert_eq!(sniff_http(buf).as_deref(), Some("2001:db8::1"));
    }

    #[test]
    fn sniff_http_empty_host_value_returns_none() {
        // RFC 7230 §5.4 forbids an empty Host value; we drop it rather than
        // returning an empty `sniff_host`.
        let buf = b"GET / HTTP/1.1\r\nHost: \r\n\r\n";
        assert_eq!(sniff_http(buf), None);
    }

    #[test]
    fn sniff_http_host_with_surrounding_whitespace() {
        // Field-value LWS must be trimmed.
        let buf = b"GET / HTTP/1.1\r\nHost:    example.com   \r\n\r\n";
        assert_eq!(sniff_http(buf).as_deref(), Some("example.com"));
    }

    /// Issue #734: a Host header carrying userinfo, a path or other
    /// non-hostname bytes is not a sniffed name.
    #[test]
    fn sniff_http_rejects_non_hostname_host_header() {
        for host in [
            "a@evil.com",
            "evil.com/x",
            "evil.com?q",
            "evil%2ecom",
            "ev il.com",
        ] {
            let buf = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            assert_eq!(sniff_http(buf.as_bytes()), None, "{host:?}");
        }
        let buf = b"GET / HTTP/1.1\r\nHost: a@evil.com:443\r\n\r\n";
        assert_eq!(sniff_http(buf), None);
    }
}
