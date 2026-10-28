use smol_str::SmolStr;

/// Parse SNI hostname from raw TLS ClientHello bytes.
///
/// Returns `SmolStr` so typical hostnames (≤ 23 bytes) are inlined without
/// a heap allocation per sniffed handshake.
pub fn sniff_tls(buf: &[u8]) -> Option<SmolStr> {
    // TLS record header: content_type(1) + version(2) + length(2)
    if buf.len() < 5 {
        return None;
    }
    // content_type must be Handshake (0x16)
    if buf[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record = buf.get(5..5 + record_len)?;

    // Handshake header: type(1) + length(3)
    if record.is_empty() || record[0] != 0x01 {
        return None;
    }
    let handshake_len =
        ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | (record[3] as usize);
    let hello = record.get(4..4 + handshake_len)?;

    // ClientHello: version(2) + random(32) = skip 34 bytes
    if hello.len() < 34 {
        return None;
    }
    let mut pos = 34;

    // Session ID: length(1) + data
    let session_id_len = *hello.get(pos)? as usize;
    pos += 1 + session_id_len;

    // Cipher suites: length(2) + data
    let cs_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
    pos += 2 + cs_len;

    // Compression methods: length(1) + data
    let comp_len = *hello.get(pos)? as usize;
    pos += 1 + comp_len;

    // Extensions: length(2) + data
    if pos + 2 > hello.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;
    while pos + 4 <= ext_end && pos + 4 <= hello.len() {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            return parse_sni_extension(hello.get(pos..pos + ext_data_len)?);
        }
        pos += ext_data_len;
    }

    None
}

fn parse_sni_extension(data: &[u8]) -> Option<SmolStr> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list = data.get(2..2 + list_len)?;

    let mut pos = 0;
    while pos + 3 <= list.len() {
        let name_type = list[pos];
        let name_len = u16::from_be_bytes([list[pos + 1], list[pos + 2]]) as usize;
        pos += 3;

        if name_type == 0x00 {
            let name_bytes = list.get(pos..pos + name_len)?;
            let s = std::str::from_utf8(name_bytes).ok()?;
            // A server_name that is not a hostname would steer the rules by
            // a name no peer dials the same way (issue #734).
            if !crate::is_valid_host(s) {
                return None;
            }
            // Hostnames are usually already lowercase — only pay for a
            // char-mapped rebuild when one actually contains uppercase.
            return Some(if s.bytes().any(|b| b.is_ascii_uppercase()) {
                s.chars().map(|c| c.to_ascii_lowercase()).collect()
            } else {
                SmolStr::new(s)
            });
        }
        pos += name_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();
        let sni_entry_len = 3 + name_bytes.len();
        let sni_list_len = sni_entry_len;
        let sni_ext_data_len = 2 + sni_list_len;

        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&[0x00, 0x00]);
        sni_ext.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        sni_ext.push(0x00);
        sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name_bytes);

        let extensions_len = sni_ext.len();

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0x00);
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
        hello.extend_from_slice(&[0x01, 0x00]);
        hello.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        hello.extend_from_slice(&sni_ext);

        let handshake_len = hello.len();

        let mut handshake = vec![
            0x01,
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&hello);

        let record_len = handshake.len();

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(record_len as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn sniff_tls_sni_extraction_cases() {
        // `very.long.subdomain.example.co.uk` is longer than the 23-byte SmolStr
        // inline limit, so it also covers the heap-allocated return path; the two
        // shorter names stay inlined. Keep all three literals.
        for host in [
            "example.com",
            "www.google.com",
            "very.long.subdomain.example.co.uk",
        ] {
            let data = build_client_hello(host);
            assert_eq!(
                sniff_tls(&data).as_deref(),
                Some(host),
                "SNI extraction failed for hostname {host:?}"
            );
        }
    }

    /// Issue #734: an SNI that is not a hostname is not a sniffed name.
    #[test]
    fn sniff_tls_rejects_non_hostname_sni() {
        for host in ["a@evil.com", "evil.com:443", "evil.com/x", "ev il.com"] {
            assert_eq!(sniff_tls(&build_client_hello(host)), None, "{host:?}");
        }
    }

    #[test]
    fn test_no_sni_on_non_tls() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(sniff_tls(data), None);
    }

    #[test]
    fn test_no_sni_on_empty() {
        assert_eq!(sniff_tls(&[]), None);
    }

    #[test]
    fn test_no_sni_on_truncated() {
        let data = build_client_hello("example.com");
        assert_eq!(sniff_tls(&data[..data.len() / 2]), None);
    }

    #[test]
    fn test_no_sni_wrong_content_type() {
        let mut data = build_client_hello("example.com");
        data[0] = 0x17;
        assert_eq!(sniff_tls(&data), None);
    }

    #[test]
    fn sniff_tls_partial_record_header_only() {
        // Only the 5-byte TLS record header, no handshake body — must not panic.
        let header = [0x16u8, 0x03, 0x01, 0x00, 0x05];
        assert_eq!(sniff_tls(&header), None);
    }

    /// Build a ClientHello whose only extension is a non-SNI extension
    /// (extended_master_secret, type 0x0017, empty data). Sniffing should
    /// return `None` rather than panicking on the missing SNI.
    fn build_client_hello_without_sni() -> Vec<u8> {
        let mut other_ext = Vec::new();
        other_ext.extend_from_slice(&[0x00, 0x17]);
        other_ext.extend_from_slice(&[0x00, 0x00]);

        let extensions_len = other_ext.len();

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0x00);
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
        hello.extend_from_slice(&[0x01, 0x00]);
        hello.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        hello.extend_from_slice(&other_ext);

        let handshake_len = hello.len();
        let mut handshake = vec![
            0x01,
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&hello);

        let record_len = handshake.len();
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(record_len as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn sniff_tls_no_sni_extension_returns_none() {
        let data = build_client_hello_without_sni();
        assert_eq!(sniff_tls(&data), None);
    }

    #[test]
    fn sniff_tls_skips_non_host_name_entries() {
        // SNI extension with a non-zero name_type entry first, then a host_name
        // entry. Per RFC 6066 §3 only name_type=0 (host_name) is currently
        // defined, so the parser must skip the unknown entry rather than
        // misinterpreting it as the hostname.
        let host = b"target.example.com";
        // Entry 1: name_type=0x99 (unknown), name="ignored"
        let unknown = b"ignored";
        // Entry 2: name_type=0x00 (host_name), name=host
        let mut list = Vec::new();
        list.push(0x99);
        list.extend_from_slice(&(unknown.len() as u16).to_be_bytes());
        list.extend_from_slice(unknown);
        list.push(0x00);
        list.extend_from_slice(&(host.len() as u16).to_be_bytes());
        list.extend_from_slice(host);

        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&[0x00, 0x00]);
        let ext_data_len = (2 + list.len()) as u16;
        sni_ext.extend_from_slice(&ext_data_len.to_be_bytes());
        sni_ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&list);

        let extensions_len = sni_ext.len();
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0x00);
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
        hello.extend_from_slice(&[0x01, 0x00]);
        hello.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        hello.extend_from_slice(&sni_ext);

        let handshake_len = hello.len();
        let mut handshake = vec![
            0x01,
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&hello);

        let record_len = handshake.len();
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(record_len as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(sniff_tls(&record).as_deref(), Some("target.example.com"));
    }
}
