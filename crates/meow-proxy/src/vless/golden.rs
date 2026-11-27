//! Frozen Wave-0 golden byte vectors (`/tmp/vless-vision-wave0/golden/`),
//! copied here as continuous-hex strings so unit tests assert against the
//! same bytes the freeze report verified structurally.  The vectors are
//! constructed from the pinned xray/mihomo encode logic, not captured on
//! the wire; padding lengths inside them are frozen illustrative values,
//! not outputs of the random padding rule.

#[cfg(test)]
pub(crate) mod vectors {
    pub(crate) const TCP_REQUEST_FIRST_UPLINK_FRAME: &str =
        include_str!("testdata/01_tcp_request_first_uplink_frame.hexstr");
    pub(crate) const TCP_REQUEST_EMPTY_FIRST_FRAME: &str =
        include_str!("testdata/02_tcp_request_empty_first_frame.hexstr");
    pub(crate) const RESPONSE_FIRST_DOWNLINK_FRAME: &str =
        include_str!("testdata/03_response_first_downlink_frame.hexstr");
    pub(crate) const TLS13_SERVERHELLO_DECISION: &str =
        include_str!("testdata/04_tls13_serverhello_decision.hexstr");
    pub(crate) const XUDP_NEW_DATA: &str = include_str!("testdata/05_xudp_new_data.hexstr");
    pub(crate) const XUDP_KEEP_END: &str = include_str!("testdata/06_xudp_keep_end.hexstr");
    pub(crate) const XUDP_REPLY_KEEP_DATA: &str =
        include_str!("testdata/07_xudp_reply_keep_data.hexstr");

    /// The documented example UUID `71884bd4-d6a0-4e19-9895-3e1d8b469317`
    /// every request/response vector embeds.
    pub(crate) const GOLDEN_UUID: [u8; 16] = [
        0x71, 0x88, 0x4b, 0xd4, 0xd6, 0xa0, 0x4e, 0x19, 0x98, 0x95, 0x3e, 0x1d, 0x8b, 0x46, 0x93,
        0x17,
    ];

    pub(crate) fn decode(hex: &str) -> Vec<u8> {
        let hex = hex.trim();
        assert_eq!(hex.len() % 2, 0, "golden hex must be byte-aligned");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("golden hex is valid"))
            .collect()
    }
}
