//! The `subscription-userinfo` response header: the plan usage a
//! subscription server reports alongside a provider payload, e.g.
//! `upload=455727941; download=6174315083; total=1073741824000; expire=1798675200`.
//!
//! The format is a convention among subscription panels, not a spec, so the
//! parser is lenient about the details panels differ in.

use std::fmt;

/// The response header carrying the usage, matched case-insensitively.
pub const HEADER: &str = "subscription-userinfo";

/// Plan usage reported by a subscription server. A field the server did not
/// report reads as 0: a `total` of 0 is an unknown (or unlimited) quota and
/// an `expire` of 0 a plan without an end date.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionUserinfo {
    /// Bytes uploaded on the plan.
    pub upload: u64,
    /// Bytes downloaded on the plan.
    pub download: u64,
    /// The plan's traffic quota in bytes.
    pub total: u64,
    /// When the plan ends, in Unix seconds.
    pub expire: u64,
}

impl SubscriptionUserinfo {
    /// Parse a header value.
    ///
    /// Fields are `;`-separated `key=value` pairs in any order; keys
    /// (`upload`, `download`, `total`, `expire`) match case-insensitively,
    /// whitespace around keys and values is ignored, unknown keys are
    /// skipped and a repeated key keeps its last value. A value is a
    /// non-negative integer, or a decimal some panels print (`1.5e10`,
    /// `1024.0`), which truncates; a number beyond `u64` saturates. A value
    /// that is not a number, empty or negative leaves its field at 0 instead
    /// of discarding the rest.
    ///
    /// `None` when no field carries a number: such a header reports nothing.
    pub fn parse(value: &str) -> Option<Self> {
        let mut info = Self::default();
        let mut reported = false;
        for field in value.split(';') {
            let Some((key, amount)) = field.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let slot = if key.eq_ignore_ascii_case("upload") {
                &mut info.upload
            } else if key.eq_ignore_ascii_case("download") {
                &mut info.download
            } else if key.eq_ignore_ascii_case("total") {
                &mut info.total
            } else if key.eq_ignore_ascii_case("expire") {
                &mut info.expire
            } else {
                continue;
            };
            if let Some(amount) = parse_amount(amount.trim()) {
                *slot = amount;
                reported = true;
            }
        }
        reported.then_some(info)
    }
}

/// Header form, which [`SubscriptionUserinfo::parse`] reads back.
impl fmt::Display for SubscriptionUserinfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "upload={}; download={}; total={}; expire={}",
            self.upload, self.download, self.total, self.expire
        )
    }
}

fn parse_amount(text: &str) -> Option<u64> {
    if let Ok(amount) = text.parse::<u64>() {
        return Some(amount);
    }
    let amount = text.parse::<f64>().ok()?;
    // `as` truncates toward zero and saturates past `u64::MAX`.
    (amount.is_finite() && amount >= 0.0).then_some(amount as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(upload: u64, download: u64, total: u64, expire: u64) -> SubscriptionUserinfo {
        SubscriptionUserinfo {
            upload,
            download,
            total,
            expire,
        }
    }

    #[test]
    fn parses_the_usual_header() {
        assert_eq!(
            SubscriptionUserinfo::parse(
                "upload=1234; download=5678; total=1073741824; expire=1700000000"
            ),
            Some(info(1234, 5678, 1_073_741_824, 1_700_000_000))
        );
    }

    #[test]
    fn missing_keys_read_as_zero() {
        assert_eq!(
            SubscriptionUserinfo::parse("upload=1; download=2; total=3"),
            Some(info(1, 2, 3, 0)),
            "no expire is a plan without an end date"
        );
        assert_eq!(
            SubscriptionUserinfo::parse("total=1073741824"),
            Some(info(0, 0, 1_073_741_824, 0))
        );
    }

    #[test]
    fn tolerates_case_whitespace_order_and_stray_separators() {
        assert_eq!(
            SubscriptionUserinfo::parse(
                "  EXPIRE = 1700000000 ;Total=30;;  Download=\t20 ; upload =10;  "
            ),
            Some(info(10, 20, 30, 1_700_000_000))
        );
        assert_eq!(
            SubscriptionUserinfo::parse("upload=1;download=2;total=3;expire=4"),
            Some(info(1, 2, 3, 4))
        );
    }

    #[test]
    fn decimals_truncate_and_huge_values_saturate() {
        assert_eq!(
            SubscriptionUserinfo::parse("upload=1.9; download=1.5e3; total=2.0E10; expire=+7"),
            Some(info(1, 1500, 20_000_000_000, 7))
        );
        assert_eq!(
            SubscriptionUserinfo::parse("total=18446744073709551615"),
            Some(info(0, 0, u64::MAX, 0)),
            "the full u64 range parses exactly"
        );
        assert_eq!(
            SubscriptionUserinfo::parse("total=99999999999999999999999"),
            Some(info(0, 0, u64::MAX, 0))
        );
    }

    #[test]
    fn unusable_values_leave_their_field_at_zero() {
        assert_eq!(
            SubscriptionUserinfo::parse("upload=-5; download=abc; total=1024; expire=; foo=9; bar"),
            Some(info(0, 0, 1024, 0))
        );
        assert_eq!(
            SubscriptionUserinfo::parse("upload=NaN; download=inf; total=-1.5; expire=12"),
            Some(info(0, 0, 0, 12))
        );
        assert_eq!(
            SubscriptionUserinfo::parse("upload=5; upload=6"),
            Some(info(6, 0, 0, 0)),
            "a repeated key keeps its last value"
        );
    }

    #[test]
    fn a_header_without_a_number_reports_nothing() {
        for header in [
            "",
            "   ",
            "garbage",
            "upload; download",
            "expire=",
            "upload=x; total=-1",
            "plan=pro; reset=1",
            "<html>",
        ] {
            assert_eq!(SubscriptionUserinfo::parse(header), None, "{header:?}");
        }
        assert_eq!(
            SubscriptionUserinfo::parse("upload=0; download=0; total=0; expire=0"),
            Some(SubscriptionUserinfo::default()),
            "explicit zeros are a report"
        );
    }

    #[test]
    fn header_form_reads_back() {
        let usage = info(1, 22, u64::MAX, 1_700_000_000);
        assert_eq!(
            usage.to_string(),
            "upload=1; download=22; total=18446744073709551615; expire=1700000000"
        );
        assert_eq!(SubscriptionUserinfo::parse(&usage.to_string()), Some(usage));
    }
}
