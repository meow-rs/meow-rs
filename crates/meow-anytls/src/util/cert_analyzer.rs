//! Certificate analysis and information extraction

use crate::util::{AnyTlsError, Result};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

/// Certificate information
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Subject (certificate owner)
    pub subject: String,
    /// Issuer (who signed the certificate)
    pub issuer: String,
    /// Serial number
    pub serial_number: String,
    /// Valid from (Not Before)
    pub not_before: SystemTime,
    /// Valid until (Not After)
    pub not_after: SystemTime,
    /// Signature algorithm
    pub signature_algorithm: String,
    /// Public key algorithm
    pub public_key_algorithm: String,
    /// Subject Alternative Names
    pub san_names: Vec<String>,
    /// Whether certificate is self-signed
    pub is_self_signed: bool,
    /// Days until expiration (can be negative if expired)
    pub days_until_expiry: i64,
}

/// Certificate status
#[derive(Debug, Clone, PartialEq)]
pub enum CertStatus {
    /// Certificate is valid
    Valid,
    /// Certificate is expiring soon (days remaining)
    ExpiringWarning(u64),
    /// Certificate has expired
    Expired,
    /// Certificate is invalid (reason)
    Invalid(String),
}

impl CertificateInfo {
    /// Parse certificate from PEM file
    pub fn from_pem_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(&path).map_err(|e| {
            AnyTlsError::Tls(format!(
                "Failed to open certificate file {:?}: {}",
                path.as_ref(),
                e
            ))
        })?;

        let mut pem_data = Vec::new();
        file.read_to_end(&mut pem_data).map_err(|e| {
            AnyTlsError::Tls(format!(
                "Failed to read certificate file {:?}: {}",
                path.as_ref(),
                e
            ))
        })?;

        Self::from_pem_bytes(&pem_data)
    }

    /// Parse certificate from PEM bytes
    pub fn from_pem_bytes(pem_data: &[u8]) -> Result<Self> {
        // Use rustls-pemfile to parse PEM
        let mut reader = BufReader::new(pem_data);
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| AnyTlsError::Tls(format!("Failed to parse PEM certificates: {}", e)))?;

        if certs.is_empty() {
            return Err(AnyTlsError::Tls("No certificates found in PEM data".into()));
        }

        // Parse X.509 certificate from the first certificate
        let (_, cert) = X509Certificate::from_der(certs[0].as_ref())
            .map_err(|e| AnyTlsError::Tls(format!("Failed to parse X.509 certificate: {}", e)))?;

        Self::from_x509(&cert)
    }

    /// Extract information from X.509 certificate
    fn from_x509(cert: &X509Certificate) -> Result<Self> {
        // Extract subject
        let subject = cert.subject().to_string();

        // Extract issuer
        let issuer = cert.issuer().to_string();

        // Extract serial number
        let serial_number = cert
            .serial
            .to_str_radix(16)
            .chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(":");

        // Extract validity period
        let not_before = asn1_time_to_system_time(&cert.validity().not_before)?;
        let not_after = asn1_time_to_system_time(&cert.validity().not_after)?;

        // Calculate days until expiry
        let now = SystemTime::now();
        let days_until_expiry = match not_after.duration_since(now) {
            Ok(duration) => (duration.as_secs() / 86400) as i64,
            Err(_) => {
                // Certificate has expired
                let duration = now.duration_since(not_after).unwrap();
                -((duration.as_secs() / 86400) as i64)
            }
        };

        // Extract signature algorithm
        let signature_algorithm = format!("{:?}", cert.signature_algorithm.algorithm);

        // Extract public key algorithm
        let public_key_algorithm = format!("{:?}", cert.public_key().algorithm.algorithm);

        // Extract SANs (Subject Alternative Names)
        let mut san_names = Vec::new();
        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                match name {
                    GeneralName::DNSName(dns) => {
                        san_names.push(dns.to_string());
                    }
                    GeneralName::IPAddress(ip) => {
                        san_names.push(format!("{:?}", ip));
                    }
                    _ => {}
                }
            }
        }

        // Check if self-signed
        let is_self_signed = cert.subject() == cert.issuer();

        Ok(CertificateInfo {
            subject,
            issuer,
            serial_number,
            not_before,
            not_after,
            signature_algorithm,
            public_key_algorithm,
            san_names,
            is_self_signed,
            days_until_expiry,
        })
    }

    /// Get certificate status
    pub fn status(&self, warning_days: u64) -> CertStatus {
        if self.days_until_expiry < 0 {
            CertStatus::Expired
        } else if (self.days_until_expiry as u64) < warning_days {
            CertStatus::ExpiringWarning(self.days_until_expiry as u64)
        } else {
            CertStatus::Valid
        }
    }

    /// Check if certificate is expired
    pub fn is_expired(&self) -> bool {
        self.days_until_expiry < 0
    }

    /// Check if certificate is expiring soon
    pub fn is_expiring_soon(&self, warning_days: u64) -> bool {
        self.days_until_expiry >= 0 && (self.days_until_expiry as u64) < warning_days
    }

    /// Format certificate info for display
    pub fn display(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("Subject: {}\n", self.subject));
        output.push_str(&format!("Issuer: {}\n", self.issuer));
        output.push_str(&format!("Serial Number: {}\n", self.serial_number));
        output.push_str(&format!(
            "Valid From: {}\n",
            format_system_time(self.not_before)
        ));
        output.push_str(&format!(
            "Valid Until: {}\n",
            format_system_time(self.not_after)
        ));
        output.push_str(&format!("Days Until Expiry: {}\n", self.days_until_expiry));
        output.push_str(&format!(
            "Signature Algorithm: {}\n",
            self.signature_algorithm
        ));
        output.push_str(&format!(
            "Public Key Algorithm: {}\n",
            self.public_key_algorithm
        ));
        output.push_str(&format!("Self-Signed: {}\n", self.is_self_signed));
        if !self.san_names.is_empty() {
            output.push_str(&format!("SANs: {}\n", self.san_names.join(", ")));
        }
        output
    }

    /// Format certificate info as a single-line summary
    pub fn summary(&self) -> String {
        format!(
            "CN={}, Issuer={}, expires in {} days",
            extract_cn(&self.subject).unwrap_or("unknown"),
            extract_cn(&self.issuer).unwrap_or("unknown"),
            self.days_until_expiry
        )
    }
}

/// Convert ASN.1 time to SystemTime
fn asn1_time_to_system_time(asn1_time: &ASN1Time) -> Result<SystemTime> {
    // Convert to Unix timestamp
    let unix_timestamp = asn1_time.timestamp();

    if unix_timestamp < 0 {
        return Err(AnyTlsError::Tls(
            "Invalid timestamp (before UNIX epoch)".into(),
        ));
    }

    Ok(UNIX_EPOCH + Duration::from_secs(unix_timestamp as u64))
}

/// Format SystemTime as human-readable string
fn format_system_time(time: SystemTime) -> String {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let Ok(secs) = i64::try_from(duration.as_secs()) else {
                return "Invalid time".to_string();
            };
            // (meow-rs RUSTSEC-2026-0543) The x509-parser prelude glob-imports
            // that crate's own `time` module, shadowing the external crate in
            // type-namespace path resolution, so `::time` must stay absolute.
            // X.509 years are four digits; cap them explicitly because
            // `time/large-dates` feature unification can widen
            // `OffsetDateTime`'s range. Use the existing invalid-time marker
            // outside the cap rather than displaying the epoch fallback as a
            // false date.
            let Ok(datetime) = ::time::OffsetDateTime::from_unix_timestamp(secs) else {
                return "Invalid time".to_string();
            };
            if datetime.year() > 9999 {
                return "Invalid time".to_string();
            }
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                datetime.year(),
                u8::from(datetime.month()),
                datetime.day(),
                datetime.hour(),
                datetime.minute(),
                datetime.second()
            )
        }
        Err(_) => "Invalid time".to_string(),
    }
}

/// Extract Common Name (CN) from subject/issuer string
fn extract_cn(dn: &str) -> Option<&str> {
    // Simple extraction of CN= field
    for part in dn.split(',') {
        let part = part.trim();
        if let Some(cn) = part.strip_prefix("CN=") {
            return Some(cn);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cn() {
        assert_eq!(extract_cn("CN=example.com, O=Test"), Some("example.com"));
        assert_eq!(
            extract_cn("O=Test, CN=example.com, C=US"),
            Some("example.com")
        );
        assert_eq!(extract_cn("O=Test, C=US"), None);
    }

    #[test]
    fn test_extract_cn_with_spaces() {
        // Leading/trailing spaces in the whole string
        assert_eq!(extract_cn(" CN=example.com "), Some("example.com"));
        // Spaces around commas
        assert_eq!(
            extract_cn("O=Test , CN=example.com , C=US"),
            Some("example.com")
        );
    }

    // (meow-rs RUSTSEC-2026-0543) Boundary coverage for the `time` migration.
    #[test]
    fn test_format_system_time_epoch() {
        assert_eq!(format_system_time(UNIX_EPOCH), "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn test_format_system_time_crosses_midnight() {
        for (secs, expected) in [
            (1_696_118_399, "2023-09-30 23:59:59 UTC"),
            (1_696_118_400, "2023-10-01 00:00:00 UTC"),
        ] {
            assert_eq!(
                format_system_time(UNIX_EPOCH + Duration::from_secs(secs)),
                expected,
                "timestamp {secs}"
            );
        }
    }

    #[test]
    fn test_format_system_time_crosses_year_boundary() {
        for (secs, expected) in [
            (1_672_531_199, "2022-12-31 23:59:59 UTC"),
            (1_672_531_200, "2023-01-01 00:00:00 UTC"),
        ] {
            assert_eq!(
                format_system_time(UNIX_EPOCH + Duration::from_secs(secs)),
                expected,
                "timestamp {secs}"
            );
        }
    }

    #[test]
    fn test_format_system_time_leap_years() {
        assert_eq!(
            format_system_time(UNIX_EPOCH + Duration::from_secs(951_827_696)),
            "2000-02-29 12:34:56 UTC"
        );
        for (secs, expected) in [
            (4_107_542_399, "2100-02-28 23:59:59 UTC"),
            (4_107_542_400, "2100-03-01 00:00:00 UTC"),
        ] {
            assert_eq!(
                format_system_time(UNIX_EPOCH + Duration::from_secs(secs)),
                expected,
                "timestamp {secs}"
            );
        }
    }

    #[test]
    fn test_format_system_time_truncates_subseconds() {
        assert_eq!(
            format_system_time(UNIX_EPOCH + Duration::new(1_696_118_400, 999_999_999)),
            "2023-10-01 00:00:00 UTC"
        );
    }

    #[test]
    fn test_format_system_time_invalid_time() {
        assert_eq!(
            format_system_time(UNIX_EPOCH - Duration::from_secs(1)),
            "Invalid time"
        );
        assert_eq!(
            format_system_time(UNIX_EPOCH + Duration::from_secs(253_402_300_799)),
            "9999-12-31 23:59:59 UTC"
        );
        assert_eq!(
            format_system_time(UNIX_EPOCH + Duration::from_secs(253_402_300_800)),
            "Invalid time"
        );
    }

    #[test]
    fn test_cert_status() {
        let info = CertificateInfo {
            subject: "CN=test".to_string(),
            issuer: "CN=issuer".to_string(),
            serial_number: "123".to_string(),
            not_before: SystemTime::now(),
            not_after: SystemTime::now() + Duration::from_secs(86400 * 90),
            signature_algorithm: "SHA256".to_string(),
            public_key_algorithm: "RSA".to_string(),
            san_names: vec![],
            is_self_signed: false,
            days_until_expiry: 90,
        };

        // Test Valid status
        assert!(matches!(info.status(30), CertStatus::Valid));

        // Test ExpiringWarning status
        let info_expiring = CertificateInfo {
            days_until_expiry: 20,
            ..info.clone()
        };
        assert!(matches!(
            info_expiring.status(30),
            CertStatus::ExpiringWarning(20)
        ));

        // Test Expired status
        let info_expired = CertificateInfo {
            days_until_expiry: -1,
            ..info.clone()
        };
        assert!(matches!(info_expired.status(30), CertStatus::Expired));
    }

    #[test]
    fn test_is_expired() {
        let info_valid = CertificateInfo {
            subject: "CN=test".to_string(),
            issuer: "CN=issuer".to_string(),
            serial_number: "123".to_string(),
            not_before: SystemTime::now(),
            not_after: SystemTime::now() + Duration::from_secs(86400 * 30),
            signature_algorithm: "SHA256".to_string(),
            public_key_algorithm: "RSA".to_string(),
            san_names: vec![],
            is_self_signed: false,
            days_until_expiry: 30,
        };
        assert!(!info_valid.is_expired());

        let info_expired = CertificateInfo {
            days_until_expiry: -10,
            ..info_valid.clone()
        };
        assert!(info_expired.is_expired());
    }

    #[test]
    fn test_is_expiring_soon() {
        let info = CertificateInfo {
            subject: "CN=test".to_string(),
            issuer: "CN=issuer".to_string(),
            serial_number: "123".to_string(),
            not_before: SystemTime::now(),
            not_after: SystemTime::now() + Duration::from_secs(86400 * 20),
            signature_algorithm: "SHA256".to_string(),
            public_key_algorithm: "RSA".to_string(),
            san_names: vec![],
            is_self_signed: false,
            days_until_expiry: 20,
        };

        assert!(info.is_expiring_soon(30));
        assert!(!info.is_expiring_soon(10));
    }

    #[test]
    fn test_cert_summary() {
        let info = CertificateInfo {
            subject: "CN=example.com, O=Test Corp".to_string(),
            issuer: "CN=Test CA, O=Test".to_string(),
            serial_number: "123456".to_string(),
            not_before: SystemTime::now(),
            not_after: SystemTime::now() + Duration::from_secs(86400 * 90),
            signature_algorithm: "SHA256withRSA".to_string(),
            public_key_algorithm: "RSA".to_string(),
            san_names: vec!["example.com".to_string(), "www.example.com".to_string()],
            is_self_signed: false,
            days_until_expiry: 90,
        };

        let summary = info.summary();
        assert!(summary.contains("example.com"));
        assert!(summary.contains("Test CA"));
        assert!(summary.contains("90"));
    }

    #[test]
    fn test_cert_display() {
        let info = CertificateInfo {
            subject: "CN=test.com".to_string(),
            issuer: "CN=CA".to_string(),
            serial_number: "abc123".to_string(),
            not_before: SystemTime::UNIX_EPOCH + Duration::from_secs(1000000),
            not_after: SystemTime::UNIX_EPOCH + Duration::from_secs(2000000),
            signature_algorithm: "SHA256".to_string(),
            public_key_algorithm: "RSA".to_string(),
            san_names: vec!["test.com".to_string()],
            is_self_signed: true,
            days_until_expiry: 100,
        };

        let display = info.display();
        assert!(display.contains("Subject: CN=test.com"));
        assert!(display.contains("Issuer: CN=CA"));
        assert!(display.contains("Serial Number: abc123"));
        assert!(display.contains("Self-Signed: true"));
        assert!(display.contains("SANs: test.com"));
    }
}
