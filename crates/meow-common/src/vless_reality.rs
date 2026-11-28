//! Shared REALITY v2 mirror configuration contract.
//!
//! `meow-config` owns YAML parsing while `meow-listener` owns runtime
//! enforcement; both use this one type and validation implementation so
//! the raw document and the typed runtime cannot drift apart.

use serde::{Deserialize, Serialize};

use crate::MeowError;

pub const MIMIC_DEFAULT_PROBE_TIMEOUT_MS: u64 = 3_000;
pub const MIMIC_PROBE_TIMEOUT_MS_RANGE: std::ops::RangeInclusive<u64> = 500..=15_000;
pub const MIMIC_DEFAULT_QUIESCENCE_MIN_MS: u64 = 15;
pub const MIMIC_QUIESCENCE_MIN_MS_RANGE: std::ops::RangeInclusive<u64> = 5..=200;
pub const MIMIC_DEFAULT_QUIESCENCE_MAX_MS: u64 = 40;
pub const MIMIC_QUIESCENCE_MAX_MS_RANGE: std::ops::RangeInclusive<u64> = 10..=500;
pub const MIMIC_DEFAULT_MAX_CONCURRENT_PROBES: usize = 64;
pub const MIMIC_MAX_CONCURRENT_PROBES_RANGE: std::ops::RangeInclusive<usize> = 1..=256;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VlessRealityMimicMode {
    #[default]
    DialFirst,
    Off,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct VlessRealityMimicSpec {
    pub mode: VlessRealityMimicMode,
    pub probe_timeout_ms: u64,
    pub quiescence_min_ms: u64,
    pub quiescence_max_ms: u64,
    pub max_concurrent_probes: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
struct VlessRealityMimicSpecWire {
    mode: VlessRealityMimicMode,
    probe_timeout_ms: u64,
    quiescence_min_ms: u64,
    quiescence_max_ms: u64,
    max_concurrent_probes: usize,
}

impl Default for VlessRealityMimicSpecWire {
    fn default() -> Self {
        let spec = VlessRealityMimicSpec::default();
        Self {
            mode: spec.mode,
            probe_timeout_ms: spec.probe_timeout_ms,
            quiescence_min_ms: spec.quiescence_min_ms,
            quiescence_max_ms: spec.quiescence_max_ms,
            max_concurrent_probes: spec.max_concurrent_probes,
        }
    }
}

impl<'de> Deserialize<'de> for VlessRealityMimicSpec {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = VlessRealityMimicSpecWire::deserialize(deserializer)?;
        let spec = Self {
            mode: wire.mode,
            probe_timeout_ms: wire.probe_timeout_ms,
            quiescence_min_ms: wire.quiescence_min_ms,
            quiescence_max_ms: wire.quiescence_max_ms,
            max_concurrent_probes: wire.max_concurrent_probes,
        };
        spec.validate().map_err(serde::de::Error::custom)?;
        Ok(spec)
    }
}

impl Default for VlessRealityMimicSpec {
    fn default() -> Self {
        Self {
            mode: VlessRealityMimicMode::DialFirst,
            probe_timeout_ms: MIMIC_DEFAULT_PROBE_TIMEOUT_MS,
            quiescence_min_ms: MIMIC_DEFAULT_QUIESCENCE_MIN_MS,
            quiescence_max_ms: MIMIC_DEFAULT_QUIESCENCE_MAX_MS,
            max_concurrent_probes: MIMIC_DEFAULT_MAX_CONCURRENT_PROBES,
        }
    }
}

impl VlessRealityMimicSpec {
    pub fn off() -> Self {
        Self {
            mode: VlessRealityMimicMode::Off,
            ..Self::default()
        }
    }

    pub fn probe_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.probe_timeout_ms)
    }

    pub fn validate(&self) -> Result<(), MeowError> {
        let invalid = |message: &str| MeowError::Config(format!("vless REALITY mimic: {message}"));
        if !MIMIC_PROBE_TIMEOUT_MS_RANGE.contains(&self.probe_timeout_ms) {
            return Err(invalid("probe-timeout-ms outside [500,15000]"));
        }
        if !MIMIC_QUIESCENCE_MIN_MS_RANGE.contains(&self.quiescence_min_ms) {
            return Err(invalid("quiescence-min-ms outside [5,200]"));
        }
        if !MIMIC_QUIESCENCE_MAX_MS_RANGE.contains(&self.quiescence_max_ms) {
            return Err(invalid("quiescence-max-ms outside [10,500]"));
        }
        if self.quiescence_min_ms > self.quiescence_max_ms
            || self.quiescence_max_ms >= self.probe_timeout_ms
        {
            return Err(invalid(
                "requires quiescence-min <= quiescence-max < probe-timeout",
            ));
        }
        if !MIMIC_MAX_CONCURRENT_PROBES_RANGE.contains(&self.max_concurrent_probes) {
            return Err(invalid("max-concurrent-probes outside [1,256]"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_v2_contract() {
        let spec = VlessRealityMimicSpec::default();
        assert_eq!(spec.mode, VlessRealityMimicMode::DialFirst);
        assert_eq!(spec.probe_timeout_ms, 3_000);
        assert_eq!(spec.quiescence_min_ms, 15);
        assert_eq!(spec.quiescence_max_ms, 40);
        assert_eq!(spec.max_concurrent_probes, 64);
        spec.validate().unwrap();
    }

    #[test]
    fn serde_defaults_unknown_keys_and_validation_are_enforced() {
        let empty: VlessRealityMimicSpec = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, VlessRealityMimicSpec::default());

        let partial: VlessRealityMimicSpec =
            serde_json::from_str(r#"{"probe-timeout-ms":4000}"#).unwrap();
        assert_eq!(partial.probe_timeout_ms, 4_000);
        assert_eq!(partial.mode, VlessRealityMimicMode::DialFirst);

        for (json, hint) in [
            (r#"{"unknown":1}"#, "unknown"),
            (r#"{"probe-timeout-ms":499}"#, "probe-timeout-ms"),
            (
                r#"{"probe-timeout-ms":500,"quiescence-max-ms":500}"#,
                "quiescence-min <= quiescence-max < probe-timeout",
            ),
        ] {
            let err = serde_json::from_str::<VlessRealityMimicSpec>(json)
                .unwrap_err()
                .to_string();
            assert!(err.contains(hint), "expected {hint:?} in {err:?}");
        }
    }

    #[test]
    fn boundary_values_validate_and_cross_field_order_is_strict() {
        for spec in [
            VlessRealityMimicSpec {
                probe_timeout_ms: 500,
                quiescence_min_ms: 5,
                quiescence_max_ms: 10,
                ..VlessRealityMimicSpec::default()
            },
            VlessRealityMimicSpec {
                probe_timeout_ms: 15_000,
                quiescence_min_ms: 200,
                quiescence_max_ms: 500,
                max_concurrent_probes: 256,
                ..VlessRealityMimicSpec::default()
            },
        ] {
            spec.validate().unwrap();
        }

        let inverted = VlessRealityMimicSpec {
            quiescence_min_ms: 41,
            ..VlessRealityMimicSpec::default()
        };
        assert!(inverted.validate().is_err());
        let touching = VlessRealityMimicSpec {
            probe_timeout_ms: 500,
            quiescence_max_ms: 500,
            ..VlessRealityMimicSpec::default()
        };
        assert!(touching.validate().is_err());
    }
}
