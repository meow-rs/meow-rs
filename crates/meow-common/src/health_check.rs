/// Periodic health-check descriptor for one fallback / url-test proxy
/// group. Extracted from `RawProxyGroup` by
/// `meow_config::extract_health_check_specs`; the tunnel's
/// `HealthCheckSupervisor` spawns/retires a probe task per spec
/// (issue #514).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HealthCheckSpec {
    pub group_name: String,
    pub url: String,
    pub interval_secs: u64,
    pub lazy: bool,
}
