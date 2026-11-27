//! Reverse interoperability: pinned xray/mihomo clients in Docker dial this
//! crate's production VLESS Vision listener. The listener runs in-process so
//! the test can assert the listener's raw DIRECT switch counters instead of
//! inferring them from a successful echo.
#![cfg(feature = "listener-vless")]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use meow_common::{Metadata, Network, ProxyAdapter};
use meow_dns::Resolver;
use meow_listener::{
    VlessFallbackLimit, VlessListener, VlessListenerSpec, VlessRealitySpec, VlessSecuritySpec,
    VlessUserSpec,
};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::Socks5Adapter;
use meow_tunnel::Tunnel;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout, Instant};

// Tags are documentation only; Docker resolves these immutable multi-arch
// index digests. The frozen interop report names the mihomo commit, which is
// normative: upstream `git ls-remote` resolves `refs/tags/v1.19.34` to
// 0455d0d28c4526937380505153e65a843d8612e8, while `refs/tags/v1.19.17`
// resolves to a001b1b11008ba469442e5e59b058dd032263470. The v1.19.17 tag
// mentioned in the original evidence request therefore cannot represent the
// frozen commit, so this harness pins the matching v1.19.34 image instead.
const IMAGE_XRAY: &str =
    "ghcr.io/xtls/xray-core@sha256:592ec4d11f656db95598d01e76dbcc6e002d67360b96a5436500a938230f52c7"; // tag 26.3.27
const IMAGE_MIHOMO: &str =
    "metacubex/mihomo@sha256:4c2495d705f152897a58eac410350f243835fd01ce2fe44949a571faa824d532"; // tag v1.19.34
const MIHOMO_TAG_COMMIT: &str = "0455d0d28c4526937380505153e65a843d8612e8";
const CLIENT_SOCKS_PORT: u16 = 1080;
const TARGET_TLS13_TCP: u16 = 10113;
const TARGET_UDP_A: u16 = 10053;
const TARGET_UDP_B: u16 = 10054;
const TARGET_UDP_443: u16 = 443;
const MEOW_TLS_PORT: u16 = 18443;
const MEOW_REALITY_PORT: u16 = 18444;
const T: Duration = Duration::from_secs(20);
static DOCKER_TEST_LANE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const VALID_UUID: &str = "11111111-1111-4111-8111-111111111111";
const WRONG_UUID: &str = "22222222-2222-4222-8222-222222222222";
const USER_UUID: [u8; 16] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];
const REALITY_PRIVATE: [u8; 32] = [0x42; 32];
const SHORT_ID_HEX: &str = "0123abcd";
const SHORT_ID: [u8; 8] = [0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0];

const TLS_INNER_DOMAIN: &str = "tls-inner.test";
const REALITY_INNER_DOMAIN: &str = "reality-inner.test";
const TLS_UDP_DOMAIN: &str = "tls-udp.test";
const REALITY_UDP_DOMAIN: &str = "reality-udp.test";
const WRONG_TCP_DOMAIN: &str = "wrong-tcp.test";
const NOFLOW_TCP_DOMAIN: &str = "noflow-tcp.test";
const TLS12_TLS_DOMAIN: &str = "tls12-tls.test";
const TLS12_REALITY_DOMAIN: &str = "tls12-reality.test";
const PLAIN_TLS_DOMAIN: &str = "plain-tls.test";
const PLAIN_REALITY_DOMAIN: &str = "plain-reality.test";
const FIRST_TLS_DOMAIN: &str = "first-tls.test";
const FIRST_REALITY_DOMAIN: &str = "first-reality.test";
const OUTER_TLS_NAME: &str = "vision.test";
const REALITY_NAME: &str = "cover.test";

fn docker_required() -> bool {
    std::env::var_os("MEOW_REQUIRE_DOCKER").is_some()
        || std::env::var_os("MIHOMO_REQUIRE_INTEGRATION_BINS").is_some()
}

fn skip_or_panic(reason: impl AsRef<str>) {
    let reason = reason.as_ref();
    assert!(!docker_required(), "{reason}");
    eprintln!("skipping vless reverse docker interop test: {reason}");
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .is_ok_and(|out| out.status.success())
}

fn ensure_image(image: &str) -> Result<(), String> {
    let cached = Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if cached {
        return Ok(());
    }
    Command::new("docker")
        .args(["pull", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
        .then_some(())
        .ok_or_else(|| format!("failed to pull docker image {image}"))
}

fn docker_prerequisites() -> Result<(), String> {
    if !docker_available() {
        return Err("docker daemon is not available".into());
    }
    ensure_image(IMAGE_XRAY)?;
    ensure_image(IMAGE_MIHOMO)?;
    image_version_evidence()
}

fn image_version_evidence() -> Result<(), String> {
    let xray = docker_stdout(&[
        "run".into(),
        "--rm".into(),
        "--network".into(),
        "none".into(),
        IMAGE_XRAY.into(),
        "version".into(),
    ])?;
    if !xray.contains("Xray 26.3.27") {
        return Err(format!(
            "pinned xray image reports an unexpected version: {xray}"
        ));
    }
    let mihomo = docker_stdout(&[
        "run".into(),
        "--rm".into(),
        "--network".into(),
        "none".into(),
        IMAGE_MIHOMO.into(),
        "-v".into(),
    ])?;
    if !mihomo.contains("Mihomo Meta v1.19.34") {
        return Err(format!(
            "pinned mihomo image reports an unexpected version: {mihomo}"
        ));
    }
    eprintln!(
        "pin evidence: xray binary {:?}; mihomo binary {:?}; mihomo tag v1.19.34 -> upstream commit {MIHOMO_TAG_COMMIT} (v1.19.17 -> a001b1b11008ba469442e5e59b058dd032263470, so v1.19.34 is the matching image)",
        xray.lines().next().unwrap_or(""),
        mihomo.lines().next().unwrap_or("")
    );
    Ok(())
}

fn docker_stdout(args: &[String]) -> Result<String, String> {
    let out = Command::new("docker")
        .args(args)
        .output()
        .map_err(|e| format!("docker {}: {e}", args.first().map_or("", String::as_str)))?;
    if !out.status.success() {
        return Err(format!(
            "docker {} failed: {}",
            args.first().map_or("", String::as_str),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

static NAMES: AtomicUsize = AtomicUsize::new(0);

fn unique_name(label: &str) -> String {
    format!(
        "meow-vless-interop-{label}-{}-{}",
        std::process::id(),
        NAMES.fetch_add(1, Ordering::Relaxed)
    )
}

struct TestNetwork {
    name: String,
    ipv6: bool,
}

fn create_network(label: &str, internal: bool, masquerade: bool) -> Result<TestNetwork, String> {
    let name = unique_name(label);
    let seq = NAMES.load(Ordering::Relaxed);
    let subnet = format!(
        "fd42:{:x}:{:x}::/64",
        std::process::id() & 0xffff,
        seq & 0xffff
    );
    let mut v6_args = vec!["network".into(), "create".into()];
    if internal {
        v6_args.push("--internal".into());
    } else if !masquerade {
        // Docker Desktop otherwise masquerades cross-bridge traffic, making
        // a client-network-only probe look like a local peer to an internal
        // target network. The real-app client/control network needs no
        // external connectivity; the in-process leg keeps masquerading so
        // clients can reach the host listener.
        v6_args.extend([
            "--opt".into(),
            "com.docker.network.bridge.enable_ip_masquerade=false".into(),
        ]);
    }
    v6_args.extend(["--ipv6".into(), "--subnet".into(), subnet, name.clone()]);
    match docker_stdout(&v6_args) {
        Ok(_) => return Ok(TestNetwork { name, ipv6: true }),
        Err(e) => eprintln!(
            "interop evidence: docker IPv6 network unavailable, using IPv4-only network: {e}"
        ),
    }
    let mut args = vec!["network".into(), "create".into()];
    if internal {
        args.push("--internal".into());
    } else if !masquerade {
        args.extend([
            "--opt".into(),
            "com.docker.network.bridge.enable_ip_masquerade=false".into(),
        ]);
    }
    args.push(name.clone());
    docker_stdout(&args)?;
    Ok(TestNetwork { name, ipv6: false })
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["network", "rm", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn connect_network(network: &TestNetwork, container: &str) -> Result<(), String> {
    docker_stdout(&[
        "network".into(),
        "connect".into(),
        network.name.clone(),
        container.into(),
    ])
    .map(|_| ())
}

fn assert_no_direct_target_path(
    client_network: &TestNetwork,
    probe_image: &str,
    target_ip: &str,
    target_port: u16,
) -> Result<(), String> {
    let out = docker_stdout(&[
        "run".into(),
        "--rm".into(),
        "--network".into(),
        client_network.name.clone(),
        probe_image.into(),
        "--probe-connect".into(),
        target_ip.into(),
        target_port.to_string(),
    ])?;
    if !out.contains("probe-connect-failure") || out.contains("probe-connect-success") {
        return Err(format!(
            "a container attached only to the client network reached the isolated target or the probe itself failed to run: {out}"
        ));
    }
    eprintln!(
        "topology evidence: active bypass probe from a client-network-only container to {target_ip}:{target_port} failed as required ({})",
        out.lines().next().unwrap_or("")
    );
    Ok(())
}

fn container_network_ips(
    container: &str,
    network: &TestNetwork,
) -> Result<(String, Option<String>), String> {
    let text = docker_stdout(&["inspect".into(), container.into()])?;
    let json: Value =
        serde_json::from_str(&text).map_err(|e| format!("docker inspect json: {e}"))?;
    let entry = json
        .get(0)
        .and_then(|v| v.get("NetworkSettings"))
        .and_then(|v| v.get("Networks"))
        .and_then(|v| v.get(&network.name))
        .ok_or_else(|| format!("container {container} is not attached to {}", network.name))?;
    let ipv4 = entry
        .get("IPAddress")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("container {container} has no IPv4 on {}", network.name))?
        .to_string();
    let ipv6 = entry
        .get("GlobalIPv6Address")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Ok((ipv4, ipv6))
}

#[derive(Debug, PartialEq, Eq)]
struct NetworkGateways {
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
}

fn parse_network_gateways(text: &str, network: &str) -> Result<NetworkGateways, String> {
    let json: Value = serde_json::from_str(text)
        .map_err(|e| format!("docker network inspect {network} json: {e}"))?;
    let root = if json.is_array() {
        json.get(0)
    } else {
        Some(&json)
    }
    .ok_or_else(|| format!("docker network inspect {network} returned an empty array"))?;
    let configs = root
        .get("IPAM")
        .and_then(|v| v.get("Config"))
        .and_then(Value::as_array)
        .ok_or_else(|| format!("docker network inspect {network} has no IPAM config"))?;
    let mut ipv4 = None;
    let mut ipv6 = None;
    for entry in configs {
        let Some(gateway) = entry
            .get("Gateway")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let ip = gateway.parse::<IpAddr>().map_err(|e| {
            format!("docker network inspect {network} has invalid gateway {gateway:?}: {e}")
        })?;
        match ip {
            IpAddr::V4(ip) if ipv4.is_none() => ipv4 = Some(ip),
            IpAddr::V6(ip) if ipv6.is_none() => ipv6 = Some(ip),
            _ => {}
        }
    }
    let ipv4 = ipv4.ok_or_else(|| {
        format!("docker network inspect {network} did not report an IPv4 gateway")
    })?;
    Ok(NetworkGateways { ipv4, ipv6 })
}

fn network_gateways(network: &TestNetwork) -> Result<NetworkGateways, String> {
    let text = docker_stdout(&["network".into(), "inspect".into(), network.name.clone()])?;
    parse_network_gateways(&text, &network.name)
}

fn inprocess_host_server(network: &TestNetwork) -> Result<String, String> {
    if cfg!(target_os = "linux") {
        let gateways = network_gateways(network)?;
        let ipv6 = gateways
            .ipv6
            .map_or_else(|| "none".to_string(), |ip| ip.to_string());
        eprintln!(
            "topology evidence: Linux in-process clients dial IPv4 bridge gateway {} on {} (IPv6 gateway: {ipv6}, unused because the harness listener binds 0.0.0.0); host.docker.internal is intentionally unused",
            gateways.ipv4, network.name
        );
        Ok(gateways.ipv4.to_string())
    } else {
        Ok("host.docker.internal".into())
    }
}

#[test]
fn network_gateway_parser_accepts_ipv6_first_ipam_config() {
    let inspect = json!([{
        "IPAM": {
            "Config": [
                { "Subnet": "fd42:aaaa:bbbb::/64", "Gateway": "fd42:aaaa:bbbb::1" },
                { "Subnet": "192.168.147.0/24", "Gateway": "192.168.147.1" },
            ],
        },
    }])
    .to_string();
    let gateways = parse_network_gateways(&inspect, "parser-test").unwrap();
    assert_eq!(gateways.ipv4, Ipv4Addr::new(192, 168, 147, 1));
    assert_eq!(gateways.ipv6, Some("fd42:aaaa:bbbb::1".parse().unwrap()));
}

#[test]
fn network_gateway_parser_requires_an_ipv4_gateway() {
    let inspect = json!([{
        "IPAM": {
            "Config": [
                { "Subnet": "fd42:aaaa:bbbb::/64", "Gateway": "fd42:aaaa:bbbb::1" },
            ],
        },
    }])
    .to_string();
    let err = parse_network_gateways(&inspect, "parser-test").unwrap_err();
    assert!(
        err.contains("did not report an IPv4 gateway"),
        "unexpected error: {err}"
    );
}

struct ManagedContainer {
    name: String,
    label: String,
}

impl ManagedContainer {
    fn logs(&self) -> String {
        let out = Command::new("docker").args(["logs", &self.name]).output();
        match out {
            Ok(out) => format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
            Err(e) => format!("failed to read docker logs: {e}"),
        }
    }

    fn running(&self) -> bool {
        Command::new("docker")
            .args(["inspect", "-f", "{{.State.Running}}", &self.name])
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "true")
    }
}

impl Drop for ManagedContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn run_managed_container(
    label: &str,
    image: &str,
    network: &TestNetwork,
    pre_image: Vec<String>,
    command: Vec<String>,
) -> Result<ManagedContainer, String> {
    let name = unique_name(label);
    let mut args = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        name.clone(),
        "--network".into(),
        network.name.clone(),
    ];
    args.extend(pre_image);
    args.push(image.into());
    args.extend(command);
    docker_stdout(&args)?;
    Ok(ManagedContainer {
        name,
        label: label.into(),
    })
}

struct TestImage {
    tag: String,
}

impl Drop for TestImage {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["image", "rm", "-f", &self.tag])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn cargo_output(args: &[&str]) -> Result<String, String> {
    let out = Command::new("cargo")
        .args(args)
        .current_dir(workspace_root())
        .output()
        .map_err(|e| format!("cargo {}: {e}", args.first().copied().unwrap_or("")))?;
    if !out.status.success() {
        return Err(format!(
            "cargo {} failed:\n{}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn cargo_target_dir() -> Result<PathBuf, String> {
    let text = cargo_output(&["metadata", "--no-deps", "--format-version", "1"])?;
    let json: Value =
        serde_json::from_str(&text).map_err(|e| format!("cargo metadata json: {e}"))?;
    json.get("target_directory")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| "cargo metadata has no target_directory".into())
}

fn docker_linux_arch() -> Result<String, String> {
    let text = docker_stdout(&["info".into(), "--format".into(), "{{.Architecture}}".into()])?;
    Ok(text.trim().to_string())
}

struct LinuxArtifacts {
    meow: PathBuf,
    target: PathBuf,
}

fn build_linux_artifacts() -> Result<LinuxArtifacts, String> {
    let docker_arch = docker_linux_arch()?;
    let host_native = cfg!(target_os = "linux") && std::env::consts::ARCH == docker_arch;
    let target_dir = cargo_target_dir()?;
    if host_native {
        cargo_output(&[
            "build",
            "--locked",
            "-p",
            "meow-app",
            "--no-default-features",
            "--features",
            "listener-vless",
            "--bin",
            "meow",
        ])?;
        cargo_output(&[
            "build",
            "--locked",
            "-p",
            "meow-listener",
            "--features",
            "listener-vless",
            "--example",
            "vless-docker-target",
        ])?;
        Ok(LinuxArtifacts {
            meow: target_dir.join("debug/meow"),
            target: target_dir.join("debug/examples/vless-docker-target"),
        })
    } else {
        let triple = match docker_arch.as_str() {
            "aarch64" => "aarch64-unknown-linux-musl",
            "x86_64" => "x86_64-unknown-linux-musl",
            other => return Err(format!("unsupported docker server architecture {other}")),
        };
        cargo_output(&[
            "zigbuild",
            "--locked",
            "-p",
            "meow-app",
            "--no-default-features",
            "--features",
            "listener-vless",
            "--bin",
            "meow",
            "--target",
            triple,
        ])?;
        cargo_output(&[
            "zigbuild",
            "--locked",
            "-p",
            "meow-listener",
            "--features",
            "listener-vless",
            "--example",
            "vless-docker-target",
            "--target",
            triple,
        ])?;
        Ok(LinuxArtifacts {
            meow: target_dir.join(format!("{triple}/debug/meow")),
            target: target_dir.join(format!("{triple}/debug/examples/vless-docker-target")),
        })
    }
}

fn binary_is_static(path: &Path) -> bool {
    if let Ok(out) = Command::new("file").arg(path).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("statically linked") {
            return true;
        }
    }
    Command::new("ldd").arg(path).output().is_ok_and(|out| {
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        text.contains("not a dynamic executable") || text.contains("statically linked")
    })
}

fn copy_into_rootfs(source: &Path, rootfs: &Path, absolute_dest: &Path) -> Result<(), String> {
    let relative = absolute_dest.strip_prefix("/").unwrap_or(absolute_dest);
    let dest = rootfs.join(relative);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::copy(source, &dest)
        .map_err(|e| format!("copy {} to {}: {e}", source.display(), dest.display()))?;
    Ok(())
}

fn copy_executable_into_rootfs(
    source: &Path,
    rootfs: &Path,
    absolute_dest: &Path,
) -> Result<(), String> {
    let relative = absolute_dest.strip_prefix("/").unwrap_or(absolute_dest);
    let dest = rootfs.join(relative);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let sysroot = Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string());
    let host = Command::new("rustc")
        .arg("-vV")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .find_map(|line| line.strip_prefix("host: ").map(str::to_string))
        });
    let objcopy = sysroot.zip(host).map(|(sysroot, host)| {
        PathBuf::from(sysroot)
            .join("lib/rustlib")
            .join(host)
            .join("bin/llvm-objcopy")
    });
    let stripped = objcopy.is_some_and(|objcopy| {
        objcopy.is_file()
            && Command::new(objcopy)
                .arg("--strip-all")
                .arg(source)
                .arg(&dest)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
    });
    if !stripped {
        std::fs::copy(source, &dest)
            .map_err(|e| format!("copy {} to {}: {e}", source.display(), dest.display()))?;
    }
    Ok(())
}

fn ldd_libraries(binary: &Path) -> Result<Vec<PathBuf>, String> {
    let out = Command::new("ldd")
        .arg(binary)
        .output()
        .map_err(|e| format!("ldd {}: {e}", binary.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut libs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.contains("linux-vdso") {
            continue;
        }
        let path = if let Some((_, resolved)) = line.split_once("=>") {
            resolved.split_whitespace().next()
        } else if line.starts_with('/') {
            line.split_whitespace().next()
        } else {
            None
        };
        if let Some(path) = path.filter(|p| p.starts_with('/')) {
            libs.push(PathBuf::from(path));
        }
    }
    Ok(libs)
}

fn stage_linux_executable(binary: &Path, rootfs: &Path, name: &str) -> Result<(), String> {
    if !binary.is_file() {
        return Err(format!(
            "built linux binary {} does not exist",
            binary.display()
        ));
    }
    copy_executable_into_rootfs(binary, rootfs, Path::new("/").join(name).as_path())?;
    if !binary_is_static(binary) {
        for lib in ldd_libraries(binary)? {
            copy_into_rootfs(&lib.clone(), rootfs, &lib)?;
        }
    }
    Ok(())
}

fn build_test_image(
    label: &str,
    binary: &Path,
    binary_name: &str,
    entrypoint: &[&str],
) -> Result<TestImage, String> {
    let context = TempDir::new().map_err(|e| format!("docker build context: {e}"))?;
    let rootfs = context.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).map_err(|e| format!("mkdir rootfs: {e}"))?;
    stage_linux_executable(binary, &rootfs, binary_name)?;
    let entry = entrypoint
        .iter()
        .map(|part| format!("\"{part}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        context.path().join("Dockerfile"),
        format!("FROM scratch\nCOPY rootfs/ /\nENTRYPOINT [{entry}]\n"),
    )
    .map_err(|e| format!("write Dockerfile: {e}"))?;
    let tag = format!("{}:latest", unique_name(label));
    docker_stdout(&[
        "build".into(),
        "--pull=false".into(),
        "-t".into(),
        tag.clone(),
        context.path().display().to_string(),
    ])?;
    Ok(TestImage { tag })
}

struct ClientContainer {
    name: String,
    kind: ClientKind,
    tcp_port: u16,
    udp_port: u16,
    _dir: TempDir,
}

impl ClientContainer {
    fn logs(&self) -> String {
        let out = Command::new("docker").args(["logs", &self.name]).output();
        match out {
            Ok(out) => format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
            Err(e) => format!("failed to read docker logs: {e}"),
        }
    }

    fn running(&self) -> bool {
        Command::new("docker")
            .args(["inspect", "-f", "{{.State.Running}}", &self.name])
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "true")
    }
}

impl Drop for ClientContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientKind {
    Xray,
    Mihomo,
}

impl ClientKind {
    fn label(self) -> &'static str {
        match self {
            Self::Xray => "xray",
            Self::Mihomo => "mihomo",
        }
    }

    fn image(self) -> &'static str {
        match self {
            Self::Xray => IMAGE_XRAY,
            Self::Mihomo => IMAGE_MIHOMO,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Security {
    Tls,
    Reality,
}

impl Security {
    fn label(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Reality => "reality",
        }
    }

    fn inner_domain(self) -> &'static str {
        match self {
            Self::Tls => TLS_INNER_DOMAIN,
            Self::Reality => REALITY_INNER_DOMAIN,
        }
    }

    fn udp_domain(self) -> &'static str {
        match self {
            Self::Tls => TLS_UDP_DOMAIN,
            Self::Reality => REALITY_UDP_DOMAIN,
        }
    }
}

#[derive(Clone, Copy)]
enum EndCase {
    Tls12,
    Plaintext,
    ServerFirst,
}

impl EndCase {
    fn label(self) -> &'static str {
        match self {
            Self::Tls12 => "tls12-inner",
            Self::Plaintext => "plaintext-inner",
            Self::ServerFirst => "server-first-inner",
        }
    }

    fn domain(self, security: Security) -> &'static str {
        match (self, security) {
            (Self::Tls12, Security::Tls) => TLS12_TLS_DOMAIN,
            (Self::Tls12, Security::Reality) => TLS12_REALITY_DOMAIN,
            (Self::Plaintext, Security::Tls) => PLAIN_TLS_DOMAIN,
            (Self::Plaintext, Security::Reality) => PLAIN_REALITY_DOMAIN,
            (Self::ServerFirst, Security::Tls) => FIRST_TLS_DOMAIN,
            (Self::ServerFirst, Security::Reality) => FIRST_REALITY_DOMAIN,
        }
    }
}

fn parse_published_port(text: &str) -> Result<u16, String> {
    text.lines()
        .next()
        .and_then(|line| line.rsplit(':').next())
        .and_then(|port| port.trim().parse().ok())
        .ok_or_else(|| format!("cannot parse docker port output {text:?}"))
}

fn published_port(name: &str, spec: &str) -> Result<u16, String> {
    let out = Command::new("docker")
        .args(["port", name, spec])
        .output()
        .map_err(|e| format!("docker port {name} {spec}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "docker port {name} {spec} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    parse_published_port(&String::from_utf8_lossy(&out.stdout))
}

struct ClientFixture {
    tls_port: u16,
    reality_port: u16,
    server: String,
    udp_hosts_ip: String,
    outer_ca_pin: String,
    reality_public_key: String,
}

fn xray_vless_outbound(
    tag: &str,
    port: u16,
    uuid: &str,
    flow: Option<&str>,
    security: &str,
    fixture: &ClientFixture,
) -> Value {
    let mut user = json!({ "id": uuid, "encryption": "none" });
    if let Some(flow) = flow {
        user["flow"] = json!(flow);
    }
    let security_settings = if security == "tls" {
        json!({
            "serverName": OUTER_TLS_NAME,
            "fingerprint": "chrome",
            "pinnedPeerCertSha256": fixture.outer_ca_pin,
            "verifyPeerCertByName": OUTER_TLS_NAME,
        })
    } else {
        json!({
            "serverName": REALITY_NAME,
            "fingerprint": "chrome",
            "publicKey": fixture.reality_public_key,
            "shortId": SHORT_ID_HEX,
            "spiderX": "/",
        })
    };
    let settings_key = if security == "tls" {
        "tlsSettings"
    } else {
        "realitySettings"
    };
    json!({
        "protocol": "vless",
        "tag": tag,
        "settings": {
            "vnext": [{
                "address": fixture.server.as_str(),
                "port": port,
                "users": [user],
            }],
        },
        "streamSettings": {
            "network": "raw",
            "security": security,
            settings_key: security_settings,
        },
    })
}

fn xray_config(fixture: &ClientFixture) -> Value {
    let tls_port = fixture.tls_port;
    let reality_port = fixture.reality_port;
    let outbounds = vec![
        xray_vless_outbound(
            "vless-tls",
            tls_port,
            VALID_UUID,
            Some("xtls-rprx-vision"),
            "tls",
            fixture,
        ),
        xray_vless_outbound(
            "vless-reality",
            reality_port,
            VALID_UUID,
            Some("xtls-rprx-vision"),
            "reality",
            fixture,
        ),
        xray_vless_outbound(
            "vless-wrong",
            tls_port,
            WRONG_UUID,
            Some("xtls-rprx-vision"),
            "tls",
            fixture,
        ),
        xray_vless_outbound("vless-noflow", tls_port, VALID_UUID, None, "tls", fixture),
    ];
    json!({
        "log": { "loglevel": "debug" },
        "inbounds": [{
            "listen": "0.0.0.0",
            "port": CLIENT_SOCKS_PORT,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true, "ip": "127.0.0.1" },
            "tag": "socks-in",
        }],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                { "type": "field", "ip": ["::/0"], "outboundTag": "vless-tls" },
                { "type": "field", "domain": ["full:tls-inner.test", "full:tls-udp.test", "full:tls12-tls.test", "full:plain-tls.test", "full:first-tls.test"], "outboundTag": "vless-tls" },
                { "type": "field", "domain": ["full:reality-inner.test", "full:reality-udp.test", "full:tls12-reality.test", "full:plain-reality.test", "full:first-reality.test"], "outboundTag": "vless-reality" },
                { "type": "field", "domain": ["full:wrong-tcp.test"], "outboundTag": "vless-wrong" },
                { "type": "field", "domain": ["full:noflow-tcp.test"], "outboundTag": "vless-noflow" },
            ],
        },
    })
}

fn mihomo_config(fixture: &ClientFixture) -> String {
    let udp_hosts_ip = &fixture.udp_hosts_ip;
    let proxy = |name: &str, port: u16, uuid: &str, flow: &str, reality: bool| {
        let mut out = format!(
            "  - name: {name}\n    type: vless\n    server: {}\n    port: {port}\n    uuid: \"{uuid}\"\n    udp: true\n    tls: true\n    client-fingerprint: chrome\n",
            fixture.server
        );
        if !flow.is_empty() {
            writeln!(out, "    flow: {flow}").unwrap();
        }
        if reality {
            write!(
                out,
                "    servername: {REALITY_NAME}\n    reality-opts:\n      public-key: \"{}\"\n      short-id: \"{SHORT_ID_HEX}\"\n      support-x25519mlkem768: false\n",
                fixture.reality_public_key
            )
            .unwrap();
        } else {
            write!(
                out,
                "    servername: {OUTER_TLS_NAME}\n    fingerprint: \"{}\"\n",
                fixture.outer_ca_pin
            )
            .unwrap();
        }
        out
    };
    format!(
        "log-level: debug\nipv6: false\nmode: rule\nallow-lan: true\nsocks-port: {CLIENT_SOCKS_PORT}\n\nhosts:\n  tls-udp.test: {udp_hosts_ip}\n  reality-udp.test: {udp_hosts_ip}\n\nproxies:\n{}{}{}{}\nrules:\n  - DOMAIN,tls-inner.test,vless-tls\n  - DOMAIN,tls-udp.test,vless-tls\n  - DOMAIN,tls12-tls.test,vless-tls\n  - DOMAIN,plain-tls.test,vless-tls\n  - DOMAIN,first-tls.test,vless-tls\n  - DOMAIN,reality-inner.test,vless-reality\n  - DOMAIN,reality-udp.test,vless-reality\n  - DOMAIN,tls12-reality.test,vless-reality\n  - DOMAIN,plain-reality.test,vless-reality\n  - DOMAIN,first-reality.test,vless-reality\n  - DOMAIN,wrong-tcp.test,vless-wrong\n  - DOMAIN,noflow-tcp.test,vless-noflow\n  - MATCH,vless-tls\n",
        proxy("vless-tls", fixture.tls_port, VALID_UUID, "xtls-rprx-vision", false),
        proxy("vless-reality", fixture.reality_port, VALID_UUID, "xtls-rprx-vision", true),
        proxy("vless-wrong", fixture.tls_port, WRONG_UUID, "xtls-rprx-vision", false),
        proxy("vless-noflow", fixture.tls_port, VALID_UUID, "", false),
    )
}

fn start_client_container(
    kind: ClientKind,
    fixture: &ClientFixture,
    network: Option<&TestNetwork>,
) -> Result<ClientContainer, String> {
    static CONTAINERS: AtomicUsize = AtomicUsize::new(0);
    let dir = TempDir::new().map_err(|e| format!("tempdir: {e}"))?;
    let (config_name, contents, args): (&str, String, Vec<String>) = match kind {
        ClientKind::Xray => (
            "config.json",
            xray_config(fixture).to_string(),
            vec!["run".into(), "-c".into(), "/client-config.json".into()],
        ),
        ClientKind::Mihomo => (
            "config.yaml",
            mihomo_config(fixture),
            vec!["-f".into(), "/client-config.yaml".into()],
        ),
    };
    let host_config = dir.path().join(config_name);
    std::fs::write(&host_config, contents).map_err(|e| format!("write client config: {e}"))?;
    let container_config = match kind {
        ClientKind::Xray => "/client-config.json",
        ClientKind::Mihomo => "/client-config.yaml",
    };
    let name = format!(
        "meow-vless-interop-{}-{}-{}",
        kind.label(),
        std::process::id(),
        CONTAINERS.fetch_add(1, Ordering::Relaxed)
    );
    let tcp_spec = format!("127.0.0.1:0:{CLIENT_SOCKS_PORT}/tcp");
    let udp_spec = format!("127.0.0.1:0:{CLIENT_SOCKS_PORT}/udp");
    let mount = format!("{}:{container_config}:ro", host_config.display());
    let mut docker_args = vec![
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        name.clone(),
    ];
    if let Some(network) = network {
        docker_args.push("--network".to_string());
        docker_args.push(network.name.clone());
    }
    docker_args.extend([
        "-v".to_string(),
        mount,
        "-p".to_string(),
        tcp_spec,
        "-p".to_string(),
        udp_spec,
        kind.image().to_string(),
    ]);
    docker_args.extend(args);
    let out = Command::new("docker")
        .args(&docker_args)
        .output()
        .map_err(|e| format!("docker run {}: {e}", kind.label()))?;
    if !out.status.success() {
        return Err(format!(
            "docker run {} failed: {}",
            kind.label(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let tcp_port = published_port(&name, &format!("{CLIENT_SOCKS_PORT}/tcp"))?;
    let udp_port = published_port(&name, &format!("{CLIENT_SOCKS_PORT}/udp"))?;
    Ok(ClientContainer {
        name,
        kind,
        tcp_port,
        udp_port,
        _dir: dir,
    })
}

async fn wait_client_ready(client: &ClientContainer) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if !client.running() {
            return Err(format!(
                "{} container exited before its SOCKS inbound was ready\n{}",
                client.kind.label(),
                client.logs()
            ));
        }
        let probe = async {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, client.tcp_port)).await?;
            stream.write_all(&[5, 1, 0]).await?;
            let mut answer = [0u8; 2];
            stream.read_exact(&mut answer).await?;
            Ok::<_, std::io::Error>(answer == [5, 0])
        };
        if matches!(timeout(Duration::from_secs(1), probe).await, Ok(Ok(true))) {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "{} SOCKS inbound never became ready\n{}",
        client.kind.label(),
        client.logs()
    ))
}

fn new_test_ca(common_name: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert, key)
}

struct IssuedCert {
    chain_pem: String,
    key_pem: String,
    chain_ders: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
}

fn issue_cert(ca: &rcgen::Certificate, ca_key: &rcgen::KeyPair, names: Vec<String>) -> IssuedCert {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(names)
        .unwrap()
        .signed_by(&key, ca, ca_key)
        .unwrap();
    let chain_pem = format!("{}{}", cert.pem(), ca.pem());
    IssuedCert {
        chain_pem,
        key_pem: key.serialize_pem(),
        chain_ders: vec![cert.der().clone()],
        key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    }
}

async fn start_tls13_echo(
    names: Vec<String>,
) -> (SocketAddr, CertificateDer<'static>, Arc<AtomicUsize>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca, ca_key) = new_test_ca("meow VLESS inner test CA");
    let issued = issue_cert(&ca, &ca_key, names);
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(issued.chain_ders, issued.key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handshakes = Arc::new(AtomicUsize::new(0));
    let task_handshakes = Arc::clone(&handshakes);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let accepted = Arc::clone(&task_handshakes);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                accepted.fetch_add(1, Ordering::Relaxed);
                let (mut rd, mut wr) = tokio::io::split(tls);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    (addr, ca.der().clone(), handshakes)
}

async fn start_tls12_echo(
    names: Vec<String>,
) -> (SocketAddr, CertificateDer<'static>, Arc<AtomicUsize>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca, ca_key) = new_test_ca("meow VLESS TLS1.2 inner test CA");
    let issued = issue_cert(&ca, &ca_key, names);
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_no_client_auth()
        .with_single_cert(issued.chain_ders, issued.key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handshakes = Arc::new(AtomicUsize::new(0));
    let task_handshakes = Arc::clone(&handshakes);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let accepted = Arc::clone(&task_handshakes);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                accepted.fetch_add(1, Ordering::Relaxed);
                let (mut rd, mut wr) = tokio::io::split(tls);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    (addr, ca.der().clone(), handshakes)
}

async fn start_server_first_echo() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut rd, mut wr) = stream.into_split();
                if wr.write_all(b"220 end-matrix ready\r\n").await.is_err() {
                    return;
                }
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    addr
}

async fn start_tls13_http_cover() -> (SocketAddr, CertificateDer<'static>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ca, ca_key) = new_test_ca("meow VLESS cover test CA");
    let issued = issue_cert(&ca, &ca_key, vec![REALITY_NAME.to_string()]);
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(issued.chain_ders, issued.key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") && request.len() < 8192 {
                    let Ok(n) = tls.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                let body = b"meow reality cover transparent response\n";
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    String::from_utf8_lossy(body)
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, ca.der().clone())
}

async fn start_counting_tcp_echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let task_accepts = Arc::clone(&accepts);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            task_accepts.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    (addr, accepts)
}

async fn start_udp_echo() -> (SocketAddr, Arc<AtomicUsize>) {
    start_udp_echo_on(IpAddr::V4(Ipv4Addr::LOCALHOST)).await
}

async fn start_udp_echo_on(ip: IpAddr) -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind((ip, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let datagrams = Arc::new(AtomicUsize::new(0));
    let task_datagrams = Arc::clone(&datagrams);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            task_datagrams.fetch_add(1, Ordering::Relaxed);
            if socket.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });
    (addr, datagrams)
}

fn tunnel_with_hosts(hosts: &[(&str, IpAddr)]) -> Tunnel {
    let mut trie = meow_trie::DomainTrie::new();
    for (name, ip) in hosts {
        trie.insert(name, vec![*ip].into());
    }
    let resolver = Arc::new(Resolver::new(
        vec!["127.0.0.1:9".parse().unwrap()],
        vec![],
        meow_common::DnsMode::Normal,
        trie,
        true,
        true,
    ));
    let tunnel = Tunnel::new(Arc::clone(&resolver));
    let slot = meow_dns::new_resolver_slot(resolver);
    let res = meow_config::rebuild_from_raw_with_resolver(
        &Default::default(),
        Some(&slot),
        None,
        &HashMap::new(),
        None,
        &meow_proxy::SelectionBacking::unpersisted(),
    )
    .unwrap();
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.update_rules(vec![Box::new(meow_rules::final_rule::FinalRule::new(
        "DIRECT",
    ))]);
    tunnel
}

fn tls_spec(certificate: String, private_key: String) -> VlessListenerSpec {
    VlessListenerSpec {
        users: vec![VlessUserSpec {
            username: "alice".into(),
            uuid: USER_UUID,
        }],
        security: VlessSecuritySpec::StandardTls {
            certificate,
            private_key,
            alpn: vec![],
        },
        udp: true,
    }
}

fn reality_spec(dest: &str) -> VlessListenerSpec {
    VlessListenerSpec {
        users: vec![VlessUserSpec {
            username: "alice".into(),
            uuid: USER_UUID,
        }],
        security: VlessSecuritySpec::Reality(VlessRealitySpec {
            dest_host: meow_config::parse_vless_reality_dest(dest).unwrap().0,
            dest_port: meow_config::parse_vless_reality_dest(dest).unwrap().1,
            private_key: REALITY_PRIVATE,
            short_ids: vec![SHORT_ID],
            server_names: vec![REALITY_NAME.into()],
            max_time_difference_us: 120_000_000,
            limit_fallback_upload: VlessFallbackLimit::default(),
            limit_fallback_download: VlessFallbackLimit::default(),
        }),
        udp: true,
    }
}

async fn start_vless_listener(
    spec: VlessListenerSpec,
    tunnel: Tunnel,
    name: &str,
) -> (u16, Arc<VlessListener>) {
    let listener = Arc::new(VlessListener::new(tunnel, name.into(), spec).unwrap());
    let socket = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let task_listener = Arc::clone(&listener);
    tokio::spawn(async move {
        let _ = task_listener.run_on(socket).await;
    });
    (port, listener)
}

fn metadata_domain(domain: &str, port: u16, network: Network) -> Metadata {
    Metadata {
        network,
        host: domain.into(),
        dst_port: port,
        ..Default::default()
    }
}

fn socks_adapter(client: &ClientContainer) -> Socks5Adapter {
    Socks5Adapter::new(
        "docker-client-socks",
        "127.0.0.1",
        client.tcp_port,
        None,
        false,
        false,
        Arc::new(DirectDialer),
    )
}

fn patterned(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i % 251) as u8 ^ seed.wrapping_mul(31))
        .collect()
}

async fn bulk_echo<S>(mut conn: S, payload: &[u8], context: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(&mut conn);
    let write = async {
        wr.write_all(payload).await?;
        wr.flush().await
    };
    let read = async {
        let mut echoed = vec![0u8; payload.len()];
        rd.read_exact(&mut echoed).await.map(|_| echoed)
    };
    let (written, echoed) = timeout(T, async { tokio::join!(write, read) })
        .await
        .unwrap_or_else(|_| panic!("{context}: bulk echo timed out"));
    written.unwrap_or_else(|e| panic!("{context}: bulk write failed: {e}"));
    let echoed = echoed.unwrap_or_else(|e| panic!("{context}: bulk read failed: {e}"));
    assert!(
        echoed == payload,
        "{context}: bulk echo corrupted the payload"
    );
}

async fn positive_tcp(
    client: &ClientContainer,
    security: Security,
    listener: &Arc<VlessListener>,
    echo: SocketAddr,
    echo_ca: &CertificateDer<'static>,
    echo_handshakes: &AtomicUsize,
) {
    let adapter = socks_adapter(client);
    let domain = security.inner_domain();
    let before = listener.vision_raw_switch_counts();
    let outer = timeout(
        T,
        adapter.dial_tcp(&metadata_domain(domain, echo.port(), Network::Tcp)),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{} {}: SOCKS dial timeout\n{}",
            client.kind.label(),
            security.label(),
            client.logs()
        )
    })
    .unwrap_or_else(|e| {
        panic!(
            "{} {}: SOCKS dial failed: {e}\n{}",
            client.kind.label(),
            security.label(),
            client.logs()
        )
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(echo_ca.clone()).unwrap();
    let inner_cfg =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(inner_cfg));
    let server_name = ServerName::try_from(domain).unwrap();
    let inner = timeout(T, connector.connect(server_name, outer))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{} {}: inner TLS timeout\n{}",
                client.kind.label(),
                security.label(),
                client.logs()
            )
        })
        .unwrap_or_else(|e| {
            panic!(
                "{} {}: inner TLS failed: {e}\n{}",
                client.kind.label(),
                security.label(),
                client.logs()
            )
        });
    assert_eq!(
        inner.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );

    // xray only enters its Vision DIRECT write mode on a complete TLS record
    // at the start of a SOCKS read batch. Wait until the inner server has
    // accepted the handshake — that proves the client's CCS/Finished flight
    // has already been consumed — then make the first application write a
    // small, isolated record before the bulk transfer.
    let accepted_before = echo_handshakes.load(Ordering::Relaxed);
    let accept_deadline = Instant::now() + Duration::from_secs(5);
    while echo_handshakes.load(Ordering::Relaxed) == accepted_before {
        if Instant::now() >= accept_deadline {
            panic!(
                "{} {}: inner TLS server never completed the handshake",
                client.kind.label(),
                security.label()
            );
        }
        sleep(Duration::from_millis(10)).await;
    }
    let mut inner = inner;
    let prime = *b"prime";
    timeout(T, inner.write_all(&prime))
        .await
        .expect("prime write timeout")
        .expect("prime write");
    timeout(T, inner.flush())
        .await
        .expect("prime flush timeout")
        .expect("prime flush");
    let mut prime_echo = [0u8; 5];
    timeout(T, inner.read_exact(&mut prime_echo))
        .await
        .expect("prime echo timeout")
        .expect("prime echo");
    assert_eq!(prime_echo, prime, "prime echo corrupted");

    let payload = patterned(
        (1 << 20) + 777,
        if security == Security::Tls { 7 } else { 8 },
    );
    let size = payload.len() + prime.len();
    let context = format!("{} {}", client.kind.label(), security.label());
    bulk_echo(inner, &payload, &context).await;

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let now = listener.vision_raw_switch_counts();
        if now.0 > before.0 && now.1 > before.1 {
            assert_eq!(
                (now.0 - before.0, now.1 - before.1),
                (1, 1),
                "{} {}: exactly one Vision TCP connection must switch each direction raw",
                client.kind.label(),
                security.label()
            );
            eprintln!(
                "interop evidence: {} {} tcp echo {size} B each way; vision raw switches +{} read/+{} write",
                client.kind.label(),
                security.label(),
                now.0 - before.0,
                now.1 - before.1
            );
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "{} {}: DIRECT switch counters stayed at {now:?} from {before:?}\n{}",
                client.kind.label(),
                security.label(),
                client.logs()
            );
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn framed_end_case(
    client: &ClientContainer,
    security: Security,
    listener: &Arc<VlessListener>,
    case: EndCase,
    target_port: u16,
    tls12_ca: &CertificateDer<'static>,
) {
    let adapter = socks_adapter(client);
    let domain = case.domain(security);
    let before = listener.vision_raw_switch_counts();
    let outer = timeout(
        T,
        adapter.dial_tcp(&metadata_domain(domain, target_port, Network::Tcp)),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{} {} {}: SOCKS dial timeout\n{}",
            client.kind.label(),
            security.label(),
            case.label(),
            client.logs()
        )
    })
    .unwrap_or_else(|e| {
        panic!(
            "{} {} {}: SOCKS dial failed: {e}\n{}",
            client.kind.label(),
            security.label(),
            case.label(),
            client.logs()
        )
    });
    let payload = patterned(513, 42);

    match case {
        EndCase::Tls12 => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(tls12_ca.clone()).unwrap();
            let cfg =
                rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
                    .with_root_certificates(roots)
                    .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
            let mut inner = timeout(
                T,
                connector.connect(ServerName::try_from(domain).unwrap(), outer),
            )
            .await
            .expect("TLS1.2 inner handshake timeout")
            .expect("TLS1.2 inner handshake");
            assert_eq!(
                inner.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_2)
            );
            timeout(T, inner.write_all(&payload))
                .await
                .expect("TLS1.2 write timeout")
                .expect("TLS1.2 write");
            timeout(T, inner.flush())
                .await
                .expect("TLS1.2 flush timeout")
                .expect("TLS1.2 flush");
            let mut echoed = vec![0u8; payload.len()];
            timeout(T, inner.read_exact(&mut echoed))
                .await
                .expect("TLS1.2 echo timeout")
                .expect("TLS1.2 echo");
            assert_eq!(echoed, payload);
        }
        EndCase::Plaintext => {
            let mut inner = outer;
            timeout(T, inner.write_all(&payload))
                .await
                .expect("plaintext write timeout")
                .expect("plaintext write");
            timeout(T, inner.flush())
                .await
                .expect("plaintext flush timeout")
                .expect("plaintext flush");
            let mut echoed = vec![0u8; payload.len()];
            timeout(T, inner.read_exact(&mut echoed))
                .await
                .expect("plaintext echo timeout")
                .expect("plaintext echo");
            assert_eq!(echoed, payload);
        }
        EndCase::ServerFirst => {
            let mut inner = outer;
            let mut greeting = vec![0u8; b"220 end-matrix ready\r\n".len()];
            timeout(T, inner.read_exact(&mut greeting))
                .await
                .expect("server-first greeting timeout")
                .expect("server-first greeting");
            assert_eq!(greeting.as_slice(), b"220 end-matrix ready\r\n");
            timeout(T, inner.write_all(&payload))
                .await
                .expect("server-first write timeout")
                .expect("server-first write");
            timeout(T, inner.flush())
                .await
                .expect("server-first flush timeout")
                .expect("server-first flush");
            let mut echoed = vec![0u8; payload.len()];
            timeout(T, inner.read_exact(&mut echoed))
                .await
                .expect("server-first echo timeout")
                .expect("server-first echo");
            assert_eq!(echoed, payload);
        }
    }

    sleep(Duration::from_millis(350)).await;
    let after = listener.vision_raw_switch_counts();
    assert_eq!(
        after, before,
        "{} {} {}: non-TLS1.3/server-first inner must stay framed END; DIRECT counters moved {:?} -> {:?}",
        client.kind.label(),
        security.label(),
        case.label(),
        before,
        after
    );
    eprintln!(
        "interop evidence: {} {} {} echoed {} B while framed END; DIRECT counters unchanged at {:?}",
        client.kind.label(),
        security.label(),
        case.label(),
        payload.len(),
        before
    );
}

#[derive(Debug)]
enum SocksUdpAddr {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

#[derive(Debug)]
struct SocksUdpSource {
    addr: SocksUdpAddr,
    port: u16,
}

struct SocksUdpAssociation {
    _control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

impl SocksUdpAssociation {
    async fn connect(client: &ClientContainer) -> std::io::Result<Self> {
        let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, client.tcp_port)).await?;
        control.write_all(&[5, 1, 0]).await?;
        let mut answer = [0u8; 2];
        control.read_exact(&mut answer).await?;
        if answer != [5, 0] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "SOCKS no-auth refused",
            ));
        }
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut head = [0u8; 4];
        control.read_exact(&mut head).await?;
        if head[1] != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("UDP ASSOCIATE reply {}", head[1]),
            ));
        }
        read_socks_addr_tcp(&mut control, head[3]).await?;
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let relay = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client.udp_port);
        Ok(Self {
            _control: control,
            socket,
            relay,
        })
    }

    async fn send_domain(&self, domain: &str, port: u16, payload: &[u8]) -> std::io::Result<()> {
        assert!(domain.len() <= 255);
        let mut packet = Vec::with_capacity(domain.len() + payload.len() + 7);
        packet.extend_from_slice(&[0, 0, 0, 3, domain.len() as u8]);
        packet.extend_from_slice(domain.as_bytes());
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(payload);
        self.socket.send_to(&packet, self.relay).await?;
        Ok(())
    }

    async fn send_ipv6(&self, ip: Ipv6Addr, port: u16, payload: &[u8]) -> std::io::Result<()> {
        let mut packet = Vec::with_capacity(payload.len() + 23);
        packet.extend_from_slice(&[0, 0, 0, 4]);
        packet.extend_from_slice(&ip.octets());
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(payload);
        self.socket.send_to(&packet, self.relay).await?;
        Ok(())
    }

    async fn recv(&self) -> std::io::Result<(Vec<u8>, SocksUdpSource)> {
        let mut buf = vec![0u8; 65536];
        let (n, _) = self.socket.recv_from(&mut buf).await?;
        parse_socks_udp_datagram(&buf[..n]).map_err(std::io::Error::other)
    }
}

async fn read_socks_addr_tcp(stream: &mut TcpStream, atyp: u8) -> std::io::Result<()> {
    let len = match atyp {
        1 => 4,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        4 => 16,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad SOCKS atyp",
            ))
        }
    };
    let mut discard = vec![0u8; len + 2];
    stream.read_exact(&mut discard).await.map(|_| ())
}

fn parse_socks_udp_datagram(packet: &[u8]) -> Result<(Vec<u8>, SocksUdpSource), String> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return Err("malformed SOCKS UDP header or nonzero fragment".into());
    }
    let atyp = packet[3];
    let (addr, used) = match atyp {
        1 => {
            if packet.len() < 4 + 4 + 2 {
                return Err("truncated IPv4 SOCKS UDP address".into());
            }
            (
                SocksUdpAddr::Ipv4(Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7])),
                4 + 4 + 2,
            )
        }
        3 => {
            let len = usize::from(*packet.get(4).ok_or("missing domain length")?);
            let end = 5 + len;
            if packet.len() < end + 2 {
                return Err("truncated domain SOCKS UDP address".into());
            }
            let domain = std::str::from_utf8(&packet[5..end])
                .map_err(|_| "non-UTF8 domain in SOCKS UDP reply")?
                .to_string();
            (SocksUdpAddr::Domain(domain), end + 2)
        }
        4 => {
            if packet.len() < 4 + 16 + 2 {
                return Err("truncated IPv6 SOCKS UDP address".into());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[4..20]);
            (SocksUdpAddr::Ipv6(Ipv6Addr::from(octets)), 4 + 16 + 2)
        }
        other => return Err(format!("unsupported SOCKS UDP atyp {other}")),
    };
    let port = u16::from_be_bytes([packet[used - 2], packet[used - 1]]);
    if packet.len() <= used {
        return Err("SOCKS UDP datagram carries no payload".into());
    }
    Ok((packet[used..].to_vec(), SocksUdpSource { addr, port }))
}

async fn positive_udp(
    client: &ClientContainer,
    security: Security,
    listener: &Arc<VlessListener>,
    echo_a: SocketAddr,
    echo_b: SocketAddr,
    echo_v6: SocketAddr,
) {
    let raw_before = listener.vision_raw_switch_counts();
    let association = timeout(T, SocksUdpAssociation::connect(client))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{} {}: UDP associate timeout\n{}",
                client.kind.label(),
                security.label(),
                client.logs()
            )
        })
        .unwrap_or_else(|e| {
            panic!(
                "{} {}: UDP associate failed: {e}\n{}",
                client.kind.label(),
                security.label(),
                client.logs()
            )
        });
    let domain = security.udp_domain();
    let mut expected = Vec::new();
    for index in 0..6 {
        let port = if index % 2 == 0 {
            echo_a.port()
        } else {
            echo_b.port()
        };
        let payload = patterned(21 + index * 137, 21 + index as u8);
        timeout(T, association.send_domain(domain, port, &payload))
            .await
            .expect("UDP send timeout")
            .expect("UDP send");
        expected.push((payload, port));
    }
    let mut replies = HashMap::new();
    for _ in 0..expected.len() {
        let (payload, source) = timeout(T, association.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} {}: UDP echo timeout\n{}",
                    client.kind.label(),
                    security.label(),
                    client.logs()
                )
            })
            .expect("UDP receive");
        replies.insert(payload, source);
    }
    for (payload, port) in &expected {
        let source = replies.get(payload).unwrap_or_else(|| {
            panic!(
                "{} {}: missing UDP echo of {} B",
                client.kind.label(),
                security.label(),
                payload.len()
            )
        });
        assert_eq!(
            source.port,
            *port,
            "{} {}: UDP reply source port must follow the per-packet target",
            client.kind.label(),
            security.label()
        );
        match client.kind {
            ClientKind::Xray => assert!(
                matches!(&source.addr, SocksUdpAddr::Domain(name) if name == domain),
                "{} {}: xray must report the domain reply source, got {:?}",
                client.kind.label(),
                security.label(),
                source.addr
            ),
            ClientKind::Mihomo => assert!(
                matches!(&source.addr, SocksUdpAddr::Ipv4(ip) if *ip == Ipv4Addr::LOCALHOST),
                "{} {}: mihomo resolves UDP before VLESS and must report the echo IP, got {:?}",
                client.kind.label(),
                security.label(),
                source.addr
            ),
        }
    }

    let ipv6_evidence = if security == Security::Tls {
        let payload = patterned(197, 166);
        timeout(
            T,
            association.send_ipv6(Ipv6Addr::LOCALHOST, echo_v6.port(), &payload),
        )
        .await
        .expect("IPv6 UDP send timeout")
        .expect("IPv6 UDP send");
        let (echo, source) = timeout(T, association.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} tls: IPv6 UDP echo timeout\n{}",
                    client.kind.label(),
                    client.logs()
                )
            })
            .expect("IPv6 UDP receive");
        assert_eq!(echo, payload, "IPv6 UDP echo corrupted");
        assert_eq!(source.port, echo_v6.port());
        assert!(
            matches!(source.addr, SocksUdpAddr::Ipv6(ip) if ip == Ipv6Addr::LOCALHOST),
            "{} tls: IPv6 UDP reply source must stay the IPv6 target, got {:?}",
            client.kind.label(),
            source.addr
        );
        format!("; ipv6 [::1]:{} echoed byte-exact", echo_v6.port())
    } else {
        "; ipv6 pinned-client coverage is on the TLS outer leg only (target family is independent of the outer security)".to_string()
    };

    sleep(Duration::from_millis(250)).await;
    assert_eq!(
        listener.vision_raw_switch_counts(),
        raw_before,
        "{} {}: XUDP must never switch the Vision TCP stream raw",
        client.kind.label(),
        security.label()
    );
    eprintln!(
        "interop evidence: {} {} xudp interleaved per-packet targets {}/{} datagrams {:?} B{}; DIRECT counters unchanged at {:?}",
        client.kind.label(),
        security.label(),
        echo_a.port(),
        echo_b.port(),
        expected.iter().map(|(payload, _)| payload.len()).collect::<Vec<_>>(),
        ipv6_evidence,
        raw_before
    );
}

async fn negative_tcp(
    client: &ClientContainer,
    domain: &'static str,
    echo: SocketAddr,
    accepts: &AtomicUsize,
    label: &str,
) {
    let before = accepts.load(Ordering::Relaxed);
    let adapter = socks_adapter(client);
    let outcome = timeout(
        T,
        adapter.dial_tcp(&metadata_domain(domain, echo.port(), Network::Tcp)),
    )
    .await;
    if let Ok(Ok(mut conn)) = outcome {
        let _ = timeout(T, conn.write_all(b"must never echo")).await;
        let _ = timeout(T, conn.flush()).await;
        let mut byte = [0u8; 1];
        match timeout(Duration::from_secs(5), conn.read(&mut byte)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!(
                "{} {label}: rejected flow produced {n} application bytes\n{}",
                client.kind.label(),
                client.logs()
            ),
            Err(_) => panic!(
                "{} {label}: rejected flow did not close\n{}",
                client.kind.label(),
                client.logs()
            ),
        }
    }
    sleep(Duration::from_millis(250)).await;
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        before,
        "{} {label}: rejected VLESS request must not dial the target",
        client.kind.label()
    );
    eprintln!(
        "interop evidence: {} {label} rejected silently, no target dial",
        client.kind.label()
    );
}

fn indented(text: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    text.lines().map(|line| format!("{pad}{line}\n")).collect()
}

fn real_app_config(target_ip: &str, outer: &IssuedCert) -> String {
    let reality_private = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(REALITY_PRIVATE);
    let cert = indented(&outer.chain_pem, 8);
    let key = indented(&outer.key_pem, 8);
    let mut hosts = String::new();
    for domain in [
        TLS_INNER_DOMAIN,
        REALITY_INNER_DOMAIN,
        TLS_UDP_DOMAIN,
        REALITY_UDP_DOMAIN,
        TLS12_TLS_DOMAIN,
        TLS12_REALITY_DOMAIN,
        PLAIN_TLS_DOMAIN,
        PLAIN_REALITY_DOMAIN,
        FIRST_TLS_DOMAIN,
        FIRST_REALITY_DOMAIN,
    ] {
        writeln!(hosts, "  {domain}: \"{target_ip}\"").unwrap();
    }
    format!(
        "log-level: debug\nmode: rule\nipv6: true\nallow-lan: true\n\nhosts:\n{hosts}\nlisteners:\n  - name: tls-in\n    type: vless\n    listen: 0.0.0.0\n    port: {MEOW_TLS_PORT}\n    certificate: |\n{cert}    private-key: |\n{key}    udp: true\n    users:\n      - username: alice\n        uuid: \"{VALID_UUID}\"\n        flow: xtls-rprx-vision\n  - name: reality-in\n    type: vless\n    listen: 0.0.0.0\n    port: {MEOW_REALITY_PORT}\n    reality-config:\n      dest: \"{target_ip}:{TARGET_TLS13_TCP}\"\n      private-key: \"{reality_private}\"\n      short-id: [\"{SHORT_ID_HEX}\"]\n      server-names: [\"{REALITY_NAME}\"]\n      max-time-difference: 120000000\n    udp: true\n    users:\n      - username: alice\n        uuid: \"{VALID_UUID}\"\n        flow: xtls-rprx-vision\n\nrules:\n  - MATCH,DIRECT\n"
    )
}

async fn wait_container_log(container: &ManagedContainer, needle: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if !container.running() {
            return Err(format!(
                "{} container exited\n{}",
                container.label,
                container.logs()
            ));
        }
        if container.logs().contains(needle) {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "{} never logged {needle:?}\n{}",
        container.label,
        container.logs()
    ))
}

async fn real_app_positive_tcp(
    client: &ClientContainer,
    security: Security,
    target_ca: &CertificateDer<'static>,
) {
    let adapter = socks_adapter(client);
    let domain = security.inner_domain();
    let outer = timeout(
        T,
        adapter.dial_tcp(&metadata_domain(domain, TARGET_TLS13_TCP, Network::Tcp)),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{} {} real-app: SOCKS dial timeout\n{}",
            client.kind.label(),
            security.label(),
            client.logs()
        )
    })
    .unwrap_or_else(|e| {
        panic!(
            "{} {} real-app: SOCKS dial failed: {e}\n{}",
            client.kind.label(),
            security.label(),
            client.logs()
        )
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(target_ca.clone()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let inner = timeout(
        T,
        connector.connect(ServerName::try_from(domain).unwrap(), outer),
    )
    .await
    .expect("real-app inner TLS timeout")
    .expect("real-app inner TLS handshake");
    assert_eq!(
        inner.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    let payload = patterned((1 << 18) + 771, 91);
    let context = format!("{} {} real-app", client.kind.label(), security.label());
    bulk_echo(inner, &payload, &context).await;
    eprintln!(
        "interop evidence: {} {} real-app TLS1.3 echo {} B end-to-end through containerized meow",
        client.kind.label(),
        security.label(),
        payload.len()
    );
}

async fn real_app_xudp_matrix(
    client: &ClientContainer,
    security: Security,
    target_v6: Option<Ipv6Addr>,
) {
    let association = timeout(T, SocksUdpAssociation::connect(client))
        .await
        .expect("real-app UDP associate timeout")
        .expect("real-app UDP associate");
    let domain = security.udp_domain();
    let mut expected = Vec::new();
    for index in 0..6 {
        let port = if index % 2 == 0 {
            TARGET_UDP_A
        } else {
            TARGET_UDP_B
        };
        let payload = patterned(64 + index * 173, 120 + index as u8);
        timeout(T, association.send_domain(domain, port, &payload))
            .await
            .expect("real-app XUDP send timeout")
            .expect("real-app XUDP send");
        expected.push((payload, port));
    }
    let udp443_payload = patterned(311, 143);
    timeout(
        T,
        association.send_domain(domain, TARGET_UDP_443, &udp443_payload),
    )
    .await
    .expect("real-app UDP/443 send timeout")
    .expect("real-app UDP/443 send");
    expected.push((udp443_payload, TARGET_UDP_443));

    let mut replies = HashMap::new();
    for _ in 0..expected.len() {
        let (payload, source) = timeout(T, association.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} {} real-app: XUDP echo timeout\n{}",
                    client.kind.label(),
                    security.label(),
                    client.logs()
                )
            })
            .expect("real-app XUDP receive");
        replies.insert(payload, source);
    }
    for (payload, port) in &expected {
        let source = replies.get(payload).unwrap_or_else(|| {
            panic!(
                "{} {} real-app: missing XUDP echo for target port {port}",
                client.kind.label(),
                security.label()
            )
        });
        assert_eq!(
            source.port,
            *port,
            "{} {} real-app: XUDP reply source port must follow the per-packet target",
            client.kind.label(),
            security.label()
        );
    }
    eprintln!(
        "interop evidence: {} {} real-app XUDP interleaved per-packet targets {TARGET_UDP_A}/{TARGET_UDP_B} plus UDP/443 echo; all {} replies source-matched",
        client.kind.label(),
        security.label(),
        expected.len()
    );

    if security == Security::Tls {
        if let Some(ip) = target_v6 {
            let payload = patterned(197, 166);
            timeout(T, association.send_ipv6(ip, TARGET_UDP_A, &payload))
                .await
                .expect("real-app IPv6 XUDP send timeout")
                .expect("real-app IPv6 XUDP send");
            let (echo, source) = timeout(T, association.recv())
                .await
                .expect("real-app IPv6 XUDP echo timeout")
                .expect("real-app IPv6 XUDP receive");
            assert_eq!(echo, payload, "IPv6 XUDP echo corrupted");
            assert_eq!(source.port, TARGET_UDP_A);
            eprintln!(
                "interop evidence: {} tls real-app XUDP IPv6 target [{ip}]:{TARGET_UDP_A} echoed byte-exact",
                client.kind.label()
            );
        } else {
            eprintln!(
                "interop evidence: {} tls real-app XUDP IPv6 target not drivable because this Docker daemon gave the target network no global IPv6 address; the in-process vless_listener_integration IPv6 case is the substitute",
                client.kind.label()
            );
        }
    }
}

async fn reality_cover_https(reality_port: u16, cover_ca: &CertificateDer<'static>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cover_ca.clone()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let raw = TcpStream::connect((Ipv4Addr::LOCALHOST, reality_port))
        .await
        .unwrap();
    let mut tls = timeout(
        T,
        connector.connect(ServerName::try_from(REALITY_NAME).unwrap(), raw),
    )
    .await
    .expect("cover TLS handshake timeout")
    .expect("cover TLS handshake");
    let request =
        format!("GET /interop HTTP/1.1\r\nHost: {REALITY_NAME}\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
    let mut response = Vec::new();
    timeout(T, tls.read_to_end(&mut response))
        .await
        .expect("cover response timeout")
        .expect("cover response read");
    let text = String::from_utf8(response).unwrap();
    assert!(
        text.starts_with("HTTP/1.1 200 OK\r\n"),
        "cover response head: {text:?}"
    );
    assert!(
        text.ends_with("meow reality cover transparent response\n"),
        "cover response body: {text:?}"
    );
    eprintln!("interop evidence: ordinary TLS client relayed to REALITY cover with byte-exact HTTPS-ish response");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_vless_vision_interop_matrix() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
    if let Err(reason) = docker_prerequisites() {
        skip_or_panic(reason);
        return;
    }
    let _lane = DOCKER_TEST_LANE.lock().await;

    let (inner_echo, inner_ca, inner_handshakes) = start_tls13_echo(vec![
        TLS_INNER_DOMAIN.to_string(),
        REALITY_INNER_DOMAIN.to_string(),
    ])
    .await;
    let (tls12_echo, tls12_ca, _tls12_handshakes) = start_tls12_echo(vec![
        TLS12_TLS_DOMAIN.to_string(),
        TLS12_REALITY_DOMAIN.to_string(),
    ])
    .await;
    let server_first_echo = start_server_first_echo().await;
    let (udp_echo_a, _udp_a_datagrams) = start_udp_echo().await;
    let (udp_echo_b, _udp_b_datagrams) = start_udp_echo().await;
    let (udp_echo_v6, _udp_v6_datagrams) = start_udp_echo_on(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let (negative_echo, negative_accepts) = start_counting_tcp_echo().await;
    let (cover, cover_ca) = start_tls13_http_cover().await;

    let tunnel = tunnel_with_hosts(&[
        (TLS_INNER_DOMAIN, inner_echo.ip()),
        (REALITY_INNER_DOMAIN, inner_echo.ip()),
        (TLS12_TLS_DOMAIN, tls12_echo.ip()),
        (TLS12_REALITY_DOMAIN, tls12_echo.ip()),
        (PLAIN_TLS_DOMAIN, negative_echo.ip()),
        (PLAIN_REALITY_DOMAIN, negative_echo.ip()),
        (FIRST_TLS_DOMAIN, server_first_echo.ip()),
        (FIRST_REALITY_DOMAIN, server_first_echo.ip()),
        (TLS_UDP_DOMAIN, udp_echo_a.ip()),
        (REALITY_UDP_DOMAIN, udp_echo_a.ip()),
        (WRONG_TCP_DOMAIN, negative_echo.ip()),
        (NOFLOW_TCP_DOMAIN, negative_echo.ip()),
    ]);

    let (outer_ca, outer_ca_key) = new_test_ca("meow VLESS outer test CA");
    let outer = issue_cert(&outer_ca, &outer_ca_key, vec![OUTER_TLS_NAME.to_string()]);
    let outer_ca_pin = hex::encode(Sha256::digest(outer_ca.der().as_ref()));
    let (tls_port, tls_listener) = start_vless_listener(
        tls_spec(outer.chain_pem, outer.key_pem),
        tunnel.clone(),
        "interop-vless-tls",
    )
    .await;
    let (reality_port, reality_listener) = start_vless_listener(
        reality_spec(&format!("{}:{}", cover.ip(), cover.port())),
        tunnel,
        "interop-vless-reality",
    )
    .await;

    let client_network = create_network("clients", false, true)
        .unwrap_or_else(|e| panic!("create isolated client network: {e}"));
    let host_server = inprocess_host_server(&client_network)
        .unwrap_or_else(|e| panic!("inspect in-process host listener address: {e}"));

    let reality_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(REALITY_PRIVATE));
    let fixture = ClientFixture {
        tls_port,
        reality_port,
        server: host_server,
        udp_hosts_ip: "127.0.0.1".into(),
        outer_ca_pin,
        reality_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(reality_public.as_bytes()),
    };

    let xray = start_client_container(ClientKind::Xray, &fixture, Some(&client_network))
        .unwrap_or_else(|e| panic!("xray client setup failed: {e}"));
    wait_client_ready(&xray)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let mihomo = start_client_container(ClientKind::Mihomo, &fixture, Some(&client_network))
        .unwrap_or_else(|e| panic!("mihomo client setup failed: {e}"));
    wait_client_ready(&mihomo)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    for client in [&xray, &mihomo] {
        for (security, listener) in [
            (Security::Tls, &tls_listener),
            (Security::Reality, &reality_listener),
        ] {
            positive_tcp(
                client,
                security,
                listener,
                inner_echo,
                &inner_ca,
                &inner_handshakes,
            )
            .await;
            positive_udp(
                client,
                security,
                listener,
                udp_echo_a,
                udp_echo_b,
                udp_echo_v6,
            )
            .await;
            for case in [EndCase::Tls12, EndCase::Plaintext, EndCase::ServerFirst] {
                let target_port = match case {
                    EndCase::Tls12 => tls12_echo.port(),
                    EndCase::Plaintext => negative_echo.port(),
                    EndCase::ServerFirst => server_first_echo.port(),
                };
                framed_end_case(client, security, listener, case, target_port, &tls12_ca).await;
            }
        }
        negative_tcp(
            client,
            WRONG_TCP_DOMAIN,
            negative_echo,
            &negative_accepts,
            "wrong-uuid",
        )
        .await;
        negative_tcp(
            client,
            NOFLOW_TCP_DOMAIN,
            negative_echo,
            &negative_accepts,
            "missing-flow",
        )
        .await;
    }

    reality_cover_https(reality_port, &cover_ca).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_vless_vision_real_app_isolated_matrix() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
    if let Err(reason) = docker_prerequisites() {
        skip_or_panic(reason);
        return;
    }
    let _lane = DOCKER_TEST_LANE.lock().await;
    eprintln!(
        "pin evidence: xray image index sha256:592ec4d11f656db95598d01e76dbcc6e002d67360b96a5436500a938230f52c7 (tag 26.3.27); mihomo image index sha256:4c2495d705f152897a58eac410350f243835fd01ce2fe44949a571faa824d532 (tag v1.19.34); upstream refs/tags/v1.19.34 is commit {MIHOMO_TAG_COMMIT}"
    );
    eprintln!(
        "topology evidence: the target network is --internal and only the target plus meow attach to it; clients have no target-network attachment, so SOCKS traffic must cross containerized meow. Docker unpublishes loopback-published ports on --internal networks, so the client/control network is a dedicated non-internal network; that is the documented control-plane deviation, not a client→target data path"
    );

    let artifacts =
        build_linux_artifacts().unwrap_or_else(|e| panic!("linux artifact build failed: {e}"));
    let target_image = build_test_image(
        "target-image",
        &artifacts.target,
        "vless-docker-target",
        &["/vless-docker-target"],
    )
    .unwrap_or_else(|e| panic!("target image build failed: {e}"));
    let app_image = build_test_image(
        "app-image",
        &artifacts.meow,
        "meow",
        &["/meow", "-f", "/etc/meow/config.yaml"],
    )
    .unwrap_or_else(|e| panic!("meow image build failed: {e}"));

    let client_network = create_network("real-clients", false, false)
        .unwrap_or_else(|e| panic!("create real client network: {e}"));
    let target_network = create_network("real-targets", true, true)
        .unwrap_or_else(|e| panic!("create isolated target network: {e}"));

    let (target_ca, target_ca_key) = new_test_ca("meow VLESS docker target CA");
    let target_cert = issue_cert(
        &target_ca,
        &target_ca_key,
        vec![
            TLS_INNER_DOMAIN.to_string(),
            REALITY_INNER_DOMAIN.to_string(),
        ],
    );
    let cert_dir = TempDir::new().expect("target cert tempdir");
    std::fs::write(cert_dir.path().join("chain.pem"), &target_cert.chain_pem).unwrap();
    std::fs::write(cert_dir.path().join("key.pem"), &target_cert.key_pem).unwrap();
    let target = run_managed_container(
        "target",
        &target_image.tag,
        &target_network,
        vec![
            "-v".into(),
            format!("{}:/certs:ro", cert_dir.path().display()),
        ],
        vec![
            "--cert".into(),
            "/certs/chain.pem".into(),
            "--key".into(),
            "/certs/key.pem".into(),
        ],
    )
    .unwrap_or_else(|e| panic!("start target container: {e}"));
    wait_container_log(&target, "target ready")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let (target_ip, target_ipv6) = container_network_ips(&target.name, &target_network)
        .unwrap_or_else(|e| panic!("inspect target network addresses: {e}"));
    let target_ipv6 = target_ipv6.and_then(|text| text.parse::<Ipv6Addr>().ok());

    let (outer_ca, outer_ca_key) = new_test_ca("meow VLESS real-app outer CA");
    let outer = issue_cert(&outer_ca, &outer_ca_key, vec![OUTER_TLS_NAME.to_string()]);
    let outer_ca_pin = hex::encode(Sha256::digest(outer_ca.der().as_ref()));
    let config_dir = TempDir::new().expect("meow config tempdir");
    std::fs::write(
        config_dir.path().join("config.yaml"),
        real_app_config(&target_ip, &outer),
    )
    .unwrap();
    let app = run_managed_container(
        "real-meow",
        &app_image.tag,
        &client_network,
        vec![
            "-v".into(),
            format!("{}:/etc/meow:ro", config_dir.path().display()),
        ],
        vec![],
    )
    .unwrap_or_else(|e| panic!("start real meow container: {e}"));
    connect_network(&target_network, &app.name)
        .unwrap_or_else(|e| panic!("attach meow to target network: {e}"));
    wait_container_log(&app, "VLESS listener 'tls-in'")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let (app_client_ip, _) = container_network_ips(&app.name, &client_network)
        .unwrap_or_else(|e| panic!("inspect meow client-network address: {e}"));
    container_network_ips(&app.name, &target_network)
        .unwrap_or_else(|e| panic!("meow must also attach to the target network: {e}"));
    assert!(
        container_network_ips(&target.name, &client_network).is_err(),
        "target container must not be attached to the client network"
    );
    assert_no_direct_target_path(
        &client_network,
        &target_image.tag,
        &target_ip,
        TARGET_TLS13_TCP,
    )
    .unwrap_or_else(|e| panic!("client-network bypass probe failed: {e}"));
    eprintln!(
        "topology evidence: clients connect only to meow at {app_client_ip}; meow is the sole container attached to both networks; target {target_ip} is absent from the client network (asserted; target-network ipv6={})",
        target_network.ipv6
    );

    let reality_public =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(REALITY_PRIVATE));
    let fixture = ClientFixture {
        tls_port: MEOW_TLS_PORT,
        reality_port: MEOW_REALITY_PORT,
        server: app_client_ip,
        udp_hosts_ip: target_ip.clone(),
        outer_ca_pin,
        reality_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(reality_public.as_bytes()),
    };
    let xray = start_client_container(ClientKind::Xray, &fixture, Some(&client_network))
        .unwrap_or_else(|e| panic!("xray real-app client setup failed: {e}"));
    wait_client_ready(&xray)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let mihomo = start_client_container(ClientKind::Mihomo, &fixture, Some(&client_network))
        .unwrap_or_else(|e| panic!("mihomo real-app client setup failed: {e}"));
    wait_client_ready(&mihomo)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    for client in [&xray, &mihomo] {
        for security in [Security::Tls, Security::Reality] {
            real_app_positive_tcp(client, security, &target_ca.der().clone()).await;
            real_app_xudp_matrix(client, security, target_ipv6).await;
        }
    }
}
