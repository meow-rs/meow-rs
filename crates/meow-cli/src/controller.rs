//! Which controller to talk to, and with what secret.
//!
//! The address comes from `--controller` / `MEOW_CONTROLLER`, else from the
//! `external-controller` of the config given with `--config` / `MEOW_CONFIG`,
//! else from the controller file of the one meow running as this user (see
//! `meow_common::controller_file`), else `127.0.0.1:9090`. The secret comes
//! from `--secret-stdin`, else `MEOW_SECRET`, else the controller file of the
//! meow at that address, else the config's `secret`. There is deliberately
//! no `--secret` flag: a secret on the command line lands in shell history
//! and in every other user's process list.

use std::fmt::Write as _;
use std::io::BufRead;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context as _};
use meow_common::controller_file;

/// The address meow's `external-controller` examples use.
const DEFAULT_CONTROLLER: &str = "127.0.0.1:9090";

#[derive(clap::Args)]
pub struct Target {
    /// Controller address, host:port [default: the config's
    /// external-controller, else the meow running as this user, else
    /// 127.0.0.1:9090]
    #[arg(short = 'c', long, env = "MEOW_CONTROLLER", global = true)]
    pub controller: Option<String>,

    /// meow config file to read external-controller and secret from
    #[arg(short = 'f', long = "config", env = "MEOW_CONFIG", global = true)]
    pub config: Option<PathBuf>,

    /// Read the API secret from the first line of stdin [default:
    /// MEOW_SECRET, else what the running meow published, else the config's
    /// secret]
    #[arg(long, global = true)]
    pub secret_stdin: bool,

    /// Seconds to wait for an answer; log and traffic, for the stream to open
    #[arg(long, default_value_t = 30, global = true, value_name = "SECS")]
    pub timeout: u64,
}

/// A resolved controller: `host:port`, the secret, and the config file
/// `reload` loads by default.
#[derive(Clone)]
pub struct Endpoint {
    pub authority: String,
    pub secret: Option<String>,
    pub config: Option<PathBuf>,
}

/// The two keys meow-cli reads from a meow config.
#[derive(Default)]
struct ConfigKeys {
    controller: Option<String>,
    secret: Option<String>,
}

impl Target {
    pub fn resolve(&self) -> anyhow::Result<Endpoint> {
        let keys = match &self.config {
            Some(path) => Some(read_config(path)?),
            None => None,
        };
        let address = match (&self.controller, &self.config, &keys) {
            (Some(address), _, _) => Some(normalize_address(address)?),
            (None, Some(path), Some(keys)) => {
                let address = keys.controller.as_deref().ok_or_else(|| {
                    anyhow!(
                        "{} sets no external-controller, so that meow serves no API",
                        path.display()
                    )
                })?;
                Some(normalize_address(address)?)
            }
            _ => None,
        };
        let running = controller_file::running();
        let (authority, published) = match address {
            Some(address) => match serving(&address, running) {
                // Dial the address meow bound, which `localhost` only names.
                Some(meow) => (meow.controller.to_string(), Some(meow)),
                None => (address, None),
            },
            None => match <[_; 1]>::try_from(running) {
                Ok([meow]) => (meow.controller.to_string(), Some(meow)),
                Err(running) if running.is_empty() => (DEFAULT_CONTROLLER.to_string(), None),
                Err(running) => bail!(several_running(&running)),
            },
        };
        let secret = if self.secret_stdin {
            Some(read_secret_line(std::io::stdin().lock())?)
        } else {
            std::env::var("MEOW_SECRET")
                .ok()
                .filter(|secret| !secret.is_empty())
                .or_else(|| published.as_ref().and_then(|meow| meow.secret.clone()))
                .or_else(|| keys.and_then(|keys| keys.secret))
        };
        Ok(Endpoint {
            authority,
            secret: secret.filter(|secret| !secret.is_empty()),
            config: self
                .config
                .clone()
                .or_else(|| published.and_then(|meow| meow.config)),
        })
    }
}

/// The running meow that serves `address`, as `normalize_address` gives
/// it: the one that bound exactly that address, or for `localhost:PORT` one
/// on the loopback at that port. Never one on another loopback address: a
/// meow on `127.0.0.1:9090` does not own `[::1]:9090`, and whoever does must
/// not get its secret.
fn serving(address: &str, running: Vec<controller_file::Entry>) -> Option<controller_file::Entry> {
    if let Ok(address) = address.parse::<SocketAddr>() {
        return running.into_iter().find(|meow| meow.controller == address);
    }
    let (host, port) = address.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    if !host.eq_ignore_ascii_case("localhost") {
        return None;
    }
    running
        .into_iter()
        .find(|meow| meow.controller.ip().is_loopback() && meow.controller.port() == port)
}

fn several_running(running: &[controller_file::Entry]) -> String {
    let mut text = format!(
        "{} meows are running; choose one with --controller:",
        running.len()
    );
    for meow in running {
        let config = meow
            .config
            .as_deref()
            .map_or_else(|| "--config-string".into(), Path::to_string_lossy);
        let _ = write!(
            text,
            "\n  {:<21}  pid {:<7}  {config}",
            meow.controller.to_string(),
            meow.pid
        );
    }
    text
}

/// `host:port` to connect to for an `external-controller` value: `:9090`
/// and unspecified addresses (`0.0.0.0`, `::`) mean this host's loopback,
/// as they do for a client on the same machine; an `http://` prefix and a
/// trailing `/` are dropped.
pub fn normalize_address(address: &str) -> anyhow::Result<String> {
    let trimmed = address.trim();
    if let Some(rest) = trimmed.strip_prefix("https://") {
        bail!("meow's controller serves plain HTTP; use {rest}");
    }
    let trimmed = trimmed.strip_prefix("http://").unwrap_or(trimmed);
    let trimmed = trimmed.trim_end_matches('/');
    if let Some(port) = trimmed.strip_prefix(':') {
        let port: u16 = port
            .parse()
            .with_context(|| format!("invalid controller port in '{address}'"))?;
        return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)).to_string());
    }
    if let Ok(mut socket) = trimmed.parse::<SocketAddr>() {
        if socket.ip().is_unspecified() {
            socket.set_ip(match socket.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            });
        }
        return Ok(socket.to_string());
    }
    // A host name: it needs a port, as the controller has no default one.
    match trimmed.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {
            Ok(trimmed.to_string())
        }
        _ => bail!("invalid controller address '{address}': expected host:port"),
    }
}

fn read_config(path: &Path) -> anyhow::Result<ConfigKeys> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    parse_config(&text).with_context(|| format!("cannot parse {}", path.display()))
}

fn parse_config(text: &str) -> anyhow::Result<ConfigKeys> {
    let doc: serde_yaml::Value = serde_yaml::from_str(text)?;
    // A number is a valid YAML secret (`secret: 123456`); read scalars as text.
    let scalar = |key: &str| match doc.get(key)? {
        serde_yaml::Value::String(text) => Some(text.clone()),
        serde_yaml::Value::Number(number) => Some(number.to_string()),
        _ => None,
    };
    Ok(ConfigKeys {
        controller: scalar("external-controller").filter(|address| !address.is_empty()),
        secret: scalar("secret"),
    })
}

fn read_secret_line(mut input: impl BufRead) -> anyhow::Result<String> {
    let mut line = String::new();
    input
        .read_line(&mut line)
        .context("cannot read the secret from stdin")?;
    let secret = line.trim_end_matches(['\r', '\n']);
    if secret.is_empty() {
        bail!("--secret-stdin read an empty line");
    }
    Ok(secret.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_addresses_resolve_for_a_local_client() {
        let cases = [
            (":9090", "127.0.0.1:9090"),
            ("0.0.0.0:9090", "127.0.0.1:9090"),
            ("[::]:9090", "[::1]:9090"),
            ("http://127.0.0.1:9097/", "127.0.0.1:9097"),
            ("192.168.1.2:9090", "192.168.1.2:9090"),
            ("router.lan:9090", "router.lan:9090"),
        ];
        for (input, expected) in cases {
            assert_eq!(normalize_address(input).unwrap(), expected, "{input}");
        }
        for input in ["router.lan", "127.0.0.1", ":http", "https://127.0.0.1:9090"] {
            assert!(normalize_address(input).is_err(), "{input}");
        }
    }

    #[test]
    fn config_keys_read_as_text() {
        let keys = parse_config(
            "mixed-port: 7890\nexternal-controller: ':9090'\nsecret: 123456\nproxies: []\n",
        )
        .unwrap();
        assert_eq!(keys.controller.as_deref(), Some(":9090"));
        assert_eq!(keys.secret.as_deref(), Some("123456"));

        let keys = parse_config("external-controller: ''\n").unwrap();
        assert!(keys.controller.is_none() && keys.secret.is_none());
    }

    #[test]
    fn a_published_secret_goes_only_to_its_own_address() {
        let meow = |pid: u32, controller: &str| controller_file::Entry {
            pid,
            controller: controller.parse().unwrap(),
            secret: Some(format!("secret {pid}")),
            config: None,
        };
        let running = || {
            vec![
                meow(1, "127.0.0.1:9090"),
                meow(2, "[::1]:9091"),
                meow(3, "192.168.1.2:9092"),
            ]
        };
        let cases = [
            ("127.0.0.1:9090", Some(1)),
            ("localhost:9090", Some(1)),
            ("LOCALHOST:9091", Some(2)),
            ("192.168.1.2:9092", Some(3)),
            // Free for any local user to bind.
            ("[::1]:9090", None),
            ("127.0.0.2:9090", None),
            ("127.0.0.1:9091", None),
            ("router.lan:9092", None),
            ("localhost:9092", None),
        ];
        for (address, pid) in cases {
            let found = serving(address, running()).map(|meow| meow.pid);
            assert_eq!(found, pid, "{address}");
        }
    }

    #[test]
    fn the_secret_is_the_first_stdin_line() {
        let secret = read_secret_line("s3cret\r\nignored\n".as_bytes()).unwrap();
        assert_eq!(secret, "s3cret");
        assert!(read_secret_line("\n".as_bytes()).is_err());
    }
}
