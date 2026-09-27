//! Certificate reloader with file watching and hot reload support
//!
//! # Vendored-code note (meow-rs issue #641)
//!
//! The file-watch reload loop below is kept verbatim from upstream but
//! has three known gaps that should not be copied into live code:
//!
//! 1. **Debounce drops the trailing event instead of coalescing it.**
//!    `last_reload` only advances on a *successful* reload, so every
//!    event inside `debounce_ms` after a success — including a second
//!    rotation — is discarded outright; the same holds inside the first
//!    `debounce_ms` after `start_watching` spawns, where `last_reload`
//!    is initialized to `Instant::now()`. (A dropped event after a
//!    *failed* reload does get rescued — the gate stays open — so the
//!    real loss cases are the two above.)
//! 2. **The fixed 100 ms pre-reload sleep** bets on the writer having
//!    finished — fine for atomic-rename writes, racy for
//!    truncate-and-write updaters.
//! 3. **A failed reload keeps the old certificate with no retry** — one
//!    transient failure (file mid-write at read time) leaves the stale
//!    pair active until the next unrelated file event.
//!
//! There are **no callers at all** — `CertReloader` is dead code
//! (meow-rs wires TLS through `meow-transport`, and the module is
//! `server`-gated off by default; even the unit tests only exercise
//! `CertReloaderConfig`), so the gaps are documented rather than
//! diverged — same policy as the `#625` notes elsewhere in this crate.

use crate::util::{AnyTlsError, CertificateInfo, Result, create_server_config_from_files};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// Certificate reloader configuration
#[derive(Debug, Clone)]
pub struct CertReloaderConfig {
    /// Path to certificate file
    pub cert_path: PathBuf,
    /// Path to private key file
    pub key_path: PathBuf,
    /// Enable file watching
    pub watch_enabled: bool,
    /// Debounce time in milliseconds
    pub debounce_ms: u64,
    /// Check certificate expiry
    pub check_expiry: bool,
    /// Warning threshold in days
    pub expiry_warning_days: u64,
}

impl Default for CertReloaderConfig {
    fn default() -> Self {
        Self {
            cert_path: PathBuf::from("cert.pem"),
            key_path: PathBuf::from("key.pem"),
            watch_enabled: true,
            debounce_ms: 500,
            check_expiry: true,
            expiry_warning_days: 30,
        }
    }
}

/// Certificate reloader
pub struct CertReloader {
    config: CertReloaderConfig,
    tls_acceptor: Arc<RwLock<Arc<TlsAcceptor>>>,
    cert_info: Arc<RwLock<Option<CertificateInfo>>>,
    reload_count: Arc<RwLock<u64>>,
    last_reload: Arc<RwLock<Option<Instant>>>,
}

impl CertReloader {
    /// Create a new certificate reloader
    pub fn new(config: CertReloaderConfig) -> Result<Self> {
        // Load initial certificate
        let tls_config = create_server_config_from_files(&config.cert_path, &config.key_path)?;
        let tls_acceptor = Arc::new(TlsAcceptor::from(tls_config));

        // Analyze certificate
        let cert_info = CertificateInfo::from_pem_file(&config.cert_path).ok();

        if let Some(ref info) = cert_info {
            info!(
                "[CertReloader] Initial certificate loaded: {}",
                info.summary()
            );

            // Check expiry
            if config.check_expiry {
                if info.is_expired() {
                    error!("[CertReloader] WARNING: Certificate has expired!");
                } else if info.is_expiring_soon(config.expiry_warning_days) {
                    warn!(
                        "[CertReloader] WARNING: Certificate expiring in {} days",
                        info.days_until_expiry
                    );
                }
            }

            // Display full info
            debug!("[CertReloader] Certificate details:\n{}", info.display());
        }

        Ok(Self {
            config,
            tls_acceptor: Arc::new(RwLock::new(tls_acceptor)),
            cert_info: Arc::new(RwLock::new(cert_info)),
            reload_count: Arc::new(RwLock::new(0)),
            last_reload: Arc::new(RwLock::new(None)),
        })
    }

    /// Get current TLS acceptor (snapshot)
    pub fn get_acceptor(&self) -> Arc<TlsAcceptor> {
        self.tls_acceptor.read().unwrap().clone()
    }

    /// Get TLS acceptor reference for hot-reloading
    pub fn get_acceptor_ref(&self) -> Arc<RwLock<Arc<TlsAcceptor>>> {
        self.tls_acceptor.clone()
    }

    /// Get current certificate info
    pub fn get_cert_info(&self) -> Option<CertificateInfo> {
        self.cert_info.read().unwrap().clone()
    }

    /// Get reload count
    pub fn get_reload_count(&self) -> u64 {
        *self.reload_count.read().unwrap()
    }

    /// Get last reload time
    pub fn get_last_reload(&self) -> Option<Instant> {
        *self.last_reload.read().unwrap()
    }

    /// Reload certificate manually
    pub fn reload(&self) -> Result<()> {
        let start = Instant::now();
        info!("[CertReloader] Reloading certificate...");

        // Load new certificate
        let new_config =
            create_server_config_from_files(&self.config.cert_path, &self.config.key_path)?;
        let new_acceptor = Arc::new(TlsAcceptor::from(new_config));

        // Analyze new certificate
        let new_cert_info = CertificateInfo::from_pem_file(&self.config.cert_path)?;

        // Log changes
        if let Some(ref old_info) = *self.cert_info.read().unwrap() {
            if old_info.serial_number != new_cert_info.serial_number {
                info!(
                    "[CertReloader] Certificate changed: {} -> {}",
                    old_info.summary(),
                    new_cert_info.summary()
                );
            } else {
                debug!("[CertReloader] Certificate reloaded (same serial number)");
            }
        }

        // Check expiry
        if self.config.check_expiry {
            if new_cert_info.is_expired() {
                return Err(AnyTlsError::Tls("New certificate has expired".to_string()));
            } else if new_cert_info.is_expiring_soon(self.config.expiry_warning_days) {
                warn!(
                    "[CertReloader] WARNING: New certificate expiring in {} days",
                    new_cert_info.days_until_expiry
                );
            }
        }

        // Update atomically
        *self.tls_acceptor.write().unwrap() = new_acceptor;
        *self.cert_info.write().unwrap() = Some(new_cert_info.clone());
        *self.reload_count.write().unwrap() += 1;
        *self.last_reload.write().unwrap() = Some(Instant::now());

        let elapsed = start.elapsed();
        info!(
            "[CertReloader] Certificate reload completed in {:?}",
            elapsed
        );
        info!(
            "[CertReloader] New certificate: {}",
            new_cert_info.summary()
        );

        Ok(())
    }

    /// Start watching certificate files for changes
    pub fn start_watching(self: Arc<Self>) -> Result<()> {
        if !self.config.watch_enabled {
            debug!("[CertReloader] File watching is disabled");
            return Ok(());
        }

        info!(
            "[CertReloader] Starting file watcher for: {:?} and {:?}",
            self.config.cert_path, self.config.key_path
        );

        let (tx, mut rx) = mpsc::unbounded_channel();
        let debounce_duration = Duration::from_millis(self.config.debounce_ms);

        // Create watcher
        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res
                    && matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_))
                {
                    let _ = tx.send(event);
                }
            },
            Config::default(),
        )
        .map_err(|e| AnyTlsError::Tls(format!("Failed to create file watcher: {}", e)))?;

        // Watch certificate file
        watcher
            .watch(&self.config.cert_path, RecursiveMode::NonRecursive)
            .map_err(|e| {
                AnyTlsError::Tls(format!(
                    "Failed to watch certificate file {:?}: {}",
                    self.config.cert_path, e
                ))
            })?;

        // Watch key file
        watcher
            .watch(&self.config.key_path, RecursiveMode::NonRecursive)
            .map_err(|e| {
                AnyTlsError::Tls(format!(
                    "Failed to watch key file {:?}: {}",
                    self.config.key_path, e
                ))
            })?;

        // Spawn watcher task
        let reloader = Arc::clone(&self);
        tokio::spawn(async move {
            let _watcher = watcher; // Keep watcher alive

            let mut last_reload = Instant::now();

            while let Some(_event) = rx.recv().await {
                // Debounce: only reload if enough time has passed
                let now = Instant::now();
                if now.duration_since(last_reload) < debounce_duration {
                    debug!("[CertReloader] Debouncing file change event");
                    continue;
                }

                debug!("[CertReloader] File change detected, reloading...");

                // Small delay to ensure file write is complete
                tokio::time::sleep(Duration::from_millis(100)).await;

                match reloader.reload() {
                    Ok(()) => {
                        info!("[CertReloader] Certificate reloaded successfully");
                        last_reload = now;
                    }
                    Err(e) => {
                        error!("[CertReloader] Failed to reload certificate: {}", e);
                        warn!("[CertReloader] Keeping current certificate active");
                    }
                }
            }
        });

        Ok(())
    }

    /// Check certificate expiry periodically
    pub fn start_expiry_checker(self: Arc<Self>, check_interval: Duration) {
        if !self.config.check_expiry {
            return;
        }

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                if let Some(ref info) = *self.cert_info.read().unwrap() {
                    if info.is_expired() {
                        error!(
                            "[CertReloader] CRITICAL: Certificate has expired! {}",
                            info.summary()
                        );
                    } else if info.is_expiring_soon(self.config.expiry_warning_days) {
                        warn!(
                            "[CertReloader] WARNING: Certificate expiring in {} days! {}",
                            info.days_until_expiry,
                            info.summary()
                        );
                    } else {
                        debug!(
                            "[CertReloader] Certificate status: {} days until expiry",
                            info.days_until_expiry
                        );
                    }
                }
            }
        });
    }

    /// Display current certificate information
    pub fn show_cert_info(&self) {
        if let Some(ref info) = *self.cert_info.read().unwrap() {
            println!("\n=== TLS Certificate Information ===\n");
            print!("{}", info.display());
            println!("===================================\n");
        } else {
            println!("No certificate information available");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_reloader_config_default() {
        let config = CertReloaderConfig::default();
        assert!(config.watch_enabled);
        assert_eq!(config.debounce_ms, 500);
        assert!(config.check_expiry);
        assert_eq!(config.expiry_warning_days, 30);
    }

    #[test]
    fn test_cert_reloader_config_custom() {
        let config = CertReloaderConfig {
            cert_path: PathBuf::from("/custom/cert.pem"),
            key_path: PathBuf::from("/custom/key.pem"),
            watch_enabled: false,
            debounce_ms: 1000,
            check_expiry: false,
            expiry_warning_days: 15,
        };

        assert!(!config.watch_enabled);
        assert_eq!(config.debounce_ms, 1000);
        assert!(!config.check_expiry);
        assert_eq!(config.expiry_warning_days, 15);
    }

    // Integration test with actual certificate files would require:
    // 1. Creating valid test certificates
    // 2. Writing them to temp files
    // 3. Testing the reload mechanism
    // This is better suited for integration tests rather than unit tests
}
