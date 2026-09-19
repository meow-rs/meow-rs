//! Background subscription auto-refresh loop.
//!
//! Extracted from `main.rs` so downstream FFI callers that build a `Tunnel`
//! directly can wire the same auto-refresh behavior in without
//! reimplementing it.

use meow_config::raw::RawConfig;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Poll subscriptions in `raw_config` every 60s; for each subscription whose
/// `interval` has elapsed (or which has never been fetched), download the
/// remote config, replace proxies/groups/rules, rebuild the tunnel, and
/// persist back to `config_path`. Runs forever; spawn as a background task.
///
/// The loop captures the tunnel weakly (issue #514): an embedder that drops
/// every `Tunnel` handle stops this loop instead of leaving it mutating a
/// dead tunnel's route table forever.
pub async fn run_loop(
    raw_config: Arc<RwLock<RawConfig>>,
    tunnel: Tunnel,
    config_path: String,
    dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>>,
    rule_providers: Arc<
        RwLock<std::collections::HashMap<String, Arc<meow_config::rule_provider::RuleProvider>>>,
    >,
) {
    // Same provider-cache directory `load_config` used at startup — trusted
    // rebuilds of the daemon's own config must keep resolving relative
    // rule-provider paths the same way, not hard-fail with `cache_dir: None`
    // (issue #429 follow-up).
    let cache_dir = meow_config::resource_cache_dir_for_config_path(&config_path);
    let weak = tunnel.weak_inner();
    drop(tunnel);
    loop {
        // Pin the tunnel for one pass only — between passes it may be
        // dropped, in which case this loop exits.
        let Some(inner) = weak.upgrade() else {
            info!("tunnel dropped; stopping subscription refresh loop");
            return;
        };
        let tunnel = Tunnel::from_inner(inner);
        let subs_to_refresh: Vec<(String, String)> = {
            let raw = raw_config.read();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            raw.subscriptions
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter(|s| match (s.interval, s.last_updated) {
                    (_, None) => true,
                    (Some(interval), Some(last)) => now - last >= interval as i64,
                    (None, Some(_)) => false,
                })
                .map(|s| (s.name.clone(), s.url.clone()))
                .collect()
        };

        for (name, url) in subs_to_refresh {
            info!("Auto-refreshing subscription '{}'", name);
            match meow_config::subscription::fetch_subscription(&url).await {
                Ok(mut fetched) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    // Pre-resolve any DNS-sourced ECH configs before taking the
                    // mutation lane — preresolve_ech is async network I/O and
                    // must not serialize other config commits.
                    meow_config::ech_dns::preresolve_ech(&mut fetched.proxies).await;

                    // Issue #514: the commit runs inside the same
                    // `CONFIG_MUTATION` lane every API mutation uses, and
                    // builds the candidate on a CLONE — `raw_config` is only
                    // written after the rebuild succeeds. Previously the
                    // fetched payload was written into the live raw config
                    // first, so a failed rebuild left `GET /configs` and the
                    // next cold start carrying a rejected config while the
                    // running routing stayed old.
                    let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
                    let candidate = {
                        let mut c = raw_config.read().clone();

                        if let Some(ref mut subs) = c.subscriptions {
                            if let Some(sub) = subs.iter_mut().find(|s| s.name == name) {
                                sub.last_updated = Some(now);
                            }
                        }

                        c.proxies = Some(fetched.proxies);
                        c.proxy_groups = Some(fetched.proxy_groups);
                        c.rules = Some(fetched.rules);
                        c
                    };

                    let resolver = tunnel.resolver_slot();
                    let rebuild = tokio::task::spawn_blocking({
                        let candidate = candidate.clone();
                        let cache_dir = cache_dir.clone();
                        move || {
                            meow_config::rebuild_from_raw_with_resolver(
                                &candidate,
                                Some(resolver),
                                Some(cache_dir.as_path()),
                                // Commit path: the candidate's provider set
                                // loads fresh and is swapped into the live
                                // registry only once validated (issue #533).
                                None,
                            )
                        }
                    })
                    .await;

                    match rebuild {
                        Ok(Ok(result)) => {
                            let meow_config::RebuildResult {
                                proxies: new_proxies,
                                rules: new_rules,
                                dialer_registry: new_registry,
                                rule_providers: new_rule_providers,
                            } = result;
                            // A swapped proxy set changes the objects a
                            // `#name` nameserver or `rule-set:` policy key
                            // references — reconcile BEFORE the raw write so
                            // the old-vs-candidate comparison still sees the
                            // previous raw (issue #514 review).
                            let dns = meow_api::routes::reconcile_dns_config(
                                &raw_config,
                                &candidate,
                                &config_path,
                                &new_proxies,
                                Some(&new_rule_providers),
                                Some(tunnel.resolver()),
                                Some(&new_registry),
                            )
                            .await;

                            // Install the rebuilt resolver before the route
                            // swap drops the old registry cell — the old
                            // resolver's chained `#name` adapters would fail
                            // closed until `publish_dns` runs (issue #533).
                            if let Ok(Some(dns)) = &dns {
                                tunnel.set_resolver(Arc::clone(&dns.resolver));
                            }
                            tunnel.update_routing(new_proxies, new_rules, new_registry);
                            // Commit point: the candidate's provider set —
                            // already referenced by the rules and DNS
                            // `rule-set:` matchers — becomes the live
                            // registry (issue #533 review).
                            *rule_providers.write() = new_rule_providers;
                            // Commit raw + routing together inside the lane:
                            // the on-disk/dashboard view and the running
                            // router can no longer diverge on failure.
                            *raw_config.write() = candidate.clone();
                            let dns_ok = match dns {
                                Ok(Some(dns)) => {
                                    meow_api::routes::publish_dns(&tunnel, &dns_server, dns).await;
                                    true
                                }
                                Ok(None) => true,
                                Err((_status, msg)) => {
                                    warn!(
                                        "subscription '{name}' committed; dns republish skipped: {msg}"
                                    );
                                    false
                                }
                            };
                            // Health-check tasks follow the new group set
                            // (issue #514).
                            tunnel.reconcile_health_checks(
                                &meow_config::extract_health_check_specs(
                                    candidate.proxy_groups.as_deref().unwrap_or(&[]),
                                ),
                            );
                            info!("Subscription '{}' refreshed successfully", name);
                            // The commit is done — release the mutation
                            // lane before the async disk write so file I/O
                            // does not serialize concurrent config commits
                            // (issue #514 review).
                            drop(_lane);
                            if dns_ok {
                                let _ =
                                    meow_config::save_raw_config_async(&config_path, &candidate)
                                        .await;
                            } else {
                                // The committed dns section failed to
                                // build — persisting it would leave a file
                                // the next cold start cannot parse
                                // (`parse_dns` is a hard error in
                                // build_config). Keep the runtime commit;
                                // skip the save (issue #514 review).
                                warn!(
                                    "subscription '{name}': dns rebuild failed; \
                                     NOT persisting — the file would fail to load \
                                     on next start"
                                );
                            }
                        }
                        Ok(Err(e)) => {
                            error!("Failed to rebuild after refreshing '{}': {}", name, e);
                            // Still stamp `last_updated` on the live raw —
                            // without it the next 60 s pass re-downloads and
                            // re-fails forever instead of honoring
                            // `interval` (issue #514 review).
                            let mut live = raw_config.write();
                            if let Some(sub) = live
                                .subscriptions
                                .as_mut()
                                .and_then(|subs| subs.iter_mut().find(|s| s.name == name))
                            {
                                sub.last_updated = Some(now);
                            }
                        }
                        Err(e) => {
                            error!(
                                "Failed to join rebuild task after refreshing '{}': {}",
                                name, e
                            );
                            // Same stamping as the rebuild-error arm — a
                            // panicking task shouldn't re-download every
                            // 60 s either.
                            let mut live = raw_config.write();
                            if let Some(sub) = live
                                .subscriptions
                                .as_mut()
                                .and_then(|subs| subs.iter_mut().find(|s| s.name == name))
                            {
                                sub.last_updated = Some(now);
                            }
                        }
                    }
                }
                Err(e) => error!("Failed to refresh subscription '{}': {}", name, e),
            }
        }

        drop(tunnel);
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}
