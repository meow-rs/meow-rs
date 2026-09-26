//! Background subscription auto-refresh loop.
//!
//! Extracted from `main.rs` so downstream FFI callers that build a `Tunnel`
//! directly can wire the same auto-refresh behavior in without
//! reimplementing it.

use meow_config::proxy_provider::ProxyProvider;
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
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is a shared handle wired at startup; grouping \
              them would only rename the same list"
)]
pub async fn run_loop(
    raw_config: Arc<RwLock<RawConfig>>,
    tunnel: Tunnel,
    config_path: String,
    dns_server: Arc<RwLock<Option<meow_api::routes::DnsServerHandle>>>,
    rule_providers: Arc<
        RwLock<std::collections::HashMap<String, Arc<meow_config::rule_provider::RuleProvider>>>,
    >,
    // The live proxy-provider registry — `materialize_proxy_providers`
    // reuses its entries for still-declared names so committed groups
    // keep the live provider's slot, health state, and fetched content
    // instead of rebinding a freshly loaded (initially empty) provider.
    proxy_providers: Arc<dashmap::DashMap<String, Arc<ProxyProvider>>>,
    // The live provider-dialer cell (`Config::provider_dialer_registry`) —
    // providers a commit materializes for newly declared defs share the
    // registry the tunnel republishes (issue #489).
    provider_dialer_registry: meow_proxy::dialer::ProxyRegistry,
    // Shared supervisor — reconciled after each committed registry swap so
    // provider additions/removals/interval changes gain/lose their refresh
    // task without a restart (issue #543).
    rule_provider_refresh: Arc<meow_config::rule_provider_refresh::RefreshSupervisor>,
    // Shared supervisor for the proxy-provider `interval` tasks —
    // `commit_proxy_providers` reconciles it against the committed
    // declarations after each registry swap (issue #625).
    proxy_provider_refresh: Arc<
        meow_config::proxy_provider_refresh::ProxyProviderRefreshSupervisor,
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
        let subs_to_refresh: Vec<(String, String, Option<String>)> = {
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
                .map(|s| (s.name.clone(), s.url.clone(), s.proxy.clone()))
                .collect()
        };

        for (name, url, proxy_name) in subs_to_refresh {
            info!("Auto-refreshing subscription '{}'", name);
            // `strict` is a property of the daemon's live config, not the
            // fetched subscription payload — it gates both payload shape
            // errors in the parser and ECH pre-resolution below.
            let strict = raw_config.read().strict.unwrap_or(false);
            // `proxy:` resolves against the route map published into the
            // provider dialer registry — a name a rebuild removed stays
            // unresolvable until the next pass (treated like a transport
            // failure: `last_updated` is not stamped, so the retry honors
            // the loop cadence, issue #625).
            let download_proxy = match meow_config::internal_http::resolve_download_proxy(
                &provider_dialer_registry,
                proxy_name.as_deref(),
            ) {
                Ok(p) => p,
                Err(e) => {
                    warn!("subscription '{name}': {e:#}");
                    continue;
                }
            };
            match meow_config::subscription::fetch_subscription(
                &url,
                strict,
                download_proxy.as_ref(),
            )
            .await
            {
                Ok(mut fetched) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    // Pre-resolve any DNS-sourced ECH configs before taking the
                    // mutation lane — preresolve_ech is async network I/O and
                    // must not serialize other config commits.
                    if let Err(e) =
                        meow_config::ech_dns::preresolve_ech(&mut fetched.proxies, strict).await
                    {
                        warn!(
                            "subscription '{}': ECH pre-resolution failed (strict mode): {}; \
                             skipping refresh",
                            name, e
                        );
                        // Same stamping as the rebuild-error arms below —
                        // a statically-defective payload shouldn't
                        // re-download every 60 s either (issue #533 review).
                        // In-lane so a sibling commit's clone→write can't
                        // silently drop the stamp.
                        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
                        let mut live = raw_config.write();
                        if let Some(sub) = live
                            .subscriptions
                            .as_mut()
                            .and_then(|subs| subs.iter_mut().find(|s| s.name == name))
                        {
                            sub.last_updated = Some(now);
                        }
                        continue;
                    }

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

                        // A `DELETE /api/subscriptions/{name}` landing while
                        // the fetch was in flight removes the entry under
                        // this lane — re-verify inside it so the fetched
                        // payload cannot resurrect a deleted subscription
                        // (same guard the manual refresh endpoint runs,
                        // issue #543 review).
                        // A same-name re-add or rewrite with a different
                        // URL is likewise stale — the fetched payload came
                        // from the old source (issue #543 review).
                        let Some(sub) = c.subscriptions.as_mut().and_then(|subs| {
                            subs.iter_mut().find(|s| s.name == name && s.url == url)
                        }) else {
                            info!(
                                "subscription '{name}' removed or changed while its \
                                 refresh was in flight; discarding fetched payload"
                            );
                            continue;
                        };
                        sub.last_updated = Some(now);

                        c.proxies = Some(fetched.proxies);
                        c.proxy_groups = Some(fetched.proxy_groups);
                        c.rules = Some(fetched.rules);
                        c
                    };

                    let resolver = tunnel.resolver_slot();
                    // Rebuild against the live provider slots and the global
                    // selector store — the empty-providers variant would
                    // strand `use:`/`include-all` group members (and the
                    // dialer chains provider nodes declare, issue #489) on
                    // every subscription commit.
                    let rebuild = tokio::task::spawn_blocking({
                        let candidate = candidate.clone();
                        let cache_dir = cache_dir.clone();
                        let provider_dialer_registry = provider_dialer_registry.clone();
                        // Snapshot inside the mutation lane so the rebuild
                        // resolves `use:` against the committed provider set.
                        let proxy_providers: std::collections::HashMap<_, _> = proxy_providers
                            .iter()
                            .map(|e| (e.key().clone(), Arc::clone(e.value())))
                            .collect();
                        move || {
                            // The runtime variant wires
                            // `SelectorStore::global()` so a `select` group
                            // in the fetched config keeps the user's
                            // persisted choice — the plain resolver variant
                            // would reset every selector to its first
                            // member on each refresh (issue #543). The
                            // candidate's provider set still loads fresh
                            // and is swapped into the live registry only
                            // once validated (issue #533).
                            meow_config::rebuild_from_raw_runtime(
                                &candidate,
                                Some(&resolver),
                                &proxy_providers,
                                Some(cache_dir.as_path()),
                                &provider_dialer_registry,
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
                                proxy_providers: new_proxy_providers,
                                prefetched_payloads: new_prefetched_payloads,
                            } = result;
                            // Same guard as `apply_raw_to_tunnel`: a group
                            // warn-dropped under lenient parsing must not
                            // commit silently — rules still reference it
                            // and would dead-route (issue #543 review).
                            if let Some(missing) = candidate
                                .proxy_groups
                                .as_deref()
                                .unwrap_or_default()
                                .iter()
                                .map(|group| group.name.clone())
                                .find(|name| !new_proxies.contains_key(name.as_str()))
                            {
                                warn!(
                                    "subscription '{name}': proxy group '{missing}' \
                                     failed validation; NOT committing"
                                );
                                let mut live = raw_config.write();
                                if let Some(sub) = live
                                    .subscriptions
                                    .as_mut()
                                    .and_then(|subs| subs.iter_mut().find(|s| s.name == name))
                                {
                                    sub.last_updated = Some(now);
                                }
                                continue;
                            }
                            // A swapped proxy set changes the objects a
                            // `#name` nameserver or `rule-set:` policy key
                            // references — reconcile BEFORE the raw write so
                            // the old-vs-candidate comparison still sees the
                            // previous raw (issue #514 review).
                            let dns = match meow_api::routes::reconcile_dns_config(
                                &raw_config,
                                &candidate,
                                &config_path,
                                &new_proxies,
                                Some(&new_rule_providers),
                                Some(&new_prefetched_payloads),
                                Some(tunnel.resolver()),
                                Some(&new_registry),
                            )
                            .await
                            {
                                Ok(dns) => dns,
                                Err((_status, msg)) => {
                                    // reconcile_dns_config's contract: Err
                                    // rejects the whole mutation. Committing
                                    // anyway would swap routing while the
                                    // retained resolver's `#name` adapters
                                    // lose their registry cell — dead refs
                                    // that fail closed forever (issue #533
                                    // review). Skip the commit entirely; the
                                    // next interval retries.
                                    warn!(
                                        "subscription '{name}': dns reconcile failed; \
                                         NOT committing: {msg}"
                                    );
                                    let mut live = raw_config.write();
                                    if let Some(sub) = live
                                        .subscriptions
                                        .as_mut()
                                        .and_then(|subs| subs.iter_mut().find(|s| s.name == name))
                                    {
                                        sub.last_updated = Some(now);
                                    }
                                    continue;
                                }
                            };

                            // Publish the rebuilt resolver to every
                            // consumer before the route swap drops the old
                            // registry cell — a `#name` upstream resolving
                            // through the standalone DNS server's or host
                            // hook's OLD resolver would fail closed until
                            // `publish_dns` runs (issue #533).
                            if let Some(dns) = &dns {
                                meow_api::routes::install_resolver_everywhere(
                                    &tunnel,
                                    dns_server.as_ref(),
                                    dns,
                                );
                            }
                            tunnel.update_routing(new_proxies, new_rules, new_registry);
                            // Commit point: the candidate's provider sets —
                            // already referenced by the rules and DNS
                            // `rule-set:` matchers — become the live
                            // registries (issue #533 review); the interval
                            // refresh loops follow the committed set
                            // (issue #543).
                            rule_provider_refresh
                                .commit_registry(&rule_providers, new_rule_providers);
                            meow_api::routes::commit_proxy_providers(
                                &proxy_providers,
                                &new_proxy_providers,
                                candidate.strict.unwrap_or(false),
                                candidate.proxy_providers.as_ref(),
                                &proxy_provider_refresh,
                            );
                            // Commit raw + routing together inside the lane:
                            // the on-disk/dashboard view and the running
                            // router can no longer diverge on failure.
                            // NB: this bypasses `swap_config_and_reconcile_tun`
                            // — sound only because a fetched subscription can
                            // never alter `tun:`/`dns:`/`max-connections`, so
                            // no TUN/DNS reconcile can be owed. If a future
                            // merge widens the candidate's sections, route it
                            // through the reconcile instead (issue #543
                            // review).
                            *raw_config.write() = candidate.clone();
                            if let Some(dns) = dns {
                                meow_api::routes::publish_dns(&tunnel, dns_server.as_ref(), &dns)
                                    .await;
                            }
                            // Health-check tasks follow the new group set
                            // (issue #514).
                            tunnel.reconcile_health_checks(
                                &meow_config::extract_health_check_specs(
                                    candidate.proxy_groups.as_deref().unwrap_or(&[]),
                                ),
                            );
                            info!("Subscription '{}' refreshed successfully", name);
                            // Save while still in the lane: every other
                            // writer serializes its rename under
                            // `CONFIG_MUTATION`, so the file's last writer
                            // must follow commit order — otherwise an older
                            // candidate's rename can land last and
                            // resurrect stale state on restart (issue #543
                            // review).
                            if let Err(e) =
                                meow_config::save_raw_config_async(&config_path, &candidate).await
                            {
                                // Runtime and raw committed — disk may
                                // diverge until the next successful save.
                                warn!("auto-save after refreshing '{name}' failed: {e}");
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
                Err(e) => {
                    error!("Failed to refresh subscription '{}': {}", name, e);
                    // A payload defect is permanent until the publisher fixes
                    // it — stamp `last_updated` so the pass honors `interval`
                    // rather than re-downloading the same garbled body every
                    // 60 s (issue #533 review). Transport failures stay
                    // unstamped so a flaky network retries next pass.
                    if e.downcast_ref::<meow_config::subscription::PayloadDefect>()
                        .is_some()
                    {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;
                        // In-lane so a sibling commit's clone→write can't
                        // silently drop the stamp.
                        let _lane = meow_api::routes::CONFIG_MUTATION.lock().await;
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
        }

        drop(tunnel);
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}
