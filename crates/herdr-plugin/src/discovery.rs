use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Result;

use crate::{
    INTERVAL,
    attached::{Discovery, DiscoverySource, Host, is_endpoint},
    herdr::MachineRegistry,
    state::{Log, State},
};

pub(crate) struct Reconciler {
    path: PathBuf,
    retry: BTreeMap<String, (Instant, u32)>,
    missing: BTreeMap<String, u32>,
    last_generation: Option<String>,
    log: Log,
}

impl Reconciler {
    pub fn new(directory: &Path, log: Log) -> Self {
        Self {
            path: directory.join("discovery-state.json"),
            retry: BTreeMap::new(),
            missing: BTreeMap::new(),
            last_generation: None,
            log,
        }
    }

    pub fn reset_absences(&mut self) {
        self.missing.clear();
    }

    pub async fn check(
        &mut self,
        discovery: &Discovery,
        source: &impl DiscoverySource,
        registry: &impl MachineRegistry,
    ) -> Result<()> {
        self.poll(&discovery.hosts, source, registry).await?;
        if !discovery.complete {
            self.reset_absences();
        } else if self.last_generation.as_ref() != Some(&discovery.generation) {
            self.prune(&discovery.hosts, registry).await?;
        }
        self.last_generation = Some(discovery.generation.clone());
        Ok(())
    }

    async fn prune(&mut self, hosts: &[Host], registry: &impl MachineRegistry) -> Result<()> {
        let mut state = State::load(&self.path)?;
        let machines = registry.machines().await?;
        self.missing.retain(|id, _| state.managed.contains_key(id));
        for (endpoint, profile) in state.managed.clone() {
            // A manually removed/replaced profile stays removed. Never transfer
            // ownership to a new profile with the same SSH target.
            let target = format!("attached-{endpoint}");
            if !machines
                .iter()
                .any(|m| m.id == profile && m.target.eq_ignore_ascii_case(&target))
            {
                state.managed.remove(&endpoint);
                state.pending.remove(&endpoint);
                self.missing.remove(&endpoint);
                state.save(&self.path)?;
                continue;
            }
            if hosts.iter().any(|host| host.endpoint_id == endpoint) {
                self.missing.remove(&endpoint);
                continue;
            }
            let misses = self.missing.entry(endpoint.clone()).or_default();
            *misses = misses.saturating_add(1);
            if *misses < 3 {
                continue;
            }
            if let Err(error) = registry.remove(&profile).await {
                self.log
                    .record(format!("Will retry removing {target}: {error:#}"));
                continue;
            }
            state.managed.remove(&endpoint);
            state.seen.remove(&endpoint);
            state.pending.remove(&endpoint);
            self.missing.remove(&endpoint);
            self.retry.remove(&endpoint);
            state.save(&self.path)?;
            self.log
                .record(format!("Removed {target} after three missing checks"));
        }
        Ok(())
    }

    pub async fn poll(
        &mut self,
        hosts: &[Host],
        source: &impl DiscoverySource,
        registry: &impl MachineRegistry,
    ) -> Result<()> {
        let mut state = State::load(&self.path)?;
        let targets = registry
            .machines()
            .await?
            .into_iter()
            .map(|m| m.target.to_ascii_lowercase())
            .collect::<std::collections::BTreeSet<_>>();
        let mut counts = BTreeMap::<String, usize>::new();
        for host in hosts {
            *counts.entry(host.host.to_ascii_lowercase()).or_default() += 1;
        }
        self.retry
            .retain(|id, _| hosts.iter().any(|host| &host.endpoint_id == id));
        let mut candidates = hosts.iter().collect::<Vec<_>>();
        // Untried hosts before cooled-down retries. A slow publisher cannot starve
        // later publishers, even if its alias never becomes ready.
        candidates.sort_by_key(|host| self.retry.get(&host.endpoint_id).copied());
        let mut attempts = 0;
        for host in candidates {
            if state.seen.contains(&host.endpoint_id) {
                continue;
            }
            let label = host.host.to_ascii_lowercase();
            let equivalent_label = counts[&label] == 1
                && !is_endpoint(&label)
                && targets.contains(&format!("attached-{label}"));
            if targets.contains(&host.ssh_target) || equivalent_label {
                // Remember manual/disabled entries too, so a subsequent manual
                // removal stays removed instead of fighting the user's choice.
                state.seen.insert(host.endpoint_id.clone());
            } else {
                let previous = self.retry.get(&host.endpoint_id).copied();
                if attempts >= 4 || previous.is_some_and(|(deadline, _)| deadline > Instant::now())
                {
                    continue;
                }
                attempts += 1;
                let failures = previous.map_or(0, |(_, failures)| failures);
                self.retry.insert(
                    host.endpoint_id.clone(),
                    (Instant::now() + INTERVAL, failures),
                );
                let display = if counts[&label] == 1 {
                    host.host.clone()
                } else {
                    format!(
                        "{} ({})",
                        &host.host[..host.host.len().min(60)],
                        &host.endpoint_id[..8]
                    )
                };
                let result = async {
                    if !source.ready(host).await? {
                        return Ok(None);
                    }
                    let profile = registry.add(&host.ssh_target, &display).await?;
                    Ok::<_, anyhow::Error>(Some(profile))
                }
                .await;
                match result {
                    Ok(None) => continue,
                    Err(error) => {
                        let delay = Duration::from_secs(
                            (INTERVAL.as_secs() * 2_u64.pow(failures.min(4))).min(300),
                        );
                        self.retry.insert(
                            host.endpoint_id.clone(),
                            (Instant::now() + delay, failures.saturating_add(1)),
                        );
                        self.log
                            .record(format!("Will retry {}: {error:#}", host.ssh_target));
                        continue;
                    }
                    Ok(Some(profile)) => {
                        state.managed.insert(host.endpoint_id.clone(), profile);
                    }
                }
                state.seen.insert(host.endpoint_id.clone());
                state
                    .pending
                    .insert(host.endpoint_id.clone(), display.clone());
                self.log
                    .record(format!("Added {display} ({})", host.ssh_target));
            }
            // Persist ownership before toasting or trying another machine.
            state.save(&self.path)?;
        }
        for (id, label) in state.pending.clone() {
            match registry.notify(&label).await {
                Ok(true) => {
                    state.pending.remove(&id);
                    state.save(&self.path)?;
                }
                Ok(false) => {}
                Err(error) => self.log.record(format!("Toast deferred: {error:#}")),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::herdr::Machine;
    use std::{cell::RefCell, collections::BTreeSet};

    #[derive(Default)]
    struct Fake {
        machines: RefCell<Vec<String>>,
        adds: RefCell<Vec<(String, String)>>,
        toasts: RefCell<Vec<String>>,
        unready: RefCell<BTreeSet<String>>,
        failing: RefCell<BTreeSet<String>>,
        toast_offline: RefCell<bool>,
        removes: RefCell<Vec<String>>,
        remove_fails: RefCell<bool>,
    }
    impl DiscoverySource for Fake {
        async fn ready(&self, host: &Host) -> Result<bool> {
            Ok(!self.unready.borrow().contains(&host.endpoint_id))
        }
    }
    impl MachineRegistry for Fake {
        async fn machines(&self) -> Result<Vec<Machine>> {
            Ok(self
                .machines
                .borrow()
                .iter()
                .map(|target| Machine {
                    id: format!("id-{target}"),
                    target: target.clone(),
                })
                .collect())
        }
        async fn add(&self, target: &str, label: &str) -> Result<String> {
            self.adds.borrow_mut().push((target.into(), label.into()));
            anyhow::ensure!(!self.failing.borrow().contains(target), "offline publisher");
            self.machines.borrow_mut().push(target.into());
            Ok(format!("id-{target}"))
        }
        async fn remove(&self, id: &str) -> Result<()> {
            self.removes.borrow_mut().push(id.into());
            anyhow::ensure!(!*self.remove_fails.borrow(), "cannot remove");
            self.machines
                .borrow_mut()
                .retain(|target| format!("id-{target}") != id);
            Ok(())
        }
        async fn notify(&self, label: &str) -> Result<bool> {
            if *self.toast_offline.borrow() {
                return Ok(false);
            }
            self.toasts.borrow_mut().push(label.into());
            Ok(true)
        }
    }
    fn host(byte: u8, label: &str) -> Host {
        let id = format!("{byte:02x}").repeat(32);
        Host {
            host: label.into(),
            ssh_target: format!("attached-{id}"),
            endpoint_id: id,
        }
    }
    fn reconciler(path: &Path) -> Reconciler {
        Reconciler::new(path, Log::new(path))
    }

    fn report(generation: u32, hosts: Vec<Host>, complete: bool) -> Discovery {
        Discovery {
            version: 1,
            generation: generation.to_string(),
            checked_at: 0,
            complete,
            hosts,
        }
    }

    #[tokio::test]
    async fn removes_only_owned_profiles_after_three_distinct_checks_and_readds_on_return() {
        let temp = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let owned = host(1, "Office");
        let manual = host(2, "Manual");
        *fake.machines.borrow_mut() = vec![manual.ssh_target.clone(), "attached-friendly".into()];
        let mut task = reconciler(temp.path());
        task.check(&report(1, vec![owned.clone(), manual], true), &fake, &fake)
            .await
            .unwrap();
        assert_eq!(State::load(&task.path).unwrap().managed.len(), 1);
        for generation in [2, 2, 2, 3] {
            task.check(&report(generation, vec![], true), &fake, &fake)
                .await
                .unwrap();
            assert!(fake.removes.borrow().is_empty());
        }
        task.check(&report(4, vec![], true), &fake, &fake)
            .await
            .unwrap();
        assert_eq!(*fake.removes.borrow(), [format!("id-{}", owned.ssh_target)]);
        assert_eq!(fake.machines.borrow().len(), 2);
        assert!(State::load(&task.path).unwrap().managed.is_empty());
        task.check(&report(5, vec![owned], true), &fake, &fake)
            .await
            .unwrap();
        assert_eq!(fake.adds.borrow().len(), 2);
        assert_eq!(fake.toasts.borrow().len(), 2);
    }

    #[tokio::test]
    async fn reappearance_partial_refresh_and_failed_checks_reset_the_grace_period() {
        let temp = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let owned = host(1, "Office");
        let mut task = reconciler(temp.path());
        task.check(&report(0, vec![owned.clone()], true), &fake, &fake)
            .await
            .unwrap();
        for generation in 1..=2 {
            task.check(&report(generation, vec![], true), &fake, &fake)
                .await
                .unwrap();
        }
        task.check(&report(3, vec![owned], true), &fake, &fake)
            .await
            .unwrap();
        for generation in 4..=5 {
            task.check(&report(generation, vec![], true), &fake, &fake)
                .await
                .unwrap();
        }
        task.check(&report(6, vec![], false), &fake, &fake)
            .await
            .unwrap();
        for generation in 7..=8 {
            task.check(&report(generation, vec![], true), &fake, &fake)
                .await
                .unwrap();
        }
        task.reset_absences(); // Malformed/stale/unreadable snapshot or failed Herdr check.
        for generation in 9..=10 {
            task.check(&report(generation, vec![], true), &fake, &fake)
                .await
                .unwrap();
        }
        assert!(fake.removes.borrow().is_empty());
        task.check(&report(11, vec![], true), &fake, &fake)
            .await
            .unwrap();
        assert_eq!(fake.removes.borrow().len(), 1);
    }

    #[tokio::test]
    async fn ownership_survives_restart_but_absence_counts_do_not() {
        let temp = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let mut task = reconciler(temp.path());
        task.check(&report(0, vec![host(1, "Office")], true), &fake, &fake)
            .await
            .unwrap();
        for generation in 1..=2 {
            task.check(&report(generation, vec![], true), &fake, &fake)
                .await
                .unwrap();
        }
        let mut restarted = reconciler(temp.path());
        for generation in 3..=4 {
            restarted
                .check(&report(generation, vec![], true), &fake, &fake)
                .await
                .unwrap();
        }
        assert!(fake.removes.borrow().is_empty());
        restarted
            .check(&report(5, vec![], true), &fake, &fake)
            .await
            .unwrap();
        assert_eq!(fake.removes.borrow().len(), 1);
    }

    #[tokio::test]
    async fn removal_failure_retries_without_forgetting_ownership_or_readding() {
        let temp = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let owned = host(1, "Office");
        let mut task = reconciler(temp.path());
        task.check(&report(0, vec![owned.clone()], true), &fake, &fake)
            .await
            .unwrap();
        *fake.remove_fails.borrow_mut() = true;
        for generation in 1..=3 {
            task.check(&report(generation, vec![], true), &fake, &fake)
                .await
                .unwrap();
        }
        assert!(
            State::load(&task.path)
                .unwrap()
                .seen
                .contains(&owned.endpoint_id)
        );
        assert_eq!(State::load(&task.path).unwrap().managed.len(), 1);
        *fake.remove_fails.borrow_mut() = false;
        task.check(&report(4, vec![], true), &fake, &fake)
            .await
            .unwrap();
        assert_eq!(fake.removes.borrow().len(), 2);
        assert!(State::load(&task.path).unwrap().managed.is_empty());
        task.check(&report(5, vec![owned], true), &fake, &fake)
            .await
            .unwrap();
        assert_eq!(fake.adds.borrow().len(), 2);
    }

    #[tokio::test]
    async fn manual_removals_replacements_and_legacy_entries_are_never_adopted() {
        for replacement in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let fake = Fake::default();
            let owned = host(1, "Office");
            let mut task = reconciler(temp.path());
            task.check(&report(0, vec![owned.clone()], true), &fake, &fake)
                .await
                .unwrap();
            if replacement {
                // A different saved ID is not the profile we added.
                let mut state = State::load(&task.path).unwrap();
                state
                    .managed
                    .insert(owned.endpoint_id.clone(), "old-profile-id".into());
                state.save(&task.path).unwrap();
            } else {
                fake.machines.borrow_mut().clear();
            }
            for generation in 1..=4 {
                task.check(&report(generation, vec![], true), &fake, &fake)
                    .await
                    .unwrap();
            }
            task.check(&report(5, vec![owned], true), &fake, &fake)
                .await
                .unwrap();
            assert!(fake.removes.borrow().is_empty());
            assert_eq!(fake.adds.borrow().len(), 1);
        }

        let temp = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let legacy = host(2, "Legacy");
        fake.machines.borrow_mut().push(legacy.ssh_target);
        let mut task = reconciler(temp.path());
        std::fs::write(
            &task.path,
            serde_json::json!({
                "seen":[legacy.endpoint_id], "pending":{}
            })
            .to_string(),
        )
        .unwrap();
        for generation in 1..=4 {
            task.check(&report(generation, vec![], true), &fake, &fake)
                .await
                .unwrap();
        }
        assert!(fake.removes.borrow().is_empty());
        assert_eq!(fake.machines.borrow().len(), 1);
    }

    #[tokio::test]
    async fn startup_and_new_hosts_add_once_and_toast_once_across_restarts() {
        let temp = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let mut task = reconciler(temp.path());
        let first = host(1, "Office");
        task.poll(&[first.clone(), first.clone()], &fake, &fake)
            .await
            .unwrap();
        let hosts = [host(1, "Renamed"), host(2, "Laptop")];
        task.poll(&hosts, &fake, &fake).await.unwrap();
        let mut restarted = reconciler(temp.path());
        restarted.poll(&hosts, &fake, &fake).await.unwrap();
        assert_eq!(fake.adds.borrow().len(), 2);
        assert_eq!(fake.toasts.borrow().len(), 2);
        assert_eq!(fake.adds.borrow()[0].0, first.ssh_target);
        // A user removal is not undone, even after disappearance/reappearance.
        fake.machines.borrow_mut().clear();
        restarted.poll(&[], &fake, &fake).await.unwrap();
        restarted.poll(&hosts, &fake, &fake).await.unwrap();
        assert_eq!(fake.adds.borrow().len(), 2);
    }

    #[tokio::test]
    async fn respects_existing_targets_label_aliases_and_duplicate_publisher_labels() {
        let temp = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let hosts = [
            host(1, "Manual"),
            host(2, "Office"),
            host(3, "duplicate"),
            host(4, "DUPLICATE"),
        ];
        *fake.machines.borrow_mut() = vec![
            hosts[0].ssh_target.to_ascii_uppercase(),
            "attached-office".into(),
            "attached-duplicate".into(),
        ];
        reconciler(temp.path())
            .poll(&hosts, &fake, &fake)
            .await
            .unwrap();
        assert_eq!(fake.adds.borrow().len(), 2);
        assert_eq!(fake.adds.borrow()[0].1, "duplicate (03030303)");
        assert_eq!(fake.adds.borrow()[1].1, "DUPLICATE (04040404)");
    }

    #[tokio::test]
    async fn failed_adds_retry_without_false_toasts_or_blocking_healthy_hosts() {
        let temp = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let hosts = [host(1, "offline"), host(2, "healthy")];
        fake.failing
            .borrow_mut()
            .insert(hosts[0].ssh_target.clone());
        let mut task = reconciler(temp.path());
        task.poll(&hosts, &fake, &fake).await.unwrap();
        assert_eq!(*fake.toasts.borrow(), ["healthy"]);
        fake.failing.borrow_mut().clear();
        task.poll(&hosts, &fake, &fake).await.unwrap();
        assert_eq!(fake.adds.borrow().len(), 2); // Backoff, not a hot loop.
        task.retry.clear();
        task.poll(&hosts, &fake, &fake).await.unwrap();
        assert_eq!(fake.adds.borrow().len(), 3);
        assert_eq!(*fake.toasts.borrow(), ["healthy", "offline"]);
    }

    #[tokio::test]
    async fn unready_tunnels_do_not_starve_new_hosts_or_dial_direct_ssh() {
        let temp = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let hosts = (0..5).map(|n| host(n, "office")).collect::<Vec<_>>();
        *fake.unready.borrow_mut() = hosts[..4].iter().map(|h| h.endpoint_id.clone()).collect();
        let mut task = reconciler(temp.path());
        task.poll(&hosts, &fake, &fake).await.unwrap();
        assert!(fake.adds.borrow().is_empty());
        task.poll(&hosts, &fake, &fake).await.unwrap();
        assert_eq!(fake.adds.borrow()[0].0, hosts[4].ssh_target);
    }

    #[tokio::test]
    async fn failed_toasts_survive_restart_without_adding_twice() {
        let temp = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        *fake.toast_offline.borrow_mut() = true;
        reconciler(temp.path())
            .poll(&[host(1, "office")], &fake, &fake)
            .await
            .unwrap();
        assert!(fake.toasts.borrow().is_empty());
        *fake.toast_offline.borrow_mut() = false;
        let mut task = reconciler(temp.path());
        task.poll(&[], &fake, &fake).await.unwrap();
        task.poll(&[], &fake, &fake).await.unwrap();
        assert_eq!(*fake.toasts.borrow(), ["office"]);
        assert_eq!(fake.adds.borrow().len(), 1);
    }
}
