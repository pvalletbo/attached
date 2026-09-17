use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Result;

use crate::{
    INTERVAL,
    attached::{DiscoverySource, Host, is_endpoint},
    herdr::MachineRegistry,
    state::{Log, State},
};

pub(crate) struct Reconciler {
    path: PathBuf,
    retry: BTreeMap<String, (Instant, u32)>,
    log: Log,
}

impl Reconciler {
    pub fn new(directory: &Path, log: Log) -> Self {
        Self {
            path: directory.join("discovery-state.json"),
            retry: BTreeMap::new(),
            log,
        }
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
                        return Ok(false);
                    }
                    registry.add(&host.ssh_target, &display).await?;
                    Ok::<_, anyhow::Error>(true)
                }
                .await;
                match result {
                    Ok(false) => continue,
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
                    Ok(true) => {}
                }
                state.seen.insert(host.endpoint_id.clone());
                state
                    .pending
                    .insert(host.endpoint_id.clone(), display.clone());
                self.log
                    .record(format!("Added {display} ({})", host.ssh_target));
            }
            // Commit each add before toasting or trying another machine. Never
            // use discovery absence as a reason to remove or disable a profile.
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
    }
    impl DiscoverySource for Fake {
        async fn hosts(&self) -> Result<Vec<Host>> {
            unreachable!()
        }
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
                    target: target.clone(),
                })
                .collect())
        }
        async fn add(&self, target: &str, label: &str) -> Result<()> {
            self.adds.borrow_mut().push((target.into(), label.into()));
            anyhow::ensure!(!self.failing.borrow().contains(target), "offline publisher");
            self.machines.borrow_mut().push(target.into());
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
