//! The replaceable Attached integration boundary. A future library-backed source
//! can implement DiscoverySource without changing reconciliation or Herdr calls.
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use tokio::process::Command;

use crate::process;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct Host {
    pub host: String,
    pub endpoint_id: String,
    pub ssh_target: String,
}

pub(crate) trait DiscoverySource {
    async fn ready(&self, host: &Host) -> Result<bool>;
}

pub(crate) struct CliAttached {
    pub binary: PathBuf,
}

impl Default for CliAttached {
    fn default() -> Self {
        Self {
            binary: "attached".into(),
        }
    }
}

/// Versioned, credential-free snapshot produced by the already-unlocked exporter.
#[derive(Debug, Deserialize)]
pub(crate) struct Discovery {
    pub version: u32,
    pub generation: String,
    pub checked_at: u64,
    pub complete: bool,
    pub hosts: Vec<Host>,
}

impl CliAttached {
    pub fn hosts(&self) -> Result<Discovery> {
        let home = std::env::var_os("HOME").context("HOME is not set")?;
        let path = PathBuf::from(home).join(".ssh/attached/discovery.json");
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(path)
            .context(
                "could not read exporter discovery; update Attached if discovery.json is missing",
            )?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o077 == 0,
            "exporter discovery must be an owner-only regular file"
        );
        let mut output = String::new();
        file.take(4 * 1024 * 1024 + 1).read_to_string(&mut output)?;
        ensure!(
            output.len() <= 4 * 1024 * 1024,
            "exporter discovery is too large"
        );
        parse_discovery(
            &output,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        )
    }
}

impl DiscoverySource for CliAttached {
    async fn ready(&self, host: &Host) -> Result<bool> {
        let mut command = Command::new("ssh");
        command.args(["-G", &host.ssh_target]);
        let output = process::output(command, Duration::from_secs(5)).await?;
        Ok(tunnel_ready(&output, &host.ssh_target))
    }
}

fn parse_discovery(output: &str, now: u64) -> Result<Discovery> {
    let mut discovery: Discovery =
        serde_json::from_str(output).context("invalid Attached JSON discovery")?;
    ensure!(
        discovery.version == 1,
        "unsupported exporter discovery version"
    );
    ensure!(
        !discovery.generation.is_empty() && discovery.generation.len() <= 64,
        "invalid exporter discovery generation"
    );
    ensure!(
        now.checked_sub(discovery.checked_at)
            .is_some_and(|age| age <= 90),
        "exporter discovery is stale or from the future"
    );
    discovery.hosts = validate_hosts(discovery.hosts)?;
    Ok(discovery)
}

fn validate_hosts(hosts: Vec<Host>) -> Result<Vec<Host>> {
    let mut unique = BTreeMap::new();
    for host in hosts {
        ensure!(
            is_endpoint(&host.endpoint_id),
            "invalid Attached endpoint identity"
        );
        ensure!(
            !host.host.is_empty()
                && host.host.len() <= 64
                && host.host.as_bytes()[0].is_ascii_alphanumeric()
                && host
                    .host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
            "invalid Attached host label"
        );
        ensure!(
            host.ssh_target == format!("attached-{}", host.endpoint_id),
            "SSH alias does not match stable identity"
        );
        if let Some(previous) = unique.insert(host.endpoint_id.clone(), host.clone()) {
            ensure!(previous == host, "conflicting Attached identities");
        }
    }
    Ok(unique.into_values().collect())
}

pub(crate) fn is_endpoint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn tunnel_ready(output: &str, target: &str) -> bool {
    // Don't let a not-yet-exported alias fall through to DNS or personal SSH rules.
    let settings: BTreeMap<_, _> = output
        .lines()
        .filter_map(|line| line.split_once(' '))
        .collect();
    settings.get("hostname") == Some(&target)
        && settings
            .get("proxycommand")
            .is_some_and(|proxy| proxy.contains(" __ssh-local-proxy "))
        && settings.get("batchmode") == Some(&"yes")
        && matches!(
            settings.get("stricthostkeychecking"),
            Some(&"yes" | &"true")
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_hosts(output: &str) -> Result<Vec<Host>> {
        validate_hosts(serde_json::from_str(output)?)
    }

    #[test]
    fn snapshots_require_a_supported_version_valid_generation_and_fresh_check() {
        let valid = serde_json::json!({
            "version":1, "generation":"one", "checked_at":100,
            "complete":true, "hosts":[]
        });
        assert!(parse_discovery(&valid.to_string(), 100).unwrap().complete);
        assert!(parse_discovery(&valid.to_string(), 191).is_err());
        assert!(parse_discovery(&valid.to_string(), 99).is_err());
        for (field, value) in [
            ("version", serde_json::json!(2)),
            ("generation", serde_json::json!("")),
            (
                "hosts",
                serde_json::json!([{"host":"Office","endpoint_id":"bad","ssh_target":"bad"}]),
            ),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(parse_discovery(&invalid.to_string(), 100).is_err());
        }
        assert!(parse_discovery("[]", 100).is_err());
    }

    #[test]
    fn parses_empty_and_duplicate_hosts_without_accepting_arbitrary_targets() {
        assert!(parse_hosts("[]").unwrap().is_empty());
        let host = serde_json::json!({"host":"Office", "endpoint_id":"a".repeat(64), "ssh_target":format!("attached-{}", "a".repeat(64))});
        assert_eq!(
            parse_hosts(&serde_json::json!([host, host]).to_string())
                .unwrap()
                .len(),
            1
        );
        for (field, value) in [
            ("endpoint_id", "--flag"),
            ("ssh_target", "direct.example"),
            ("host", "bad\nname"),
            ("host", "$(touch exploit)"),
        ] {
            let mut invalid = host.clone();
            invalid[field] = value.into();
            assert!(parse_hosts(&serde_json::json!([invalid]).to_string()).is_err());
        }
        let mut conflict = host.clone();
        conflict["host"] = "other".into();
        assert!(parse_hosts(&serde_json::json!([host, conflict]).to_string()).is_err());
    }

    #[test]
    fn readiness_requires_the_attached_proxy_and_fail_closed_ssh_settings() {
        let valid = "hostname attached-id\nproxycommand /path/attached __ssh-local-proxy /tmp/socket\nbatchmode yes\nstricthostkeychecking true\n";
        assert!(tunnel_ready(valid, "attached-id"));
        assert!(!tunnel_ready(valid, "different"));
        for (old, new) in [
            ("__ssh-local-proxy", "direct-proxy"),
            ("batchmode yes", "batchmode no"),
            ("checking true", "checking no"),
        ] {
            assert!(!tunnel_ready(&valid.replace(old, new), "attached-id"));
        }
        assert!(!tunnel_ready(
            "hostname attached-id\nproxycommand false",
            "attached-id"
        ));
    }
}
