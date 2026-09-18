//! The replaceable Attached integration boundary. A future library-backed source
//! can implement DiscoverySource without changing reconciliation or Herdr calls.
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use tokio::process::Command;

use crate::process;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct Host {
    #[serde(default = "default_workspace")]
    pub workspace: String,
    pub host: String,
    pub endpoint_id: String,
    pub ssh_target: String,
}

fn default_workspace() -> String {
    "default".into()
}

impl Host {
    pub(crate) fn key(&self) -> String {
        // Preserve the pre-workspace seen/pending state for default machines.
        if self.workspace == "default" {
            self.endpoint_id.clone()
        } else {
            format!("{}/{}", self.workspace, self.endpoint_id)
        }
    }

    pub(crate) fn label_target(&self) -> String {
        self.target(&self.host.to_ascii_lowercase())
    }

    fn target(&self, host: &str) -> String {
        if self.workspace == "default" {
            format!("attached-{host}")
        } else {
            format!("attached-{}--{host}", self.workspace)
        }
    }

    pub(crate) fn display(&self) -> String {
        if self.workspace == "default" {
            self.host.clone()
        } else {
            format!("{} / {}", self.workspace, self.host)
        }
    }
}

pub(crate) trait DiscoverySource {
    async fn hosts(&self) -> Result<Vec<Host>>;
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

impl DiscoverySource for CliAttached {
    async fn hosts(&self) -> Result<Vec<Host>> {
        let mut command = Command::new(&self.binary);
        command.args(["sessions", "list", "--json"]);
        let output = process::output(command, Duration::from_secs(20)).await
            .context("Attached discovery failed (requires unattended credentials and sessions list --json)")?;
        parse_hosts(&output)
    }

    async fn ready(&self, host: &Host) -> Result<bool> {
        let mut command = Command::new("ssh");
        command.args(["-G", &host.ssh_target]);
        let output = process::output(command, Duration::from_secs(5)).await?;
        Ok(tunnel_ready(&output, &host.ssh_target))
    }
}

pub(crate) fn parse_hosts(output: &str) -> Result<Vec<Host>> {
    let hosts: Vec<Host> =
        serde_json::from_str(output).context("invalid Attached JSON host list")?;
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
            !host.workspace.is_empty()
                && host.workspace.len() <= 32
                && host.workspace.as_bytes()[0].is_ascii_alphanumeric()
                && host
                    .workspace
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
                && !host.workspace.contains("--"),
            "invalid Attached workspace"
        );
        ensure!(
            host.ssh_target == host.target(&host.endpoint_id),
            "SSH alias does not match stable identity"
        );
        if let Some(previous) = unique.insert(host.key(), host.clone()) {
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
    fn workspace_metadata_must_match_the_ssh_namespace_and_identity() {
        let id = "a".repeat(64);
        let host = serde_json::json!({"workspace": "client-acme", "host": "office", "endpoint_id": id, "ssh_target": format!("attached-client-acme--{id}")});
        let parsed = parse_hosts(&serde_json::json!([host]).to_string()).unwrap();
        assert_eq!(parsed[0].key(), format!("client-acme/{id}"));
        assert_eq!(parsed[0].display(), "client-acme / office");
        assert_eq!(parsed[0].label_target(), "attached-client-acme--office");
        for workspace in ["other", "Client", "../escape", "work--office", ""] {
            let mut invalid = host.clone();
            invalid["workspace"] = workspace.into();
            assert!(parse_hosts(&serde_json::json!([invalid]).to_string()).is_err());
        }
        let mut default = host.clone();
        default["workspace"] = "default".into();
        default["ssh_target"] = format!("attached-{id}").into();
        let parsed = parse_hosts(&serde_json::json!([host, default]).to_string()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_ne!(parsed[0].key(), parsed[1].key());
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
