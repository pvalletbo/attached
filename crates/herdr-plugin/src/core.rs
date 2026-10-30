//! herdr-app uses herdr-core's registry, not the legacy TUI's saved profiles.
use std::{cell::RefCell, path::PathBuf, time::Duration};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::{
    herdr::{Machine, MachineRegistry},
    process,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct SavedMachine {
    id: String,
    name: String,
    target: String,
    #[serde(default)]
    via: bool,
    #[serde(default)]
    temporary: bool,
    #[serde(default)]
    session: Option<String>,
}

impl SavedMachine {
    fn ownership(&self) -> Result<String> {
        // hc's id identifies the REMOTE CORE, not a local registration. Include
        // its local name, transport and session so renames/replacements aren't
        // accidentally adopted. Never infer ownership from an endpoint alone.
        Ok(serde_json::to_string(self)?)
    }
}

pub(crate) struct Core {
    binary: PathBuf,
    install: bool,
    pub notices: RefCell<Vec<String>>,
    pub error: RefCell<Option<String>>,
}

impl Core {
    pub fn new(install: bool) -> Self {
        Self {
            binary: std::env::var_os("ATTACHED_HERDR_CORE")
                .map(PathBuf::from)
                .unwrap_or_else(|| "hc".into()),
            install,
            notices: RefCell::default(),
            error: RefCell::default(),
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.binary);
        command.args(args);
        command
    }

    async fn saved(&self) -> Result<Vec<SavedMachine>> {
        #[derive(Deserialize)]
        struct Response {
            machines: Vec<SavedMachine>,
        }
        let output = process::output(
            self.command(&["machine", "ls", "--json"]),
            Duration::from_secs(10),
        )
        .await?;
        Ok(serde_json::from_str::<Response>(&output)
            .context("invalid hc machine list")?
            .machines)
    }

    async fn enroll(&self, target: &str, label: &str) -> Result<String> {
        let endpoint = target
            .strip_prefix("attached-")
            .context("not an Attached target")?;
        ensure!(
            crate::attached::is_endpoint(endpoint),
            "invalid Attached identity"
        );
        let name = machine_name(label, endpoint);
        let machines = self.saved().await?;
        ensure!(
            !machines.iter().any(
                |m| m.name.eq_ignore_ascii_case(&name) || m.target.eq_ignore_ascii_case(target)
            ),
            "machine name or target was registered concurrently; leaving it alone"
        );
        let mut command = self.command(&["machine", "add", target, "--name", &name, "--json"]);
        if self.install {
            command.arg("--install");
        }
        let output = process::output(command, Duration::from_secs(60)).await?;
        let saved: SavedMachine =
            serde_json::from_str(&output).context("invalid hc machine add response")?;
        ensure!(
            saved.name == name
                && saved.target == target
                && !saved.id.is_empty()
                && !saved.via
                && !saved.temporary
                && saved.session.is_none(),
            "hc returned an unexpected registration; refusing ownership"
        );
        saved.ownership()
    }
}

fn machine_name(label: &str, endpoint: &str) -> String {
    // Duplicate publisher labels arrive as "host (endpoint-prefix)" from the
    // shared reconciler. hc permits 32 characters total: reserve 18 for the
    // attached- prefix and endpoint suffix, leaving 14 for the publisher label.
    let host = label.split(' ').next().unwrap_or("machine");
    let host = host
        .chars()
        .take(14)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!("attached-{host}-{}", &endpoint[..8])
}

impl MachineRegistry for Core {
    async fn machines(&self) -> Result<Vec<Machine>> {
        self.saved()
            .await?
            .into_iter()
            .map(|machine| {
                Ok(Machine {
                    id: machine.ownership()?,
                    target: machine.target,
                })
            })
            .collect()
    }

    async fn add(&self, target: &str, label: &str) -> Result<String> {
        let result = self.enroll(target, label).await;
        if let Err(error) = &result {
            *self.error.borrow_mut() = Some(format!("{label}: {error:#}"));
        }
        result
    }

    async fn remove(&self, ownership: &str) -> Result<()> {
        let owned: SavedMachine =
            serde_json::from_str(ownership).context("invalid core ownership")?;
        // hc removes by name, not registration id. Resolve the saved identity
        // again immediately before removing. hc has no conditional-delete API:
        // an identical-name replacement racing this final check is undetectable.
        ensure!(
            self.saved().await?.contains(&owned),
            "registration changed; refusing removal"
        );
        let result = process::output(
            self.command(&["machine", "rm", &owned.name, "--json"]),
            Duration::from_secs(10),
        )
        .await;
        if let Err(error) = &result {
            *self.error.borrow_mut() = Some(format!("{}: {error:#}", owned.name));
        }
        result.map(|_| ())
    }

    async fn notify(&self, label: &str) -> Result<bool> {
        self.notices.borrow_mut().push(label.into());
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_includes_the_local_registration_not_just_remote_core_id() {
        let original: SavedMachine = serde_json::from_value(serde_json::json!({
            "id":"remote-core", "name":"owned", "target":"attached-endpoint"
        }))
        .unwrap();
        for change in ["name", "target", "session", "via", "temporary"] {
            let mut replacement = serde_json::to_value(&original).unwrap();
            replacement[change] = if matches!(change, "via" | "temporary") {
                serde_json::json!(true)
            } else {
                serde_json::json!("replacement")
            };
            let replacement: SavedMachine = serde_json::from_value(replacement).unwrap();
            assert_ne!(
                original.ownership().unwrap(),
                replacement.ownership().unwrap()
            );
        }
    }

    struct Fixture {
        root: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;
            let root = tempfile::tempdir().unwrap();
            let script = root.path().join("hc");
            std::fs::write(root.path().join("rows"), "").unwrap();
            std::fs::write(
                &script,
                r#"#!/bin/sh
set -eu
ROOT=$(dirname "$0")
case "$1 $2" in
  'machine ls')
    [ "$3" = '--json' ] || exit 80
    printf '{"machines":['; paste -sd ',' "$ROOT/rows"; printf ']}\n';;
  'machine add')
    [ "$4" = '--name' ] && [ "$6" = '--json' ] && [ "${#5}" -le 32 ] || exit 81
    if read -r input; then exit 82; fi
    [ "$SSH_ASKPASS_REQUIRE" = never ] || exit 83
    printf 'attempt %s\n' "${7:-no-install}" >> "$ROOT/events"
    if [ -f "$ROOT/needs-install" ] && [ "${7:-}" != '--install' ]; then
      printf 'hc_missing: install the remote core first\n' >&2; exit 4
    fi
    id=$(printf '%s' "${3#attached-}" | cut -c1-32)
    row=$(printf '{"id":"%s","name":"%s","target":"%s"}' "$id" "$5" "$3")
    printf '%s\n' "$row" >> "$ROOT/rows"
    if [ -f "$ROOT/invalid-response" ]; then printf 'not JSON\n'; else printf '%s\n' "$row"; fi;;
  'machine rm')
    [ "$4" = '--json' ] && [ "$#" = 4 ] || exit 84
    printf 'remove %s\n' "$3" >> "$ROOT/events"
    grep -v "\"name\":\"$3\"" "$ROOT/rows" > "$ROOT/rows.new" || :
    mv "$ROOT/rows.new" "$ROOT/rows"
    printf '{}\n';;
  *) exit 90;;
esac
"#,
            )
            .unwrap();
            std::fs::set_permissions(script, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { root }
        }

        fn core(&self, install: bool) -> Core {
            let mut core = Core::new(install);
            core.binary = self.root.path().join("hc");
            core
        }

        fn rows(&self, rows: &[serde_json::Value]) {
            let text = rows
                .iter()
                .map(|row| format!("{row}\n"))
                .collect::<String>();
            std::fs::write(self.root.path().join("rows"), text).unwrap();
        }

        fn events(&self) -> String {
            std::fs::read_to_string(self.root.path().join("events")).unwrap_or_default()
        }

        fn reconciler(&self) -> crate::discovery::Reconciler {
            crate::discovery::Reconciler::new(
                self.root.path(),
                crate::state::Log::new(self.root.path()),
            )
        }
    }

    struct Ready;
    impl crate::attached::DiscoverySource for Ready {
        async fn ready(&self, _: &crate::attached::Host) -> Result<bool> {
            Ok(true)
        }
    }

    fn snapshot(generation: u32, ids: &[u8]) -> crate::attached::Discovery {
        crate::attached::Discovery {
            version: 1,
            generation: generation.to_string(),
            checked_at: 0,
            complete: true,
            hosts: ids
                .iter()
                .map(|id| {
                    let endpoint = format!("{id:02x}").repeat(32);
                    crate::attached::Host {
                        host: "office".into(),
                        ssh_target: format!("attached-{endpoint}"),
                        endpoint_id: endpoint,
                    }
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn core_enrolls_once_prunes_owned_registrations_and_preserves_manual_machines() {
        let fixture = Fixture::new();
        let target = format!("attached-{}", "02".repeat(32));
        fixture
            .rows(&[serde_json::json!({"id":"manual-core", "name":"homelab-ai", "target":target})]);
        let core = fixture.core(false);
        let mut task = fixture.reconciler();
        task.check(&snapshot(0, &[1, 2]), &Ready, &core)
            .await
            .unwrap();
        task.check(&snapshot(0, &[1, 2]), &Ready, &core)
            .await
            .unwrap();
        assert_eq!(core.saved().await.unwrap().len(), 2);
        assert_eq!(*core.notices.borrow(), ["office (01010101)"]);
        for generation in [1, 1, 1, 2] {
            task.check(&snapshot(generation, &[]), &Ready, &core)
                .await
                .unwrap();
            assert!(!fixture.events().contains("remove"));
        }
        task.check(&snapshot(3, &[]), &Ready, &core).await.unwrap();
        let machines = core.saved().await.unwrap();
        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0].name, "homelab-ai");
        task.check(&snapshot(4, &[1, 2]), &Ready, &core)
            .await
            .unwrap();
        assert_eq!(core.saved().await.unwrap().len(), 2);
        assert_eq!(fixture.events().matches("attempt").count(), 2);
        assert!(!fixture.events().contains("--install"));
    }

    #[tokio::test]
    async fn remote_installs_require_opt_in_and_failed_adds_never_claim_ownership() {
        let fixture = Fixture::new();
        std::fs::write(fixture.root.path().join("needs-install"), "").unwrap();
        let core = fixture.core(false);
        fixture
            .reconciler()
            .check(&snapshot(0, &[1]), &Ready, &core)
            .await
            .unwrap();
        assert!(core.saved().await.unwrap().is_empty());
        assert!(core.notices.borrow().is_empty());
        assert!(core.error.borrow().as_ref().unwrap().contains("hc_missing"));
        assert!(
            crate::state::State::load(&fixture.root.path().join("discovery-state.json"))
                .unwrap()
                .managed
                .is_empty()
        );
        let opted_in = fixture.core(true);
        fixture
            .reconciler()
            .check(&snapshot(1, &[1]), &Ready, &opted_in)
            .await
            .unwrap();
        assert_eq!(opted_in.saved().await.unwrap().len(), 1);
        assert!(fixture.events().contains("attempt --install"));
    }

    #[tokio::test]
    async fn same_remote_id_with_a_manual_name_or_session_is_never_removed_or_readopted() {
        let fixture = Fixture::new();
        let core = fixture.core(false);
        let mut task = fixture.reconciler();
        task.check(&snapshot(0, &[1]), &Ready, &core).await.unwrap();
        let owned = core.saved().await.unwrap().remove(0);
        let ownership = owned.ownership().unwrap();
        let mut manual = owned.clone();
        manual.name = "manual".into();
        fixture.rows(&[serde_json::to_value(&manual).unwrap()]);
        assert!(core.remove(&ownership).await.is_err());
        for generation in 1..=4 {
            task.check(&snapshot(generation, &[]), &Ready, &core)
                .await
                .unwrap();
        }
        task.check(&snapshot(5, &[1]), &Ready, &core).await.unwrap();
        assert_eq!(core.saved().await.unwrap(), [manual]);
        assert!(!fixture.events().contains("remove"));
        assert_eq!(fixture.events().matches("attempt").count(), 1);
    }

    #[tokio::test]
    async fn long_publisher_labels_enroll_with_names_accepted_by_hc() {
        let fixture = Fixture::new();
        let core = fixture.core(false);
        for (byte, label) in [
            (1, "proxmox-internal-1"),
            (2, "task-f157c02357a5482bb520a8fb76fe634f"),
        ] {
            let target = format!("attached-{}", format!("{byte:02x}").repeat(32));
            core.add(&target, label).await.unwrap();
        }
        assert!(
            core.saved()
                .await
                .unwrap()
                .iter()
                .all(|m| m.name.len() <= 32)
        );
    }

    #[tokio::test]
    async fn conflicting_names_and_invalid_add_responses_fail_closed() {
        let fixture = Fixture::new();
        let core = fixture.core(false);
        let endpoint = "01".repeat(32);
        let name = machine_name("office", &endpoint);
        fixture.rows(&[serde_json::json!({"id":"manual", "name":name, "target":"direct.example"})]);
        assert!(
            core.add(&format!("attached-{endpoint}"), "office")
                .await
                .is_err()
        );
        assert!(fixture.events().is_empty());
        assert!(core.add("direct.example", "office").await.is_err());
        fixture.rows(&[]);
        std::fs::write(fixture.root.path().join("invalid-response"), "").unwrap();
        assert!(
            core.add(&format!("attached-{endpoint}"), "office")
                .await
                .is_err()
        );
        assert!(core.notices.borrow().is_empty());
    }

    #[test]
    fn names_are_bounded_safe_and_disambiguated_by_stable_endpoint() {
        let first = "01".repeat(32);
        let second = "02".repeat(32);
        assert_eq!(
            machine_name("Office (01010101)", &first),
            "attached-office-01010101"
        );
        assert_ne!(
            machine_name("Office", &first),
            machine_name("Office", &second)
        );
        assert_eq!(machine_name(&"X".repeat(100), &first).len(), 32);
        assert!(machine_name("proxmox-internal-1", &first).len() <= 32);
        assert!(machine_name("task-f157c02357a5482bb520a8fb76fe634f", &first).len() <= 32);
    }
}
