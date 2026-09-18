//! Local names for independent synchronization accounts. The legacy directory is
//! the implicit `default` workspace: no keys, host pins, or salts are moved.
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::secure_state::{self, StateDir};

pub(crate) const DEFAULT: &str = "default";
pub(crate) const INDEX: &str = "workspace-index.json";
pub(crate) const MAX_INDEX_BYTES: usize = 16 * 1024;
const LOCK: &str = "workspace-index.lock";
const MAX_WORKSPACES: usize = 64;

#[derive(Clone, Debug)]
pub(crate) struct Workspace {
    pub name: String,
    pub path: PathBuf,
}

impl Workspace {
    pub(crate) fn ssh_target(&self, endpoint: &str) -> String {
        ssh_target(&self.name, endpoint)
    }
}

// `--` separates the workspace from the host. Forbidding it in workspace names
// prevents client-acme/office and client/acme-office from sharing an alias.
pub(crate) fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 32
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
            && !name.contains("--"),
        "workspace names must be 1–32 lowercase letters, digits, underscores or hyphens, start with a letter or digit, and not contain `--`"
    );
    Ok(())
}

pub(crate) fn ssh_target(workspace: &str, host: &str) -> String {
    if workspace == DEFAULT {
        format!("attached-{host}")
    } else {
        qualified_target(workspace, host)
    }
}

pub(crate) fn qualified_target(workspace: &str, host: &str) -> String {
    format!("attached-{workspace}--{host}")
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u8,
    selected: String,
    names: BTreeSet<String>,
}

impl Default for Index {
    fn default() -> Self {
        Self {
            version: 1,
            selected: DEFAULT.into(),
            names: BTreeSet::from([DEFAULT.into()]),
        }
    }
}

impl Index {
    fn read(directory: &StateDir) -> Result<Self> {
        let bytes = directory.read_secret_optional_bounded(INDEX, MAX_INDEX_BYTES)?;
        Self::parse(bytes.as_ref().map(|bytes| bytes.as_slice()))
    }

    fn parse(bytes: Option<&[u8]>) -> Result<Self> {
        let index = match bytes {
            Some(bytes) => {
                ensure!(
                    bytes.len() <= MAX_INDEX_BYTES,
                    "workspace index is too large"
                );
                serde_json::from_slice::<Self>(bytes).context("invalid workspace index")?
            }
            None => Self::default(),
        };
        ensure!(index.version == 1, "unsupported workspace index version");
        ensure!(index.names.len() <= MAX_WORKSPACES, "too many workspaces");
        ensure!(
            index.names.contains(DEFAULT) && index.names.contains(&index.selected),
            "invalid selected workspace"
        );
        for name in &index.names {
            validate_name(name)?;
        }
        Ok(index)
    }

    fn save(&self, directory: &StateDir) -> Result<()> {
        directory.atomic_replace(INDEX, &serde_json::to_vec(self)?)
    }
}

/// Uninstall only descends into names registered in a validated local index.
/// The caller reads it through its pinned, no-follow directory handle.
pub(crate) fn registered_names(bytes: Option<&[u8]>) -> Result<Vec<String>> {
    Ok(Index::parse(bytes)?
        .names
        .into_iter()
        .filter(|name| name != DEFAULT)
        .collect())
}

pub(crate) struct Workspaces {
    root: PathBuf,
}

impl Workspaces {
    pub(crate) fn new(root: &Path) -> Result<Self> {
        secure_state::prepare_private_dir(root)?;
        Ok(Self {
            root: root.to_owned(),
        })
    }

    fn at(&self, name: &str) -> Workspace {
        Workspace {
            name: name.into(),
            path: if name == DEFAULT {
                self.root.clone()
            } else {
                self.root.join("workspaces").join(name)
            },
        }
    }

    /// Resolve once, before starting a long-running operation. Changing the
    /// selection in another process must never redirect an existing publisher.
    pub(crate) fn resolve(&self, name: Option<&str>, allow_new: bool) -> Result<Workspace> {
        secure_state::with_exclusive_lock(&self.root, LOCK, |directory| {
            let index = Index::read(directory)?;
            let name = name.unwrap_or(&index.selected);
            validate_name(name)?;
            ensure!(
                index.names.contains(name) || index.names.len() < MAX_WORKSPACES,
                "at most {MAX_WORKSPACES} workspaces are supported"
            );
            ensure!(
                allow_new || index.names.contains(name),
                "unknown workspace `{name}`; use `attached account create --workspace {name}`, `account import --workspace {name}`, or `serve --workspace {name}` first"
            );
            let workspace = self.at(name);
            // All components are opened without following symlinks by StateDir.
            secure_state::prepare_private_dir(&workspace.path)?;
            Ok(workspace)
        })
    }

    pub(crate) fn register(&self, workspace: &Workspace) -> Result<()> {
        validate_name(&workspace.name)?;
        ensure!(
            workspace.path == self.at(&workspace.name).path,
            "workspace path mismatch"
        );
        secure_state::with_exclusive_lock(&self.root, LOCK, |directory| {
            let mut index = Index::read(directory)?;
            if index.names.insert(workspace.name.clone()) {
                ensure!(
                    index.names.len() <= MAX_WORKSPACES,
                    "at most {MAX_WORKSPACES} workspaces are supported"
                );
                index.save(directory)?;
            }
            Ok(())
        })
    }

    pub(crate) fn select(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        secure_state::with_exclusive_lock(&self.root, LOCK, |directory| {
            let mut index = Index::read(directory)?;
            ensure!(
                index.names.contains(name),
                "unknown workspace `{name}`; create or import its account first"
            );
            index.selected = name.into();
            index.save(directory)
        })
    }

    pub(crate) fn list(&self) -> Result<(String, Vec<Workspace>)> {
        secure_state::with_exclusive_lock(&self.root, LOCK, |directory| {
            let index = Index::read(directory)?;
            Ok((
                index.selected,
                index.names.iter().map(|name| self.at(name)).collect(),
            ))
        })
    }

    pub(crate) fn selection(&self, name: Option<&str>, all: bool) -> Result<Vec<Workspace>> {
        ensure!(
            !all || name.is_none(),
            "--workspace conflicts with --all-workspaces"
        );
        if all {
            Ok(self.list()?.1)
        } else {
            Ok(vec![self.resolve(name, false)?])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preserves_legacy_state_and_selection_is_persistent_but_not_live() {
        let root = crate::test_support::canonical_tempdir();
        let store = Workspaces::new(root.path()).unwrap();
        let original = store.resolve(None, false).unwrap();
        assert_eq!(original.path, root.path());
        let work = store.resolve(Some("work"), true).unwrap();
        assert_eq!(work.path, root.path().join("workspaces/work"));
        assert!(store.resolve(Some("work"), false).is_err());
        store.register(&work).unwrap();
        store.select("work").unwrap();
        assert_eq!(
            Workspaces::new(root.path())
                .unwrap()
                .resolve(None, false)
                .unwrap()
                .path,
            work.path
        );
        assert_eq!(original.path, root.path());
        assert_eq!(
            store.resolve(Some(DEFAULT), false).unwrap().path,
            root.path()
        );
        assert_eq!(store.selection(None, true).unwrap().len(), 2);
        assert!(store.selection(Some("work"), true).is_err());
    }

    #[test]
    fn rejects_unsafe_names_unknown_selections_and_symlinks() {
        let root = crate::test_support::canonical_tempdir();
        let store = Workspaces::new(root.path()).unwrap();
        for name in [
            "",
            "..",
            "../outside",
            "/tmp",
            "Work",
            "a.b",
            "-work",
            "work--one",
            "work\n",
            &"a".repeat(33),
        ] {
            assert!(store.resolve(Some(name), true).is_err(), "{name}");
        }
        assert!(store.select("missing").is_err());
        std::os::unix::fs::symlink("/tmp", root.path().join("workspaces")).unwrap();
        assert!(store.resolve(Some("work"), true).is_err());
    }

    #[test]
    fn concurrent_registration_does_not_lose_workspaces() {
        let root = crate::test_support::canonical_tempdir();
        std::thread::scope(|scope| {
            for name in ["work", "personal", "client-acme"] {
                let path = root.path();
                scope.spawn(move || {
                    let store = Workspaces::new(path).unwrap();
                    let workspace = store.resolve(Some(name), true).unwrap();
                    store.register(&workspace).unwrap();
                });
            }
        });
        assert_eq!(
            Workspaces::new(root.path())
                .unwrap()
                .list()
                .unwrap()
                .1
                .len(),
            4
        );
    }

    #[test]
    fn aliases_have_unambiguous_workspace_boundaries() {
        assert_eq!(ssh_target(DEFAULT, "office"), "attached-office");
        assert_eq!(ssh_target("work", "office"), "attached-work--office");
        assert_ne!(
            ssh_target("client-acme", "office"),
            ssh_target("client", "acme-office")
        );
    }
}
