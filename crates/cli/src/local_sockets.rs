use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use rustix::process::geteuid;
use tempfile::{Builder, TempDir};
use tokio::net::UnixListener;

const TUI_SOCKET_NAME: &str = "herdr-client.sock";

pub struct SocketWorkspace {
    _directory: TempDir,
    tui_path: PathBuf,
}

impl SocketWorkspace {
    pub async fn create() -> Result<(Self, UnixListener)> {
        let directory = Builder::new()
            .prefix("attached-tunnel-")
            .tempdir()
            .context("failed to create private proxy directory")?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        validate_private(directory.path(), 0o700)?;

        let tui_path = directory.path().join(TUI_SOCKET_NAME);
        let tui = bind_private(&tui_path).await?;

        Ok((
            Self {
                _directory: directory,
                tui_path,
            },
            tui,
        ))
    }

    pub fn tui_path(&self) -> &Path {
        &self.tui_path
    }
}

async fn bind_private(path: &Path) -> Result<UnixListener> {
    let listener = UnixListener::bind(path)
        .with_context(|| format!("failed to bind private proxy socket {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    validate_private(path, 0o600)?;
    Ok(listener)
}

fn validate_private(path: &Path, expected_mode: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.uid() == geteuid().as_raw(),
        "{} is not owned by the current user",
        path.display()
    );
    ensure!(
        metadata.mode() & 0o777 == expected_mode,
        "{} does not have mode {:03o}",
        path.display(),
        expected_mode
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory_path(workspace: &SocketWorkspace) -> &Path {
        workspace._directory.path()
    }

    #[tokio::test]
    async fn workspaces_are_unique_private_and_removed_on_drop() {
        let (first, first_listeners) = SocketWorkspace::create().await.unwrap();
        let (second, second_listeners) = SocketWorkspace::create().await.unwrap();
        assert_ne!(directory_path(&first), directory_path(&second));
        assert_eq!(first.tui_path().file_name().unwrap(), TUI_SOCKET_NAME);
        assert_eq!(
            fs::metadata(directory_path(&first)).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(first.tui_path()).unwrap().mode() & 0o777,
            0o600
        );

        let first_directory = directory_path(&first).to_owned();
        drop(first_listeners);
        drop(first);
        assert!(!first_directory.exists());

        drop(second_listeners);
        drop(second);
    }
}
