use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, ensure};

use crate::{attached_version::AttachedVersion, identity, local_encryption};

const ATTACHED_BINARY: &str = "attached";
const INSTALLER_URL: &str = "https://install.attached.sh";
const REMOTE_UPDATE_TIMEOUT: Duration = Duration::from_secs(120);
const REMOTE_UPDATE_OUTPUT_LIMIT: u64 = 64 * 1024;

pub fn update() -> Result<()> {
    let executable = current_attached_executable()?;
    let install_dir = executable
        .parent()
        .context("the current Attached executable has no parent directory")?;

    run_installer(
        INSTALLER_URL,
        install_dir,
        Path::new("curl"),
        Path::new("sh"),
    )
}

pub fn uninstall(assume_yes: bool, configured_directory: &Path) -> Result<()> {
    let plan = UninstallPlan::discover(configured_directory)?;

    if !assume_yes {
        ensure!(
            io::stdin().is_terminal(),
            "standard input is not a terminal; rerun with `attached uninstall --yes` to confirm permanent credential deletion"
        );
        if !confirm_uninstall(&plan, &mut io::stdin().lock(), &mut io::stderr().lock())? {
            eprintln!("Uninstall cancelled.");
            return Ok(());
        }
    }

    plan.execute()?;
    eprintln!(
        "Attached was uninstalled. Managed local state was deleted; any 1Password-managed encryption password was preserved for other computers and custom state directories."
    );
    Ok(())
}

pub(crate) fn current_attached_executable() -> Result<PathBuf> {
    let executable =
        env::current_exe().context("could not locate the current Attached executable")?;
    validate_executable_path(&executable)?;
    Ok(executable)
}

fn validate_executable_path(executable: &Path) -> Result<()> {
    ensure!(
        executable.file_name() == Some(OsStr::new(ATTACHED_BINARY)),
        "cannot safely manage an Attached executable renamed to {}",
        executable.display()
    );
    ensure!(
        executable.is_absolute(),
        "the current Attached executable path is not absolute"
    );
    let metadata = fs::symlink_metadata(executable).with_context(|| {
        format!(
            "could not inspect the current Attached executable {}",
            executable.display()
        )
    })?;
    ensure!(
        metadata.file_type().is_file(),
        "the current Attached executable is not a regular file: {}",
        executable.display()
    );
    Ok(())
}

pub(crate) struct PreparedRemoteUpdate {
    executable: PathBuf,
    rollback: Option<tempfile::NamedTempFile>,
    candidate_version: AttachedVersion,
}

impl PreparedRemoteUpdate {
    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(crate) const fn candidate_version(&self) -> AttachedVersion {
        self.candidate_version
    }

    pub(crate) fn commit(mut self) -> Result<()> {
        let rollback = self
            .rollback
            .take()
            .context("update rollback is unavailable")?;
        rollback
            .close()
            .context("could not remove the previous Attached binary after commit")?;
        sync_parent(&self.executable)
    }

    pub(crate) fn rollback(mut self) -> Result<()> {
        let rollback = self
            .rollback
            .take()
            .context("update rollback is unavailable")?;
        restore_backup(&self.executable, rollback)
    }
}

impl Drop for PreparedRemoteUpdate {
    fn drop(&mut self) {
        if let Some(rollback) = self.rollback.take() {
            let _ = restore_backup(&self.executable, rollback);
        }
    }
}

pub(crate) fn prepare_remote_update() -> Result<PreparedRemoteUpdate> {
    prepare_remote_update_at(&current_attached_executable()?)
}

fn prepare_remote_update_at(executable: &Path) -> Result<PreparedRemoteUpdate> {
    validate_executable_path(executable)?;
    let install_dir = executable
        .parent()
        .context("the current Attached executable has no parent directory")?;
    let rollback = tempfile::Builder::new()
        .prefix(".attached-rollback-")
        .tempfile_in(install_dir)
        .with_context(|| {
            format!(
                "could not create an update rollback file in {}",
                install_dir.display()
            )
        })?;
    fs::copy(executable, rollback.path()).with_context(|| {
        format!(
            "could not retain the current Attached binary {}",
            executable.display()
        )
    })?;
    fs::set_permissions(rollback.path(), fs::metadata(executable)?.permissions())?;
    rollback
        .as_file()
        .sync_all()
        .context("could not sync the retained Attached binary")?;

    let mut prepared = PreparedRemoteUpdate {
        executable: executable.to_owned(),
        rollback: Some(rollback),
        candidate_version: crate::attached_version::current(),
    };
    let result = (|| {
        let output = crate::bounded_process::run(
            executable,
            [OsStr::new("update")].as_slice(),
            REMOTE_UPDATE_TIMEOUT,
            REMOTE_UPDATE_OUTPUT_LIMIT,
        )?;
        ensure!(
            output.status.success(),
            "remote `attached update` exited with status {}: {}",
            output.status,
            crate::bounded_process::diagnostic(&output.stderr)
        );
        validate_executable_path(executable)
            .context("the updater did not leave a valid Attached executable")?;
        let candidate_version = crate::attached_version::query(executable)
            .context("could not verify the updated Attached executable")?;
        ensure!(
            candidate_version >= crate::attached_version::current(),
            "the Attached updater installed older version {candidate_version}"
        );
        prepared.candidate_version = candidate_version;
        sync_parent(executable)?;
        Ok(())
    })();
    if let Err(error) = result {
        return match prepared.rollback() {
            Ok(()) => Err(error),
            Err(rollback) => Err(rollback.context(error)),
        };
    }
    Ok(prepared)
}

fn restore_backup(executable: &Path, rollback: tempfile::NamedTempFile) -> Result<()> {
    rollback
        .as_file()
        .sync_all()
        .context("could not sync the retained Attached binary")?;
    let rollback = rollback.into_temp_path();
    fs::rename(&rollback, executable).with_context(|| {
        format!(
            "could not restore the previous Attached binary at {}",
            executable.display()
        )
    })?;
    sync_parent(executable)
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("Attached binary has no parent directory")?;
    fs::File::open(parent)
        .with_context(|| format!("could not open {} for synchronization", parent.display()))?
        .sync_all()
        .with_context(|| format!("could not synchronize {}", parent.display()))
}

fn run_installer(
    url: &str,
    install_dir: &Path,
    curl_executable: &Path,
    shell_executable: &Path,
) -> Result<()> {
    let installer = tempfile::NamedTempFile::new()
        .context("could not create a temporary file for the Attached installer")?;
    let download_status = Command::new(curl_executable)
        .args([
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--retry",
            "3",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
        ])
        .arg(url)
        .arg("--output")
        .arg(installer.path())
        .status()
        .with_context(|| format!("could not run {}", curl_executable.display()))?;
    ensure!(
        download_status.success(),
        "could not download the Attached installer from {url}: curl exited with status {download_status}"
    );

    let installer_status = Command::new(shell_executable)
        .arg(installer.path())
        .env("ATTACHED_INSTALL_DIR", install_dir)
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("could not run {}", shell_executable.display()))?;
    ensure!(
        installer_status.success(),
        "the Attached installer exited with status {installer_status}"
    );
    Ok(())
}

#[derive(Debug)]
struct UninstallPlan {
    executable: PathBuf,
    data_directories: Vec<PathBuf>,
    installer_files: Vec<PathBuf>,
}

impl UninstallPlan {
    fn discover(configured_directory: &Path) -> Result<Self> {
        let executable = current_attached_executable()?;
        let home = env::var_os("HOME").context("HOME is not set")?;
        let home = PathBuf::from(home);
        ensure!(!home.as_os_str().is_empty(), "HOME is empty");
        ensure!(home.is_absolute(), "HOME must be an absolute path");

        Ok(Self {
            executable,
            data_directories: attached_data_directories(
                &home,
                env::var_os("XDG_CONFIG_HOME"),
                Some(configured_directory),
            )?,
            installer_files: vec![home.join(".config/fish/conf.d/attached.env.fish")],
        })
    }

    fn execute(&self) -> Result<()> {
        self.execute_with_store(local_encryption::active_store())
    }

    fn execute_with_store(&self, store: &dyn local_encryption::MasterKeyStore) -> Result<()> {
        validate_executable_path(&self.executable)?;
        for cleanup_path in self
            .data_directories
            .iter()
            .chain(self.installer_files.iter())
        {
            ensure!(
                cleanup_path.is_absolute()
                    && cleanup_path != &self.executable
                    && !self.executable.starts_with(cleanup_path),
                "refusing to uninstall because cleanup path {} overlaps the Attached executable",
                cleanup_path.display()
            );
        }
        ensure_install_directory_is_writable(&self.executable)?;

        local_encryption::with_key_coordination(|| {
            for directory in &self.data_directories {
                remove_path_if_present(directory).with_context(|| {
                    format!(
                        "could not delete Attached credentials and state from {}",
                        directory.display()
                    )
                })?;
            }
            for file in &self.installer_files {
                remove_path_if_present(file).with_context(|| {
                    format!(
                        "could not delete installer metadata from {}",
                        file.display()
                    )
                })?;
            }

            // A 1Password-managed password can be shared by custom directories
            // and other computers that uninstall cannot discover. Preserve it
            // rather than stranding encrypted state outside the managed paths.
            let _ = store;

            fs::remove_file(&self.executable).with_context(|| {
                format!(
                    "credentials and state were deleted, but the Attached executable could not be removed from {}; remove it manually",
                    self.executable.display()
                )
            })?;
            Ok(())
        })
    }
}

fn attached_data_directories(
    home: &Path,
    xdg_config_home: Option<std::ffi::OsString>,
    configured_directory: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let state_directory = identity::state_dir_for_home(home)?;
    ensure!(
        state_directory.is_absolute(),
        "the Attached state directory is not absolute"
    );
    let mut directories = vec![state_directory];

    if let Some(xdg_config_home) = xdg_config_home.filter(|path| !path.is_empty()) {
        let xdg_config_home = PathBuf::from(xdg_config_home);
        ensure!(
            xdg_config_home.is_absolute(),
            "XDG_CONFIG_HOME must be an absolute path"
        );
        let installer_directory = xdg_config_home.join(ATTACHED_BINARY);
        if !directories.contains(&installer_directory) {
            directories.push(installer_directory);
        }
    }

    if let Some(configured_directory) = configured_directory {
        ensure!(
            configured_directory.is_absolute(),
            "the configured Attached directory must be an absolute path"
        );
        if !directories.iter().any(|path| path == configured_directory) {
            directories.push(configured_directory.to_owned());
        }
    }

    Ok(directories)
}

fn ensure_install_directory_is_writable(executable: &Path) -> Result<()> {
    let install_directory = executable
        .parent()
        .context("the current Attached executable has no parent directory")?;
    tempfile::Builder::new()
        .prefix(".attached-uninstall-check-")
        .tempfile_in(install_directory)
        .with_context(|| {
            format!(
                "cannot uninstall Attached because {} is not writable; use the package manager or account that installed it",
                install_directory.display()
            )
        })?;
    Ok(())
}

fn remove_path_if_present(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };

    if metadata.file_type().is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn confirm_uninstall(
    plan: &UninstallPlan,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<bool> {
    writeln!(
        output,
        "This permanently removes Attached and its managed local state:"
    )?;
    writeln!(output, "  binary: {}", plan.executable.display())?;
    for directory in &plan.data_directories {
        writeln!(output, "  data:   {}", directory.display())?;
    }
    writeln!(
        output,
        "Any 1Password-managed encryption password is preserved because other computers and custom state directories cannot be discovered."
    )?;
    writeln!(
        output,
        "Exported account bundle files are not tracked and must be deleted separately."
    )?;
    write!(output, "Continue? [y/N] ")?;
    output.flush()?;

    let mut answer = String::new();
    input
        .read_line(&mut answer)
        .context("could not read uninstall confirmation")?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Cursor,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use super::*;
    use zeroize::Zeroizing;

    #[derive(Default)]
    struct RemovalStore {
        remove_calls: std::sync::Mutex<usize>,
        unavailable: bool,
    }

    impl crate::local_encryption::MasterKeyStore for RemovalStore {
        fn load_or_create(
            &self,
            _directory: &crate::secure_state::StateDir,
            _create: bool,
        ) -> Result<Zeroizing<[u8; 32]>> {
            unreachable!()
        }

        fn remove(&self) -> Result<()> {
            *self.remove_calls.lock().unwrap() += 1;
            if self.unavailable {
                anyhow::bail!("synthetic backend detail")
            }
            Ok(())
        }
    }

    fn executable(root: &Path) -> PathBuf {
        let bin = root.join("bin");
        fs::create_dir(&bin).unwrap();
        let executable = bin.join(ATTACHED_BINARY);
        fs::write(&executable, b"synthetic attached").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        executable
    }

    fn script(path: &Path, body: &str) {
        fs::write(path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn updater_downloads_securely_and_reuses_the_current_install_directory() {
        let root = crate::test_support::canonical_tempdir();
        let curl = root.path().join("curl");
        let installer_fixture = root.path().join("installer-fixture");
        let curl_arguments = root.path().join("curl-arguments");
        let observed_install_dir = root.path().join("observed-install-dir");
        let install_dir = root.path().join("install target");
        fs::create_dir(&install_dir).unwrap();

        script(
            &installer_fixture,
            &format!(
                "printf '%s' \"$ATTACHED_INSTALL_DIR\" > '{}'",
                observed_install_dir.display()
            ),
        );
        script(
            &curl,
            &format!(
                "printf '%s\\n' \"$@\" > '{}'\nout=''\nfor argument in \"$@\"; do out=$argument; done\ncp '{}' \"$out\"",
                curl_arguments.display(),
                installer_fixture.display()
            ),
        );

        run_installer(INSTALLER_URL, &install_dir, &curl, Path::new("/bin/sh")).unwrap();

        assert_eq!(
            fs::read_to_string(observed_install_dir).unwrap(),
            install_dir.to_str().unwrap()
        );
        let arguments = fs::read_to_string(curl_arguments).unwrap();
        for expected in [
            "--proto",
            "=https",
            "--proto-redir",
            "--tlsv1.2",
            "--fail",
            "--location",
            INSTALLER_URL,
        ] {
            assert!(
                arguments.lines().any(|argument| argument == expected),
                "{arguments}"
            );
        }
    }

    #[test]
    fn updater_reports_download_and_installer_failures() {
        let root = crate::test_support::canonical_tempdir();
        let failed_curl = root.path().join("failed-curl");
        script(&failed_curl, "exit 22");
        let error = run_installer(
            INSTALLER_URL,
            root.path(),
            &failed_curl,
            Path::new("/bin/sh"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("curl exited with status"), "{error}");
        assert!(error.contains("22"), "{error}");

        let installer_fixture = root.path().join("failed-installer");
        script(&installer_fixture, "exit 17");
        let curl = root.path().join("curl");
        script(
            &curl,
            &format!(
                "out=''\nfor argument in \"$@\"; do out=$argument; done\ncp '{}' \"$out\"",
                installer_fixture.display()
            ),
        );
        let error = run_installer(INSTALLER_URL, root.path(), &curl, Path::new("/bin/sh"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("installer exited with status"), "{error}");
        assert!(error.contains("17"), "{error}");
    }

    #[test]
    fn prepared_remote_update_commits_or_restores_on_rollback_and_drop() {
        enum Finish {
            Commit,
            Rollback,
            Drop,
        }
        for finish in [Finish::Commit, Finish::Rollback, Finish::Drop] {
            let root = crate::test_support::canonical_tempdir();
            let executable = root.path().join(ATTACHED_BINARY);
            let candidate = root.path().join("candidate");
            script(
                &candidate,
                "if [ \"${1-}\" = --version ]; then printf 'attached 9.9.9\\n'; exit 0; fi\nexit 9",
            );
            script(
                &executable,
                &format!(
                    "if [ \"${{1-}}\" = update ]; then cp '{}' \"$0.next\"; chmod 700 \"$0.next\"; mv \"$0.next\" \"$0\"; exit 0; fi\nif [ \"${{1-}}\" = --version ]; then printf 'attached {}\\n'; exit 0; fi\nexit 9",
                    candidate.display(),
                    env!("CARGO_PKG_VERSION")
                ),
            );

            let original = fs::read(&executable).unwrap();
            let prepared = prepare_remote_update_at(&executable).unwrap();
            assert_eq!(prepared.candidate_version(), AttachedVersion::new(9, 9, 9));
            assert_eq!(
                crate::attached_version::query(&executable).unwrap(),
                AttachedVersion::new(9, 9, 9)
            );
            let committed = matches!(finish, Finish::Commit);
            match finish {
                Finish::Commit => prepared.commit().unwrap(),
                Finish::Rollback => prepared.rollback().unwrap(),
                Finish::Drop => drop(prepared),
            }
            if committed {
                assert_eq!(
                    fs::read(&executable).unwrap(),
                    fs::read(&candidate).unwrap()
                );
            } else {
                assert_eq!(fs::read(&executable).unwrap(), original);
            }
            assert_eq!(
                fs::read_dir(root.path()).unwrap().count(),
                2,
                "rollback file leaked"
            );
        }
    }

    #[test]
    fn failed_remote_update_restores_the_previous_binary() {
        let root = crate::test_support::canonical_tempdir();
        let executable = root.path().join(ATTACHED_BINARY);
        let broken = root.path().join("broken");
        script(&broken, "printf broken; exit 19");
        script(
            &executable,
            &format!(
                "if [ \"${{1-}}\" = update ]; then cp '{}' \"$0.next\"; chmod 700 \"$0.next\"; mv \"$0.next\" \"$0\"; exit 7; fi\nif [ \"${{1-}}\" = --version ]; then printf 'attached {}\\n'; exit 0; fi\nexit 9",
                broken.display(),
                env!("CARGO_PKG_VERSION")
            ),
        );

        let error = prepare_remote_update_at(&executable)
            .err()
            .expect("failed updater was accepted");
        assert!(error.to_string().contains("status"), "{error:#}");
        assert_eq!(
            crate::attached_version::query(&executable).unwrap(),
            crate::attached_version::current()
        );
    }

    #[test]
    fn uninstall_removes_the_binary_credentials_state_and_installer_receipt() {
        let root = crate::test_support::canonical_tempdir();
        let executable = executable(root.path());
        let home = root.path().join("home");
        let state = home.join(".config/attached");
        let xdg_state = root.path().join("xdg/attached");
        let fish_configuration = home.join(".config/fish/conf.d/attached.env.fish");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&xdg_state).unwrap();
        fs::create_dir_all(fish_configuration.parent().unwrap()).unwrap();
        fs::write(state.join("sync-account.json"), b"credential").unwrap();
        fs::write(xdg_state.join("attached-receipt.json"), b"receipt").unwrap();
        fs::write(&fish_configuration, b"installer path setup").unwrap();

        let plan = UninstallPlan {
            executable: executable.clone(),
            data_directories: attached_data_directories(
                &home,
                Some(root.path().join("xdg").into_os_string()),
                None,
            )
            .unwrap(),
            installer_files: vec![fish_configuration.clone()],
        };
        let store = RemovalStore::default();
        plan.execute_with_store(&store).unwrap();

        assert!(!executable.exists());
        assert!(!state.exists());
        assert!(!xdg_state.exists());
        assert!(!fish_configuration.exists());
        assert_eq!(*store.remove_calls.lock().unwrap(), 0);
    }

    #[test]
    fn uninstall_preserves_shared_key_for_undiscoverable_custom_state() {
        let root = crate::test_support::canonical_tempdir();
        let executable = executable(root.path());
        let managed_state = root.path().join("managed-state");
        fs::create_dir(&managed_state).unwrap();
        let custom_state = root.path().join("custom-state");
        fs::create_dir(&custom_state).unwrap();
        fs::write(custom_state.join("ciphertext"), b"still encrypted").unwrap();
        let plan = UninstallPlan {
            executable,
            data_directories: vec![managed_state],
            installer_files: Vec::new(),
        };
        let store = RemovalStore::default();

        plan.execute_with_store(&store).unwrap();

        assert_eq!(*store.remove_calls.lock().unwrap(), 0);
        assert_eq!(
            fs::read(custom_state.join("ciphertext")).unwrap(),
            b"still encrypted"
        );
    }

    #[test]
    fn uninstall_does_not_touch_the_shared_one_password_item() {
        let root = crate::test_support::canonical_tempdir();
        let executable = executable(root.path());
        let state = root.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::write(state.join("ciphertext"), b"encrypted").unwrap();
        let plan = UninstallPlan {
            executable: executable.clone(),
            data_directories: vec![state.clone()],
            installer_files: Vec::new(),
        };
        let store = RemovalStore {
            unavailable: true,
            ..RemovalStore::default()
        };

        plan.execute_with_store(&store).unwrap();
        assert!(!state.exists());
        assert!(!executable.exists());
        assert_eq!(*store.remove_calls.lock().unwrap(), 0);
    }

    #[test]
    fn uninstall_does_not_follow_a_state_directory_symlink() {
        let root = crate::test_support::canonical_tempdir();
        let executable = executable(root.path());
        let external = root.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("keep"), b"keep").unwrap();
        let linked_state = root.path().join("linked-state");
        symlink(&external, &linked_state).unwrap();

        let plan = UninstallPlan {
            executable: executable.clone(),
            data_directories: vec![linked_state.clone()],
            installer_files: Vec::new(),
        };
        plan.execute_with_store(&RemovalStore::default()).unwrap();

        assert!(!executable.exists());
        assert!(!linked_state.exists());
        assert_eq!(fs::read(external.join("keep")).unwrap(), b"keep");
    }

    #[test]
    fn uninstall_rejects_cleanup_paths_that_overlap_the_executable() {
        let root = crate::test_support::canonical_tempdir();
        let executable = executable(root.path());
        let error = UninstallPlan {
            executable: executable.clone(),
            data_directories: vec![executable.clone()],
            installer_files: Vec::new(),
        }
        .execute()
        .unwrap_err()
        .to_string();

        assert!(error.contains("overlaps"), "{error}");
        assert!(executable.exists());
    }

    #[test]
    fn uninstall_confirmation_is_explicit_and_warns_about_exported_bundles() {
        let plan = UninstallPlan {
            executable: PathBuf::from("/home/person/.local/bin/attached"),
            data_directories: vec![PathBuf::from("/home/person/.config/attached")],
            installer_files: Vec::new(),
        };

        for accepted in ["y\n", "YES\n", " yes \n"] {
            let mut output = Vec::new();
            assert!(confirm_uninstall(&plan, &mut Cursor::new(accepted), &mut output).unwrap());
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains("permanently"), "{output}");
            assert!(output.contains("bundle files"), "{output}");
        }
        for rejected in ["\n", "n\n", "anything else\n"] {
            assert!(
                !confirm_uninstall(&plan, &mut Cursor::new(rejected), &mut Vec::new()).unwrap()
            );
        }
    }

    #[test]
    fn uninstall_includes_the_configured_directory_without_duplicates() {
        let root = crate::test_support::canonical_tempdir();
        let home = root.path().join("home");
        let configured = root.path().join("configured");

        let directories = attached_data_directories(&home, None, Some(&configured)).unwrap();
        assert_eq!(
            directories,
            vec![home.join(".config/attached"), configured.clone()]
        );

        let default = home.join(".config/attached");
        assert_eq!(
            attached_data_directories(&home, None, Some(&default)).unwrap(),
            vec![default]
        );
    }

    #[test]
    fn lifecycle_commands_reject_renamed_executables_and_relative_config_roots() {
        let root = crate::test_support::canonical_tempdir();
        let renamed = root.path().join("renamed");
        fs::write(&renamed, b"binary").unwrap();
        assert!(validate_executable_path(&renamed).is_err());

        let error = attached_data_directories(root.path(), Some("relative".into()), None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("XDG_CONFIG_HOME"), "{error}");
    }
}
