use std::{
    fs::File,
    io::{self, Read as _},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use rustix::fs::{Mode, OFlags};
use serde::Deserialize;

use crate::{identity, secure_state};

const CONFIG_FILE: &str = "config.toml";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PasswordSource {
    #[default]
    Password,
    #[serde(rename = "1password")]
    OnePassword,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    password_source: PasswordSource,
    config_directory: Option<PathBuf>,
    notification_terminal: Option<PathBuf>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Config {
    password_source: PasswordSource,
    config_directory: PathBuf,
    notification_terminal: Option<PathBuf>,
}

impl Config {
    pub(crate) fn load() -> Result<Self> {
        let default_directory = identity::default_state_dir()?;
        secure_state::prepare_private_dir(&default_directory)
            .context("could not prepare the Attached configuration directory")?;
        Self::load_from(&default_directory.join(CONFIG_FILE), default_directory)
    }

    fn load_from(path: &Path, default_directory: PathBuf) -> Result<Self> {
        let Some(mut file) = open_config_file(path)? else {
            return Ok(Self {
                password_source: PasswordSource::default(),
                config_directory: default_directory,
                notification_terminal: None,
            });
        };

        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("could not read configuration {}", path.display()))?;
        ensure!(
            bytes.len() as u64 <= MAX_CONFIG_BYTES,
            "configuration {} exceeds {MAX_CONFIG_BYTES} bytes",
            path.display()
        );
        let contents = std::str::from_utf8(&bytes)
            .with_context(|| format!("configuration {} is not valid UTF-8", path.display()))?;
        let parsed: FileConfig = toml::from_str(contents)
            .with_context(|| format!("could not parse configuration {}", path.display()))?;
        let config_directory = parsed.config_directory.unwrap_or(default_directory);
        ensure!(
            !config_directory.as_os_str().is_empty(),
            "`config_directory` in {} cannot be empty",
            path.display()
        );
        ensure!(
            config_directory.is_absolute(),
            "`config_directory` in {} must be an absolute path",
            path.display()
        );

        ensure!(
            parsed
                .notification_terminal
                .as_ref()
                .is_none_or(|terminal| !terminal.as_os_str().is_empty()),
            "`notification_terminal` in {} cannot be empty",
            path.display()
        );
        Ok(Self {
            password_source: parsed.password_source,
            config_directory,
            notification_terminal: parsed.notification_terminal,
        })
    }

    pub(crate) fn use_one_password(&self, cli_override: bool) -> bool {
        cli_override || self.password_source == PasswordSource::OnePassword
    }

    pub(crate) fn resolve_notification_terminal(
        &self,
        cli_override: Option<PathBuf>,
    ) -> Option<PathBuf> {
        cli_override.or_else(|| self.notification_terminal.clone())
    }

    pub(crate) fn config_directory(&self) -> &Path {
        &self.config_directory
    }
}

fn open_config_file(path: &Path) -> Result<Option<File>> {
    // A FIFO at the config path would block a normal File::open until another
    // process opens the writer end. Open nonblocking, then accept regular files
    // only; O_NONBLOCK has no effect on ordinary configuration files.
    let file = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(error) => {
            let error = io::Error::from(error);
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(error)
                .with_context(|| format!("could not open configuration {}", path.display()));
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect configuration {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "configuration {} is not a regular file",
        path.display()
    );
    Ok(Some(file))
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use super::*;

    #[test]
    fn missing_file_uses_existing_attached_defaults() {
        let root = crate::test_support::canonical_tempdir();
        let default_directory = root.path().join("attached");

        assert_eq!(
            Config::load_from(
                &default_directory.join(CONFIG_FILE),
                default_directory.clone()
            )
            .unwrap(),
            Config {
                password_source: PasswordSource::Password,
                config_directory: default_directory,
                notification_terminal: None,
            }
        );
    }

    #[test]
    fn reads_password_source_and_config_directory_from_toml() {
        let root = crate::test_support::canonical_tempdir();
        let default_directory = root.path().join("attached");
        fs::create_dir(&default_directory).unwrap();
        let configured_directory = root.path().join("custom-attached");
        fs::write(
            default_directory.join(CONFIG_FILE),
            format!(
                "password_source = \"1password\"\nconfig_directory = {:?}\n",
                configured_directory
            ),
        )
        .unwrap();

        assert_eq!(
            Config::load_from(
                &default_directory.join(CONFIG_FILE),
                default_directory.clone()
            )
            .unwrap(),
            Config {
                password_source: PasswordSource::OnePassword,
                config_directory: configured_directory,
                notification_terminal: None,
            }
        );
    }

    #[test]
    fn each_setting_can_be_omitted_independently() {
        let root = crate::test_support::canonical_tempdir();
        let default_directory = root.path().join("attached");
        fs::create_dir(&default_directory).unwrap();
        fs::write(
            default_directory.join(CONFIG_FILE),
            "password_source = \"1password\"\n",
        )
        .unwrap();

        let loaded = Config::load_from(
            &default_directory.join(CONFIG_FILE),
            default_directory.clone(),
        )
        .unwrap();
        assert_eq!(loaded.password_source, PasswordSource::OnePassword);
        assert_eq!(loaded.config_directory, default_directory);
    }

    #[test]
    fn notification_terminal_and_password_overrides_follow_config_precedence() {
        let root = crate::test_support::canonical_tempdir();
        let path = root.path().join(CONFIG_FILE);
        let missing = Config::load_from(&path, root.path().to_path_buf()).unwrap();
        assert!(
            !missing.use_one_password(false),
            "password prompt remains the default"
        );
        assert!(missing.use_one_password(true));
        assert_eq!(missing.resolve_notification_terminal(None), None);
        for (source, use_one_password) in [("password", false), ("1password", true)] {
            fs::write(
                &path,
                format!("password_source = {source:?}\nnotification_terminal = \"ghostty\"\n"),
            )
            .unwrap();
            let config = Config::load_from(&path, root.path().to_path_buf()).unwrap();
            assert_eq!(config.use_one_password(false), use_one_password);
            assert!(config.use_one_password(true));
            assert_eq!(
                config.resolve_notification_terminal(None),
                Some("ghostty".into())
            );
            assert_eq!(
                config.resolve_notification_terminal(Some("terminal".into())),
                Some("terminal".into())
            );
        }
        fs::write(
            &path,
            "notification_terminal = \"/Users/me/My Apps/Ghostty.app\"\n",
        )
        .unwrap();
        let config = Config::load_from(&path, root.path().to_path_buf()).unwrap();
        assert_eq!(
            config.resolve_notification_terminal(None),
            Some("/Users/me/My Apps/Ghostty.app".into())
        );
        assert!(!config.use_one_password(false));
    }

    #[test]
    fn rejects_invalid_sources_unknown_fields_and_relative_directories() {
        let root = crate::test_support::canonical_tempdir();
        let default_directory = root.path().join("attached");
        fs::create_dir(&default_directory).unwrap();
        let path = default_directory.join(CONFIG_FILE);

        for contents in [
            "password_source = \"keychain\"\n",
            "unknown = true\n",
            "config_directory = \"relative\"\n",
            "notification_terminal = \"\"\n",
            "notification_terminal = true\n",
        ] {
            fs::write(&path, contents).unwrap();
            assert!(
                Config::load_from(&path, default_directory.clone()).is_err(),
                "accepted invalid configuration: {contents}"
            );
        }
    }

    #[test]
    fn configuration_file_must_be_a_regular_file() {
        let root = crate::test_support::canonical_tempdir();
        let default_directory = root.path().join("attached");
        fs::create_dir(&default_directory).unwrap();
        let path = default_directory.join(CONFIG_FILE);
        fs::create_dir(&path).unwrap();

        let error = Config::load_from(&path, default_directory)
            .unwrap_err()
            .to_string();

        assert!(error.contains("not a regular file"), "{error}");
    }

    #[test]
    fn configuration_file_symlink_to_regular_file_is_supported() {
        let root = crate::test_support::canonical_tempdir();
        let default_directory = root.path().join("attached");
        fs::create_dir(&default_directory).unwrap();
        let target = root.path().join("outside.toml");
        fs::write(&target, "password_source = \"1password\"\n").unwrap();
        let path = default_directory.join(CONFIG_FILE);
        symlink(&target, &path).unwrap();

        assert_eq!(
            Config::load_from(&path, default_directory.clone()).unwrap(),
            Config {
                password_source: PasswordSource::OnePassword,
                config_directory: default_directory,
                notification_terminal: None,
            }
        );
        assert_eq!(
            fs::read_to_string(target).unwrap(),
            "password_source = \"1password\"\n"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn fifo_configuration_is_rejected_without_waiting_for_a_writer() {
        let root = crate::test_support::canonical_tempdir();
        let default_directory = root.path().join("attached");
        fs::create_dir(&default_directory).unwrap();
        let directory = File::open(&default_directory).unwrap();
        rustix::fs::mkfifoat(&directory, CONFIG_FILE, Mode::RUSR | Mode::WUSR).unwrap();
        let path = default_directory.join(CONFIG_FILE);

        let started = std::time::Instant::now();
        let error = Config::load_from(&path, default_directory)
            .unwrap_err()
            .to_string();

        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "FIFO configuration open blocked for {:?}",
            started.elapsed()
        );
        assert!(error.contains("not a regular file"), "{error}");
    }
}
