use std::{
    fs::File,
    io::{self, Read as _},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
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
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Config {
    password_source: PasswordSource,
    config_directory: PathBuf,
}

impl Config {
    pub(crate) fn load() -> Result<Self> {
        let default_directory = identity::default_state_dir()?;
        secure_state::prepare_private_dir(&default_directory)
            .context("could not prepare the Attached configuration directory")?;
        Self::load_from(&default_directory.join(CONFIG_FILE), default_directory)
    }

    fn load_from(path: &Path, default_directory: PathBuf) -> Result<Self> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    password_source: PasswordSource::default(),
                    config_directory: default_directory,
                });
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("could not open configuration {}", path.display()));
            }
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

        Ok(Self {
            password_source: parsed.password_source,
            config_directory,
        })
    }

    pub(crate) const fn password_source(&self) -> PasswordSource {
        self.password_source
    }

    pub(crate) fn config_directory(&self) -> &Path {
        &self.config_directory
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

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
    fn rejects_invalid_sources_unknown_fields_and_relative_directories() {
        let root = crate::test_support::canonical_tempdir();
        let default_directory = root.path().join("attached");
        fs::create_dir(&default_directory).unwrap();
        let path = default_directory.join(CONFIG_FILE);

        for contents in [
            "password_source = \"keychain\"\n",
            "unknown = true\n",
            "config_directory = \"relative\"\n",
        ] {
            fs::write(&path, contents).unwrap();
            assert!(
                Config::load_from(&path, default_directory.clone()).is_err(),
                "accepted invalid configuration: {contents}"
            );
        }
    }
}
