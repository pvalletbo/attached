use std::{
    io::{Write as _, stdout},
    path::PathBuf,
};

use anyhow::{Context, Result, ensure};
use attached_session_sync_protocol::account::ApiKeyScope;
use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroizing;

use crate::{
    account_clipboard, download_account, herdr_version, identity, installation, local_encryption,
    publish_account, secure_state, server, session,
    session_picker::{self, SessionSelection},
    sync,
};

#[derive(Parser)]
#[command(
    version,
    about = "Discover and attach to synchronized Herdr sessions over Iroh"
)]
pub struct Cli {
    /// Increase diagnostic verbosity (`-v` for lifecycle, `-vv` for debug details).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Write span timings in folded-stack format for flamegraph generation.
    ///
    /// Pass `-vv` as well to print each span's busy and idle durations.
    #[arg(long, value_name = "FILE", global = true)]
    flamegraph: Option<PathBuf>,

    /// Have 1Password generate and store the encryption password instead of prompting for one.
    #[arg(long, global = true)]
    use_1password: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create, export, or import synchronization credentials.
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },

    /// Publish this host's running Herdr sessions.
    Serve {
        /// Path to the Herdr executable used for session discovery.
        #[arg(long, default_value = "herdr")]
        herdr_bin: PathBuf,

        /// Stable label shown for this host in synchronized catalogs.
        #[arg(long)]
        host_label: Option<String>,

        /// Publish bundle file used when ATTACHED_PUBLISH_BUNDLE is unset.
        ///
        /// On first use without either source, Attached prompts for the bundle with input hidden.
        #[arg(long, value_name = "FILE")]
        bundle_file: Option<PathBuf>,

        /// Override persistent state location (primarily for testing).
        #[arg(long, hide = true)]
        state_dir: Option<PathBuf>,
    },

    /// Inspect synchronized remote Herdr sessions.
    Sessions {
        #[command(subcommand)]
        command: SessionsCommand,
    },

    /// Select and attach to a local or synchronized Herdr session.
    Attach {
        /// Synchronized `HOST/SESSION`; omit to choose local or synchronized with fzf.
        target: Option<String>,

        /// Path to the local Herdr executable.
        #[arg(long, default_value = "herdr")]
        herdr_bin: PathBuf,

        /// In noninteractive use, request an upgrade when remote Herdr is older than local Herdr.
        ///
        /// The authenticated host runs exactly `herdr update --handoff` with its configured Herdr
        /// executable. This installs from the remote configured channel and attempts Herdr's live
        /// handoff; no requested release is selected. Attachment starts only if the installed
        /// version then exactly matches the local Herdr version. A newer remote fails with
        /// guidance to update local Herdr and is never mutated by this option.
        #[arg(long)]
        upgrade_remote: bool,

        /// Override persistent state location (primarily for testing).
        #[arg(long, hide = true)]
        state_dir: Option<PathBuf>,
    },

    /// Update Attached to the latest release.
    #[command(visible_alias = "upgrade")]
    Update,

    /// Uninstall Attached and permanently delete all managed credentials and local state.
    Uninstall {
        /// Skip the confirmation prompt.
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

const DEFAULT_SERVICE_ORIGIN: &str = "https://herdr.attached.sh";

#[derive(Subcommand)]
enum SessionsCommand {
    /// Refresh and list synchronized remote sessions.
    List {
        /// Path to the local Herdr executable used for compatibility checks.
        #[arg(long, default_value = "herdr")]
        herdr_bin: PathBuf,

        /// Override persistent state location (primarily for testing).
        #[arg(long, hide = true)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum AccountCommand {
    /// Create an account and save it in encrypted local state.
    Create {
        /// Synchronization service used for the new account.
        #[arg(long, default_value = DEFAULT_SERVICE_ORIGIN)]
        service: String,

        #[arg(long, hide = true)]
        state_dir: Option<PathBuf>,
    },

    /// Import a download-only account bundle for controlling synchronized machines.
    Import {
        /// Read the bundle from a file instead of prompting with hidden input.
        #[arg(long, value_name = "FILE", conflicts_with = "bundle_stdin")]
        bundle_file: Option<PathBuf>,

        /// Read the bundle from standard input instead of prompting with hidden input.
        #[arg(long, conflicts_with = "bundle_file")]
        bundle_stdin: bool,

        #[arg(long, hide = true)]
        state_dir: Option<PathBuf>,
    },

    /// Export one scoped secret bundle to the clipboard temporarily or to an explicit file.
    Export {
        /// API-key scope to export (`publish` is also accepted as `push`).
        #[arg(long = "type", value_enum)]
        key_type: AccountKeyType,

        /// Write to a new owner-only file instead of the clipboard. Refuses to overwrite a file.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,

        #[arg(long, hide = true)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AccountKeyType {
    #[value(alias = "push")]
    Publish,
    Download,
}

impl From<AccountKeyType> for ApiKeyScope {
    fn from(value: AccountKeyType) -> Self {
        match value {
            AccountKeyType::Publish => Self::Publish,
            AccountKeyType::Download => Self::Download,
        }
    }
}

impl Cli {
    pub fn verbosity(&self) -> u8 {
        self.verbose
    }

    pub fn flamegraph(&self) -> Option<&std::path::Path> {
        self.flamegraph.as_deref()
    }

    #[tracing::instrument(name = "cli_run", level = "debug", skip_all)]
    pub async fn run(self) -> Result<i32> {
        local_encryption::configure_use_one_password(self.use_1password);
        match self.command {
            Command::Account { command } => {
                match command {
                    AccountCommand::Create { service, state_dir } => {
                        let state_dir = resolved_state_dir(state_dir)?;
                        sync::account::create(&state_dir, &service).await?;
                        eprintln!(
                            "Account created and saved in encrypted local state; no portable account bundle was written."
                        );
                        eprintln!(
                            "Use `attached account export --type publish` to copy a publish-only bundle, then paste it into `attached serve` on the serving host."
                        );
                        eprintln!(
                            "To add another downloader, export with `attached account export --type download --output account.bundle`, transfer the file securely, then run `attached account import --bundle-file account.bundle` there."
                        );
                    }
                    AccountCommand::Import {
                        bundle_file,
                        bundle_stdin,
                        state_dir,
                    } => {
                        let state_dir = resolved_state_dir(state_dir)?;
                        download_account::install(
                            &state_dir,
                            bundle_file.as_deref(),
                            bundle_stdin,
                        )?;
                    }
                    AccountCommand::Export {
                        key_type,
                        output,
                        state_dir,
                    } => {
                        let state_dir = resolved_state_dir(state_dir)?;
                        let scope = ApiKeyScope::from(key_type);
                        let bundle = Zeroizing::new(sync::account::export(&state_dir, scope)?);
                        if let Some(output) = output {
                            write_account_bundle(&bundle, &output)?;
                        } else {
                            account_clipboard::copy(&bundle).context(
                                "could not copy the account bundle to the clipboard; no file was written (retry from a graphical session or pass `--output FILE`)",
                            )?;
                            let destination = match scope {
                                ApiKeyScope::Publish => {
                                    "Paste it into `attached serve` on the serving host"
                                }
                                ApiKeyScope::Download => {
                                    "Paste it into `attached account import` on another computer"
                                }
                            };
                            eprintln!(
                                "Account bundle copied to the clipboard for {} minutes. {destination}; Attached requested that clipboard managers not save it.",
                                account_clipboard::RETENTION.as_secs() / 60
                            );
                        }
                    }
                }
                Ok(0)
            }
            Command::Serve {
                herdr_bin,
                host_label,
                bundle_file,
                state_dir,
            } => {
                let state_dir = resolved_state_dir(state_dir)?;
                publish_account::ensure_configured(&state_dir, bundle_file.as_deref())?;
                server::serve(state_dir, herdr_bin, host_label).await?;
                Ok(0)
            }
            Command::Sessions { command } => match command {
                SessionsCommand::List {
                    herdr_bin,
                    state_dir,
                } => {
                    let state_dir = resolved_state_dir(state_dir)?;
                    sync::state::load_account(&state_dir, ApiKeyScope::Download)
                        .context("`sessions list` requires a download account bundle")?;
                    let local_version = herdr_version::query(&herdr_bin).context(
                        "could not determine the local Herdr version; catalog refresh was not started",
                    )?;
                    let refreshed = sync::refresh::refresh_sessions(&state_dir, local_version)
                        .await
                        .context("could not refresh synchronized sessions")?;
                    for warning in refresh_warnings_to_display(&refreshed.warnings, self.verbose) {
                        eprintln!("Warning: {warning}");
                    }
                    let rendered = session_picker::render_synchronized_list(&refreshed.sessions)?;
                    stdout()
                        .lock()
                        .write_all(rendered.as_bytes())
                        .context("could not write synchronized session list")?;
                    Ok(0)
                }
            },
            Command::Attach {
                target,
                herdr_bin,
                upgrade_remote,
                state_dir,
            } => {
                let state_dir = resolved_state_dir(state_dir)?;
                let local_sessions = if target.is_none() {
                    match session::discover_active(herdr_bin.clone()).await {
                        Ok(sessions) => sessions,
                        Err(error) => {
                            eprintln!(
                                "Warning: could not discover local Herdr sessions: {error:#}"
                            );
                            Vec::new()
                        }
                    }
                } else {
                    Vec::new()
                };

                let has_download_account = if target.is_some() {
                    sync::state::load_account(&state_dir, ApiKeyScope::Download)
                        .context("`attach HOST/SESSION` requires a download account bundle")?;
                    true
                } else {
                    match sync::state::has_download_account(&state_dir) {
                        Ok(available) => available,
                        Err(error) => {
                            eprintln!(
                                "Warning: could not inspect the synchronization account: {error:#}"
                            );
                            false
                        }
                    }
                };
                let synchronized_sessions = if has_download_account {
                    let local_version = herdr_version::query(&herdr_bin).context(
                        "could not determine the local Herdr version; catalog refresh and attachment were not started",
                    )?;
                    let refreshed = sync::refresh::refresh_sessions(&state_dir, local_version)
                        .await
                        .context("could not refresh synchronized sessions")?;
                    for warning in refresh_warnings_to_display(&refreshed.warnings, self.verbose) {
                        eprintln!("Warning: {warning}");
                    }
                    refreshed.sessions
                } else {
                    Vec::new()
                };

                let selection = match target {
                    Some(target) => {
                        ensure!(
                            synchronized_sessions
                                .iter()
                                .any(|session| session.target == target),
                            "synchronized session `{target}` is unavailable"
                        );
                        SessionSelection::Synchronized(target)
                    }
                    None => {
                        let Some(selection) =
                            session_picker::select(&local_sessions, &synchronized_sessions).await?
                        else {
                            return Ok(0);
                        };
                        selection
                    }
                };

                match selection {
                    SessionSelection::Local(name) => {
                        let selected = local_sessions
                            .iter()
                            .find(|session| session.name() == name)
                            .context("selected local Herdr session is no longer available")?;
                        selected.attach_local(&herdr_bin).await
                    }
                    SessionSelection::Synchronized(target) => {
                        sync::attach::attach(&state_dir, &target, herdr_bin, upgrade_remote).await
                    }
                }
            }
            Command::Update => {
                installation::update()?;
                Ok(0)
            }
            Command::Uninstall { yes } => {
                installation::uninstall(yes)?;
                Ok(0)
            }
        }
    }
}

fn refresh_warnings_to_display(
    warnings: &[sync::refresh::RefreshWarning],
    verbosity: u8,
) -> impl Iterator<Item = &sync::refresh::RefreshWarning> {
    warnings
        .iter()
        .filter(move |warning| verbosity > 0 || !warning.is_verbose_only())
}

fn resolved_state_dir(state_dir: Option<PathBuf>) -> Result<PathBuf> {
    let path = state_dir.map_or_else(identity::default_state_dir, Ok)?;
    secure_state::prepare_private_dir(&path)?;
    Ok(path)
}

fn write_account_bundle(bundle: &str, output_path: &std::path::Path) -> Result<()> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(bundle.len() + 1));
    bytes.extend_from_slice(bundle.as_bytes());
    bytes.push(b'\n');
    secure_state::create_secret_output(output_path, &bytes)?;
    eprintln!(
        "Account bundle written to {}. It contains remote-shell-equivalent credentials; protect this owner-only file.",
        output_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use attached_session_sync_protocol::account::RecordId;
    use clap::{CommandFactory, Parser};

    use super::*;

    #[test]
    fn exposes_only_the_simplified_command_surface() {
        for args in [
            vec![
                "attached",
                "account",
                "create",
                "--service",
                "https://sync.example",
            ],
            vec!["attached", "account", "export", "--type", "publish"],
            vec!["attached", "account", "import"],
            vec!["attached", "account", "import", "--bundle-stdin"],
            vec![
                "attached",
                "account",
                "import",
                "--bundle-file",
                "/tmp/download.bundle",
            ],
            vec![
                "attached",
                "account",
                "export",
                "--type",
                "push",
                "--output",
                "/tmp/publish.bundle",
            ],
            vec!["attached", "sessions", "list"],
            vec![
                "attached",
                "serve",
                "--host-label",
                "office",
                "--bundle-file",
                "/run/secrets/attached-publish",
            ],
            vec!["attached", "attach"],
            vec!["attached", "attach", "office/work"],
            vec!["attached", "update"],
            vec!["attached", "upgrade"],
            vec!["attached", "uninstall"],
            vec!["attached", "uninstall", "--yes"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }

        for removed in ["connect", "remote", "session", "admin", "sync"] {
            assert!(Cli::try_parse_from(["attached", removed]).is_err());
        }
    }

    #[test]
    fn account_creation_defaults_to_the_hosted_service_and_accepts_an_override() {
        let default = Cli::try_parse_from(["attached", "account", "create"]).unwrap();
        let Command::Account {
            command: AccountCommand::Create { service, .. },
        } = default.command
        else {
            unreachable!();
        };
        assert_eq!(service, DEFAULT_SERVICE_ORIGIN);

        let overridden = Cli::try_parse_from([
            "attached",
            "account",
            "create",
            "--service",
            "https://sync.example",
        ])
        .unwrap();
        let Command::Account {
            command: AccountCommand::Create { service, .. },
        } = overridden.command
        else {
            unreachable!();
        };
        assert_eq!(service, "https://sync.example");
    }

    #[test]
    fn account_imports_prompt_by_default_and_accept_explicit_sources() {
        let interactive = Cli::try_parse_from(["attached", "account", "import"]).unwrap();
        let Command::Account {
            command:
                AccountCommand::Import {
                    bundle_file,
                    bundle_stdin,
                    ..
                },
        } = interactive.command
        else {
            unreachable!();
        };
        assert_eq!(bundle_file, None);
        assert!(!bundle_stdin);

        let file = Cli::try_parse_from([
            "attached",
            "account",
            "import",
            "--bundle-file",
            "account.bundle",
        ])
        .unwrap();
        let Command::Account {
            command:
                AccountCommand::Import {
                    bundle_file,
                    bundle_stdin,
                    ..
                },
        } = file.command
        else {
            unreachable!();
        };
        assert_eq!(bundle_file, Some(PathBuf::from("account.bundle")));
        assert!(!bundle_stdin);

        let stdin =
            Cli::try_parse_from(["attached", "account", "import", "--bundle-stdin"]).unwrap();
        let Command::Account {
            command:
                AccountCommand::Import {
                    bundle_file,
                    bundle_stdin,
                    ..
                },
        } = stdin.command
        else {
            unreachable!();
        };
        assert_eq!(bundle_file, None);
        assert!(bundle_stdin);

        assert!(
            Cli::try_parse_from([
                "attached",
                "account",
                "import",
                "--bundle-file",
                "account.bundle",
                "--bundle-stdin",
            ])
            .is_err()
        );
    }

    #[test]
    fn account_exports_default_to_clipboard_and_require_output_for_files() {
        assert!(
            Cli::try_parse_from([
                "attached",
                "account",
                "create",
                "--output",
                "account.bundle",
            ])
            .is_err()
        );

        let export =
            Cli::try_parse_from(["attached", "account", "export", "--type", "publish"]).unwrap();
        let Command::Account {
            command: AccountCommand::Export { output, .. },
        } = export.command
        else {
            unreachable!();
        };
        assert_eq!(output, None);

        let file_export = Cli::try_parse_from([
            "attached",
            "account",
            "export",
            "--type",
            "download",
            "--output",
            "account.bundle",
        ])
        .unwrap();
        let Command::Account {
            command: AccountCommand::Export { output, .. },
        } = file_export.command
        else {
            unreachable!();
        };
        assert_eq!(output, Some(PathBuf::from("account.bundle")));

        assert!(
            Cli::try_parse_from([
                "attached",
                "account",
                "create",
                "--service",
                "https://sync.example",
                "--stdout",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "attached", "account", "export", "--type", "publish", "--stdout",
            ])
            .is_err()
        );
    }

    #[test]
    fn attach_rejects_forwarded_herdr_commands() {
        assert!(
            Cli::try_parse_from([
                "attached",
                "attach",
                "office/work",
                "--",
                "workspace",
                "list",
            ])
            .is_err()
        );
    }

    #[test]
    fn help_lists_the_simplified_and_lifecycle_commands() {
        let help = Cli::command().render_long_help().to_string();
        for command in [
            "account",
            "serve",
            "sessions",
            "attach",
            "update",
            "uninstall",
        ] {
            assert!(help.contains(command), "{help}");
        }
        for removed in ["connect", "remote", "session", "admin", "sync"] {
            assert!(!help.contains(&format!("  {removed}  ")), "{help}");
        }
        assert!(!help.contains(account_clipboard::HELPER_COMMAND), "{help}");

        let mut command = Cli::command();
        let export_help = command
            .find_subcommand_mut("account")
            .unwrap()
            .find_subcommand_mut("export")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(export_help.contains("clipboard"), "{export_help}");
        assert!(export_help.contains("--output <FILE>"), "{export_help}");

        let mut command = Cli::command();
        let import_help = command
            .find_subcommand_mut("account")
            .unwrap()
            .find_subcommand_mut("import")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(import_help.contains("download-only"), "{import_help}");
        assert!(
            import_help.contains("--bundle-file <FILE>"),
            "{import_help}"
        );
        assert!(import_help.contains("--bundle-stdin"), "{import_help}");
        assert!(import_help.contains("hidden input"), "{import_help}");
    }

    #[test]
    fn serve_accepts_a_publish_bundle_file() {
        let cli = Cli::try_parse_from([
            "attached",
            "serve",
            "--bundle-file",
            "/run/secrets/attached-publish",
        ])
        .unwrap();
        let Command::Serve { bundle_file, .. } = cli.command else {
            unreachable!();
        };
        assert_eq!(
            bundle_file,
            Some(PathBuf::from("/run/secrets/attached-publish"))
        );
    }

    #[test]
    fn user_password_is_default_and_one_password_is_explicit_and_global() {
        let default = Cli::try_parse_from(["attached", "attach"]).unwrap();
        assert!(!default.use_1password);

        let before = Cli::try_parse_from(["attached", "--use-1password", "serve"]).unwrap();
        assert!(before.use_1password);

        let after = Cli::try_parse_from(["attached", "attach", "--use-1password"]).unwrap();
        assert!(after.use_1password);

        assert!(Cli::try_parse_from(["attached", "attach", "--local-unsecure-storage"]).is_err());
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("--use-1password"), "{help}");
        assert!(help.contains("generate and store"), "{help}");
    }

    #[test]
    fn discarded_refresh_warnings_require_verbose_output() {
        let discarded_record = RecordId::from_bytes([0x42; 16]);
        let warnings = vec![
            sync::refresh::RefreshWarning::CatalogRebuilt(anyhow::anyhow!("invalid catalog")),
            sync::refresh::RefreshWarning::RecordDiscarded {
                record_id: discarded_record,
                error: anyhow::anyhow!("session access descriptor expired"),
            },
            sync::refresh::RefreshWarning::EndpointRegistryUnavailable,
        ];

        let standard = refresh_warnings_to_display(&warnings, 0)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(standard.len(), 2, "{standard:?}");
        assert!(
            standard
                .iter()
                .all(|warning| !warning.contains(&discarded_record.to_string())),
            "{standard:?}"
        );

        let verbose = refresh_warnings_to_display(&warnings, 1)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(verbose.len(), 3, "{verbose:?}");
        assert!(
            verbose.iter().any(|warning| {
                warning.contains(&discarded_record.to_string()) && warning.contains("expired")
            }),
            "{verbose:?}"
        );
    }

    #[test]
    fn verbosity_and_flamegraph_output_are_global() {
        let cli = Cli::try_parse_from(["attached", "serve", "-vv", "--flamegraph", "serve.folded"])
            .unwrap();
        assert_eq!(cli.verbosity(), 2);
        assert_eq!(cli.flamegraph(), Some(std::path::Path::new("serve.folded")));

        let cli = Cli::try_parse_from([
            "attached",
            "-v",
            "--flamegraph",
            "attach.folded",
            "attach",
            "office/work",
        ])
        .unwrap();
        assert_eq!(cli.verbosity(), 1);
        assert_eq!(
            cli.flamegraph(),
            Some(std::path::Path::new("attach.folded"))
        );
    }
}
