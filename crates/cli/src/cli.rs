use std::{
    io::{BufRead, Read, Write as _, stdin, stdout},
    path::PathBuf,
};

use anyhow::{Context, Result, bail, ensure};
use attached_session_sync_protocol::{account::ApiKeyScope, limits::MAX_BUNDLE_ENCODED_BYTES};
use clap::{Parser, Subcommand, ValueEnum};

use crate::{
    herdr_version, identity, installation, secure_state, server, session,
    session_picker::{self, SessionSelection},
    sync,
};

const MAX_ACCOUNT_BUNDLE_LINE_BYTES: usize = MAX_BUNDLE_ENCODED_BYTES + 2;
#[derive(Parser)]
#[command(
    version,
    about = "Discover and attach to synchronized Herdr sessions over Iroh"
)]
pub struct Cli {
    /// Increase diagnostic verbosity (`-v` for lifecycle, `-vv` for debug details).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    verbose: u8,

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
    /// Create an account, then write its download bundle securely.
    Create {
        /// Synchronization service used for the new account.
        #[arg(long, default_value = DEFAULT_SERVICE_ORIGIN)]
        service: String,

        /// New owner-only file for the download bundle. Defaults to `account.bundle` and refuses
        /// to overwrite an existing file.
        #[arg(long, default_value = "account.bundle")]
        output: PathBuf,

        #[arg(long, hide = true)]
        state_dir: Option<PathBuf>,
    },

    /// Import a scoped secret bundle from standard input.
    Import {
        #[arg(long, required = true)]
        bundle_stdin: bool,

        #[arg(long, hide = true)]
        state_dir: Option<PathBuf>,
    },

    /// Export one scoped secret bundle from a locally created account.
    Export {
        /// API-key scope to export (`publish` is also accepted as `push`).
        #[arg(long = "type", value_enum)]
        key_type: AccountKeyType,

        /// New owner-only file for the exported bundle. Defaults to `publish.bundle` and refuses
        /// to overwrite an existing file.
        #[arg(long, default_value = "publish.bundle")]
        output: PathBuf,

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

    pub async fn run(self) -> Result<i32> {
        match self.command {
            Command::Account { command } => {
                match command {
                    AccountCommand::Create {
                        service,
                        output,
                        state_dir,
                    } => {
                        let state_dir = resolved_state_dir(state_dir)?;
                        let bundle = sync::account::create(&state_dir, &service).await?;
                        write_account_bundle(&bundle, &output).context(
                            "the account was saved locally, but its download bundle could not be written; export a new download bundle from the saved account",
                        )?;
                        eprintln!(
                            "Use `attached account export --type publish` to create a publish-only bundle for serving hosts."
                        );
                    }
                    AccountCommand::Import {
                        bundle_stdin,
                        state_dir,
                    } => {
                        debug_assert!(bundle_stdin, "clap requires --bundle-stdin");
                        let state_dir = resolved_state_dir(state_dir)?;
                        let bundle = read_account_bundle(&mut stdin().lock())?;
                        sync::account::import(&state_dir, bundle.as_bytes())?;
                    }
                    AccountCommand::Export {
                        key_type,
                        output,
                        state_dir,
                    } => {
                        let state_dir = resolved_state_dir(state_dir)?;
                        let scope = ApiKeyScope::from(key_type);
                        let bundle = sync::account::export(&state_dir, scope)?;
                        write_account_bundle(&bundle, &output)?;
                    }
                }
                Ok(0)
            }
            Command::Serve {
                herdr_bin,
                host_label,
                state_dir,
            } => {
                let state_dir = resolved_state_dir(state_dir)?;
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
    let mut bytes = Vec::with_capacity(bundle.len() + 1);
    bytes.extend_from_slice(bundle.as_bytes());
    bytes.push(b'\n');
    secure_state::create_secret_output(output_path, &bytes)?;
    eprintln!(
        "Account bundle written to {}. It contains remote-shell-equivalent credentials; protect this owner-only file.",
        output_path.display()
    );
    Ok(())
}

fn read_account_bundle(reader: &mut impl BufRead) -> Result<String> {
    let mut line = String::new();
    let mut limited = reader
        .by_ref()
        .take((MAX_ACCOUNT_BUNDLE_LINE_BYTES + 1) as u64);
    limited
        .read_line(&mut line)
        .context("could not read account bundle from standard input")?;
    let bundle = line.trim();
    if line.len() > MAX_ACCOUNT_BUNDLE_LINE_BYTES || bundle.len() > MAX_BUNDLE_ENCODED_BYTES {
        bail!("account bundle is too long (maximum {MAX_BUNDLE_ENCODED_BYTES} bytes)");
    }

    let bundle = bundle.to_owned();
    if bundle.is_empty() {
        bail!("account bundle is empty");
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

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
            vec!["attached", "account", "import", "--bundle-stdin"],
            vec!["attached", "account", "export", "--type", "publish"],
            vec![
                "attached",
                "account",
                "export",
                "--type",
                "push",
                "--output",
                "/tmp/publish.bundle",
            ],
            vec!["attached", "serve", "--host-label", "office"],
            vec!["attached", "sessions", "list"],
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
    fn account_bundle_io_uses_safe_default_files() {
        assert!(Cli::try_parse_from(["attached", "account", "import"]).is_err());

        let create = Cli::try_parse_from([
            "attached",
            "account",
            "create",
            "--service",
            "https://sync.example",
        ])
        .unwrap();
        let Command::Account {
            command: AccountCommand::Create { output, .. },
        } = create.command
        else {
            unreachable!();
        };
        assert_eq!(output, PathBuf::from("account.bundle"));

        let export =
            Cli::try_parse_from(["attached", "account", "export", "--type", "publish"]).unwrap();
        let Command::Account {
            command: AccountCommand::Export { output, .. },
        } = export.command
        else {
            unreachable!();
        };
        assert_eq!(output, PathBuf::from("publish.bundle"));

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
    }

    #[test]
    fn account_bundle_input_is_one_trimmed_bounded_line() {
        let mut input = Cursor::new(b"  c3ludGhldGlj  \r\nignored\n");
        assert_eq!(
            read_account_bundle(&mut input).unwrap().as_str(),
            "c3ludGhldGlj"
        );

        let maximum = "A".repeat(MAX_BUNDLE_ENCODED_BYTES);
        let mut exact = Cursor::new(format!("{maximum}\r\n"));
        assert_eq!(read_account_bundle(&mut exact).unwrap(), maximum);

        let mut oversized = Cursor::new(format!("{}\n", "x".repeat(MAX_BUNDLE_ENCODED_BYTES + 1)));
        let error = read_account_bundle(&mut oversized).unwrap_err().to_string();
        assert!(error.contains("too long"), "{error}");
        assert!(!error.contains(&"x".repeat(32)), "{error}");
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
    fn verbosity_is_repeatable_and_global() {
        let cli = Cli::try_parse_from(["attached", "serve", "-vv"]).unwrap();
        assert_eq!(cli.verbosity(), 2);

        let cli = Cli::try_parse_from(["attached", "-v", "attach", "office/work"]).unwrap();
        assert_eq!(cli.verbosity(), 1);
    }
}
