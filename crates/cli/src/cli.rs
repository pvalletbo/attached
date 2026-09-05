use std::{
    io::{self, stdout},
    path::PathBuf,
};

use anyhow::{Context, Result, ensure};
use attached_session_sync_protocol::account::ApiKeyScope;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use zeroize::Zeroizing;

use crate::{
    account_clipboard,
    config::{self, PasswordSource},
    download_account, herdr_version, installation, local_encryption, publish_account, secure_state,
    server, session,
    session_picker::{self, SessionSelection},
    sync,
};

#[derive(Parser)]
#[command(
    version,
    about = "Discover and attach to synchronized Herdr sessions over Iroh",
    after_long_help = "CONFIGURATION:\n    Attached reads $HOME/.config/attached/config.toml when it exists. Supported TOML settings:\n\n        password_source = \"password\" # or \"1password\"\n        config_directory = \"/absolute/path\" # defaults to $HOME/.config/attached\n\n    --use-1password overrides password_source for the current invocation."
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
        /// The authenticated host stages `herdr update --handoff` noninteractively with inherited
        /// Herdr session routing removed, atomically installs it, and hands off every live session.
        /// Failures restore the previous binary and live version. If the binary was already
        /// updated by an incomplete attempt, Attached retries Herdr's native handoff directly.
        /// Attachment starts only after the binary and all live sessions exactly match local. A
        /// newer remote fails with guidance to update local Herdr and is never mutated by this
        /// option. Package-managed remote installations must be updated on their serving host.
        #[arg(long)]
        upgrade_remote: bool,

        /// Override persistent state location (primarily for testing).
        #[arg(long, hide = true)]
        state_dir: Option<PathBuf>,
    },

    /// Update Attached to the latest release locally or on a synchronized host.
    #[command(visible_alias = "upgrade")]
    Update {
        /// Update the host serving `HOST/SESSION`; omit the target to choose with fzf.
        #[arg(long, value_name = "HOST/SESSION", num_args = 0..=1)]
        remote: Option<Option<String>>,

        /// Override persistent state location (primarily for testing remote updates).
        #[arg(long, hide = true)]
        state_dir: Option<PathBuf>,
    },

    #[command(name = "__handoff-serve", hide = true)]
    HandoffServe,

    /// Generate a completion script for a supported shell.
    Completions {
        /// Shell whose completion script should be generated.
        #[arg(value_enum)]
        shell: Shell,
    },

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

fn write_completions(shell: Shell, output: &mut impl std::io::Write) -> Result<()> {
    let mut command = Cli::command();
    let mut generated = Vec::new();
    clap_complete::generate(shell, &mut command, "attached", &mut generated);
    output
        .write_all(&generated)
        .with_context(|| format!("could not write {shell} completion script"))
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
        if let Command::Completions { shell } = &self.command {
            write_completions(*shell, &mut stdout().lock())?;
            return Ok(0);
        }

        let configuration =
            config::Config::load().context("could not load Attached configuration")?;
        local_encryption::configure_use_one_password(
            self.use_1password || configuration.password_source() == PasswordSource::OnePassword,
        );
        match self.command {
            Command::Account { command } => {
                match command {
                    AccountCommand::Create { service, state_dir } => {
                        let state_dir = resolved_state_dir(state_dir, &configuration)?;
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
                        let state_dir = resolved_state_dir(state_dir, &configuration)?;
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
                        let state_dir = resolved_state_dir(state_dir, &configuration)?;
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
                let state_dir = resolved_state_dir(state_dir, &configuration)?;
                publish_account::ensure_configured(&state_dir, bundle_file.as_deref())?;
                server::serve(state_dir, herdr_bin, host_label).await?;
                Ok(0)
            }
            Command::Sessions { command } => match command {
                SessionsCommand::List {
                    herdr_bin,
                    state_dir,
                } => {
                    let state_dir = resolved_state_dir(state_dir, &configuration)?;
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
                    write_session_list(&mut stdout().lock(), &rendered)?;
                    Ok(0)
                }
            },
            Command::Attach {
                target,
                herdr_bin,
                upgrade_remote,
                state_dir,
            } => {
                let state_dir = resolved_state_dir(state_dir, &configuration)?;
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
                    let refreshed = async {
                        let local_version = herdr_version::query(&herdr_bin).context(
                            "could not determine the local Herdr version; remote discovery was not started",
                        )?;
                        sync::refresh::refresh_sessions(&state_dir, local_version)
                            .await
                            .context("could not refresh synchronized sessions")
                    }.await;
                    attach_refresh_result(
                        refreshed,
                        target.is_none(),
                        self.verbose,
                        &mut std::io::stderr(),
                    )?
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
            Command::Update { remote, state_dir } => {
                if let Some(target) = remote {
                    let state_dir = resolved_state_dir(state_dir, &configuration)?;
                    sync::attached_update::update(&state_dir, target.as_deref(), self.verbose)
                        .await?;
                } else {
                    ensure!(
                        state_dir.is_none(),
                        "--state-dir can only be used with --remote"
                    );
                    installation::update()?;
                }
                Ok(0)
            }
            Command::HandoffServe => {
                server::serve_candidate().await?;
                Ok(0)
            }
            Command::Completions { .. } => unreachable!("handled before configuration loading"),
            Command::Uninstall { yes } => {
                installation::uninstall(yes, configuration.config_directory())?;
                Ok(0)
            }
        }
    }
}

fn attach_refresh_result(
    refreshed: Result<sync::refresh::RefreshResult>,
    interactive: bool,
    verbosity: u8,
    output: &mut impl std::io::Write,
) -> Result<Vec<sync::state_catalog::SyncedSession>> {
    let refreshed = match refreshed {
        Ok(refreshed) => refreshed,
        Err(error) if interactive => {
            writeln!(
                output,
                "Warning: remote discovery failed: {error:#}. Showing local sessions only; check synchronization connectivity and credentials, then retry `attached attach`."
            )?;
            tracing::debug!(
                operation = "attach_discovery",
                stage = "remote",
                outcome = "degraded",
                "continuing with local session selection"
            );
            // Do not silently reuse cached descriptors or extend their validity.
            return Ok(Vec::new());
        }
        Err(error) => return Err(error),
    };
    for warning in refresh_warnings_to_display(&refreshed.warnings, verbosity) {
        writeln!(output, "Warning: {warning}")?;
    }
    Ok(refreshed.sessions)
}

fn refresh_warnings_to_display(
    warnings: &[sync::refresh::RefreshWarning],
    verbosity: u8,
) -> impl Iterator<Item = &sync::refresh::RefreshWarning> {
    warnings
        .iter()
        .filter(move |warning| verbosity > 0 || !warning.is_verbose_only())
}

fn resolved_state_dir(
    state_dir: Option<PathBuf>,
    configuration: &config::Config,
) -> Result<PathBuf> {
    let path = state_dir.unwrap_or_else(|| configuration.config_directory().to_owned());
    secure_state::prepare_private_dir(&path)?;
    Ok(path)
}

fn write_session_list(output: &mut impl io::Write, rendered: &str) -> Result<()> {
    match output.write_all(rendered.as_bytes()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error).context("could not write synchronized session list"),
    }
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
            vec!["attached", "update", "--remote"],
            vec!["attached", "update", "--remote", "office/work"],
            vec!["attached", "upgrade"],
            vec!["attached", "completions", "bash"],
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
            "completions",
            "uninstall",
        ] {
            assert!(help.contains(command), "{help}");
        }
        for removed in ["connect", "remote", "session", "admin", "sync"] {
            assert!(!help.contains(&format!("  {removed}  ")), "{help}");
        }
        assert!(!help.contains(account_clipboard::HELPER_COMMAND), "{help}");
        assert!(
            !help.contains(crate::serve_handoff::INTERNAL_COMMAND),
            "{help}"
        );

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
    fn generates_completions_for_every_supported_shell() {
        for &shell in Shell::value_variants() {
            let mut generated = Vec::new();
            write_completions(shell, &mut generated).unwrap();
            let generated = String::from_utf8(generated).unwrap();

            assert!(!generated.is_empty(), "empty {shell} completion script");
            assert!(generated.contains("sessions"), "{shell}: {generated}");
            assert!(generated.contains("completions"), "{shell}: {generated}");
        }
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
        assert!(help.contains("password_source = \"password\""), "{help}");
        assert!(help.contains("config_directory"), "{help}");
    }

    #[tokio::test]
    async fn sync_outage_degrades_only_interactive_attachment_and_explains_the_cause() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let root = crate::test_support::canonical_tempdir();
            let state_dir = root.path().join("state");
            sync::state::test_support::create_account(
                &state_dir, &format!("http://{}", listener.local_addr().unwrap()),
            ).unwrap();
            assert!(sync::state::has_download_account(&state_dir).unwrap());
            let server = tokio::spawn(async move {
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        let mut chunk = [0; 1024];
                        let n = stream.read(&mut chunk).await.unwrap();
                        assert!(n > 0 && request.len() < 8192);
                        request.extend_from_slice(&chunk[..n]);
                    }
                    stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                }
            });
            for interactive in [true, false] {
                let refreshed = sync::refresh::refresh_sessions(&state_dir, attached_tunnel_protocol::HerdrVersion::new(3, 2, 1)).await
                    .context("could not refresh synchronized sessions");
                let mut warnings = Vec::new();
                let result = attach_refresh_result(refreshed, interactive, 0, &mut warnings);
                if interactive {
                    assert!(result.unwrap().is_empty(), "no stale remote cache fallback");
                    let warnings = String::from_utf8(warnings).unwrap();
                    assert!(warnings.contains("503"), "{warnings}");
                    assert!(warnings.contains("local sessions only"), "{warnings}");
                    assert!(warnings.contains("retry"), "{warnings}");
                } else {
                    assert!(format!("{:#}", result.unwrap_err()).contains("503"));
                    assert!(warnings.is_empty(), "explicit remote attachment must fail");
                }
            }
            server.await.unwrap();
        }).await.expect("outage fixture timed out");
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
    fn session_list_ignores_only_broken_pipes() {
        struct FailingWriter(io::ErrorKind);

        impl io::Write for FailingWriter {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(self.0, "synthetic failure"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        assert!(
            write_session_list(
                &mut FailingWriter(io::ErrorKind::BrokenPipe),
                "session list"
            )
            .is_ok()
        );
        let error = write_session_list(
            &mut FailingWriter(io::ErrorKind::PermissionDenied),
            "session list",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("could not write synchronized session list"));
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
