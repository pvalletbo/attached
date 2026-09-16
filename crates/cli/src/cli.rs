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
    download_account, host_picker, installation, local_encryption, publish_account, secure_state,
    server, sync,
};

#[derive(Parser)]
#[command(
    version,
    about = "Discover machines and connect over SSH through secure Iroh tunnels",
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

    /// Publish this machine and serve authorized SSH tunnels.
    Serve {
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

    /// Discover remote machines available through Attached SSH tunnels.
    Sessions {
        #[command(subcommand)]
        command: SessionsCommand,
    },

    /// Execute a command or a non-PTY shell through an authorized publisher tunnel.
    ///
    /// Uses system OpenSSH and automatic, connection-scoped keys. Publisher consent:
    /// `attached ssh-access enable`. Commands run as the publisher's OS account.
    /// For concurrent relayed connections, use one --expose-config broker: separate
    /// Attached processes share the consumer Iroh identity and can displace one
    /// another on relays.
    Ssh {
        /// Publisher host label or stable endpoint ID.
        target: String,
        /// Print an OpenSSH configuration path and serve it in the foreground until Ctrl-C.
        /// Use `ssh -F PATH attached-ENDPOINT-ID`; nothing modifies ~/.ssh/config.
        #[arg(long, conflicts_with = "command")]
        expose_config: bool,
        /// Refresh publisher discovery before connecting.
        #[arg(long)]
        no_cache: bool,
        /// Deliberately replace this stable publisher's pinned SSH host identity.
        /// Use only after independently verifying the publisher's key/account change.
        #[arg(long)]
        trust_new_host_key: bool,
        #[arg(long, hide = true)]
        state_dir: Option<PathBuf>,
        /// Command interpreted by the publisher's account shell; omit for a non-PTY shell.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Grant or revoke persistent account-level SSH access for the configured consumer.
    SshAccess {
        #[command(subcommand)]
        command: SshAccessCommand,
        #[arg(long, hide = true, global = true)]
        state_dir: Option<PathBuf>,
    },

    #[command(name = "__ssh-local-proxy", hide = true)]
    SshLocalProxy { socket: PathBuf },

    /// Update Attached to the latest release locally or on a synchronized host.
    #[command(visible_alias = "upgrade")]
    Update {
        /// Update a publisher by host label or endpoint ID; omit the target to choose with fzf.
        #[arg(long, value_name = "HOST", num_args = 0..=1)]
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

#[derive(Subcommand)]
enum SshAccessCommand {
    /// Permit arbitrary shell execution as this publisher OS account. Persists until disabled.
    Enable,
    /// Reject new SSH connections and cancel existing ones within one second.
    Disable,
}

const DEFAULT_SERVICE_ORIGIN: &str = "https://herdr.attached.sh";

#[derive(Subcommand)]
enum SessionsCommand {
    /// Refresh and list SSH-enabled machines (not application sessions).
    List {
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

        if let Command::SshLocalProxy { socket } = &self.command {
            return crate::ssh::local_proxy(socket.clone()).await;
        }

        let configuration =
            config::Config::load().context("could not load Attached configuration")?;
        local_encryption::configure_use_one_password(
            self.use_1password || configuration.password_source() == PasswordSource::OnePassword,
        );
        match self.command {
            Command::Ssh {
                target,
                command,
                expose_config,
                no_cache,
                trust_new_host_key,
                state_dir,
            } => {
                use std::io::IsTerminal;
                local_encryption::configure_noninteractive(
                    !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal(),
                );
                let state_dir = resolved_state_dir(state_dir, &configuration)?;
                crate::ssh::connect(
                    &state_dir,
                    &target,
                    command,
                    expose_config,
                    no_cache,
                    trust_new_host_key,
                )
                .await
            }
            Command::SshAccess { command, state_dir } => {
                let state_dir = resolved_state_dir(state_dir, &configuration)?;
                crate::ssh::set_access(&state_dir, matches!(command, SshAccessCommand::Enable))?;
                Ok(0)
            }
            Command::SshLocalProxy { .. } => unreachable!(),
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
                host_label,
                bundle_file,
                state_dir,
            } => {
                let state_dir = resolved_state_dir(state_dir, &configuration)?;
                publish_account::ensure_configured(&state_dir, bundle_file.as_deref())?;
                server::serve(state_dir, host_label).await?;
                Ok(0)
            }
            Command::Sessions { command } => match command {
                SessionsCommand::List { state_dir } => {
                    let state_dir = resolved_state_dir(state_dir, &configuration)?;
                    sync::state::load_account(&state_dir, ApiKeyScope::Download)
                        .context("`sessions list` requires a download account bundle")?;
                    let refreshed = sync::refresh::refresh_hosts(&state_dir)
                        .await
                        .context("could not refresh synchronized hosts")?;
                    for warning in refresh_warnings_to_display(&refreshed.warnings, self.verbose) {
                        eprintln!("Warning: {warning}");
                    }
                    let rendered = host_picker::render_list(&refreshed.hosts)?;
                    write_session_list(&mut stdout().lock(), &rendered)?;
                    Ok(0)
                }
            },
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
        Err(error) => Err(error).context("could not write synchronized host list"),
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
    fn ssh_cli_preserves_openssh_style_commands_and_explicit_consent() {
        let cli = Cli::try_parse_from(["attached", "ssh", "host", "printf", "%s", "--remote-flag"])
            .unwrap();
        assert!(
            matches!(cli.command, Command::Ssh { target, command, .. } if target == "host" && command == ["printf", "%s", "--remote-flag"])
        );
        let cli = Cli::try_parse_from([
            "attached",
            "ssh",
            "--expose-config",
            "--trust-new-host-key",
            "host",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Ssh {
                expose_config: true,
                trust_new_host_key: true,
                ..
            }
        ));
        assert!(
            Cli::try_parse_from(["attached", "ssh", "--expose-config", "host", "cmd"]).is_err()
        );
        for action in ["enable", "disable"] {
            assert!(Cli::try_parse_from(["attached", "ssh-access", action]).is_ok());
        }
        assert!(Cli::try_parse_from(["attached", "ssh-access"]).is_err());
    }

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
            vec!["attached", "update"],
            vec!["attached", "update", "--remote"],
            vec!["attached", "update", "--remote", "office"],
            vec!["attached", "upgrade"],
            vec!["attached", "completions", "bash"],
            vec!["attached", "uninstall"],
            vec!["attached", "uninstall", "--yes"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }

        for removed in ["attach", "connect", "remote", "session", "admin", "sync"] {
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
    fn help_lists_the_simplified_and_lifecycle_commands() {
        let help = Cli::command().render_long_help().to_string();
        for command in [
            "account",
            "serve",
            "sessions",
            "ssh",
            "ssh-access",
            "update",
            "completions",
            "uninstall",
        ] {
            assert!(help.contains(command), "{help}");
        }
        for removed in ["attach", "connect", "remote", "session", "admin", "sync"] {
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
        let default = Cli::try_parse_from(["attached", "serve"]).unwrap();
        assert!(!default.use_1password);

        let before = Cli::try_parse_from(["attached", "--use-1password", "serve"]).unwrap();
        assert!(before.use_1password);

        let after = Cli::try_parse_from(["attached", "serve", "--use-1password"]).unwrap();
        assert!(after.use_1password);

        assert!(Cli::try_parse_from(["attached", "serve", "--local-unsecure-storage"]).is_err());
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("--use-1password"), "{help}");
        assert!(help.contains("generate and store"), "{help}");
        assert!(help.contains("password_source = \"password\""), "{help}");
        assert!(help.contains("config_directory"), "{help}");
    }

    #[test]
    fn discarded_refresh_warnings_require_verbose_output() {
        let discarded_record = RecordId::from_bytes([0x42; 16]);
        let warnings = vec![
            sync::refresh::RefreshWarning::CatalogRebuilt(anyhow::anyhow!("invalid catalog")),
            sync::refresh::RefreshWarning::RecordDiscarded {
                record_id: discarded_record,
                error: anyhow::anyhow!("host access descriptor expired"),
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
        assert!(error.contains("could not write synchronized host list"));
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
            "ssh.folded",
            "ssh",
            "office",
        ])
        .unwrap();
        assert_eq!(cli.verbosity(), 1);
        assert_eq!(cli.flamegraph(), Some(std::path::Path::new("ssh.folded")));
    }
}
