use std::{
    ffi::{OsStr, OsString},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
#[cfg(any(target_os = "macos", test))]
use tokio::io::AsyncReadExt;
use tokio::{process::Command, time::timeout};

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod linux;

use super::tracker::{Notice, text};

#[path = "macos_terminal.rs"]
mod macos_terminal;

#[derive(Clone)]
pub struct Launch {
    pub attached: PathBuf,
    pub terminal: Option<PathBuf>,
}

impl Launch {
    fn attach_args(&self, target: &str) -> Vec<OsString> {
        // Match a manual attachment: resolve state, Herdr, and authentication
        // from the new process's configuration/defaults, not watcher overrides.
        // Verbosity exposes the underlying cause if loading the account fails.
        vec!["attach".into(), "-v".into(), "--".into(), target.into()]
    }

    #[cfg(any(target_os = "macos", test))]
    fn callback_args(&self, target: &str) -> Vec<OsString> {
        let mut args = vec!["notifications".into(), "open".into(), "-v".into()];
        if let Some(terminal) = &self.terminal {
            args.extend([
                OsString::from("--terminal"),
                terminal.clone().into_os_string(),
            ]);
        }
        args.extend([OsString::from("--"), target.into()]);
        args
    }

    pub async fn open(&self, target: &str) -> Result<()> {
        crate::sync::attach::parse_target(target)?;
        #[cfg(target_os = "macos")]
        let launch = Self {
            terminal: Some(macos_terminal::resolve(self.terminal.as_deref()).await?),
            ..self.clone()
        };
        #[cfg(not(target_os = "macos"))]
        let launch = self;
        let mut command = launch.terminal_command(target, cfg!(target_os = "macos"))?;
        // A notification callback must not inherit the pane/session routing of
        // the terminal from which the watcher was originally started.
        for (name, _) in std::env::vars_os() {
            if name.as_encoded_bytes().starts_with(b"HERDR_") {
                command.env_remove(name);
            }
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .context("could not open a terminal for attachment")?;
        // Catch immediate launch/permission failures, but do not wait for the
        // window lifetime or kill interactive windows when the watcher exits.
        match timeout(Duration::from_millis(500), child.wait()).await {
            Ok(status) => ensure!(
                status?.success(),
                "terminal launcher failed; check app installation and desktop/automation permissions"
            ),
            Err(_) => {
                tokio::spawn(async move {
                    let _ = child.wait().await;
                });
            }
        }
        Ok(())
    }

    fn terminal_command(&self, target: &str, macos: bool) -> Result<Command> {
        if macos {
            return macos_terminal::command(
                self.terminal
                    .as_deref()
                    .context("macOS terminal selection was not resolved")?,
                &self.attached,
                &self.attach_args(target),
            );
        }
        let terminal = match &self.terminal {
            Some(path) => path.clone(),
            None => find_terminal()?,
        };
        let mut command = Command::new(&terminal);
        match terminal.file_name().and_then(OsStr::to_str) {
            Some("gnome-terminal") => {
                command.args(["--window", "--"]);
            }
            Some("wezterm") => {
                command.args(["start", "--always-new-process", "--"]);
            }
            _ => {
                command.arg("-e");
            }
        }
        command.arg(&self.attached).args(self.attach_args(target));
        Ok(command)
    }
}

#[derive(Clone)]
pub struct Desktop {
    #[cfg(target_os = "linux")]
    linux: std::sync::Arc<linux::Linux>,
    #[cfg(target_os = "macos")]
    helper: PathBuf,
    #[cfg(target_os = "macos")]
    launch: Launch,
}

impl Desktop {
    pub async fn detect(launch: Launch) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let mut launch = launch;
            launch.terminal = Some(match &launch.terminal {
                Some(path) => program(path)?,
                None => find_terminal()?,
            });
            Ok(Self {
                linux: std::sync::Arc::new(linux::Linux::connect(launch).await?),
            })
        }
        #[cfg(target_os = "macos")]
        {
            let mut launch = launch;
            launch.terminal = Some(macos_terminal::resolve(launch.terminal.as_deref()).await?);
            let helper = program(Path::new("terminal-notifier"))
                .context("clickable notifications on macOS require `brew install terminal-notifier`; allow its notifications in System Settings")?;
            Ok(Self { helper, launch })
        }
    }

    pub async fn show(&self, target: &str, notice: &Notice) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.linux.show(target, notice).await
        }
        #[cfg(target_os = "macos")]
        {
            let mut command = mac_notification_command(&self.helper, &self.launch, target, notice)?;
            run(&mut command, Duration::from_secs(10)).await?;
            Ok(())
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn mac_notification_command(
    helper: &Path,
    launch: &Launch,
    target: &str,
    notice: &Notice,
) -> Result<Command> {
    let callback = shell_command(&launch.attached, &launch.callback_args(target))?;
    let mut command = Command::new(helper);
    command.args([
        "-title",
        &notice.title,
        "-subtitle",
        &text(target, 160),
        "-message",
        &notice.body,
        "-group",
        target,
        "-execute",
        &callback,
    ]);
    Ok(command)
}

pub fn program(path: &Path) -> Result<PathBuf> {
    let candidates: Vec<_> = if path.components().count() > 1 || path.is_absolute() {
        vec![path.to_path_buf()]
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join(path))
            .collect()
    };
    for candidate in candidates {
        if std::fs::metadata(&candidate)
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        {
            // Preserve the executable name: terminal alternatives may select their
            // invocation mode from argv[0]. Make the pathname absolute, not canonical.
            return Ok(std::path::absolute(candidate)?);
        }
    }
    bail!("executable {} was not found", path.display())
}

fn find_terminal() -> Result<PathBuf> {
    for name in [
        "x-terminal-emulator",
        "gnome-terminal",
        "konsole",
        "ghostty",
        "kitty",
        "alacritty",
        "foot",
        "wezterm",
        "xterm",
    ] {
        if let Ok(path) = program(Path::new(name)) {
            return Ok(path);
        }
    }
    bail!(
        "no supported terminal found; pass --terminal /path/to/terminal (must support -e PROGRAM ARGS)"
    )
}

#[cfg(any(target_os = "linux", test))]
fn escape_markup(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn shell_command(program: &Path, args: &[OsString]) -> Result<String> {
    std::iter::once(program.as_os_str())
        .chain(args.iter().map(OsString::as_os_str))
        .map(|arg| {
            let arg = arg
                .to_str()
                .context("notification click commands require UTF-8 paths on macOS")?;
            ensure!(!arg.contains('\0'), "invalid command argument");
            Ok(format!("'{}'", arg.replace('\'', "'\\''")))
        })
        .collect::<Result<Vec<_>>>()
        .map(|args| args.join(" "))
}

#[cfg(any(target_os = "macos", test))]
async fn run(command: &mut Command, deadline: Duration) -> Result<Vec<u8>> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .context("could not launch notification helper")?;
    let mut stdout = child
        .stdout
        .take()
        .context("missing notification helper output")?
        .take(8193);
    timeout(deadline, async {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await?;
        ensure!(
            output.len() <= 8192,
            "notification helper output exceeds limit"
        );
        ensure!(
            child.wait().await?.success(),
            "notification helper failed; check desktop notification permissions and action support"
        );
        Ok(output)
    })
    .await
    .context("notification helper timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn click_arguments_use_user_defaults_and_preserve_explicit_target() {
        for terminal in ["ghostty", "terminal"] {
            let launch = Launch {
                attached: "/tmp/attached executable".into(),
                terminal: Some(terminal.into()),
            };
            let args = launch.attach_args("host/work");
            let callback = launch.callback_args("host/work");
            assert_eq!(args, ["attach", "-v", "--", "host/work"]);
            for args in [&args, &callback] {
                assert_eq!(args.last().unwrap(), "host/work");
                assert_eq!(args[args.len() - 2], "--");
                assert!(!args.contains(&OsString::from("--use-1password")));
                assert!(!args.contains(&OsString::from("--state-dir")));
                assert!(!args.contains(&OsString::from("--herdr-bin")));
                assert!(args.contains(&OsString::from("-v")));
                assert!(!args.contains(&OsString::from("--upgrade-remote")));
                assert!(
                    <crate::cli::Cli as clap::Parser>::try_parse_from(
                        std::iter::once(launch.attached.clone().into_os_string())
                            .chain(args.iter().cloned())
                    )
                    .is_ok()
                );
            }
            assert!(
                !args.contains(&OsString::from("--terminal")),
                "terminal selector belongs to the callback, not attach"
            );
            assert!(
                callback
                    .windows(2)
                    .any(|pair| pair == ["--terminal", terminal])
            );
            let terminal = launch.terminal_command("host/work", true).unwrap();
            let initial = terminal
                .as_std()
                .get_args()
                .last()
                .unwrap()
                .to_string_lossy();
            assert!(initial.contains("'/tmp/attached executable' 'attach'"));
            assert!(!initial.contains("--use-1password"));
        }
    }
    #[test]
    fn macos_shell_launch_delivers_the_minimal_attach_argv() {
        let root = crate::test_support::canonical_tempdir();
        let attached = root.path().join("attached ' executable");
        std::fs::write(&attached, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
        std::fs::set_permissions(&attached, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = "host/work';$(id)";
        for terminal in ["ghostty", "terminal"] {
            let launch = Launch {
                attached: attached.clone(),
                terminal: Some(terminal.into()),
            };
            let command = launch.terminal_command(target, true).unwrap();
            let initial = command
                .as_std()
                .get_args()
                .last()
                .unwrap()
                .to_str()
                .unwrap();
            let shell = if terminal == "ghostty" {
                // Ghostty supplies this wrapper on macOS.
                format!(
                    "exec -l {}",
                    initial.strip_prefix("--initial-command=shell:").unwrap()
                )
            } else {
                initial.to_owned()
            };
            let output = std::process::Command::new("/bin/bash")
                .args(["--noprofile", "--norc", "-c", &shell])
                .output()
                .unwrap();
            assert!(output.status.success(), "{terminal}: {:?}", output.stderr);
            assert_eq!(
                output.stdout,
                format!("attach\n-v\n--\n{target}\n").as_bytes()
            );
        }
    }

    #[test]
    fn macos_click_is_data_not_applescript_source_and_never_uses_notice_text() {
        let launch = Launch {
            attached: "/tmp/attached executable".into(),
            terminal: Some("terminal".into()),
        };
        let target = "host/work'\";$(id)";
        let terminal = launch.terminal_command(target, true).unwrap();
        let args: Vec<_> = terminal.as_std().get_args().collect();
        assert_eq!(terminal.as_std().get_program(), "/usr/bin/osascript");
        assert!(!args[1].to_string_lossy().contains(target));
        assert!(args[3].to_string_lossy().starts_with("exec '"));
        let command = mac_notification_command(
            Path::new("terminal-notifier"),
            &launch,
            target,
            &Notice {
                title: "untrusted title".into(),
                body: "$(touch bad)".into(),
            },
        )
        .unwrap();
        let args: Vec<_> = command.as_std().get_args().collect();
        let callback = args.last().unwrap().to_string_lossy();
        assert!(callback.contains("'notifications' 'open'"));
        assert!(!callback.contains("untrusted title"));
        assert!(!callback.contains("touch bad"));
        assert!(!callback.contains("--state-dir"));
        assert!(!callback.contains("--herdr-bin"));
        assert!(!callback.contains("--use-1password"));
    }

    #[test]
    fn shell_quoting_never_executes_remote_text() {
        let args = [OsString::from(
            "x'; touch /tmp/injected; $(id)\n\" end tell",
        )];
        let shell = shell_command(
            Path::new("/usr/bin/printf"),
            &[OsString::from("%s"), args[0].clone()],
        )
        .unwrap();
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &shell])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, args[0].as_encoded_bytes());
        assert_eq!(escape_markup("<b>a&b</b>"), "&lt;b&gt;a&amp;b&lt;/b&gt;");
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn terminal_receives_distinct_arguments_without_a_shell() {
        let root = crate::test_support::canonical_tempdir();
        let terminal = root.path().join("terminal");
        let output = root.path().join("argv");
        std::fs::write(
            &terminal,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
                output.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&terminal, std::fs::Permissions::from_mode(0o700)).unwrap();
        let launch = Launch {
            attached: "/tmp/attached with spaces".into(),
            terminal: Some(terminal),
        };
        launch.open("host/session").await.unwrap();
        for _ in 0..100 {
            if output.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let args = std::fs::read_to_string(output).unwrap();
        assert_eq!(
            args,
            "-e\n/tmp/attached with spaces\nattach\n-v\n--\nhost/session\n"
        );
    }
    #[tokio::test]
    async fn helper_failure_timeout_and_oversized_output_are_bounded() {
        assert!(
            run(
                Command::new("/bin/sh").args(["-c", "exit 2"]),
                Duration::from_secs(1)
            )
            .await
            .is_err()
        );
        assert!(
            run(
                Command::new("/bin/sleep").arg("10"),
                Duration::from_millis(20)
            )
            .await
            .is_err()
        );
        assert!(
            run(
                Command::new("/bin/sh").args(["-c", "printf '%09000d' 1"]),
                Duration::from_secs(1)
            )
            .await
            .is_err()
        );
    }
}
