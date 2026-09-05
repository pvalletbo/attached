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

#[derive(Clone)]
pub struct Launch {
    pub attached: PathBuf,
    pub state_dir: PathBuf,
    pub herdr_bin: PathBuf,
    pub terminal: Option<PathBuf>,
    pub one_password: bool,
}

impl Launch {
    fn attach_args(&self, target: &str) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("attach"),
            "--state-dir".into(),
            self.state_dir.clone().into_os_string(),
            "--herdr-bin".into(),
            self.herdr_bin.clone().into_os_string(),
        ];
        if self.one_password {
            args.push("--use-1password".into());
        }
        args.extend([OsString::from("--"), target.into()]);
        args
    }

    #[cfg(any(target_os = "macos", test))]
    fn callback_args(&self, target: &str) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("notifications"),
            "open".into(),
            "--state-dir".into(),
            self.state_dir.clone().into_os_string(),
            "--herdr-bin".into(),
            self.herdr_bin.clone().into_os_string(),
        ];
        if let Some(terminal) = &self.terminal {
            args.extend([
                OsString::from("--terminal"),
                terminal.clone().into_os_string(),
            ]);
        }
        if self.one_password {
            args.push("--use-1password".into());
        }
        args.extend([OsString::from("--"), target.into()]);
        args
    }

    pub async fn open(&self, target: &str) -> Result<()> {
        crate::sync::attach::parse_target(target)?;
        let mut command = self.terminal_command(target, cfg!(target_os = "macos"))?;
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
                "terminal launcher failed; check desktop/Terminal automation permissions"
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
            ensure!(
                self.terminal.is_none(),
                "--terminal is currently Linux-only; macOS uses Terminal.app"
            );
            let shell = shell_command(&self.attached, &self.attach_args(target))?;
            let mut command = Command::new("/usr/bin/osascript");
            // The command is an AppleScript argument, never AppleScript source.
            command.args(["-e", "on run argv\ntell application \"Terminal\"\nactivate\ndo script (item 1 of argv)\nend tell\nend run", "--", &format!("exec {shell}")]);
            return Ok(command);
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
            ensure!(
                launch.terminal.is_none(),
                "--terminal is Linux-only; macOS uses Terminal.app"
            );
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
    fn click_arguments_preserve_target_state_and_password_source() {
        let launch = Launch {
            attached: "/tmp/attached executable".into(),
            state_dir: "/tmp/state dir".into(),
            herdr_bin: "/tmp/herdr".into(),
            terminal: None,
            one_password: true,
        };
        let args = launch.attach_args("host/work");
        assert_eq!(args.last().unwrap(), "host/work");
        assert_eq!(args[args.len() - 2], "--");
        assert!(args.contains(&OsString::from("--use-1password")));
        assert!(args.contains(&OsString::from("/tmp/state dir")));
        assert!(
            !launch
                .callback_args("host/work")
                .contains(&OsString::from("--upgrade-remote"))
        );
    }
    #[test]
    fn macos_click_is_data_not_applescript_source_and_never_uses_notice_text() {
        let launch = Launch {
            attached: "/tmp/attached executable".into(),
            state_dir: "/tmp/state's dir".into(),
            herdr_bin: "/tmp/herdr".into(),
            terminal: None,
            one_password: true,
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
        assert!(callback.contains("--state-dir"));
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
            state_dir: root.path().into(),
            herdr_bin: "/tmp/herdr".into(),
            terminal: Some(terminal),
            one_password: false,
        };
        launch.open("host/session").await.unwrap();
        for _ in 0..100 {
            if output.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let args = std::fs::read_to_string(output).unwrap();
        assert!(args.starts_with("-e\n/tmp/attached with spaces\nattach\n--state-dir\n"));
        assert!(args.ends_with("--\nhost/session\n"));
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
