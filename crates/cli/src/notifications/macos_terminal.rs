//! macOS terminal selection. Query only Launch Services' Unix-executable handler,
//! not the terminal hosting the watcher (which can differ from the user's default).
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use tokio::process::Command;

// Ghostty's "Make Ghostty the Default Terminal" menu sets this same UTI handler.
// This script is read-only and contains no user-controlled source interpolation.
#[cfg(any(target_os = "macos", test))]
const DEFAULT_TERMINAL_SCRIPT: &str = r#"ObjC.import('CoreServices');
var handler = $.LSCopyDefaultRoleHandlerForContentType($('public.unix-executable'), $.kLSRolesAll);
var identifier = ObjC.unwrap(handler);
if (!identifier) throw new Error('No default terminal is registered');
identifier;"#;

#[cfg(any(target_os = "macos", test))]
fn default_query_command() -> Command {
    let mut command = Command::new("/usr/bin/osascript");
    command.args(["-l", "JavaScript", "-e", DEFAULT_TERMINAL_SCRIPT]);
    command
}

#[cfg(target_os = "macos")]
pub(super) async fn resolve(selection: Option<&Path>) -> Result<PathBuf> {
    resolve_with(selection, || async {
        super::run(&mut default_query_command(), std::time::Duration::from_secs(5)).await
            .context("could not read the macOS default terminal; set notification_terminal in config or pass --terminal ghostty (or terminal)")
    }).await
}

#[cfg(any(target_os = "macos", test))]
async fn resolve_with<F, Fut>(selection: Option<&Path>, query: F) -> Result<PathBuf>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    if let Some(selection) = selection {
        return normalize(selection);
    }
    let output = query().await?;
    let identifier = std::str::from_utf8(&output)
        .context("macOS default terminal is not UTF-8")?
        .trim();
    // The explicit choice is carried into click callbacks, rather than detecting
    // a possibly different default later or relying on the callback's environment.
    normalize(Path::new(identifier)).context(
        "unsupported macOS default terminal; pass --terminal ghostty or --terminal terminal",
    )
}

fn normalize(selection: &Path) -> Result<PathBuf> {
    let name = selection
        .to_str()
        .context("macOS terminal selection must be UTF-8")?;
    match name.to_ascii_lowercase().as_str() {
        "ghostty" | "ghostty.app" | "com.mitchellh.ghostty" => Ok("ghostty".into()),
        "terminal" | "terminal.app" | "com.apple.terminal" => Ok("terminal".into()),
        _ if selection.is_absolute()
            && selection
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("Ghostty.app")) =>
        {
            Ok(selection.to_path_buf())
        }
        _ => bail!("macOS supports ghostty, terminal, or an absolute path to Ghostty.app"),
    }
}

pub(super) fn command(selection: &Path, executable: &Path, args: &[OsString]) -> Result<Command> {
    let selection = normalize(selection)?;
    if selection == Path::new("terminal") {
        let shell = super::shell_command(executable, args)?;
        let mut command = Command::new("/usr/bin/osascript");
        // The command is an argument, never AppleScript source.
        command.args(["-e", "on run argv\ntell application \"Terminal\"\nactivate\ndo script (item 1 of argv)\nend tell\nend run", "--", &format!("exec {shell}")]);
        return Ok(command);
    }
    let mut command = Command::new("/usr/bin/open");
    // A new app instance is essential: macOS otherwise activates an existing
    // Ghostty instance and can ignore --args. Use one initial-command option so
    // AppKit doesn't interpret absolute executable/state paths as documents to
    // open (older Ghostty releases have that problem with separate -e arguments).
    // The shell prefix is supported by Ghostty 1.2+. Every argument is quoted;
    // these process-local options never change the user's Ghostty config.
    command.arg("-n");
    if selection == Path::new("ghostty") {
        command.args(["-b", "com.mitchellh.ghostty"]);
    } else {
        command.arg("-a").arg(selection);
    }
    let shell = super::shell_command(executable, args)?;
    command
        .args([
            "--args",
            "--quit-after-last-window-closed=true",
            "--shell-integration=none",
        ])
        .arg(format!("--initial-command=shell:exec {shell}"));
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn explicit_choices_never_query_the_machine_default() {
        for (input, expected) in [
            ("Ghostty", "ghostty"),
            ("com.apple.Terminal", "terminal"),
            (
                "/Users/me/My Apps/Ghostty.app",
                "/Users/me/My Apps/Ghostty.app",
            ),
        ] {
            let selected = resolve_with(Some(Path::new(input)), || async {
                panic!("explicit choice must not inspect default")
            })
            .await
            .unwrap();
            assert_eq!(selected, Path::new(expected));
        }
        assert!(
            resolve_with(Some(Path::new("unknown")), || async {
                panic!("invalid choice must not inspect default")
            })
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn supported_defaults_are_resolved_using_mock_results_only() {
        for (id, expected) in [
            ("com.mitchellh.ghostty\n", "ghostty"),
            ("com.apple.Terminal\n", "terminal"),
        ] {
            let selected = resolve_with(None, || async { Ok(id.as_bytes().to_vec()) })
                .await
                .unwrap();
            assert_eq!(selected, Path::new(expected));
        }
        for bad in [b"com.example.unsupported\n".as_slice(), b"", b"\xff"] {
            assert!(
                resolve_with(None, || async { Ok(bad.to_vec()) })
                    .await
                    .is_err()
            );
        }
        assert!(
            resolve_with(None, || async { bail!("lookup unavailable") })
                .await
                .is_err()
        );
        let command = default_query_command();
        let args: Vec<_> = command.as_std().get_args().collect();
        assert_eq!(args[..3], ["-l", "JavaScript", "-e"]);
        assert!(
            args[3]
                .to_string_lossy()
                .contains("LSCopyDefaultRoleHandlerForContentType")
        );
        assert!(args[3].to_string_lossy().contains("public.unix-executable"));
        assert!(!args[3].to_string_lossy().contains("LSSet"));
    }

    #[test]
    fn ghostty_launches_new_instance_with_one_escaped_initial_command() {
        let target = "host/work';$(id)";
        let args = [OsString::from("%s"), target.into()];
        let launch = command(Path::new("ghostty"), Path::new("/usr/bin/printf"), &args).unwrap();
        assert_eq!(launch.as_std().get_program(), "/usr/bin/open");
        let actual: Vec<_> = launch.as_std().get_args().collect();
        assert_eq!(
            actual[..6],
            [
                "-n",
                "-b",
                "com.mitchellh.ghostty",
                "--args",
                "--quit-after-last-window-closed=true",
                "--shell-integration=none"
            ]
        );
        assert_eq!(
            actual.len(),
            7,
            "no executable/config paths passed as AppKit documents"
        );
        let initial = actual[6]
            .to_str()
            .unwrap()
            .strip_prefix("--initial-command=shell:")
            .unwrap();
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", initial])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            output.stdout,
            target.as_bytes(),
            "shell syntax must remain literal data"
        );
    }

    #[test]
    fn ghostty_app_path_with_spaces_is_one_argument_and_unknown_apps_fail() {
        let launch = command(
            Path::new("/Users/me/My Apps/Ghostty.app"),
            Path::new("/tmp/attached"),
            &[],
        )
        .unwrap();
        let actual: Vec<_> = launch.as_std().get_args().collect();
        assert_eq!(
            actual,
            [
                "-n",
                "-a",
                "/Users/me/My Apps/Ghostty.app",
                "--args",
                "--quit-after-last-window-closed=true",
                "--shell-integration=none",
                "--initial-command=shell:exec '/tmp/attached'"
            ]
        );
        for unsupported in [
            "iTerm.app",
            "/tmp/Other.app",
            "../Ghostty.app",
            "ghostty -e sh",
        ] {
            assert!(command(Path::new(unsupported), Path::new("attached"), &[]).is_err());
        }
    }
}
