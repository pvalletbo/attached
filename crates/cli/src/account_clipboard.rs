use std::{
    ffi::OsStr,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use attached_session_sync_protocol::limits::MAX_BUNDLE_ENCODED_BYTES;
use zeroize::Zeroizing;

use crate::{
    endpoint_registry,
    secure_state::{self, StateDir},
};

#[cfg(target_os = "macos")]
use arboard::SetExtApple as _;
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
))]
use arboard::SetExtLinux as _;

pub(crate) const HELPER_COMMAND: &str = "__clipboard-serve";

const READY: &[u8] = b"ready\n";
const GENERATION_BYTES: usize = 16;
const GENERATION_FILE: &str = "generation";
const GENERATION_LOCK: &str = "generation.lock";
pub(crate) const RETENTION: Duration = Duration::from_secs(120);

/// Recognizes only the exact private invocation emitted by [`copy`]. Running
/// before Tokio starts avoids initializing clipboard support inside its runtime.
pub(crate) fn helper_requested() -> bool {
    is_helper_invocation(std::env::args_os())
}

fn is_helper_invocation<I, S>(arguments: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut arguments = arguments.into_iter();
    let _executable = arguments.next();
    arguments
        .next()
        .is_some_and(|argument| argument.as_ref() == OsStr::new(HELPER_COMMAND))
        && arguments.next().is_none()
}

/// Copies a bundle through a short-lived background helper so Linux clipboard
/// ownership survives this command and every platform can clear the secret later.
pub(crate) fn copy(bundle: &str) -> Result<()> {
    ensure!(!bundle.is_empty(), "account bundle is empty");
    ensure!(
        bundle.len() <= MAX_BUNDLE_ENCODED_BYTES,
        "account bundle exceeds clipboard limit"
    );

    let executable = std::env::current_exe().context("could not locate the Attached executable")?;
    let mut child = Command::new(executable)
        .arg(HELPER_COMMAND)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("could not start the clipboard helper")?;

    let result = send_to_helper(&mut child, bundle);
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

fn send_to_helper(child: &mut Child, bundle: &str) -> Result<()> {
    let mut input = child
        .stdin
        .take()
        .context("clipboard helper input is unavailable")?;
    input
        .write_all(bundle.as_bytes())
        .context("could not send the account bundle to the clipboard helper")?;
    drop(input);

    let mut output = child
        .stdout
        .take()
        .context("clipboard helper output is unavailable")?;
    let mut readiness = [0_u8; READY.len()];
    output
        .read_exact(&mut readiness)
        .context("clipboard helper exited before copying the account bundle")?;
    ensure!(
        readiness == READY,
        "clipboard helper returned an invalid readiness response"
    );
    Ok(())
}

/// Runs in the background helper process. The bundle arrives over stdin rather
/// than command-line arguments or the environment, where it would be easier to
/// expose through process inspection.
pub(crate) fn serve() -> Result<()> {
    let mut clipboard = SystemClipboard::open()?;
    let coordination = default_coordination_dir()?;
    let generation = new_generation()?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve_with(
        &mut clipboard,
        stdin.lock(),
        stdout.lock(),
        RETENTION,
        &coordination,
        generation,
    )
}

fn serve_with(
    clipboard: &mut impl SecretClipboard,
    input: impl Read,
    mut readiness: impl Write,
    retention: Duration,
    coordination: &Path,
    generation: [u8; GENERATION_BYTES],
) -> Result<()> {
    let bundle = read_bundle(input)?;
    claim_clipboard(clipboard, &bundle, coordination, &generation)?;

    if let Err(error) = readiness
        .write_all(READY)
        .and_then(|()| readiness.flush())
        .context("could not confirm clipboard readiness")
    {
        let _ = clear_if_latest(clipboard, &bundle, coordination, &generation);
        return Err(error);
    }

    retain_then_clear(clipboard, &bundle, retention, coordination, &generation)
}

fn read_bundle(input: impl Read) -> Result<Zeroizing<String>> {
    let mut bundle = Zeroizing::new(String::new());
    input
        .take((MAX_BUNDLE_ENCODED_BYTES + 1) as u64)
        .read_to_string(&mut bundle)
        .context("clipboard helper input is not valid UTF-8")?;
    ensure!(
        !bundle.is_empty(),
        "clipboard helper received an empty bundle"
    );
    ensure!(
        bundle.len() <= MAX_BUNDLE_ENCODED_BYTES,
        "clipboard helper input exceeds the account bundle limit"
    );
    Ok(bundle)
}

fn default_coordination_dir() -> Result<PathBuf> {
    let registry_dir = endpoint_registry::default_dir()?;
    let user_root = registry_dir
        .parent()
        .context("endpoint registry has no private user root")?;
    Ok(user_root.join("clipboard"))
}

fn new_generation() -> Result<[u8; GENERATION_BYTES]> {
    let mut generation = [0_u8; GENERATION_BYTES];
    getrandom::fill(&mut generation)
        .context("operating-system randomness is unavailable for clipboard coordination")?;
    Ok(generation)
}

// A non-secret generation prevents an older helper from clearing a newer copy
// when deterministic exports place the same bundle on the clipboard again.
fn claim_clipboard(
    clipboard: &mut impl SecretClipboard,
    bundle: &str,
    coordination: &Path,
    generation: &[u8; GENERATION_BYTES],
) -> Result<()> {
    with_coordination_lock(coordination, |directory| {
        clipboard
            .set_secret(bundle)
            .context("could not place the account bundle on the clipboard")?;
        if let Err(error) = write_generation(directory, generation) {
            let _ = clear_if_current(clipboard, bundle);
            return Err(error);
        }
        Ok(())
    })
}

fn write_generation(directory: &StateDir, generation: &[u8; GENERATION_BYTES]) -> Result<()> {
    match directory.read_secret_optional_bounded(GENERATION_FILE, GENERATION_BYTES)? {
        Some(existing) => {
            ensure!(
                existing.len() == GENERATION_BYTES,
                "clipboard generation file has invalid length"
            );
            directory.atomic_replace(GENERATION_FILE, generation)
        }
        None => {
            ensure!(
                directory.create_noclobber(GENERATION_FILE, generation)?,
                "clipboard generation appeared while its lock was held"
            );
            Ok(())
        }
    }
}

fn clear_if_latest(
    clipboard: &mut impl SecretClipboard,
    bundle: &str,
    coordination: &Path,
    generation: &[u8; GENERATION_BYTES],
) -> Result<()> {
    with_coordination_lock(coordination, |directory| {
        let Some(current) =
            directory.read_secret_optional_bounded(GENERATION_FILE, GENERATION_BYTES)?
        else {
            return Ok(());
        };
        ensure!(
            current.len() == GENERATION_BYTES,
            "clipboard generation file has invalid length"
        );
        if current.as_slice() == generation {
            clear_if_current(clipboard, bundle)?;
        }
        Ok(())
    })
}

fn with_coordination_lock<T>(
    coordination: &Path,
    operation: impl FnOnce(&StateDir) -> Result<T>,
) -> Result<T> {
    let user_root = coordination
        .parent()
        .context("clipboard coordination directory has no private user root")?;
    let _root =
        StateDir::open(user_root).context("clipboard coordination user root is not private")?;
    secure_state::with_exclusive_lock(coordination, GENERATION_LOCK, operation)
        .context("could not coordinate clipboard ownership")
}

fn retain_then_clear(
    clipboard: &mut impl SecretClipboard,
    bundle: &str,
    retention: Duration,
    coordination: &Path,
    generation: &[u8; GENERATION_BYTES],
) -> Result<()> {
    thread::sleep(retention);
    clear_if_latest(clipboard, bundle, coordination, generation)
}

fn clear_if_current(clipboard: &mut impl SecretClipboard, bundle: &str) -> Result<()> {
    if clipboard.current_matches(bundle) {
        clipboard
            .clear_secret()
            .context("could not clear the exported account bundle from the clipboard")?;
    }
    Ok(())
}

trait SecretClipboard {
    fn set_secret(&mut self, secret: &str) -> Result<()>;
    fn current_matches(&mut self, secret: &str) -> bool;
    fn clear_secret(&mut self) -> Result<()>;
}

struct SystemClipboard {
    inner: arboard::Clipboard,
}

impl SystemClipboard {
    fn open() -> Result<Self> {
        arboard::Clipboard::new()
            .map(|inner| Self { inner })
            .context("system clipboard is unavailable")
    }
}

impl SecretClipboard for SystemClipboard {
    fn set_secret(&mut self, secret: &str) -> Result<()> {
        self.inner
            .set()
            .exclude_from_history()
            .text(secret)
            .context("system clipboard rejected the account bundle")
    }

    fn current_matches(&mut self, secret: &str) -> bool {
        self.inner.get_text().is_ok_and(|current| {
            let current = Zeroizing::new(current);
            current.as_str() == secret
        })
    }

    fn clear_secret(&mut self) -> Result<()> {
        self.inner
            .clear()
            .context("system clipboard could not be cleared")
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[derive(Default)]
    struct FakeClipboard {
        contents: Option<String>,
        set_count: usize,
        clear_count: usize,
    }

    impl SecretClipboard for FakeClipboard {
        fn set_secret(&mut self, secret: &str) -> Result<()> {
            self.contents = Some(secret.to_owned());
            self.set_count += 1;
            Ok(())
        }

        fn current_matches(&mut self, secret: &str) -> bool {
            self.contents.as_deref() == Some(secret)
        }

        fn clear_secret(&mut self) -> Result<()> {
            self.contents = None;
            self.clear_count += 1;
            Ok(())
        }
    }

    #[test]
    fn private_helper_invocation_must_match_exactly() {
        assert!(is_helper_invocation(["attached", HELPER_COMMAND]));
        assert!(!is_helper_invocation(["attached"]));
        assert!(!is_helper_invocation(["attached", HELPER_COMMAND, "extra"]));
        assert!(!is_helper_invocation([
            "attached",
            "account",
            HELPER_COMMAND
        ]));
    }

    #[test]
    fn helper_copies_without_echoing_and_clears_after_retention() {
        let secret = "synthetic-account-bundle";
        let root = crate::test_support::canonical_tempdir();
        let coordination = root.path().join("private-user-root").join("clipboard");
        let generation = [0x11; GENERATION_BYTES];
        let mut clipboard = FakeClipboard::default();
        let mut readiness = Vec::new();

        serve_with(
            &mut clipboard,
            Cursor::new(secret),
            &mut readiness,
            Duration::ZERO,
            &coordination,
            generation,
        )
        .unwrap();

        assert_eq!(readiness, READY);
        assert!(
            !readiness
                .windows(secret.len())
                .any(|bytes| bytes == secret.as_bytes())
        );
        assert_eq!(clipboard.set_count, 1);
        assert_eq!(clipboard.clear_count, 1);
        assert!(clipboard.contents.is_none());
        assert_eq!(
            std::fs::read(coordination.join(GENERATION_FILE)).unwrap(),
            generation
        );
        assert_ne!(generation.as_slice(), secret.as_bytes());
    }

    #[test]
    fn failed_readiness_signal_clears_the_secret() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "synthetic failure",
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let root = crate::test_support::canonical_tempdir();
        let coordination = root.path().join("private-user-root").join("clipboard");
        let mut clipboard = FakeClipboard::default();
        assert!(
            serve_with(
                &mut clipboard,
                Cursor::new("synthetic-account-bundle"),
                FailingWriter,
                Duration::ZERO,
                &coordination,
                [0x22; GENERATION_BYTES],
            )
            .is_err()
        );
        assert_eq!(clipboard.clear_count, 1);
        assert!(clipboard.contents.is_none());
    }

    #[test]
    fn cleanup_never_clears_clipboard_content_copied_later() {
        let mut clipboard = FakeClipboard {
            contents: Some("new user content".to_owned()),
            ..FakeClipboard::default()
        };

        clear_if_current(&mut clipboard, "old account bundle").unwrap();

        assert_eq!(clipboard.contents.as_deref(), Some("new user content"));
        assert_eq!(clipboard.clear_count, 0);
    }

    #[test]
    fn older_helper_never_clears_an_identical_newer_export() {
        let root = crate::test_support::canonical_tempdir();
        let coordination = root.path().join("private-user-root").join("clipboard");
        let first = [0x31; GENERATION_BYTES];
        let second = [0x32; GENERATION_BYTES];
        let bundle = "deterministic-account-bundle";
        let mut clipboard = FakeClipboard::default();

        claim_clipboard(&mut clipboard, bundle, &coordination, &first).unwrap();
        claim_clipboard(&mut clipboard, bundle, &coordination, &second).unwrap();
        clear_if_latest(&mut clipboard, bundle, &coordination, &first).unwrap();

        assert_eq!(clipboard.contents.as_deref(), Some(bundle));
        assert_eq!(clipboard.clear_count, 0);

        clear_if_latest(&mut clipboard, bundle, &coordination, &second).unwrap();
        assert!(clipboard.contents.is_none());
        assert_eq!(clipboard.clear_count, 1);
    }

    #[test]
    fn helper_rejects_empty_oversized_and_non_utf8_input_before_copying() {
        let root = crate::test_support::canonical_tempdir();
        let coordination = root.path().join("private-user-root").join("clipboard");
        let oversized = vec![b'x'; MAX_BUNDLE_ENCODED_BYTES + 1];
        for input in [Vec::new(), oversized, vec![0xff]] {
            let mut clipboard = FakeClipboard::default();
            let mut readiness = Vec::new();
            let error = serve_with(
                &mut clipboard,
                Cursor::new(input),
                &mut readiness,
                Duration::ZERO,
                &coordination,
                [0x41; GENERATION_BYTES],
            )
            .unwrap_err()
            .to_string();

            assert!(!error.is_empty());
            assert_eq!(clipboard.set_count, 0);
            assert!(readiness.is_empty());
        }
    }
}
