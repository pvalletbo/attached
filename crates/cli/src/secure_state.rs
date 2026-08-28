use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use fs4::FileExt;
use rustix::{
    fs::{AtFlags, Mode, OFlags},
    process::geteuid,
};
use zeroize::Zeroizing;

/// Runs a state mutation while holding an owner-only inter-process lock.
///
/// Durable file creation and replacement remain in `StateDir`. Once an
/// operation succeeds, an unlock failure is diagnostic only: reporting an
/// ordinary failure could cause callers to retry an already committed mutation.
pub(crate) fn with_exclusive_lock<T>(
    state_dir: &Path,
    lock_name: &str,
    operation: impl FnOnce(&StateDir) -> Result<T>,
) -> Result<T> {
    with_locked_inner(StateDir::open(state_dir)?, state_dir, lock_name, operation)
}

pub(crate) fn with_exclusive_lock_until<T>(
    state_dir: &Path,
    lock_name: &str,
    deadline: Instant,
    operation: impl FnOnce(&StateDir) -> Result<T>,
) -> Result<T> {
    let directory = StateDir::open(state_dir)?;
    let lock = acquire_lock_until(&directory, state_dir, lock_name, deadline)?;
    finish_locked_operation(lock, operation(&directory))
}

pub(crate) fn with_locked_existing<T>(
    state_dir: &Path,
    lock_name: &str,
    operation: impl FnOnce(&StateDir) -> Result<T>,
) -> Result<T> {
    with_locked_inner(
        StateDir::open_existing(state_dir)?,
        state_dir,
        lock_name,
        operation,
    )
}

fn with_locked_inner<T>(
    directory: StateDir,
    state_dir: &Path,
    lock_name: &str,
    operation: impl FnOnce(&StateDir) -> Result<T>,
) -> Result<T> {
    let lock = acquire_lock(&directory, state_dir, lock_name)?;
    finish_locked_operation(lock, operation(&directory))
}

fn finish_locked_operation<T>(lock: File, result: Result<T>) -> Result<T> {
    let unlock = FileExt::unlock(&lock).context("failed to unlock state lock");
    match (result, unlock) {
        (Err(error), _) => Err(error),
        (Ok(value), Err(error)) => {
            tracing::warn!(error = %error, "state mutation committed but explicit unlock failed");
            Ok(value)
        }
        (Ok(value), Ok(())) => Ok(value),
    }
}

fn acquire_lock(directory: &StateDir, state_dir: &Path, lock_name: &str) -> Result<File> {
    let lock = open_validated_lock(directory, lock_name)?;
    FileExt::lock(&lock).with_context(|| format!("failed to lock state file {lock_name}"))?;
    verify_locked_path(directory, state_dir, lock_name, &lock)?;
    Ok(lock)
}

fn acquire_lock_until(
    directory: &StateDir,
    state_dir: &Path,
    lock_name: &str,
    deadline: Instant,
) -> Result<File> {
    let lock = open_validated_lock(directory, lock_name)?;
    loop {
        match FileExt::try_lock(&lock) {
            Ok(()) => break,
            Err(fs4::TryLockError::WouldBlock) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                ensure!(
                    !remaining.is_zero(),
                    "timed out waiting for state lock {lock_name}"
                );
                std::thread::sleep(remaining.min(Duration::from_millis(10)));
            }
            Err(fs4::TryLockError::Error(error)) => {
                return Err(error)
                    .with_context(|| format!("failed to lock state file {lock_name}"));
            }
        }
    }
    verify_locked_path(directory, state_dir, lock_name, &lock)?;
    Ok(lock)
}

fn open_validated_lock(directory: &StateDir, lock_name: &str) -> Result<File> {
    validate_name(lock_name, "state lock")?;
    let (lock, created) = match openat_file(
        &directory.directory,
        lock_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
            openat_file(
                &directory.directory,
                lock_name,
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| format!("failed to reopen state lock {lock_name}"))?,
            false,
        ),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to create state lock {lock_name}"));
        }
    };
    if created {
        protect_file(&lock).with_context(|| format!("failed to protect state lock {lock_name}"))?;
    }
    validate_file(&lock, lock_name, 0o600)?;
    if created {
        directory
            .directory
            .sync_all()
            .context("failed to sync state directory after creating lock")?;
    }
    Ok(lock)
}

fn verify_locked_path(
    directory: &StateDir,
    state_dir: &Path,
    lock_name: &str,
    lock: &File,
) -> Result<()> {
    validate_private_dir(&directory.directory, state_dir)?;
    verify_path_identity(&directory.directory, lock_name, lock)
}

pub fn prepare_private_dir(path: &Path) -> Result<()> {
    open_state_directory(path, true, true).map(drop)
}

/// Creates a credential export as a new owner-only file without involving the
/// shell's redirection semantics. The final path is never followed or replaced.
pub(crate) fn create_secret_output(path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .context("bundle output path has no file name")?;
    validate_name(file_name, "bundle output")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)
    .context("could not open bundle output directory")?;
    let mut file = rustix::fs::openat(
        &directory,
        file_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(std::io::Error::from)
    .context("could not create bundle output without overwriting an existing file")?;
    let write = (|| -> Result<()> {
        protect_file(&file)?;
        validate_file(&file, "bundle output", 0o600)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write {
        let _ = unlinkat(&directory, file_name);
        return Err(error).context("could not securely write bundle output");
    }
    directory
        .sync_all()
        .context("could not sync bundle output directory")
}

pub(crate) struct StateDir {
    directory: File,
}

impl StateDir {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        open_state_directory(path, true, false).map(|directory| Self { directory })
    }

    fn open_existing(path: &Path) -> Result<Self> {
        open_state_directory(path, false, false).map(|directory| Self { directory })
    }

    pub(crate) fn open_private_lock_file(&self, name: &str, create: bool) -> Result<Option<File>> {
        validate_name(name, "lock file")?;
        let (file, created) = match openat_file(
            &self.directory,
            name,
            OFlags::RDWR
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | if create {
                    OFlags::CREATE | OFlags::EXCL
                } else {
                    OFlags::empty()
                },
            if create {
                Mode::RUSR | Mode::WUSR
            } else {
                Mode::empty()
            },
        ) {
            Ok(file) => (file, create),
            Err(error) if create && error.kind() == std::io::ErrorKind::AlreadyExists => (
                openat_file(
                    &self.directory,
                    name,
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("failed to reopen lock file {name}"))?,
                false,
            ),
            Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to open lock file {name}"));
            }
        };
        if created {
            protect_file(&file).with_context(|| format!("failed to protect lock file {name}"))?;
        }
        validate_file(&file, name, 0o600)?;
        if created {
            self.directory
                .sync_all()
                .context("failed to sync state directory after creating lock file")?;
        }
        Ok(Some(file))
    }

    pub(crate) fn verify_locked_file(&self, path: &Path, name: &str, file: &File) -> Result<()> {
        validate_private_dir(&self.directory, path)?;
        verify_path_identity(&self.directory, name, file)
    }

    #[cfg(test)]
    pub(crate) fn read_optional_bounded(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Option<Vec<u8>>> {
        validate_name(name, "state file")?;
        let file = match openat_file(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("failed to open state file {name}"));
            }
        };
        let bytes = read_bounded_file(file, name, limit)?;
        Ok(Some(bytes))
    }

    #[cfg(test)]
    pub(crate) fn read_bounded(&self, name: &str, limit: usize) -> Result<Vec<u8>> {
        self.read_optional_bounded(name, limit)?
            .with_context(|| format!("state file {name} is missing"))
    }

    pub(crate) fn read_secret_optional_bounded(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        validate_name(name, "state file")?;
        let file = match openat_file(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("failed to open state file {name}"));
            }
        };
        read_secret_bounded_file(file, name, limit).map(Some)
    }

    pub(crate) fn read_secret_bounded(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.read_secret_optional_bounded(name, limit)?
            .with_context(|| format!("state file {name} is missing"))
    }

    /// Replaces one validated state file through a synced temporary file and
    /// atomic rename. After rename, failures are diagnostic only because the
    /// new bytes are already visible and an ordinary error would invite an
    /// unsafe retry of an already committed mutation.
    pub(crate) fn atomic_replace(&self, name: &str, bytes: &[u8]) -> Result<()> {
        validate_name(name, "state file")?;
        validate_existing(&self.directory, name)?;
        let temporary_name = temporary_name(name)?;
        let mut temporary = openat_file(
            &self.directory,
            &temporary_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        let pre_rename = (|| -> Result<()> {
            protect_file(&temporary)?;
            validate_file(&temporary, &temporary_name, 0o600)?;
            temporary.write_all(bytes)?;
            temporary.sync_all()?;
            validate_existing(&self.directory, name)?;
            renameat(&self.directory, &temporary_name, name)?;
            Ok(())
        })();
        if let Err(error) = pre_rename {
            let _ = unlinkat(&self.directory, &temporary_name);
            return Err(error).context("could not durably replace state file");
        }
        if let Err(error) = self.directory.sync_all() {
            tracing::warn!(%error, name, "state file was replaced but directory sync failed");
        }
        Ok(())
    }

    /// Creates one owner-only file without replacing a concurrently installed
    /// value. The caller decides whether an existing validated file is usable.
    pub(crate) fn create_noclobber(&self, name: &str, bytes: &[u8]) -> Result<bool> {
        validate_name(name, "state file")?;
        let mut file = match openat_file(
            &self.directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = openat_file(
                    &self.directory,
                    name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                validate_file(&existing, name, 0o600)?;
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        let before_sync = (|| -> Result<()> {
            protect_file(&file)?;
            validate_file(&file, name, 0o600)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(error) = before_sync {
            let _ = unlinkat(&self.directory, name);
            return Err(error).context("could not durably create state file");
        }
        if let Err(error) = self.directory.sync_all() {
            tracing::warn!(%error, name, "state file was created but directory sync failed");
        }
        Ok(true)
    }
}

fn open_state_directory(path: &Path, create: bool, repair_permissions: bool) -> Result<File> {
    ensure!(!path.as_os_str().is_empty(), "state path is empty");
    let start = if path.is_absolute() { "/" } else { "." };
    let mut directory = open_directory_path(Path::new(start))?;

    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = open_or_create_directory_at(&directory, name.as_bytes(), create)
                    .with_context(|| {
                        format!("failed to traverse state directory {}", path.display())
                    })?;
            }
            Component::ParentDir => {
                anyhow::bail!("state path must not contain a parent component")
            }
            Component::Prefix(_) => anyhow::bail!("unsupported state path prefix"),
        }
    }

    if repair_permissions {
        let metadata = directory.metadata()?;
        ensure!(
            metadata.uid() == geteuid().as_raw(),
            "{} is not owned by the current user",
            path.display()
        );
        if metadata.mode() & 0o7777 != 0o700 {
            protect_directory(&directory)
                .with_context(|| format!("failed to protect state directory {}", path.display()))?;
        }
    }
    validate_private_dir(&directory, path)?;
    Ok(directory)
}

fn open_directory_path(path: &Path) -> Result<File> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)
    .context("failed to open traversal root")
}

fn open_or_create_directory_at(parent: &File, name: &[u8], create: bool) -> Result<File> {
    let mut created = false;
    let mut directory = openat_directory(parent, name);
    if let Err(error) = &directory
        && create
        && error.kind() == std::io::ErrorKind::NotFound
    {
        match rustix::fs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) => created = true,
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => {
                return Err(std::io::Error::from(error))
                    .context("failed to create state directory component");
            }
        }
        directory = openat_directory(parent, name);
    }
    let directory = directory.context("failed to open state directory component")?;
    if created {
        protect_directory(&directory).context("failed to protect state directory component")?;
        let metadata = directory.metadata()?;
        validate_owner_mode(&metadata, "new state directory component", 0o700)?;
        directory
            .sync_all()
            .context("failed to sync new state directory component")?;
        #[cfg(test)]
        tests::record_directory_sync(name, "child");
        parent
            .sync_all()
            .context("failed to sync parent after creating state directory component")?;
        #[cfg(test)]
        tests::record_directory_sync(name, "parent");
    }
    Ok(directory)
}

fn openat_directory(parent: &File, name: &[u8]) -> std::io::Result<File> {
    rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)
}

#[cfg(test)]
fn read_bounded_file(file: File, name: &str, limit: usize) -> Result<Vec<u8>> {
    validate_file(&file, name, 0o600)?;
    ensure!(
        file.metadata()?.len() <= limit as u64,
        "state file {name} exceeds {limit} bytes"
    );
    read_bounded_contents(file, name, limit)
}

#[cfg(test)]
fn read_bounded_contents(mut file: File, name: &str, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read state file {name}"))?;
    ensure!(
        bytes.len() <= limit,
        "state file {name} exceeds {limit} bytes"
    );
    Ok(bytes)
}

fn read_secret_bounded_file(
    mut file: File,
    name: &str,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    validate_file(&file, name, 0o600)?;
    ensure!(
        file.metadata()?.len() <= limit as u64,
        "state file {name} exceeds {limit} bytes"
    );
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit.min(8192)));
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read state file {name}"))?;
    ensure!(
        bytes.len() <= limit,
        "state file {name} exceeds {limit} bytes"
    );
    Ok(bytes)
}

fn validate_private_dir(directory: &File, path: &Path) -> Result<()> {
    let metadata = directory.metadata()?;
    ensure!(metadata.is_dir(), "{} is not a directory", path.display());
    validate_owner_mode(&metadata, &path.display().to_string(), 0o700)
}

fn validate_existing(directory: &File, name: &str) -> Result<()> {
    match openat_file(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => validate_file(&file, name, 0o600),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to inspect state file {name}")),
    }
}

fn temporary_name(name: &str) -> Result<String> {
    let mut nonce = [0u8; 16];
    File::open("/dev/urandom")
        .context("failed to open operating-system random source")?
        .read_exact(&mut nonce)
        .context("failed to generate temporary state filename")?;
    Ok(format!(".{name}.tmp.{}", hex(&nonce)))
}

fn protect_file(file: &File) -> std::io::Result<()> {
    rustix::fs::fchmod(file, Mode::RUSR | Mode::WUSR).map_err(std::io::Error::from)
}

fn protect_directory(directory: &File) -> std::io::Result<()> {
    rustix::fs::fchmod(directory, Mode::RUSR | Mode::WUSR | Mode::XUSR)
        .map_err(std::io::Error::from)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn openat_file(directory: &File, name: &str, flags: OFlags, mode: Mode) -> std::io::Result<File> {
    rustix::fs::openat(directory, name, flags, mode)
        .map(File::from)
        .map_err(std::io::Error::from)
}

fn renameat(directory: &File, old: &str, new: &str) -> std::io::Result<()> {
    rustix::fs::renameat(directory, old, directory, new).map_err(std::io::Error::from)
}

fn unlinkat(directory: &File, name: &str) -> std::io::Result<()> {
    rustix::fs::unlinkat(directory, name, AtFlags::empty()).map_err(std::io::Error::from)
}

fn validate_name(name: &str, kind: &str) -> Result<()> {
    ensure!(
        Path::new(name).components().count() == 1
            && matches!(
                Path::new(name).components().next(),
                Some(Component::Normal(_))
            ),
        "{kind} name must be one normal path component"
    );
    ensure!(!name.as_bytes().contains(&0), "{kind} name contains NUL");
    Ok(())
}

fn validate_file(file: &File, name: &str, expected_mode: u32) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "{name} is not a regular file");
    validate_owner_mode(&metadata, name, expected_mode)?;
    ensure!(metadata.nlink() == 1, "{name} has multiple hard links");
    Ok(())
}

fn validate_owner_mode(metadata: &fs::Metadata, name: &str, expected: u32) -> Result<()> {
    let effective_uid = geteuid().as_raw();
    ensure!(
        metadata.uid() == effective_uid,
        "{name} is not owned by the current user"
    );
    let actual = metadata.mode() & 0o7777;
    ensure!(
        actual == expected,
        "{name} has unsafe permissions {actual:04o}; expected {expected:04o}"
    );
    Ok(())
}

fn verify_path_identity(directory: &File, name: &str, file: &File) -> Result<()> {
    let reopened = openat_file(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("state lock path {name} changed while locking"))?;
    validate_file(&reopened, name, 0o600)?;
    let locked = file.metadata()?;
    let current = reopened.metadata()?;
    ensure!(
        locked.dev() == current.dev() && locked.ino() == current.ino(),
        "state lock path {name} changed while locking"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, sync::mpsc, thread, time::Duration};

    use super::*;

    thread_local! {
        static DIRECTORY_SYNC_TRACE: std::cell::RefCell<Option<Vec<String>>> = const {
            std::cell::RefCell::new(None)
        };
    }

    fn with_locked<T>(
        state_dir: &Path,
        lock_name: &str,
        operation: impl FnOnce(&StateDir) -> Result<T>,
    ) -> Result<T> {
        with_locked_inner(StateDir::open(state_dir)?, state_dir, lock_name, operation)
    }

    fn read_bounded(state_dir: &Path, name: &str, limit: usize) -> Result<Vec<u8>> {
        StateDir::open(state_dir)?.read_bounded(name, limit)
    }

    fn atomic_replace(state_dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
        StateDir::open(state_dir)?.atomic_replace(name, bytes)
    }

    pub(super) fn record_directory_sync(name: &[u8], target: &str) {
        DIRECTORY_SYNC_TRACE.with(|trace| {
            if let Some(events) = trace.borrow_mut().as_mut() {
                events.push(format!("{}:{target}", String::from_utf8_lossy(name)));
            }
        });
    }

    fn capture_directory_syncs_for_test(operation: impl FnOnce()) -> Vec<String> {
        DIRECTORY_SYNC_TRACE.with(|trace| {
            assert!(trace.borrow().is_none(), "directory sync capture is nested");
            *trace.borrow_mut() = Some(Vec::new());
        });
        operation();
        DIRECTORY_SYNC_TRACE
            .with(|trace| trace.borrow_mut().take().expect("sync capture was armed"))
    }

    #[test]
    fn successful_mutation_is_not_reported_as_failed_when_unlock_fails() {
        let root = crate::test_support::canonical_tempdir();
        let path = root.path().join("lock");
        fs::write(&path, b"").unwrap();
        let invalid = rustix::fs::open(&path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
            .map(File::from)
            .unwrap();
        assert!(
            FileExt::unlock(&invalid).is_err(),
            "O_PATH fixture must reject unlocking"
        );
        let invalid = rustix::fs::open(&path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
            .map(File::from)
            .unwrap();

        assert_eq!(finish_locked_operation(invalid, Ok(7)).unwrap(), 7);
    }

    #[test]
    fn private_directory_is_created_owner_only() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        assert!(state.is_dir());
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o7777,
            0o700
        );
    }

    #[test]
    fn private_directory_creation_rejects_a_symlinked_ancestor() {
        let root = crate::test_support::canonical_tempdir();
        let real_parent = root.path().join("real-parent");
        fs::create_dir(&real_parent).unwrap();
        std::os::unix::fs::symlink(&real_parent, root.path().join("linked-parent")).unwrap();

        let state = root.path().join("linked-parent").join("state");
        assert!(prepare_private_dir(&state).is_err());
        assert!(!real_parent.join("state").exists());
    }

    #[test]
    fn nested_directory_creation_syncs_each_child_then_its_pinned_parent() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("first").join("second");

        let syncs = capture_directory_syncs_for_test(|| prepare_private_dir(&state).unwrap());

        assert_eq!(
            syncs,
            [
                "first:child",
                "first:parent",
                "second:child",
                "second:parent",
            ]
        );
    }

    #[test]
    fn existing_directory_with_unsafe_permissions_is_repaired() {
        // APFS may clear setgid during chmod, so use permission changes that
        // every supported filesystem preserves. Other Unix targets also cover
        // the special-bit case.
        #[cfg(target_os = "macos")]
        let modes = [0o775, 0o755, 0o750];
        #[cfg(not(target_os = "macos"))]
        let modes = [0o775, 0o755, 0o750, 0o2700];

        for mode in modes {
            let root = crate::test_support::canonical_tempdir();
            let state = root.path().join("state");
            fs::create_dir(&state).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(mode)).unwrap();

            prepare_private_dir(&state).unwrap();

            assert_eq!(
                fs::metadata(&state).unwrap().permissions().mode() & 0o7777,
                0o700
            );
        }
    }

    #[test]
    fn bounded_read_rejects_symlinks_hardlinks_nonregular_wrong_mode_and_oversized_files() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        fs::write(state.join("target"), b"12345").unwrap();
        fs::set_permissions(state.join("target"), fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink("target", state.join("symlink")).unwrap();
        fs::hard_link(state.join("target"), state.join("hardlink")).unwrap();
        fs::create_dir(state.join("directory")).unwrap();
        fs::write(state.join("wrong-mode"), b"x").unwrap();
        fs::set_permissions(state.join("wrong-mode"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_bounded(&state, "symlink", 5).is_err());
        assert!(read_bounded(&state, "hardlink", 5).is_err());
        assert!(read_bounded(&state, "target", 4).is_err());
        assert!(read_bounded(&state, "directory", 5).is_err());
        assert!(read_bounded(&state, "wrong-mode", 5).is_err());
    }

    #[test]
    fn streamed_bound_catches_growth_after_metadata_check() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        fs::write(state.join("data"), b"1234").unwrap();
        fs::set_permissions(state.join("data"), fs::Permissions::from_mode(0o600)).unwrap();
        let file = File::open(state.join("data")).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 4);
        let mut writer = fs::OpenOptions::new()
            .append(true)
            .open(state.join("data"))
            .unwrap();
        writer.write_all(b"5").unwrap();

        let result = read_bounded_contents(file, "data", 4);
        assert!(result.unwrap_err().to_string().contains("exceeds 4 bytes"));
    }

    #[test]
    fn secret_bounded_reads_return_zeroizing_storage_from_the_boundary() {
        fn assert_zeroizing(_: &zeroize::Zeroizing<Vec<u8>>) {}
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        fs::write(state.join("secret"), b"synthetic-secret").unwrap();
        fs::set_permissions(state.join("secret"), fs::Permissions::from_mode(0o600)).unwrap();

        let bytes = StateDir::open(&state)
            .unwrap()
            .read_secret_bounded("secret", 64)
            .unwrap();

        assert_zeroizing(&bytes);
        assert_eq!(bytes.as_slice(), b"synthetic-secret");
    }

    #[test]
    fn bundle_output_is_owner_only_and_noclobber() {
        let root = crate::test_support::canonical_tempdir();
        let output = root.path().join("download.bundle");

        create_secret_output(&output, b"synthetic bundle").unwrap();

        assert_eq!(fs::read(&output).unwrap(), b"synthetic bundle");
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert!(create_secret_output(&output, b"replacement").is_err());
        assert_eq!(fs::read(&output).unwrap(), b"synthetic bundle");

        let target = root.path().join("target");
        fs::write(&target, b"existing").unwrap();
        let link = root.path().join("linked.bundle");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(create_secret_output(&link, b"replacement").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"existing");
    }

    #[test]
    fn atomic_replace_writes_complete_owner_only_file() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        fs::write(state.join("registry.json"), b"old").unwrap();
        fs::set_permissions(
            state.join("registry.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        atomic_replace(&state, "registry.json", b"new complete").unwrap();
        assert_eq!(
            fs::read(state.join("registry.json")).unwrap(),
            b"new complete"
        );
        assert_eq!(
            fs::metadata(state.join("registry.json")).unwrap().mode() & 0o7777,
            0o600
        );
    }

    #[test]
    fn exclusive_state_mutations_serialize_on_a_stable_lock_file() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        let (first_entered_tx, first_entered_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first_state = state.clone();
        let first = thread::spawn(move || {
            with_exclusive_lock(&first_state, "registry.lock", |_| {
                first_entered_tx.send(()).unwrap();
                release_first_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
        });
        first_entered_rx.recv().unwrap();
        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let second_state = state.clone();
        let second = thread::spawn(move || {
            with_exclusive_lock(&second_state, "registry.lock", |_| {
                second_entered_tx.send(()).unwrap();
                Ok(())
            })
            .unwrap();
        });
        assert!(
            second_entered_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
        release_first_tx.send(()).unwrap();
        second_entered_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        first.join().unwrap();
        second.join().unwrap();
    }

    #[test]
    fn transaction_keeps_using_locked_directory_after_path_replacement() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        with_exclusive_lock(&state, "registry.lock", |transaction| {
            let locked_state = root.path().join("locked-state");
            fs::rename(&state, &locked_state).unwrap();
            fs::create_dir(&state).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
            transaction.atomic_replace("registry.json", b"pinned")?;
            assert_eq!(transaction.read_bounded("registry.json", 32)?, b"pinned");
            assert!(!state.join("registry.json").exists());
            assert_eq!(
                fs::read(locked_state.join("registry.json")).unwrap(),
                b"pinned"
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn no_clobber_creation_preserves_concurrently_installed_file() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        let transaction = StateDir::open(&state).unwrap();
        fs::write(state.join("identity.key"), b"old-binary-key").unwrap();
        fs::set_permissions(
            state.join("identity.key"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(
            !transaction
                .create_noclobber("identity.key", b"new-key")
                .unwrap()
        );
        assert_eq!(
            fs::read(state.join("identity.key")).unwrap(),
            b"old-binary-key"
        );
    }

    #[test]
    fn post_lock_wrong_mode_replacement_fails_before_rename() {
        let root = crate::test_support::canonical_tempdir();
        let state = root.path().join("state");
        prepare_private_dir(&state).unwrap();
        let error = with_exclusive_lock(&state, "registry.lock", |transaction| {
            fs::write(state.join("registry.json"), b"unsafe").unwrap();
            fs::set_permissions(
                state.join("registry.json"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            transaction.atomic_replace("registry.json", b"new")?;
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("unsafe permissions"));
        assert_eq!(fs::read(state.join("registry.json")).unwrap(), b"unsafe");
    }

    #[test]
    fn unsafe_lock_file_types_modes_and_links_are_rejected() {
        for setup in 0..3 {
            let root = crate::test_support::canonical_tempdir();
            let state = root.path().join("state");
            prepare_private_dir(&state).unwrap();
            let lock = state.join("registry.lock");
            match setup {
                0 => fs::create_dir(&lock).unwrap(),
                1 => {
                    fs::write(&lock, b"").unwrap();
                    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
                }
                _ => {
                    fs::write(&lock, b"").unwrap();
                    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::hard_link(&lock, state.join("lock-copy")).unwrap();
                }
            }
            assert!(with_locked(&state, "registry.lock", |_| Ok(())).is_err());
        }
    }
}
