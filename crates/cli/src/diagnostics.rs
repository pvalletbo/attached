use std::{
    fs::{self, File},
    io::{self, IsTerminal, Write},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context as _, Result, anyhow};
use tracing::Level;
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    fmt::format::FmtSpan,
    layer::Layer as _,
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(1);
static TERMINAL_OUTPUT: Mutex<DeferredOutput> = Mutex::new(DeferredOutput::new());

const MAX_DEFERRED_BYTES: usize = 256 * 1024;
const MAX_LOG_BYTES: u64 = 1024 * 1024;
const MAX_LOG_FILES: usize = 5;
const LOG_DIRECTORY: &str = "logs";
const LOG_FILE: &str = "attached.log";
const LOG_LOCK: &str = ".attached.log.lock";
const OVERSIZED_EVENT_NOTICE: &[u8] =
    b"WARN oversized diagnostics event omitted reason=\"event_exceeds_file_limit\"\n";
const TRUNCATED_NOTICE: &[u8] =
    b"Warning: additional tunnel diagnostics were omitted while Herdr owned the terminal.\n";

struct DeferredOutput {
    guards: usize,
    bytes: Vec<u8>,
    truncated: bool,
}

impl DeferredOutput {
    const fn new() -> Self {
        Self {
            guards: 0,
            bytes: Vec::new(),
            truncated: false,
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        let available = MAX_DEFERRED_BYTES.saturating_sub(self.bytes.len());
        let retained = available.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..retained]);
        self.truncated |= retained != bytes.len();
    }

    fn take(&mut self) -> Vec<u8> {
        if self.truncated {
            self.bytes.extend_from_slice(TRUNCATED_NOTICE);
        }
        self.truncated = false;
        std::mem::take(&mut self.bytes)
    }
}

#[derive(Clone, Copy)]
struct TerminalSafeWriter;

struct TerminalSafeWrite;

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for TerminalSafeWriter {
    type Writer = TerminalSafeWrite;

    fn make_writer(&'writer self) -> Self::Writer {
        TerminalSafeWrite
    }
}

impl Write for TerminalSafeWrite {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut output = TERMINAL_OUTPUT
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if output.guards > 0 {
            output.append(bytes);
            return Ok(bytes.len());
        }
        drop(output);
        io::stderr().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        let deferred = TERMINAL_OUTPUT
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .guards
            > 0;
        if deferred {
            Ok(())
        } else {
            io::stderr().flush()
        }
    }
}

/// Keeps tracing output away from an interactive Herdr terminal and replays it
/// after the terminal is released. Output is bounded so a long-running client
/// cannot grow memory without limit.
pub struct TerminalOutputGuard {
    active: bool,
}

impl TerminalOutputGuard {
    pub fn for_interactive_client() -> Self {
        let active =
            io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal();
        if active {
            let mut output = TERMINAL_OUTPUT
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            output.guards += 1;
        }
        Self { active }
    }
}

impl Drop for TerminalOutputGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let bytes = {
            let mut output = TERMINAL_OUTPUT
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            output.guards = output.guards.saturating_sub(1);
            if output.guards == 0 {
                output.take()
            } else {
                Vec::new()
            }
        };
        if !bytes.is_empty() {
            let _ = io::stderr().write_all(&bytes);
            let _ = io::stderr().flush();
        }
    }
}

pub struct DiagnosticsGuard {
    failures: Arc<AtomicU64>,
}

impl Drop for DiagnosticsGuard {
    fn drop(&mut self) {
        let failures = self.failures.load(Ordering::Relaxed);
        if failures > 0 {
            eprintln!(
                "Warning: {failures} diagnostics events could not be written to the private disk log."
            );
        }
    }
}

pub fn init(verbosity: u8) -> Result<DiagnosticsGuard> {
    let terminal_filter = Targets::new()
        .with_default(LevelFilter::WARN)
        .with_target("attached", level_for(verbosity));
    let terminal = tracing_subscriber::fmt::layer()
        .with_writer(TerminalSafeWriter)
        .with_target(verbosity >= 2)
        .with_span_events(FmtSpan::NONE)
        .with_ansi(false)
        .compact()
        .with_filter(terminal_filter);

    let log_dir = crate::identity::default_state_dir()?.join(LOG_DIRECTORY);
    crate::secure_state::prepare_private_dir(&log_dir)
        .context("failed to prepare private diagnostics directory")?;
    let writer = BoundedLogWriter::open(log_dir)?;
    let writer = DiskMakeWriter::new(writer);
    let failures = writer.failures.clone();
    let disk_filter = Targets::new()
        .with_default(LevelFilter::WARN)
        .with_target("attached", LevelFilter::DEBUG);
    let disk = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_target(true)
        .with_span_events(FmtSpan::NONE)
        .with_ansi(false)
        .compact()
        .with_filter(disk_filter);
    tracing_subscriber::registry()
        .with(terminal)
        .with(disk)
        .try_init()
        .map_err(|error| anyhow!("failed to initialize diagnostics: {error}"))?;
    tracing::debug!(
        log_retention_files = MAX_LOG_FILES,
        log_file_limit_bytes = MAX_LOG_BYTES,
        "diagnostics initialized"
    );
    Ok(DiagnosticsGuard { failures })
}

#[derive(Clone, Debug)]
struct BoundedLogWriter {
    directory: PathBuf,
}

impl BoundedLogWriter {
    fn open(directory: PathBuf) -> Result<Self> {
        crate::secure_state::with_exclusive_lock(&directory, LOG_LOCK, |_| {
            validate_retained_logs(&directory)?;
            let current = open_current_log(&directory)?;
            if current.metadata()?.len() == MAX_LOG_BYTES {
                drop(current);
                rotate_logs(&directory)?;
                open_current_log(&directory)?;
            }
            Ok(())
        })?;
        Ok(Self { directory })
    }
}

#[derive(Clone)]
struct DiskMakeWriter {
    writer: BoundedLogWriter,
    failures: Arc<AtomicU64>,
}

impl DiskMakeWriter {
    fn new(writer: BoundedLogWriter) -> Self {
        Self {
            writer,
            failures: Arc::new(AtomicU64::new(0)),
        }
    }

    #[cfg(test)]
    fn failure_count(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for DiskMakeWriter {
    type Writer = BufferedDiskEvent;

    fn make_writer(&'writer self) -> Self::Writer {
        BufferedDiskEvent {
            writer: self.writer.clone(),
            failures: self.failures.clone(),
            bytes: Vec::new(),
        }
    }
}

struct BufferedDiskEvent {
    writer: BoundedLogWriter,
    failures: Arc<AtomicU64>,
    bytes: Vec<u8>,
}

impl Write for BufferedDiskEvent {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let retained_limit = MAX_LOG_BYTES as usize + 1;
        let available = retained_limit.saturating_sub(self.bytes.len());
        self.bytes
            .extend_from_slice(&bytes[..bytes.len().min(available)]);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for BufferedDiskEvent {
    fn drop(&mut self) {
        if self.writer.write_all(&self.bytes).is_err()
            && self.failures.fetch_add(1, Ordering::Relaxed) == 0
        {
            let mut terminal =
                tracing_subscriber::fmt::MakeWriter::make_writer(&TerminalSafeWriter);
            let _ = terminal.write_all(
                b"Warning: private disk diagnostics failed; later events may be unavailable.\n",
            );
        }
    }
}

impl Write for BoundedLogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let payload = if bytes.len() as u64 > MAX_LOG_BYTES {
            OVERSIZED_EVENT_NOTICE
        } else {
            bytes
        };
        crate::secure_state::with_exclusive_lock(&self.directory, LOG_LOCK, |_| {
            validate_retained_logs(&self.directory)?;
            let mut file = open_current_log(&self.directory)?;
            let current = file.metadata()?.len();
            if current > 0 && current + payload.len() as u64 > MAX_LOG_BYTES {
                drop(file);
                rotate_logs(&self.directory)?;
                file = open_current_log(&self.directory)?;
            }
            file.write_all(payload)?;
            file.flush()?;
            Ok(())
        })
        .map_err(io::Error::other)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_retained_logs(directory: &Path) -> Result<()> {
    for index in 0..MAX_LOG_FILES {
        if let Some(file) = open_existing_log(&directory.join(log_name(index)))? {
            validate_log_file(&file)?;
        }
    }
    Ok(())
}

fn rotate_logs(directory: &Path) -> io::Result<()> {
    let oldest = directory.join(log_name(MAX_LOG_FILES - 1));
    match fs::remove_file(&oldest) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    for index in (1..MAX_LOG_FILES).rev() {
        let source = directory.join(log_name(index - 1));
        let destination = directory.join(log_name(index));
        match fs::rename(source, destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    create_log_file(&directory.join(LOG_FILE)).map(drop)
}

fn log_name(index: usize) -> String {
    if index == 0 {
        LOG_FILE.to_owned()
    } else {
        format!("{LOG_FILE}.{index}")
    }
}

fn open_current_log(directory: &Path) -> Result<File> {
    let path = directory.join(LOG_FILE);
    if let Some(file) = open_existing_log(&path)? {
        validate_log_file(&file)?;
        Ok(file)
    } else {
        create_log_file(&path).context("failed to create diagnostics log")
    }
}

fn open_existing_log(path: &Path) -> Result<Option<File>> {
    match rustix::fs::open(
        path,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::APPEND
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(file) => Ok(Some(File::from(file))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(io::Error::from(error)).context("failed to open diagnostics log"),
    }
}

fn create_log_file(path: &Path) -> io::Result<File> {
    let file = rustix::fs::open(
        path,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::APPEND
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map(File::from)
    .map_err(io::Error::from)?;
    rustix::fs::fchmod(&file, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)
        .map_err(io::Error::from)?;
    validate_log_file(&file).map_err(io::Error::other)?;
    Ok(file)
}

fn validate_log_file(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file(), "diagnostics log is not a regular file");
    anyhow::ensure!(
        metadata.uid() == rustix::process::geteuid().as_raw(),
        "diagnostics log is not owned by the current user"
    );
    anyhow::ensure!(
        metadata.mode() & 0o7777 == 0o600,
        "diagnostics log permissions are not 0600"
    );
    anyhow::ensure!(metadata.nlink() == 1, "diagnostics log has multiple links");
    anyhow::ensure!(
        metadata.len() <= MAX_LOG_BYTES,
        "diagnostics log exceeds {MAX_LOG_BYTES} bytes"
    );
    Ok(())
}

pub fn level_for(verbosity: u8) -> Level {
    match verbosity {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::DEBUG,
    }
}

pub fn next_connection_id() -> u64 {
    NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn next_stream_id() -> u64 {
    NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn format_error(error: &anyhow::Error, verbosity: u8) -> String {
    if verbosity == 0 {
        error.to_string()
    } else {
        format!("{error:#}")
    }
}

pub fn log_stream_closed(
    connection_id: u64,
    stream_id: u64,
    session: Option<&str>,
    upstream_bytes: u64,
    downstream_bytes: u64,
    elapsed_ms: u128,
    closure_reason: &'static str,
) {
    tracing::info!(
        connection_id,
        stream_id,
        session = session.unwrap_or("local-client"),
        upstream_bytes,
        downstream_bytes,
        elapsed_ms,
        closure_reason,
        "proxy stream closed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        os::unix::fs::PermissionsExt as _,
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for Capture {
        type Writer = CaptureWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CaptureWriter(self.0.clone())
        }
    }

    impl Capture {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    #[test]
    fn verbosity_maps_to_increasing_detail() {
        assert_eq!(level_for(0), tracing::Level::WARN);
        assert_eq!(level_for(1), tracing::Level::INFO);
        assert_eq!(level_for(2), tracing::Level::DEBUG);
        assert_eq!(level_for(9), tracing::Level::DEBUG);
    }

    #[test]
    fn generated_connection_and_stream_ids_are_unique() {
        assert_ne!(next_connection_id(), next_connection_id());
        assert_ne!(next_stream_id(), next_stream_id());
    }

    #[test]
    fn error_detail_respects_verbosity() {
        let error = anyhow::anyhow!("root cause").context("outer context");
        assert_eq!(format_error(&error, 0), "outer context");
        let verbose = format_error(&error, 1);
        assert!(verbose.contains("outer context"));
        assert!(verbose.contains("root cause"));
    }

    #[test]
    fn stream_log_contains_safe_routing_fields_without_payload_or_secret() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_writer(capture.clone())
            .without_time()
            .with_target(false)
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            log_stream_closed(41, 99, Some("default"), 123, 456, 7, "clean_eof");
        });
        let log = capture.contents();
        for expected in [
            "connection_id=41",
            "stream_id=99",
            "session=\"default\"",
            "upstream_bytes=123",
            "downstream_bytes=456",
            "closure_reason=\"clean_eof\"",
        ] {
            assert!(log.contains(expected), "missing {expected:?} in {log:?}");
        }
        assert!(!log.contains("terminal-payload"));
        assert!(!log.contains("capability-secret"));
        assert!(!log.contains("iroh1"));
    }

    #[test]
    fn deferred_output_is_bounded_and_marks_truncation() {
        let mut output = DeferredOutput::new();
        output.append(&vec![b'x'; MAX_DEFERRED_BYTES + 1]);
        let bytes = output.take();

        assert_eq!(&bytes[..MAX_DEFERRED_BYTES], vec![b'x'; MAX_DEFERRED_BYTES]);
        assert!(bytes.ends_with(TRUNCATED_NOTICE));
        assert!(output.bytes.is_empty());
        assert!(!output.truncated);
    }

    #[test]
    fn terminal_writer_defers_diagnostics_while_guarded() {
        {
            let mut output = TERMINAL_OUTPUT.lock().unwrap();
            assert_eq!(output.guards, 0);
            assert!(output.bytes.is_empty());
            output.guards = 1;
        }

        TerminalSafeWrite.write_all(b"deferred warning\n").unwrap();

        let mut output = TERMINAL_OUTPUT.lock().unwrap();
        assert_eq!(output.bytes, b"deferred warning\n");
        output.guards = 0;
        assert_eq!(output.take(), b"deferred warning\n");
    }

    #[test]
    fn application_verbosity_does_not_enable_dependency_info() {
        let capture = Capture::default();
        let filter = Targets::new()
            .with_default(LevelFilter::WARN)
            .with_target("attached", Level::DEBUG);
        let subscriber = tracing_subscriber::registry().with(filter).with(
            tracing_subscriber::fmt::layer()
                .with_writer(capture.clone())
                .without_time()
                .with_target(false)
                .with_ansi(false),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "attached", "application event");
            tracing::info!(target: "dependency", "dependency event");
            tracing::warn!(target: "dependency", "dependency warning");
        });
        let log = capture.contents();
        assert!(log.contains("application event"), "{log}");
        assert!(!log.contains("dependency event"), "{log}");
        assert!(log.contains("dependency warning"), "{log}");
    }

    #[test]
    fn diagnostics_rejects_a_precreated_symlink_log_without_touching_its_target() {
        let root = crate::test_support::canonical_tempdir();
        let directory = root.path().join("logs");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let victim = root.path().join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&victim, directory.join(LOG_FILE)).unwrap();

        let error = BoundedLogWriter::open(directory).unwrap_err().to_string();

        assert!(error.contains("failed to open diagnostics log"), "{error}");
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
    }

    #[test]
    fn diagnostics_rejects_an_existing_log_with_unsafe_permissions() {
        let root = crate::test_support::canonical_tempdir();
        let directory = root.path().join("logs");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let log = directory.join(LOG_FILE);
        fs::write(&log, b"existing").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o640)).unwrap();

        let error = BoundedLogWriter::open(directory).unwrap_err().to_string();

        assert!(error.contains("permissions are not 0600"), "{error}");
        assert_eq!(fs::read(log).unwrap(), b"existing");
    }

    #[test]
    fn diagnostics_rejects_an_existing_hardlinked_log() {
        let root = crate::test_support::canonical_tempdir();
        let directory = root.path().join("logs");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let log = directory.join(LOG_FILE);
        fs::write(&log, b"existing").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = root.path().join("alias");
        fs::hard_link(&log, &alias).unwrap();

        let error = BoundedLogWriter::open(directory).unwrap_err().to_string();

        assert!(error.contains("multiple links"), "{error}");
        assert_eq!(fs::read(alias).unwrap(), b"existing");
    }

    fn private_log_directory(root: &Path) -> PathBuf {
        let directory = root.join("logs");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn diagnostics_rotates_before_an_event_crosses_the_size_boundary() {
        let root = crate::test_support::canonical_tempdir();
        let directory = private_log_directory(root.path());
        let mut writer = BoundedLogWriter::open(directory.clone()).unwrap();
        writer
            .write_all(&vec![b'a'; MAX_LOG_BYTES as usize - 4])
            .unwrap();

        writer.write_all(b"event\n").unwrap();

        assert_eq!(fs::read(directory.join(LOG_FILE)).unwrap(), b"event\n");
        assert_eq!(
            fs::metadata(directory.join(log_name(1))).unwrap().len(),
            MAX_LOG_BYTES - 4
        );
    }

    #[test]
    fn diagnostics_reconciles_size_between_independent_writers() {
        let root = crate::test_support::canonical_tempdir();
        let directory = private_log_directory(root.path());
        let mut first = BoundedLogWriter::open(directory.clone()).unwrap();
        let mut second = BoundedLogWriter::open(directory.clone()).unwrap();
        first
            .write_all(&vec![b'a'; MAX_LOG_BYTES as usize - 3])
            .unwrap();

        second.write_all(b"next\n").unwrap();

        assert_eq!(fs::read(directory.join(LOG_FILE)).unwrap(), b"next\n");
        assert_eq!(
            fs::metadata(directory.join(log_name(1))).unwrap().len(),
            MAX_LOG_BYTES - 3
        );
    }

    #[test]
    fn diagnostics_rejects_an_oversized_retained_log() {
        let root = crate::test_support::canonical_tempdir();
        let directory = private_log_directory(root.path());
        let retained = directory.join(log_name(1));
        fs::write(&retained, vec![0_u8; MAX_LOG_BYTES as usize + 1]).unwrap();
        fs::set_permissions(&retained, fs::Permissions::from_mode(0o600)).unwrap();

        let error = BoundedLogWriter::open(directory).unwrap_err().to_string();

        assert!(error.contains("exceeds"), "{error}");
    }

    #[test]
    fn diagnostics_omits_one_oversized_event_without_writing_a_partial_record() {
        let root = crate::test_support::canonical_tempdir();
        let directory = private_log_directory(root.path());
        let mut writer = BoundedLogWriter::open(directory.clone()).unwrap();

        writer
            .write_all(&vec![b'x'; MAX_LOG_BYTES as usize + 1])
            .unwrap();

        let log = fs::read_to_string(directory.join(LOG_FILE)).unwrap();
        assert!(log.contains("oversized diagnostics event omitted"), "{log}");
        assert!(!log.contains("xxx"), "oversized payload was persisted");
        assert!(fs::metadata(directory.join(LOG_FILE)).unwrap().len() <= MAX_LOG_BYTES);
    }

    #[test]
    fn diagnostics_retains_only_the_five_newest_bounded_files() {
        let root = crate::test_support::canonical_tempdir();
        let directory = private_log_directory(root.path());
        let mut writer = BoundedLogWriter::open(directory.clone()).unwrap();

        for marker in b'a'..=b'g' {
            let mut event = vec![marker; MAX_LOG_BYTES as usize / 2 + 1];
            event.push(b'\n');
            writer.write_all(&event).unwrap();
        }

        let retained = (0..MAX_LOG_FILES)
            .map(|index| directory.join(log_name(index)))
            .filter(|path| path.exists())
            .collect::<Vec<_>>();
        assert_eq!(retained.len(), MAX_LOG_FILES);
        for path in &retained {
            assert!(fs::metadata(path).unwrap().len() <= MAX_LOG_BYTES);
        }
        assert_eq!(fs::read(&retained[0]).unwrap()[0], b'g');
        assert_eq!(fs::read(&retained[4]).unwrap()[0], b'c');
    }

    #[test]
    fn diagnostics_writer_surfaces_runtime_filesystem_failures() {
        let root = crate::test_support::canonical_tempdir();
        let directory = private_log_directory(root.path());
        let mut writer = BoundedLogWriter::open(directory.clone()).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o000)).unwrap();

        let error = writer.write_all(b"event\n").unwrap_err();

        assert!(
            error.to_string().contains("state directory")
                || error.kind() == io::ErrorKind::PermissionDenied,
            "{error:#}"
        );
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn disk_layer_records_runtime_write_failures() {
        let root = crate::test_support::canonical_tempdir();
        let directory = private_log_directory(root.path());
        let make_writer = DiskMakeWriter::new(BoundedLogWriter::open(directory.clone()).unwrap());
        let observer = make_writer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(make_writer)
            .without_time()
            .with_ansi(false)
            .finish();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o000)).unwrap();

        tracing::subscriber::with_default(subscriber, || tracing::warn!("must be observed"));

        assert_eq!(observer.failure_count(), 1);
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn disk_layer_persists_an_event_before_the_logging_call_returns() {
        let root = crate::test_support::canonical_tempdir();
        let directory = private_log_directory(root.path());
        let make_writer = DiskMakeWriter::new(BoundedLogWriter::open(directory.clone()).unwrap());
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_writer(make_writer)
            .without_time()
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || tracing::debug!("durable-before-return"));

        let log = fs::read_to_string(directory.join(LOG_FILE)).unwrap();
        assert!(log.contains("durable-before-return"), "{log}");
    }
}
