use std::{
    io::{self, IsTerminal, Write},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Result, anyhow};
use tracing::Level;
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    fmt::format::FmtSpan,
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(1);
static TERMINAL_OUTPUT: Mutex<DeferredOutput> = Mutex::new(DeferredOutput::new());

const MAX_DEFERRED_BYTES: usize = 256 * 1024;
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

pub fn init(verbosity: u8) -> Result<()> {
    let filter = Targets::new()
        .with_default(LevelFilter::WARN)
        .with_target("attached", level_for(verbosity));
    let formatter = tracing_subscriber::fmt::layer()
        .with_writer(TerminalSafeWriter)
        .with_target(verbosity >= 2)
        .with_span_events(FmtSpan::NONE)
        .with_ansi(false)
        .compact();
    tracing_subscriber::registry()
        .with(filter)
        .with(formatter)
        .try_init()
        .map_err(|error| anyhow!("failed to initialize diagnostics: {error}"))
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
}
