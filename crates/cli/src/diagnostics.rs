use std::{
    fs::File,
    io::BufWriter,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Result, anyhow};
use tracing::{
    Event, Level, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{
    filter::{Filtered, LevelFilter, Targets},
    fmt::format::FmtSpan,
    layer::{Context, Layer, SubscriberExt},
    registry::Registry,
    util::SubscriberInitExt,
};

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
const IROH_NET_REPORT_TARGET: &str = "iroh::net_report::report";
const EXPECTED_QAD_MAPPING_WARNINGS: [&str; 2] = [
    "IPv4 address detected by QAD varies by destination",
    "IPv6 address detected by QAD varies by destination",
];

/// Iroh records destination-dependent QAD mappings so it can adapt to hard NATs.
/// They are expected network characteristics, not actionable connection failures.
#[derive(Clone, Copy)]
struct SuppressExpectedQadMappingWarnings;

impl<S> Layer<S> for SuppressExpectedQadMappingWarnings
where
    S: Subscriber,
{
    fn event_enabled(&self, event: &Event<'_>, _ctx: Context<'_, S>) -> bool {
        !is_expected_qad_mapping_warning(event)
    }
}

fn is_expected_qad_mapping_warning(event: &Event<'_>) -> bool {
    let metadata = event.metadata();
    if metadata.target() != IROH_NET_REPORT_TARGET || metadata.level() != &Level::WARN {
        return false;
    }

    let mut visitor = MessageVisitor::default();
    event.record(&mut visitor);
    visitor
        .message
        .as_deref()
        .is_some_and(|message| EXPECTED_QAD_MAPPING_WARNINGS.contains(&message))
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_owned());
        }
    }
}

type FlameWriter = BufWriter<File>;
type FlameGuard = tracing_flame::FlushGuard<FlameWriter>;
type ProfileLayer = Filtered<tracing_flame::FlameLayer<Registry, FlameWriter>, Targets, Registry>;

pub struct DiagnosticsGuard {
    _flame: Option<FlameGuard>,
}

fn profile_layer(path: &Path) -> Result<(ProfileLayer, FlameGuard)> {
    let (layer, guard) = tracing_flame::FlameLayer::<Registry, FlameWriter>::with_file(path)
        .map_err(|error| {
            anyhow!(
                "could not create flamegraph trace {}: {error}",
                path.display()
            )
        })?;
    let filter = Targets::new()
        .with_default(LevelFilter::OFF)
        .with_target("attached", LevelFilter::DEBUG);
    let layer = layer
        .with_threads_collapsed(true)
        .with_module_path(false)
        .with_file_and_line(false)
        .with_filter(filter);
    Ok((layer, guard))
}

pub fn init(verbosity: u8, flamegraph: Option<&Path>) -> Result<DiagnosticsGuard> {
    let terminal_filter = Targets::new()
        .with_default(LevelFilter::WARN)
        .with_target("attached", level_for(verbosity));
    let formatter = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(verbosity >= 2)
        .with_span_events(if flamegraph.is_some() {
            FmtSpan::CLOSE
        } else {
            FmtSpan::NONE
        })
        .with_ansi(false)
        .compact()
        .with_filter(terminal_filter);
    let (profile, flame) = match flamegraph {
        Some(path) => {
            let (layer, guard) = profile_layer(path)?;
            (Some(layer), Some(guard))
        }
        None => (None, None),
    };
    tracing_subscriber::registry()
        .with(profile)
        .with(SuppressExpectedQadMappingWarnings)
        .with(formatter)
        .try_init()
        .map_err(|error| anyhow!("failed to initialize diagnostics: {error}"))?;
    Ok(DiagnosticsGuard { _flame: flame })
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

pub fn format_error(error: &anyhow::Error, verbosity: u8) -> String {
    if verbosity == 0 {
        error.to_string()
    } else {
        format!("{error:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
        time::Duration,
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
    fn expected_qad_mapping_warnings_are_suppressed_selectively() {
        let capture = Capture::default();
        let filter = Targets::new().with_default(LevelFilter::WARN);
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(SuppressExpectedQadMappingWarnings)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(capture.clone())
                    .without_time()
                    .with_target(false)
                    .with_ansi(false),
            );

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                target: IROH_NET_REPORT_TARGET,
                marker = "suppressed-ipv4",
                "IPv4 address detected by QAD varies by destination"
            );
            tracing::warn!(
                target: IROH_NET_REPORT_TARGET,
                marker = "suppressed-ipv6",
                "IPv6 address detected by QAD varies by destination"
            );
            tracing::warn!(
                target: IROH_NET_REPORT_TARGET,
                marker = "retained-iroh-warning",
                "received IPv6 address from IPv4 QAD"
            );
            tracing::warn!(
                target: "dependency",
                marker = "retained-other-target",
                "IPv4 address detected by QAD varies by destination"
            );
            tracing::error!(
                target: IROH_NET_REPORT_TARGET,
                marker = "retained-error",
                "IPv4 address detected by QAD varies by destination"
            );
        });

        let log = capture.contents();
        assert!(!log.contains("suppressed-ipv4"), "{log}");
        assert!(!log.contains("suppressed-ipv6"), "{log}");
        assert!(log.contains("retained-iroh-warning"), "{log}");
        assert!(log.contains("retained-other-target"), "{log}");
        assert!(log.contains("retained-error"), "{log}");
    }

    #[test]
    fn flame_profile_records_nested_application_spans_without_fields() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("attached.folded");
        let (profile, guard) = profile_layer(&output).unwrap();
        let subscriber = tracing_subscriber::registry().with(profile);

        tracing::subscriber::with_default(subscriber, || {
            let root = tracing::debug_span!(
                target: "attached",
                "profile_root",
                password = "must-not-be-recorded"
            );
            let _root = root.enter();
            std::thread::sleep(Duration::from_millis(1));
            let child = tracing::debug_span!(target: "attached", "profile_child");
            let _child = child.enter();
            std::thread::sleep(Duration::from_millis(1));
        });
        drop(guard);

        let folded = std::fs::read_to_string(output).unwrap();
        assert!(folded.contains("profile_root"), "{folded}");
        assert!(folded.contains("profile_root; profile_child"), "{folded}");
        assert!(!folded.contains("must-not-be-recorded"), "{folded}");
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
