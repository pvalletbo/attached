use std::{
    fmt::Write as _,
    io::{IsTerminal, stderr, stdin},
    process::Stdio,
};

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use tokio::{io::AsyncWriteExt, process::Command};
use tracing::debug;

use crate::{session::Session, sync::state_catalog::SyncedSession};

const LOCAL_HOST_LABEL: &str = "(local)";
const MAX_FUTURE_CLOCK_SKEW_SECONDS: i64 = 30;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionSelection {
    Local(String),
    Synchronized(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PickerCandidate {
    host: String,
    session: String,
    published_at: Option<DateTime<Utc>>,
    selection: SessionSelection,
}

pub async fn select(
    local_sessions: &[Session],
    synchronized_sessions: &[SyncedSession],
) -> Result<Option<SessionSelection>> {
    ensure!(
        stdin().is_terminal() && stderr().is_terminal(),
        "a session target is required when not running in an interactive terminal"
    );
    let candidates = picker_candidates(local_sessions, synchronized_sessions);
    ensure!(
        !candidates.is_empty(),
        "no local or synchronized Herdr sessions are available"
    );

    let (input, header) = render_input(&candidates)?;
    debug!(
        candidate_count = candidates.len(),
        local_count = local_sessions.len(),
        synchronized_count = synchronized_sessions.len(),
        "launching interactive session picker"
    );
    let mut child = Command::new("fzf")
        .arg("--delimiter=\t")
        .arg("--with-nth=2")
        .arg("--no-multi")
        .arg("--layout=reverse")
        .arg("--height=60%")
        .arg("--border")
        .arg("--prompt=Herdr session> ")
        .arg(format!("--header={header}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("failed to launch fzf; install fzf or pass `HOST/SESSION` explicitly")?;

    let mut picker_stdin = child
        .stdin
        .take()
        .context("failed to open the fzf candidate input")?;
    picker_stdin
        .write_all(input.as_bytes())
        .await
        .context("failed to send sessions to fzf")?;
    picker_stdin
        .shutdown()
        .await
        .context("failed to finish the fzf candidate input")?;

    let output = child
        .wait_with_output()
        .await
        .context("failed to wait for fzf")?;
    if !output.status.success() {
        return match output.status.code() {
            Some(1 | 130) => Ok(None),
            _ => bail!("fzf exited with status {}", output.status),
        };
    }

    let selected = String::from_utf8(output.stdout).context("fzf returned non-UTF-8 output")?;
    parse_selection(&selected, &candidates).map(Some)
}

fn picker_candidates(
    local_sessions: &[Session],
    synchronized_sessions: &[SyncedSession],
) -> Vec<PickerCandidate> {
    let mut candidates = local_sessions
        .iter()
        .map(|session| PickerCandidate {
            host: LOCAL_HOST_LABEL.to_owned(),
            session: session.name().to_owned(),
            published_at: None,
            selection: SessionSelection::Local(session.name().to_owned()),
        })
        .chain(synchronized_sessions.iter().map(|session| PickerCandidate {
            host: session.host.clone(),
            session: session.session.clone(),
            published_at: session.published_at,
            selection: SessionSelection::Synchronized(session.target.clone()),
        }))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        selection_rank(&left.selection)
            .cmp(&selection_rank(&right.selection))
            .then_with(|| left.host.cmp(&right.host))
            .then_with(|| left.session.cmp(&right.session))
            .then_with(|| {
                selection_identity(&left.selection).cmp(selection_identity(&right.selection))
            })
    });
    candidates
}

const fn selection_rank(selection: &SessionSelection) -> u8 {
    match selection {
        SessionSelection::Local(_) => 0,
        SessionSelection::Synchronized(_) => 1,
    }
}

fn selection_identity(selection: &SessionSelection) -> &str {
    match selection {
        SessionSelection::Local(session) | SessionSelection::Synchronized(session) => session,
    }
}

fn render_input(candidates: &[PickerCandidate]) -> Result<(String, String)> {
    render_input_at(candidates, Utc::now())
}

fn render_input_at(candidates: &[PickerCandidate], now: DateTime<Utc>) -> Result<(String, String)> {
    for candidate in candidates {
        ensure!(
            [&candidate.host, &candidate.session]
                .into_iter()
                .all(|value| !value.chars().any(char::is_control)),
            "session catalog contains control characters"
        );
    }
    let host_width = candidates
        .iter()
        .map(|candidate| candidate.host.chars().count())
        .max()
        .unwrap_or_default()
        .max("HOST".len());
    let session_width = candidates
        .iter()
        .map(|candidate| candidate.session.chars().count())
        .max()
        .unwrap_or_default()
        .max("SESSION".len());
    let publish_width = candidates
        .iter()
        .map(|candidate| publish_summary(candidate, now).chars().count())
        .max()
        .unwrap_or_default()
        .max("LAST PUBLISH".len());
    let header = format!(
        "{:<host_width$}  {:<session_width$}  {:<publish_width$}",
        "HOST", "SESSION", "LAST PUBLISH"
    );
    let mut input = String::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let published = publish_summary(candidate, now);
        writeln!(
            input,
            "{index}\t{:<host_width$}  {:<session_width$}  {:<publish_width$}",
            candidate.host, candidate.session, published
        )
        .expect("writing session candidates to a String cannot fail");
    }
    Ok((input, header))
}

fn publish_summary(candidate: &PickerCandidate, now: DateTime<Utc>) -> String {
    if matches!(candidate.selection, SessionSelection::Local(_)) {
        return "local".to_owned();
    }
    let Some(published_at) = candidate.published_at else {
        return "unknown".to_owned();
    };
    if published_at - now > chrono::Duration::seconds(MAX_FUTURE_CLOCK_SKEW_SECONDS) {
        return "clock skew".to_owned();
    }
    let age_seconds = (now - published_at).num_seconds().max(0);
    if age_seconds < 60 {
        format!("{age_seconds}s ago")
    } else if age_seconds < 3_600 {
        format!("{}m ago", age_seconds / 60)
    } else if age_seconds < 86_400 {
        format!("{}h ago", age_seconds / 3_600)
    } else {
        format!("{}d ago", age_seconds / 86_400)
    }
}

fn parse_selection(selected: &str, candidates: &[PickerCandidate]) -> Result<SessionSelection> {
    let selected = selected.trim_end_matches(['\r', '\n']);
    ensure!(!selected.contains('\n'), "fzf returned multiple selections");
    let (index, _) = selected
        .split_once('\t')
        .context("fzf returned an invalid session selection")?;
    let index = index
        .parse::<usize>()
        .context("fzf returned an invalid session selection")?;
    candidates
        .get(index)
        .map(|candidate| candidate.selection.clone())
        .context("fzf returned an unknown session target")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn picker_groups_hosts_and_displays_publish_age() {
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let synchronized = [
            SyncedSession {
                target: "studio/render".to_owned(),
                host: "studio".to_owned(),
                session: "render".to_owned(),
                published_at: Some(now - chrono::Duration::minutes(4)),
            },
            SyncedSession {
                target: "office/review".to_owned(),
                host: "office".to_owned(),
                session: "review".to_owned(),
                published_at: Some(now - chrono::Duration::seconds(30)),
            },
            SyncedSession {
                target: "office/deep-work".to_owned(),
                host: "office".to_owned(),
                session: "deep-work".to_owned(),
                published_at: Some(now - chrono::Duration::seconds(30)),
            },
        ];

        let candidates = picker_candidates(&[], &synchronized);
        let (input, header) = render_input_at(&candidates, now).unwrap();
        let rows = input.lines().collect::<Vec<_>>();

        assert!(!header.contains("STATUS"));
        assert!(header.contains("LAST PUBLISH"));
        assert!(
            ["🟢", "🟡", "⚪"]
                .iter()
                .all(|status| !input.contains(status))
        );
        assert!(rows[0].contains("office") && rows[0].contains("deep-work"));
        assert!(rows[1].contains("office") && rows[1].contains("review"));
        assert!(rows[2].contains("studio") && rows[2].contains("render"));
        assert!(rows[0].contains("30s ago"));
        assert!(rows[2].contains("4m ago"));
    }

    #[test]
    fn publication_just_beyond_future_skew_allowance_reports_clock_skew() {
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let candidate = PickerCandidate {
            host: "office".to_owned(),
            session: "future-edge".to_owned(),
            published_at: Some(
                now + chrono::Duration::seconds(MAX_FUTURE_CLOCK_SKEW_SECONDS)
                    + chrono::Duration::nanoseconds(1),
            ),
            selection: SessionSelection::Synchronized("office/future-edge".to_owned()),
        };

        assert_eq!(publish_summary(&candidate, now), "clock skew");
    }

    #[test]
    fn picker_handles_unknown_future_and_publish_times() {
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let synchronized = [
            SyncedSession {
                target: "alpha/unknown".to_owned(),
                host: "alpha".to_owned(),
                session: "unknown".to_owned(),
                published_at: None,
            },
            SyncedSession {
                target: "beta/future".to_owned(),
                host: "beta".to_owned(),
                session: "future".to_owned(),
                published_at: Some(now + chrono::Duration::minutes(5)),
            },
            SyncedSession {
                target: "gamma/fresh-boundary".to_owned(),
                host: "gamma".to_owned(),
                session: "fresh-boundary".to_owned(),
                published_at: Some(now - chrono::Duration::seconds(180)),
            },
            SyncedSession {
                target: "gamma/stale-boundary".to_owned(),
                host: "gamma".to_owned(),
                session: "stale-boundary".to_owned(),
                published_at: Some(now - chrono::Duration::seconds(181)),
            },
        ];

        let candidates = picker_candidates(&[], &synchronized);
        let (input, _) = render_input_at(&candidates, now).unwrap();
        let rows = input.lines().collect::<Vec<_>>();

        assert!(rows[0].contains("unknown"));
        assert!(rows[1].contains("clock skew"));
        assert!(rows[2].contains("3m ago"));
        assert!(rows[3].contains("3m ago"));
    }

    #[test]
    fn picker_lists_local_sessions_first_and_keeps_selection_kinds_distinct() {
        let local = [Session::new(
            "local-work".to_owned(),
            PathBuf::from("/synthetic/tui.sock"),
        )];
        let synchronized = [SyncedSession {
            target: "office/deep-work".to_owned(),
            host: "office".to_owned(),
            session: "deep-work".to_owned(),
            published_at: None,
        }];
        let candidates = picker_candidates(&local, &synchronized);
        let (input, header) = render_input(&candidates).unwrap();
        let rows = input.lines().collect::<Vec<_>>();

        assert!(header.contains("HOST"));
        assert!(header.contains("SESSION"));
        assert!(rows[0].contains("(local)"));
        assert!(rows[0].contains("local-work"));
        assert!(rows[1].contains("office"));
        assert!(rows[1].contains("deep-work"));
        assert_eq!(
            parse_selection(rows[0], &candidates).unwrap(),
            SessionSelection::Local("local-work".to_owned())
        );
        assert_eq!(
            parse_selection(rows[1], &candidates).unwrap(),
            SessionSelection::Synchronized("office/deep-work".to_owned())
        );
        assert!(parse_selection("99\tunknown", &candidates).is_err());
    }
}
