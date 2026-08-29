use std::{io::Write, path::Path};

use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{
    herdr_version,
    sync::{self, refresh::RefreshResult, state_catalog::SyncedSession},
};

pub(crate) async fn refresh(state_dir: &Path, herdr_bin: &Path) -> Result<RefreshResult> {
    if !sync::state::has_download_account(state_dir)
        .context("could not inspect the synchronization account")?
    {
        return Ok(RefreshResult {
            sessions: Vec::new(),
            warnings: Vec::new(),
        });
    }

    let local_version = herdr_version::query(herdr_bin)
        .context("could not determine the local Herdr version; catalog refresh was not started")?;
    let result = sync::refresh::refresh_sessions(state_dir, local_version)
        .await
        .context("could not refresh synchronized sessions")?;
    tracing::info!(
        session_count = result.sessions.len(),
        warning_count = result.warnings.len(),
        "refreshed synchronized sessions for machine-readable listing"
    );
    Ok(result)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionJson<'a> {
    target: &'a str,
    host: &'a str,
    session: &'a str,
    published_at: Option<DateTime<Utc>>,
}

pub(crate) fn write_json(mut writer: impl Write, sessions: &[SyncedSession]) -> Result<()> {
    let rows = sessions
        .iter()
        .map(|session| SessionJson {
            target: &session.target,
            host: &session.host,
            session: &session.session,
            published_at: session.published_at,
        })
        .collect::<Vec<_>>();
    serde_json::to_writer(&mut writer, &rows)
        .context("could not encode session catalog as JSON")?;
    writer
        .write_all(b"\n")
        .context("could not write session catalog JSON")
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Utc};

    use crate::sync::state_catalog::SyncedSession;

    #[tokio::test]
    async fn catalog_without_download_account_is_empty_without_invoking_herdr() {
        let root = crate::test_support::canonical_tempdir();
        let state_dir = root.path().join("state");
        crate::secure_state::prepare_private_dir(&state_dir).unwrap();

        let refreshed = super::refresh(
            &state_dir,
            std::path::Path::new("/definitely/missing/herdr"),
        )
        .await
        .unwrap();

        assert!(refreshed.sessions.is_empty());
        assert!(refreshed.warnings.is_empty());
    }

    #[test]
    fn json_catalog_exposes_only_stable_public_session_fields() {
        let sessions = vec![
            SyncedSession {
                target: "office/deep work".to_owned(),
                host: "office".to_owned(),
                session: "deep work".to_owned(),
                published_at: Some(Utc.with_ymd_and_hms(2026, 8, 29, 12, 34, 56).unwrap()),
            },
            SyncedSession {
                target: "travel/shell".to_owned(),
                host: "travel".to_owned(),
                session: "shell".to_owned(),
                published_at: None,
            },
        ];
        let mut output = Vec::new();

        super::write_json(&mut output, &sessions).unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            concat!(
                "[{\"target\":\"office/deep work\",\"host\":\"office\",\"session\":\"deep work\",",
                "\"publishedAt\":\"2026-08-29T12:34:56Z\"},{\"target\":\"travel/shell\",",
                "\"host\":\"travel\",\"session\":\"shell\",\"publishedAt\":null}]\n"
            )
        );
    }
}
