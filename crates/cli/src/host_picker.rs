use std::{
    fmt::Write as _,
    io::{IsTerminal, stderr, stdin},
    process::Stdio,
};

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use tokio::{io::AsyncWriteExt, process::Command};

use crate::sync::state_catalog::SyncedHost;

/// Returns the stable endpoint identity, never an ambiguous display label.
pub async fn select(hosts: &[SyncedHost]) -> Result<Option<String>> {
    ensure!(
        stdin().is_terminal() && stderr().is_terminal(),
        "a host label or endpoint ID is required when not running in an interactive terminal"
    );
    ensure!(
        !hosts.is_empty(),
        "no SSH-enabled Attached hosts are available"
    );
    let (input, header) = render_input_at(hosts, Utc::now())?;
    let mut child = Command::new("fzf")
        .args([
            "--delimiter=\t",
            "--with-nth=2",
            "--no-multi",
            "--layout=reverse",
            "--height=60%",
            "--border",
            "--prompt=Attached host> ",
        ])
        .arg(format!("--header={header}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context(
            "failed to launch fzf; install fzf or pass a host label or endpoint ID explicitly",
        )?;
    let mut input_pipe = child.stdin.take().context("failed to open fzf input")?;
    input_pipe
        .write_all(input.as_bytes())
        .await
        .context("failed to send hosts to fzf")?;
    input_pipe.shutdown().await?;
    // Shutdown alone does not close a Unix pipe; fzf needs EOF before wait.
    drop(input_pipe);
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
    parse_selection(
        &String::from_utf8(output.stdout).context("fzf returned non-UTF-8 output")?,
        hosts,
    )
    .map(Some)
}

pub fn render_list(hosts: &[SyncedHost]) -> Result<String> {
    let (input, header) = render_input_at(hosts, Utc::now())?;
    let mut output = format!("{header}\n");
    for line in input.lines() {
        let (_, columns) = line
            .split_once('\t')
            .expect("rendered candidate has an index");
        writeln!(output, "{columns}")?;
    }
    Ok(output)
}

fn render_input_at(hosts: &[SyncedHost], now: DateTime<Utc>) -> Result<(String, String)> {
    for host in hosts {
        ensure!(
            [&host.host, &host.target]
                .into_iter()
                .all(|value| !value.chars().any(char::is_control)),
            "host catalog contains control characters"
        );
    }
    let host_width = hosts
        .iter()
        .map(|host| host.host.chars().count())
        .max()
        .unwrap_or_default()
        .max(4);
    let version = |host: &SyncedHost| {
        let [major, minor, patch] = host.attached_version;
        format!("{major}.{minor}.{patch}")
    };
    let version_width = hosts
        .iter()
        .map(|host| version(host).len())
        .max()
        .unwrap_or_default()
        .max(8);
    let header = format!(
        "{:<host_width$}  {:<64}  {:<version_width$}  LAST PUBLISH",
        "HOST", "ENDPOINT ID", "ATTACHED"
    );
    let mut input = String::new();
    for (index, host) in hosts.iter().enumerate() {
        writeln!(
            input,
            "{index}\t{:<host_width$}  {:<64}  {:<version_width$}  {}",
            host.host,
            host.target,
            version(host),
            publish_age(host.published_at, now)
        )?;
    }
    Ok((input, header))
}

fn publish_age(published: Option<DateTime<Utc>>, now: DateTime<Utc>) -> String {
    let Some(published) = published else {
        return "unknown".into();
    };
    if published - now > chrono::Duration::seconds(30) {
        return "clock skew".into();
    }
    let seconds = (now - published).num_seconds().max(0);
    match seconds {
        0..60 => format!("{seconds}s ago"),
        60..3600 => format!("{}m ago", seconds / 60),
        3600..86400 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86400),
    }
}

fn parse_selection(selected: &str, hosts: &[SyncedHost]) -> Result<String> {
    let selected = selected.trim_end_matches(['\r', '\n']);
    ensure!(!selected.contains('\n'), "fzf returned multiple selections");
    let (index, _) = selected
        .split_once('\t')
        .context("fzf returned an invalid host selection")?;
    let index: usize = index
        .parse()
        .context("fzf returned an invalid host selection")?;
    hosts
        .get(index)
        .map(|host| host.target.clone())
        .context("fzf returned an unknown host")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hosts() -> Vec<SyncedHost> {
        [1, 2]
            .into_iter()
            .map(|byte| SyncedHost {
                target: iroh::SecretKey::from_bytes(&[byte; 32])
                    .public()
                    .to_string(),
                host: "office".into(),
                attached_version: [0, 2, 14],
                published_at: None,
            })
            .collect()
    }
    #[test]
    fn listing_contains_hosts_versions_and_stable_ids_not_application_sessions() {
        let hosts = hosts();
        let rendered = render_list(&hosts).unwrap();
        assert_eq!(rendered.lines().count(), 3);
        for expected in [
            "HOST",
            "ENDPOINT ID",
            "ATTACHED",
            "LAST PUBLISH",
            "office",
            "0.2.14",
            "unknown",
        ] {
            assert!(rendered.contains(expected), "{rendered}");
        }
        assert!(
            !rendered.contains("SESSION")
                && !rendered.contains("HERDR")
                && !rendered.contains('\t')
        );
        for host in hosts {
            assert!(rendered.contains(&host.target));
        }
    }
    #[test]
    fn picker_uses_identity_even_when_labels_collide_and_rejects_invalid_output() {
        let hosts = hosts();
        let (input, _) = render_input_at(&hosts, Utc::now()).unwrap();
        for (line, host) in input.lines().zip(&hosts) {
            assert_eq!(parse_selection(line, &hosts).unwrap(), host.target);
        }
        for invalid in ["", "0", "99\tunknown", "-1\tbad", "0\tone\n1\ttwo"] {
            assert!(parse_selection(invalid, &hosts).is_err());
        }
        let mut unsafe_hosts = hosts;
        unsafe_hosts[0].host = "escape\x1b[2J".into();
        assert!(render_list(&unsafe_hosts).is_err());
    }
    #[test]
    fn publication_age_handles_skew_and_boundaries() {
        let now = Utc::now();
        for (offset, expected) in [
            (31, "clock skew"),
            (30, "0s ago"),
            (-59, "59s ago"),
            (-60, "1m ago"),
            (-3600, "1h ago"),
            (-86400, "1d ago"),
        ] {
            assert_eq!(
                publish_age(Some(now + chrono::Duration::seconds(offset)), now),
                expected
            );
        }
        assert_eq!(render_list(&[]).unwrap().lines().count(), 1);
    }
}
