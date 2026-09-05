//! Opt-in compatibility test against an unmodified official Herdr binary.
//! Uses an isolated HOME/config/state and a named session; never the caller's session.
use super::super::tracker::Tracker;
use super::*;
use std::{path::PathBuf, process::Stdio};

async fn api(path: &Path, method: &str, params: Value) -> Result<Value> {
    timeout(Duration::from_secs(5), async {
        let mut lines = request(path, method, params).await?;
        response(&mut lines).await
    })
    .await?
}

#[tokio::test]
#[ignore = "set ATTACHED_TEST_HERDR to an official Herdr 0.8.2 executable"]
async fn official_herdr_passive_finished_and_attention_events() {
    let executable = std::env::var_os("ATTACHED_TEST_HERDR").expect("ATTACHED_TEST_HERDR");
    let root = crate::test_support::canonical_tempdir();
    let config = root.path().join("config");
    let session = config.join("herdr/sessions/notifications-test");
    let path = session.join("herdr.sock");
    let mut command = tokio::process::Command::new(executable);
    for (name, _) in std::env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"HERDR_") {
            command.env_remove(name);
        }
    }
    let log = std::fs::File::create(root.path().join("server.log")).unwrap();
    let mut child = command
        .args(["--session", "notifications-test", "server"])
        .env("HOME", root.path())
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", root.path().join("state"))
        .current_dir(root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let result: Result<()> = timeout(Duration::from_secs(40), async {
        for _ in 0..100 {
            if UnixStream::connect(&path).await.is_ok() { break; }
            ensure!(child.try_wait()?.is_none(), "isolated Herdr exited during startup");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut panes = list_panes(&path).await?;
        if panes.is_empty() {
            api(&path, "workspace.create", json!({})).await?;
            panes = list_panes(&path).await?;
        }
        let pane = panes.first().context("test session has no pane")?.pane_id.clone();
        api(&path, "pane.report_agent", json!({"pane_id":pane,"source":"custom:attached-test","agent":"test-agent","state":"working","seq":1})).await?;
        let before = api(&path, "session.snapshot", json!({})).await?;
        let (mut send, receive) = tokio::io::duplex(8192);
        let bridge_path = path.clone();
        let bridge_task = tokio::spawn(async move { bridge(&bridge_path, &mut send).await });
        // Ensure the bridge task is always cancelled, including on assertion failure.
        struct Abort(tokio::task::JoinHandle<Result<()>>);
        impl Drop for Abort { fn drop(&mut self) { self.0.abort(); } }
        let _bridge = Abort(bridge_task);
        let mut lines = Lines::new(BufReader::new(receive));
        let mut tracker = Tracker::default();
        let baseline = decode_message(&lines.next().await?)?;
        ensure!(tracker.apply(baseline).is_empty(), "bootstrap replayed a notification");
        for (seq, state, expected) in [(2, "blocked", "needs attention"), (3, "idle", "finished")] {
            api(&path, "pane.report_agent", json!({"pane_id":pane,"source":"custom:attached-test","agent":"test-agent","state":state,"seq":seq})).await?;
            loop {
                let message = decode_message(&lines.next().await?)?;
                let notices = tracker.apply(message);
                if let Some(notice) = notices.first() {
                    ensure!(notice.title.ends_with(expected), "unexpected notification: {}", notice.title);
                    break;
                }
            }
        }
        let after = api(&path, "session.snapshot", json!({})).await?;
        ensure!(before["snapshot"].is_object() && after["snapshot"].is_object(), "missing session snapshots");
        for key in ["focused_pane_id", "focused_tab_id", "focused_workspace_id", "layouts"] {
            ensure!(before["snapshot"][key] == after["snapshot"][key], "passive observer changed {key}");
        }
        let split = api(&path, "pane.split", json!({"pane_id":pane,"direction":"right","focus":false})).await?;
        let new_pane = split["pane"]["pane_id"].as_str().context("split has no pane id")?.to_owned();
        api(&path, "pane.report_agent", json!({"pane_id":new_pane,"source":"custom:attached-test","agent":"test-agent","state":"working","seq":1})).await?;
        loop {
            let message = decode_message(&lines.next().await?)?;
            let discovered = matches!(&message, Message::Snapshot { panes } if panes.iter().any(|p| p.pane_id == new_pane));
            ensure!(tracker.apply(message).is_empty(), "new pane discovery replayed state");
            if discovered { break; }
        }
        api(&path, "pane.report_agent", json!({"pane_id":new_pane,"source":"custom:attached-test","agent":"test-agent","state":"blocked","seq":2})).await?;
        loop {
            let notices = tracker.apply(decode_message(&lines.next().await?)?);
            if let Some(notice) = notices.first() {
                ensure!(notice.title.ends_with("needs attention"), "new pane was not subscribed");
                break;
            }
        }
        api(&path, "pane.close", json!({"pane_id":new_pane})).await?;
        loop {
            let message = decode_message(&lines.next().await?)?;
            let removed = matches!(&message, Message::Snapshot { panes } if panes.iter().all(|p| p.pane_id != new_pane));
            ensure!(tracker.apply(message).is_empty(), "closed pane emitted a notification");
            if removed { break; }
        }
        // Stop only the named session created in this isolated config root.
        Ok(())
    }).await.context("official Herdr event test timed out").and_then(|result| result);
    let _ = child.kill().await;
    let _ = child.wait().await;
    if result.is_err() {
        eprintln!(
            "isolated server log: {}",
            std::fs::read_to_string(root.path().join("server.log")).unwrap_or_default()
        );
    }
    result.unwrap();
    // Keep the test explicitly scoped to the isolated session, not environment routing.
    assert!(PathBuf::from(&path).starts_with(root.path()));
}
