use super::*;
use std::os::unix::fs::PermissionsExt;
use tokio::{io::AsyncBufReadExt, net::UnixListener};

fn target() -> PaneFocus {
    PaneFocus {
        pane_id: "w1:p2".into(),
        terminal_id: Some("term-original".into()),
    }
}

#[tokio::test]
async fn focus_wire_is_bounded_and_rejects_unknown_fields_and_invalid_ids() {
    let pane = target();
    let mut bytes = Vec::new();
    write_request(&mut bytes, &pane).await.unwrap();
    assert_eq!(read_request(&mut bytes.as_slice()).await.unwrap(), pane);
    for body in [
        r#"{"pane_id":"w1:p2","terminal_id":null,"method":"pane.close"}"#.to_owned(),
        r#"{"pane_id":"","terminal_id":null}"#.to_owned(),
        r#"{"pane_id":"w1:p2","terminal_id":""}"#.to_owned(),
        r#"{"pane_id":"w1:\np2","terminal_id":null}"#.to_owned(),
        format!(r#"{{"pane_id":"{}","terminal_id":null}}"#, "x".repeat(129)),
    ] {
        let mut bytes = (body.len() as u16).to_be_bytes().to_vec();
        bytes.extend(body.as_bytes());
        assert!(read_request(&mut bytes.as_slice()).await.is_err());
    }
    let too_long = ((MAX_REQUEST + 1) as u16).to_be_bytes();
    assert!(read_request(&mut too_long.as_slice()).await.is_err());
    assert!(read_request(&mut b"\0\x10short".as_slice()).await.is_err());
    assert!(read_result(&mut [7].as_slice()).await.is_err());
    assert!(read_result(&mut [0].as_slice()).await.unwrap());
    assert!(!read_result(&mut [1].as_slice()).await.unwrap());
}

#[tokio::test]
async fn focus_checks_occupant_and_only_issues_fixed_pane_operations() {
    for (occupant, expected_focus) in [("term-original", true), ("replacement", false)] {
        let root = crate::test_support::canonical_tempdir();
        let path = root.path().join("herdr.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let service = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&line).unwrap(),
                json!({
                    "id":"attached-focus", "method":"pane.get", "params":{"pane_id":"w1:p2"}
                })
            );
            let response = json!({"id":"attached-focus", "result":{"pane":{"pane_id":"w1:p2","terminal_id":occupant}}});
            stream
                .get_mut()
                .write_all(format!("{response}\n").as_bytes())
                .await
                .unwrap();
            if expected_focus {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                line.clear();
                stream.read_line(&mut line).await.unwrap();
                assert_eq!(
                    serde_json::from_str::<Value>(&line).unwrap(),
                    json!({
                        "id":"attached-focus", "method":"pane.focus", "params":{"pane_id":"w1:p2"}
                    })
                );
                stream
                    .get_mut()
                    .write_all(b"{\"id\":\"attached-focus\",\"result\":{}}\n")
                    .await
                    .unwrap();
            }
            assert!(
                timeout(Duration::from_millis(30), listener.accept())
                    .await
                    .is_err()
            );
        });
        let session = Session::new("work".into(), path.with_file_name("herdr-client.sock"));
        assert_eq!(focus(&session, &target()).await.unwrap(), expected_focus);
        service.await.unwrap();
    }
}

#[tokio::test]
async fn missing_api_falls_back_but_malformed_focus_requests_fail_closed() {
    let root = crate::test_support::canonical_tempdir();
    let session = Session::new("work".into(), root.path().join("herdr-client.sock"));
    let mut request = Vec::new();
    write_request(&mut request, &target()).await.unwrap();
    let mut response = Vec::new();
    serve(&mut request.as_slice(), &mut response, &session)
        .await
        .unwrap();
    assert_eq!(response, [1]);
    response.clear();
    assert!(
        serve(&mut b"\0\x01{".as_slice(), &mut response, &session)
            .await
            .is_err()
    );
    assert!(response.is_empty());
}

#[tokio::test]
#[ignore = "set ATTACHED_TEST_HERDR to official Herdr 0.8.2; isolated session only"]
async fn official_herdr_focus_selects_the_notified_pane_and_stale_clicks_do_not_move_focus() {
    let executable = std::env::var_os("ATTACHED_TEST_HERDR").expect("ATTACHED_TEST_HERDR");
    // macOS's default temp directory plus Herdr's session suffix exceeds sun_path.
    let root = tempfile::Builder::new()
        .prefix("af-")
        .tempdir_in("/tmp")
        .unwrap();
    let config = root.path().join("config");
    let directory = config.join("herdr/sessions/focus-test");
    let path = directory.join("herdr.sock");
    let mut command = tokio::process::Command::new(executable);
    for (name, _) in std::env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"HERDR_") {
            command.env_remove(name);
        }
    }
    let mut child = command
        .args(["--session", "focus-test", "server"])
        .env("HOME", root.path())
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", root.path().join("state"))
        .current_dir(root.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(root.path().join("server.log")).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let result: Result<()> = timeout(Duration::from_secs(20), async {
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            ensure!(child.try_wait()?.is_none(), "isolated Herdr exited");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Create two workspaces so pane.focus must also select the owning workspace/tab.
        let first = raw_api(&path, "workspace.create", json!({})).await?;
        let first_workspace = first["workspace"]["workspace_id"]
            .as_str()
            .context("workspace id")?;
        let listed = raw_api(&path, "pane.list", json!({"workspace_id":first_workspace})).await?;
        let first = &listed["panes"][0];
        let pane = PaneFocus {
            pane_id: first["pane_id"].as_str().context("pane id")?.into(),
            terminal_id: Some(first["terminal_id"].as_str().context("terminal id")?.into()),
        };
        raw_api(&path, "workspace.create", json!({})).await?;
        let session = Session::new("focus-test".into(), directory.join("herdr-client.sock"));
        ensure!(focus(&session, &pane).await?, "focus failed");
        let snapshot = raw_api(&path, "session.snapshot", json!({})).await?;
        ensure!(
            snapshot["snapshot"]["focused_pane_id"] == pane.pane_id,
            "wrong pane focused"
        );
        ensure!(
            snapshot["snapshot"]["focused_workspace_id"] == first["workspace_id"],
            "wrong workspace focused"
        );
        ensure!(
            snapshot["snapshot"]["focused_tab_id"] == first["tab_id"],
            "wrong tab focused"
        );
        let stale = PaneFocus {
            terminal_id: Some("old-terminal".into()),
            ..pane.clone()
        };
        ensure!(
            !focus(&session, &stale).await?,
            "stale occupant was focused"
        );
        raw_api(&path, "pane.close", json!({"pane_id":pane.pane_id})).await?;
        let before = raw_api(&path, "session.snapshot", json!({})).await?;
        let mut request = Vec::new();
        write_request(&mut request, &pane).await?;
        let mut response = Vec::new();
        serve(&mut request.as_slice(), &mut response, &session).await?;
        ensure!(response == [1], "closed pane must fall back");
        let after = raw_api(&path, "session.snapshot", json!({})).await?;
        ensure!(
            before["snapshot"]["focused_pane_id"] == after["snapshot"]["focused_pane_id"],
            "closed pane changed focus"
        );
        Ok(())
    })
    .await
    .context("isolated focus test timed out")
    .and_then(|result| result);
    let _ = child.kill().await;
    let _ = child.wait().await;
    if result.is_err() {
        eprintln!(
            "isolated Herdr log: {}",
            std::fs::read_to_string(root.path().join("server.log")).unwrap_or_default()
        );
    }
    result.unwrap();
}

async fn raw_api(path: &Path, method: &str, params: Value) -> Result<Value> {
    let mut stream = UnixStream::connect(path).await?;
    let request = json!({"id":"test", "method":method, "params":params});
    stream.write_all(format!("{request}\n").as_bytes()).await?;
    let response: Value =
        serde_json::from_slice(&Lines::new(BufReader::new(stream)).next().await?)?;
    ensure!(
        response.get("error").is_none(),
        "isolated API rejected {method}: {response}"
    );
    Ok(response["result"].clone())
}
