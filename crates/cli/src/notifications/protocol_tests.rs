use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn fragmented_lines_survive_cancelled_reads_and_coalesced_frames() {
    let (mut writer, reader) = tokio::io::duplex(128);
    let mut lines = Lines::new(BufReader::new(reader));
    writer.write_all(b"{\"event\":").await.unwrap();
    assert!(
        timeout(Duration::from_millis(10), lines.next())
            .await
            .is_err()
    );
    writer.write_all(b"1}\n{\"event\":2}\n").await.unwrap();
    assert_eq!(lines.next().await.unwrap(), b"{\"event\":1}\n");
    assert_eq!(lines.next().await.unwrap(), b"{\"event\":2}\n");
    drop(writer);
    assert!(lines.next().await.is_err());
}

#[tokio::test]
async fn rejects_oversized_unterminated_and_malformed_frames() {
    let oversized = vec![b'x'; MAX_LINE + 1];
    assert!(Lines::new(oversized.as_slice()).next().await.is_err());
    assert!(Lines::new(b"partial".as_slice()).next().await.is_err());
    assert!(parse_event(b"not json\n").is_err());
    assert!(parse_event(br#"{"event":"pane.output_changed","data":{"text":"secret"}}"#).is_err());
}

#[test]
fn wire_snapshots_and_retained_field_sizes_are_bounded() {
    let pane = Pane {
        pane_id: "w1:p1".into(),
        workspace_id: "w1".into(),
        terminal_id: None,
        agent_status: Status::Working,
        agent: Some("pi".into()),
        title: None,
    };
    let duplicate = Message::Snapshot {
        panes: vec![pane.clone(), pane.clone()],
    };
    assert!(decode_message(&serde_json::to_vec(&duplicate).unwrap()).is_err());
    let oversized = Message::Snapshot {
        panes: vec![pane.clone(); MAX_PANES + 1],
    };
    assert!(decode_message(&serde_json::to_vec(&oversized).unwrap()).is_err());
    let mut oversized_field = pane;
    oversized_field.title = Some("x".repeat(1025));
    assert!(
        decode_message(
            &serde_json::to_vec(&Message::State {
                pane: oversized_field
            })
            .unwrap()
        )
        .is_err()
    );
}

#[test]
fn parses_official_082_status_envelopes_and_ignores_new_fields() {
    let pane = parse_event(br#"{"event":"pane.agent_status_changed","data":{"pane_id":"w1:p1","workspace_id":"w1","agent_status":"done","agent":"pi","display_agent":"Custom label","future_field":true}}"#).unwrap();
    assert_eq!(pane.agent_status, Status::Done);
    assert_eq!(pane.agent.as_deref(), Some("pi"));
    assert_eq!(pane.terminal_id, None);
    let pane = parse_event(br#"{"event":"pane.agent_status_changed","data":{"pane_id":"w1:p1","workspace_id":"w1","agent_status":"future_status"}}"#).unwrap();
    assert_eq!(pane.agent_status, Status::Unknown);
}

#[tokio::test]
async fn bridge_issues_only_fixed_read_only_requests_and_no_tui_handshake() {
    let root = crate::test_support::canonical_tempdir();
    let path = root.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let api = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let request: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(request["method"], "pane.list");
        assert_eq!(request["params"], json!({}));
        reader.get_mut().write_all(b"{\"id\":\"attached-events\",\"result\":{\"type\":\"pane_list\",\"panes\":[{\"pane_id\":\"w1:p1\",\"terminal_id\":\"term_1\",\"workspace_id\":\"w1\",\"agent\":\"pi\",\"agent_status\":\"working\"}]}}\n").await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let request: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(request["method"], "events.subscribe");
        assert_eq!(
            request["params"],
            json!({"subscriptions":[{"type":"pane.agent_status_changed","pane_id":"w1:p1"}]})
        );
        reader.get_mut().write_all(b"{\"id\":\"attached-events\",\"result\":{\"type\":\"subscription_started\"}}\n{\"event\":\"pane.agent_status_changed\",\"data\":{\"pane_id\":\"w1:p1\",\"workspace_id\":\"w1\",\"agent\":\"pi\",\"agent_status\":\"done\"}}\n").await.unwrap();
        // The bridge must never forward any subscriber input to this socket.
        let mut byte = [0];
        assert_eq!(reader.read(&mut byte).await.unwrap(), 0);
    });
    let (mut send, receive) = tokio::io::duplex(4096);
    let proxy = tokio::spawn(async move { bridge(&path, &mut send).await });
    let mut lines = Lines::new(BufReader::new(receive));
    let baseline: Message = serde_json::from_slice(&lines.next().await.unwrap()).unwrap();
    assert!(matches!(baseline, Message::Snapshot { .. }));
    let event: Message = serde_json::from_slice(&lines.next().await.unwrap()).unwrap();
    assert!(matches!(
        event,
        Message::State {
            pane: Pane {
                agent_status: Status::Done,
                ..
            }
        }
    ));
    proxy.abort();
    let _ = proxy.await;
    timeout(Duration::from_secs(2), api).await.unwrap().unwrap();
}

#[tokio::test]
async fn rejected_api_requests_fail_without_forwarding_error_content() {
    let root = crate::test_support::canonical_tempdir();
    let path = root.path().join("api.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let api = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 1024];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream
            .write_all(b"{\"id\":\"attached-events\",\"error\":{\"message\":\"TOKEN=secret\"}}\n")
            .await
            .unwrap();
    });
    let error = list_panes(&path).await.unwrap_err().to_string();
    assert!(!error.contains("TOKEN"));
    api.await.unwrap();
}
