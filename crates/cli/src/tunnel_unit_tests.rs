use super::*;

#[tokio::test]
async fn client_endpoint_uses_the_persistent_identity() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let identity = iroh::SecretKey::generate();
        let expected = identity.public();

        let endpoint = bind_client_endpoint(&identity).await.unwrap();

        assert_eq!(endpoint.id(), expected);
        endpoint.close().await;
    })
    .await
    .expect("persistent client endpoint bind timed out");
}

#[tokio::test]
async fn missing_selected_session_socket_is_reported_without_fallback() {
    let root = tempfile::tempdir().unwrap();
    let other_tui = root.path().join("other.sock");
    let _other_listener = UnixListener::bind(&other_tui).unwrap();
    let selected = Session::new(
        "selected".to_owned(),
        root.path().join("selected-tui-missing.sock"),
    );

    let error = connect_session_tui_socket(&selected).await.unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("Herdr session `selected`"));
    assert!(message.contains("selected-tui-missing.sock"));
    assert!(!message.contains("other.sock"));
}

#[test]
fn remote_setup_failures_are_classified_for_catalog_pruning() {
    let error = remote_unavailable(anyhow!("peer is offline"));
    assert!(is_remote_unavailable(&error));
    assert!(error.to_string().contains("peer is offline"));
    assert!(!is_remote_unavailable(&anyhow!("local child failed")));
}

#[test]
fn remote_upgrade_errors_are_classified_for_catalog_pruning() {
    let error = finish_upgrade_result::<()>(Err(anyhow!("upgrade peer offline"))).unwrap_err();
    assert!(is_remote_unavailable(&error), "{error:#}");
}

#[test]
fn reachable_upgrade_rejections_are_not_classified_as_unavailable() {
    for response in [
        UpgradeResponse::Busy,
        UpgradeResponse::Failed("installer rejected update".to_owned()),
    ] {
        let error = finish_upgrade_response(response).unwrap_err();
        assert!(!is_remote_unavailable(&error), "{error:#}");
    }
}

#[test]
fn maps_normal_and_signal_exit_statuses() {
    assert_eq!(exit_code(ExitStatus::from_raw(7 << 8)), 7);
    assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
}

#[tokio::test]
async fn spawned_herdr_uses_direct_client_mode_and_local_keybindings() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("herdr");
    std::fs::write(
        &executable,
        b"#!/bin/sh\ntest -z \"$HERDR_SOCKET_PATH\" && test \"$HERDR_CLIENT_SOCKET_PATH\" = /tmp/tui.sock && test \"$HERDR_REMOTE_KEYBINDINGS\" = local && test \"$#\" -eq 1 && test \"$1\" = client\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = spawn_herdr(&executable, Path::new("/tmp/tui.sock")).unwrap();

    assert!(child.wait().await.unwrap().success());
}

#[tokio::test]
async fn child_shutdown_is_bounded() {
    let mut child = Command::new("sleep")
        .arg("60")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let status = timeout(
        CHILD_EXIT_GRACE + Duration::from_secs(1),
        stop_child(&mut child),
    )
    .await
    .expect("child shutdown exceeded its bound")
    .unwrap();
    assert!(!status.success());
}

#[tokio::test]
async fn unexpected_forwarder_completion_stops_and_reaps_live_child() {
    let mut child = Command::new("sleep")
        .arg("60")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let cancellation = CancellationToken::new();
    let mut forwarders = JoinSet::new();
    forwarders.spawn(async { Ok(()) });

    let error = timeout(
        Duration::from_secs(2),
        supervise_connect_runtime(
            &mut child,
            &mut forwarders,
            cancellation.clone(),
            std::future::pending::<String>(),
            std::future::pending::<Result<()>>(),
        ),
    )
    .await
    .expect("supervisor waited for the sleeping child")
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("local proxy forwarder stopped unexpectedly"),
        "{error:#}"
    );
    assert!(cancellation.is_cancelled());
    assert!(child.try_wait().unwrap().is_some(), "Herdr was not reaped");
}

#[tokio::test]
async fn forwarder_error_stops_and_reaps_live_child() {
    let mut child = Command::new("sleep")
        .arg("60")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let cancellation = CancellationToken::new();
    let mut forwarders = JoinSet::new();
    forwarders.spawn(async { Err(anyhow!("forwarder broke")) });

    let error = timeout(
        Duration::from_secs(2),
        supervise_connect_runtime(
            &mut child,
            &mut forwarders,
            cancellation.clone(),
            std::future::pending::<String>(),
            std::future::pending::<Result<()>>(),
        ),
    )
    .await
    .expect("supervisor waited for the sleeping child")
    .unwrap_err();

    assert!(
        format!("{error:#}").contains("local proxy forwarder failed: forwarder broke"),
        "{error:#}"
    );
    assert!(cancellation.is_cancelled());
    assert!(child.try_wait().unwrap().is_some(), "Herdr was not reaped");
}

#[tokio::test]
async fn forwarder_panic_stops_and_reaps_live_child() {
    let mut child = Command::new("sleep")
        .arg("60")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let cancellation = CancellationToken::new();
    let mut forwarders = JoinSet::new();
    forwarders.spawn(async {
        panic!("forwarder panicked");
        #[allow(unreachable_code)]
        Result::<()>::Ok(())
    });

    let error = timeout(
        Duration::from_secs(2),
        supervise_connect_runtime(
            &mut child,
            &mut forwarders,
            cancellation.clone(),
            std::future::pending::<String>(),
            std::future::pending::<Result<()>>(),
        ),
    )
    .await
    .expect("supervisor waited for the sleeping child")
    .unwrap_err();

    let message = format!("{error:#}");
    assert!(
        message.contains("local proxy forwarder task failed"),
        "{message}"
    );
    assert!(message.contains("forwarder panicked"), "{message}");
    assert!(cancellation.is_cancelled());
    assert!(child.try_wait().unwrap().is_some(), "Herdr was not reaped");
}

#[tokio::test]
async fn shutdown_signal_error_stops_and_reaps_live_child() {
    let mut child = Command::new("sleep")
        .arg("60")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let cancellation = CancellationToken::new();
    let mut forwarders = JoinSet::new();
    forwarders.spawn(std::future::pending::<Result<()>>());

    let error = timeout(
        Duration::from_secs(2),
        supervise_connect_runtime(
            &mut child,
            &mut forwarders,
            cancellation.clone(),
            std::future::pending::<String>(),
            async { Err(std::io::Error::other("signal receiver failed")) },
        ),
    )
    .await
    .expect("supervisor waited for the sleeping child")
    .unwrap_err();

    assert!(
        format!("{error:#}").contains("failed to listen for Ctrl-C: signal receiver failed"),
        "{error:#}"
    );
    assert!(cancellation.is_cancelled());
    assert!(child.try_wait().unwrap().is_some(), "Herdr was not reaped");
}

#[tokio::test]
async fn connection_loss_is_classified_and_reaps_the_local_child() {
    let mut child = Command::new("sleep")
        .arg("60")
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let error = timeout(
        Duration::from_secs(2),
        finish_connect_outcome(
            &mut child,
            ConnectOutcome::ConnectionLost("peer stopped".to_owned()),
        ),
    )
    .await
    .expect("supervisor waited for the sleeping child")
    .unwrap_err();

    assert!(is_remote_unavailable(&error), "{error:#}");
    assert!(error.to_string().contains("peer stopped"), "{error:#}");
    assert!(child.try_wait().unwrap().is_some(), "Herdr was not reaped");
}

#[tokio::test]
async fn child_wait_error_stops_and_reaps_live_child() {
    let mut child = Command::new("sleep")
        .arg("60")
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let error = timeout(
        Duration::from_secs(2),
        finish_connect_outcome(
            &mut child,
            ConnectOutcome::Child(Err(std::io::Error::other("wait failed"))),
        ),
    )
    .await
    .expect("supervisor waited for the sleeping child")
    .unwrap_err();

    assert!(
        format!("{error:#}").contains("failed to wait for Herdr: wait failed"),
        "{error:#}"
    );
    assert!(child.try_wait().unwrap().is_some(), "Herdr was not reaped");
}

#[tokio::test]
async fn interrupted_child_wait_error_stops_and_reaps_live_child() {
    let mut child = Command::new("sleep")
        .arg("60")
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let error = timeout(
        Duration::from_secs(2),
        finish_interrupted_child_wait(
            &mut child,
            Err(std::io::Error::other("interrupted wait failed")),
        ),
    )
    .await
    .expect("supervisor waited for the sleeping child")
    .unwrap_err();

    assert!(
        format!("{error:#}")
            .contains("failed to wait for Herdr after Ctrl-C: interrupted wait failed"),
        "{error:#}"
    );
    assert!(child.try_wait().unwrap().is_some(), "Herdr was not reaped");
}

#[tokio::test]
async fn remote_setup_operation_errors_are_classified() {
    let error = setup_remote_step(
        async { Result::<()>::Err(anyhow!("peer offline")) },
        std::future::pending::<Result<()>>(),
        Duration::from_secs(1),
        "connecting",
    )
    .await
    .unwrap_err();

    assert!(is_remote_unavailable(&error), "{error:#}");
}

#[tokio::test]
async fn local_setup_cancellation_is_not_classified_as_remote() {
    let error = setup_remote_step(
        std::future::pending::<Result<()>>(),
        async { Result::<()>::Ok(()) },
        Duration::from_secs(1),
        "connecting",
    )
    .await
    .unwrap_err();

    assert!(!is_remote_unavailable(&error), "{error:#}");
}

#[tokio::test]
async fn remote_setup_timeout_is_classified_as_unavailable() {
    let error = setup_remote_step(
        std::future::pending::<Result<()>>(),
        std::future::pending::<Result<()>>(),
        Duration::from_millis(10),
        "connecting",
    )
    .await
    .unwrap_err();

    assert!(is_remote_unavailable(&error), "{error:#}");
    assert!(error.to_string().contains("timed out"), "{error:#}");
}

#[tokio::test]
async fn setup_step_is_cancelled_by_shutdown() {
    let error = setup_step(
        std::future::pending::<Result<()>>(),
        async { Result::<()>::Ok(()) },
        Duration::from_secs(60),
        "binding local Iroh endpoint",
    )
    .await
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("interrupted while binding local Iroh endpoint"),
        "{error:#}"
    );
}

#[tokio::test]
async fn setup_step_has_a_bounded_deadline() {
    let error = setup_step(
        std::future::pending::<Result<()>>(),
        std::future::pending::<Result<()>>(),
        Duration::from_millis(20),
        "connecting to Iroh endpoint",
    )
    .await
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("timed out while connecting to Iroh endpoint"),
        "{error:#}"
    );
}
