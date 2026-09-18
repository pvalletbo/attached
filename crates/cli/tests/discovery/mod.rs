use super::*;

#[tokio::test]
async fn machine_discovery_reports_identity_and_filters_disabled_publishers() {
    timeout(DEADLINE * 3, async {
        let fixture = CliFixture::new();
        // Any accidental application-specific invocation must fail the test.
        fixture.script("herdr", "touch \"$FIXTURE_ROOT/unexpected-herdr\"; exit 99");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        import(
            &fixture,
            &format!("http://{}", listener.local_addr().unwrap()),
        )
        .await;
        let identity = iroh::SecretKey::from_bytes(&[47; 32]).public();
        let ticket = EndpointTicket::new(iroh::EndpointAddr::new(identity)).to_string();
        let server = async {
            for (revision, enabled) in [(1, false), (2, true), (3, false)] {
                let (index, record) = catalog_with_access(&ticket, revision, enabled);
                respond(&mut checked_request(&listener, false).await, &index, "").await;
                respond(
                    &mut checked_request(&listener, true).await,
                    &record,
                    &format!("ETag: \"{revision}\"\r\n"),
                )
                .await;
            }
        };
        let client = async {
            for enabled in [false, true, false] {
                let output = fixture.run(&["--use-1password", "sessions", "list"]).await;
                output.assert_code(0);
                let lines: Vec<_> = output.stdout.lines().collect();
                assert!(
                    lines[0].contains("ENDPOINT ID")
                        && !lines[0].contains("HERDR")
                        && !lines[0].contains("SESSION"),
                    "{output:?}"
                );
                assert_eq!(lines.len(), if enabled { 2 } else { 1 }, "{output:?}");
                if enabled {
                    assert!(
                        lines[1].contains(&identity.to_string())
                            && lines[1].contains("remote")
                            && lines[1].contains("0.2.9"),
                        "{output:?}"
                    );
                }
            }
        };
        tokio::join!(server, client);
        assert!(!fixture.path("unexpected-herdr").exists());
        assert_private(&fixture.path("home/.config/attached/host-catalog.json"));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn json_discovery_refreshes_and_only_reports_ssh_enabled_public_metadata() {
    timeout(DEADLINE * 3, async {
        let fixture = CliFixture::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        import(
            &fixture,
            &format!("http://{}", listener.local_addr().unwrap()),
        )
        .await;
        let identity = iroh::SecretKey::from_bytes(&[47; 32]).public();
        let ticket = EndpointTicket::new(iroh::EndpointAddr::new(identity)).to_string();
        let server = async {
            for (revision, enabled) in [(1, false), (2, true), (3, false)] {
                let (index, record) = catalog_with_access(&ticket, revision, enabled);
                respond(&mut checked_request(&listener, false).await, &index, "").await;
                respond(
                    &mut checked_request(&listener, true).await,
                    &record,
                    &format!("ETag: \"{revision}\"\r\n"),
                )
                .await;
            }
        };
        let client = async {
            for enabled in [false, true, false] {
                let output = fixture
                    .run(&["--use-1password", "sessions", "list", "--json"])
                    .await;
                output.assert_code(0);
                let rows: serde_json::Value = serde_json::from_str(&output.stdout).unwrap();
                assert_eq!(rows.as_array().unwrap().len(), usize::from(enabled));
                if enabled {
                    assert_eq!(rows[0].as_object().unwrap().len(), 6);
                    assert_eq!(rows[0]["workspace"], "default");
                    assert_eq!(rows[0]["host"], "remote");
                    assert_eq!(rows[0]["endpoint_id"], identity.to_string());
                    assert_eq!(rows[0]["ssh_target"], format!("attached-{identity}"));
                    assert_eq!(rows[0]["attached_version"], "0.2.9");
                    assert!(rows[0]["published_at"].as_str().is_some());
                }
            }
        };
        tokio::join!(server, client);
        // A background plugin must never prompt on /dev/tty or emit partial JSON.
        let locked = fixture.run(&["-v", "sessions", "list", "--json"]).await;
        locked.assert_code(1);
        assert!(locked.stdout.is_empty());
        assert!(
            locked.stderr.contains("credentials are locked"),
            "{locked:?}"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn remote_attached_update_targets_a_machine_even_when_ssh_is_disabled() {
    use attached_tunnel_protocol::{
        AttachedUpdateRequest, AttachedUpdateResponse, read_attached_update_request,
        write_attached_update_response,
    };
    timeout(DEADLINE * 2, async {
        let fixture = CliFixture::new();
        fixture.script("herdr", "touch \"$FIXTURE_ROOT/unexpected-herdr\"; exit 99");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        import(
            &fixture,
            &format!("http://{}", listener.local_addr().unwrap()),
        )
        .await;
        let publisher = endpoint().await;
        let ticket = EndpointTicket::new(publisher.addr()).to_string();
        let (index, record) = catalog_with_access(&ticket, 1, false);
        let discovery = async {
            respond(&mut checked_request(&listener, false).await, &index, "").await;
            respond(
                &mut checked_request(&listener, true).await,
                &record,
                "ETag: \"1\"\r\n",
            )
            .await;
        };
        let update = async {
            let connection = publisher.accept().await.unwrap().await.unwrap();
            assert_eq!(connection.alpn(), ATTACHED_UPDATE_ALPN);
            assert_eq!(
                connection.remote_id(),
                iroh::SecretKey::from_bytes(&IDENTITY).public()
            );
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            let request =
                read_attached_update_request(&mut receive, &CapabilitySecret::from_bytes([46; 32]))
                    .await
                    .unwrap();
            assert_eq!(request, AttachedUpdateRequest::Start);
            write_attached_update_response(
                &mut send,
                AttachedUpdateResponse::Current(attached_tunnel_protocol::AttachedVersion::new(
                    0, 2, 9,
                )),
            )
            .await
            .unwrap();
            let _ = send.stopped().await;
        };
        let client = async {
            let output = fixture
                .run(&["--use-1password", "update", "--remote", "remote"])
                .await;
            output.assert_code(0);
            assert!(output.stdout.is_empty());
            assert!(
                output.stderr.contains("serving with Attached 0.2.9"),
                "{output:?}"
            );
        };
        tokio::join!(discovery, update, client);
        publisher.close().await;
        assert!(!fixture.path("unexpected-herdr").exists());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn obsolete_application_commands_and_options_are_rejected() {
    let fixture = CliFixture::new();
    for args in [
        vec!["attach"],
        vec!["serve", "--herdr-bin", "anything"],
        vec!["sessions", "list", "--herdr-bin", "anything"],
        vec!["ssh", "--upgrade-remote", "office"],
    ] {
        fixture.run(&args).await.assert_code(2);
    }
}
