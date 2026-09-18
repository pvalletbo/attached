//! Black-box multi-account UX, real OpenSSH routing, and simultaneous serving.
use super::*;
use attached_session_sync_protocol::account::ApiKeyScope;

async fn import_workspace(
    fixture: &CliFixture,
    discovery: &Discovery,
    name: &str,
    identity: [u8; 32],
) -> String {
    let encoded = bundle(&discovery.origin, identity);
    fs::write(fixture.path("workspace.bundle"), &encoded).unwrap();
    fixture
        .run(&[
            "--use-1password",
            "account",
            "import",
            "--workspace",
            name,
            "--bundle-file",
            "workspace.bundle",
        ])
        .await
        .assert_code(0);
    encoded
}

async fn workspace_rows(fixture: &CliFixture) -> serde_json::Value {
    let output = fixture
        .run(&["--use-1password", "workspace", "list", "--json"])
        .await;
    output.assert_code(0);
    serde_json::from_str(&output.stdout).unwrap()
}

#[tokio::test]
async fn combined_export_routes_duplicate_labels_through_their_own_accounts_and_keeps_selection_pinned()
 {
    let fixture = CliFixture::new();
    let work = Discovery::new().await;
    let personal = Discovery::new().await;
    let work_identity = iroh::SecretKey::generate().to_bytes();
    let personal_identity = iroh::SecretKey::generate().to_bytes();
    let work_bundle = import_workspace(&fixture, &work, "work", work_identity).await;
    import_workspace(&fixture, &personal, "personal", personal_identity).await;
    // Importing the same account under another local name must reuse its endpoint.
    import_workspace(&fixture, &work, "work-copy", work_identity).await;
    let work_host = Publisher::new(work_identity, 81).await;
    let personal_host = Publisher::new(personal_identity, 82).await;
    work_host.advertise(&work, "Office", 1, true, 300).await;
    personal_host
        .advertise(&personal, "Office", 1, true, 300)
        .await;
    let rows = workspace_rows(&fixture).await;
    assert_eq!(rows.as_array().unwrap().len(), 4);
    assert_eq!(rows[0]["name"], "default");
    assert_eq!(rows[0]["selected"], true);
    assert_eq!(rows[0]["consume"], false);
    for row in &rows.as_array().unwrap()[1..] {
        assert_eq!(row["publish"], false);
        assert_eq!(row["consume"], true);
    }

    let broker = start_with(&fixture, &["--all-workspaces"]);
    let configured = wait_config(&fixture, |text| {
        text.contains(" attached-work--office\n")
            && text.contains(" attached-personal--office\n")
            && text.contains(" attached-work-copy--office\n")
    })
    .await;
    assert!(!configured.contains(" attached-office\n"));
    let config = fixture.path("home/.ssh/config");
    let ((), (), ()) = tokio::join!(
        check_command(&config, "attached-work--office"),
        check_command(&config, "attached-personal--office"),
        check_command(&config, "attached-work-copy--office"),
    );
    let target = format!("attached-work--{}", work_host.endpoint.id());
    let evaluated = tokio::process::Command::new("ssh")
        .args(["-G", "-F"])
        .arg(&config)
        .arg(&target)
        .output()
        .await
        .unwrap();
    assert!(
        String::from_utf8(evaluated.stdout)
            .unwrap()
            .contains(&format!("hostname {target}\n"))
    );
    assert_eq!(work_host.commands.load(Ordering::SeqCst), 2);
    assert_eq!(personal_host.commands.load(Ordering::SeqCst), 1);

    // The default influences subsequent invocations only, not the live exporter.
    fixture
        .run(&["workspace", "use", "personal"])
        .await
        .assert_code(0);
    fixture
        .run(&[
            "--use-1password",
            "account",
            "export",
            "--workspace",
            "work",
            "--type",
            "download",
            "--output",
            "export.bundle",
        ])
        .await
        .assert_code(0);
    assert_eq!(
        fs::read_to_string(fixture.path("export.bundle"))
            .unwrap()
            .trim(),
        work_bundle
    );
    let selected = fixture
        .run(&["--use-1password", "sessions", "list", "--json"])
        .await;
    selected.assert_code(0);
    let selected: serde_json::Value = serde_json::from_str(&selected.stdout).unwrap();
    assert_eq!(selected.as_array().unwrap().len(), 1);
    assert_eq!(selected[0]["workspace"], "personal");
    assert_eq!(
        selected[0]["endpoint_id"],
        personal_host.endpoint.id().to_string()
    );
    let overridden = fixture
        .run(&[
            "--use-1password",
            "sessions",
            "list",
            "--json",
            "--workspace",
            "work",
        ])
        .await;
    overridden.assert_code(0);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&overridden.stdout).unwrap()[0]["workspace"],
        "work"
    );
    check_command(&config, "attached-work--office").await;

    // One failed service neither hides healthy workspaces nor steals their aliases.
    *work.records.lock().await = None;
    let combined = fixture
        .run(&[
            "--use-1password",
            "sessions",
            "list",
            "--all-workspaces",
            "--json",
        ])
        .await;
    combined.assert_code(1);
    let combined: serde_json::Value = serde_json::from_str(&combined.stdout).unwrap();
    assert_eq!(combined.as_array().unwrap().len(), 1);
    assert_eq!(combined[0]["workspace"], "personal");
    check_command(&config, "attached-personal--office").await;
    personal.records.lock().await.as_mut().unwrap().clear();
    wait_config(&fixture, |text| {
        !text.contains(" attached-personal--office\n") && text.contains(" attached-work--office\n")
    })
    .await;
    check_command(&config, "attached-work--office").await;
    stop(broker, rustix::process::Signal::TERM).await;
    for path in runtime_files(&configured) {
        assert!(!path.exists());
    }
    assert_eq!(fs::read(&config).unwrap(), b"");
    work_host.stop().await;
    personal_host.stop().await;
    work.stop().await;
    personal.stop().await;
}

#[tokio::test]
async fn a_running_publisher_can_import_and_consume_another_workspace_without_losing_incoming_ssh()
{
    let machine = CliFixture::new();
    let visitor = CliFixture::new();
    let personal = Discovery::new().await;
    let work = Discovery::new().await;
    let personal_identity = iroh::SecretKey::generate().to_bytes();
    let work_identity = iroh::SecretKey::generate().to_bytes();
    let publish = AccountBundle::Scoped(
        ScopedAccountBundle::from_parts(
            ServiceOrigin::parse(&personal.origin).unwrap(),
            AccountId::parse(ACCOUNT).unwrap(),
            ApiKeyScope::Publish,
            ApiToken::from_bytes([99; 32]),
            AccountRootKey::from_bytes(ROOT_KEY),
            Some(ConsumerIdentitySecret::from_bytes(personal_identity).authorized_identity()),
        )
        .unwrap(),
    )
    .encode();
    fs::write(machine.path("publish.bundle"), &publish).unwrap();
    let mut serving = machine
        .command(&[
            "--use-1password",
            "serve",
            "--workspace",
            "personal",
            "--host-label",
            "desktop",
            "--bundle-file",
            "publish.bundle",
        ])
        .stdout(fs::File::create(machine.path("serve.stdout")).unwrap())
        .stderr(fs::File::create(machine.path("serve.stderr")).unwrap())
        .spawn()
        .unwrap();
    timeout(DEADLINE, async {
        while personal.records.lock().await.as_ref().unwrap().is_empty() {
            assert!(
                serving.try_wait().unwrap().is_none(),
                "publisher failed: {}",
                fs::read_to_string(machine.path("serve.stderr")).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .unwrap();
    let identity_path =
        machine.path("home/.config/attached/workspaces/personal/admin-identity.key");
    let before = fs::read(&identity_path).unwrap();
    let publish_path =
        machine.path("home/.config/attached/workspaces/personal/sync-account.bundle");
    let publish_before = fs::read(&publish_path).unwrap();
    import_with_identity(&visitor, &personal.origin, personal_identity).await;
    let mut incoming = visitor
        .command(&["--use-1password", "ssh", "desktop", "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(fs::File::create(visitor.path("incoming.stderr")).unwrap())
        .spawn()
        .unwrap();
    let mut input = incoming.stdin.take().unwrap();
    let mut output = incoming.stdout.take().unwrap();
    round_trip(&mut input, &mut output, b"before-import\n").await;

    import_workspace(&machine, &work, "work", work_identity).await;
    // Supplement the running publisher's own workspace too, retaining its bundle.
    import_workspace(&machine, &personal, "personal", personal_identity).await;
    machine
        .run(&["workspace", "use", "work"])
        .await
        .assert_code(0);
    let rows = workspace_rows(&machine).await;
    let own = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "personal")
        .unwrap();
    assert_eq!(own["publish"], true);
    assert_eq!(own["consume"], true);
    assert_eq!(fs::read(&identity_path).unwrap(), before);
    assert_eq!(fs::read(&publish_path).unwrap(), publish_before);
    assert_private(
        &machine.path("home/.config/attached/workspaces/personal/sync-account.download.bundle"),
    );

    let work_host = Publisher::new(work_identity, 83).await;
    work_host.advertise(&work, "Office", 1, true, 300).await;
    let broker = start(&machine); // selected workspace is work, not personal
    wait_config(&machine, |text| text.contains(" attached-work--office\n")).await;
    let config = machine.path("home/.ssh/config");
    let ((), ()) = tokio::join!(
        round_trip(
            &mut input,
            &mut output,
            b"still-serving-after-import-and-default-switch\n"
        ),
        check_command(&config, "attached-work--office"),
    );
    drop(input);
    assert!(
        timeout(DEADLINE, incoming.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    assert!(serving.try_wait().unwrap().is_none());
    assert_eq!(fs::read(identity_path).unwrap(), before);
    stop(broker, rustix::process::Signal::TERM).await;
    stop(serving, rustix::process::Signal::INT).await;
    work_host.stop().await;
    personal.stop().await;
    work.stop().await;
}

#[tokio::test]
async fn named_account_creation_and_invalid_imports_never_overwrite_the_default() {
    let fixture = CliFixture::new();
    let default_service = Discovery::new().await;
    let original = import_with_identity(
        &fixture,
        &default_service.origin,
        iroh::SecretKey::generate().to_bytes(),
    )
    .await;
    let before = fs::read(fixture.path("home/.config/attached/sync-account.bundle")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let creation = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(
            request(&mut stream)
                .await
                .starts_with("POST /v1/accounts HTTP/1.1")
        );
        let response = attached_session_sync_protocol::api::CreateAccountResponse::new(
            AccountId::parse(ACCOUNT).unwrap(),
            ApiToken::from_bytes([101; 32]),
            ApiToken::from_bytes([102; 32]),
        )
        .unwrap();
        reply(
            &mut stream,
            "201 Created",
            &serde_json::to_vec(&response).unwrap(),
            "Cache-Control: no-store\r\n",
        )
        .await;
    });
    fixture
        .run(&[
            "--use-1password",
            "account",
            "create",
            "--workspace",
            "created",
            "--service",
            &origin,
        ])
        .await
        .assert_code(0);
    timeout(DEADLINE, creation).await.unwrap().unwrap();
    let rows = workspace_rows(&fixture).await;
    let created = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "created")
        .unwrap();
    assert_eq!(created["publish"], true);
    assert_eq!(created["consume"], true);
    let duplicate = fixture
        .run(&[
            "--use-1password",
            "account",
            "create",
            "--workspace",
            "created",
            "--service",
            &origin,
        ])
        .await;
    assert!(!duplicate.status.success());
    assert!(duplicate.stderr.contains("already configured"));
    fs::write(fixture.path("bad.bundle"), "not-a-bundle").unwrap();
    assert!(
        !fixture
            .run(&[
                "--use-1password",
                "account",
                "import",
                "--workspace",
                "bad",
                "--bundle-file",
                "bad.bundle"
            ])
            .await
            .status
            .success()
    );
    assert!(
        !fixture
            .run(&["workspace", "use", "bad"])
            .await
            .status
            .success()
    );
    assert!(
        !fixture
            .run(&["sessions", "list", "--workspace", "missing"])
            .await
            .status
            .success()
    );
    // Clap's global arguments can be supplied on an ancestor command. Runtime
    // selection also rejects conflicting selectors before touching discovery.
    let conflicting = fixture
        .run(&[
            "--workspace",
            "created",
            "sessions",
            "list",
            "--all-workspaces",
        ])
        .await;
    assert!(!conflicting.status.success());
    assert!(conflicting.stderr.contains("conflicts"));
    fixture
        .run(&[
            "--use-1password",
            "account",
            "export",
            "--type",
            "download",
            "--output",
            "default.bundle",
        ])
        .await
        .assert_code(0);
    assert_eq!(
        fs::read_to_string(fixture.path("default.bundle"))
            .unwrap()
            .trim(),
        original
    );
    assert_eq!(
        fs::read(fixture.path("home/.config/attached/sync-account.bundle")).unwrap(),
        before
    );
    default_service.stop().await;
}
