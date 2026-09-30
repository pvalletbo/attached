//! CLI/broker contract tests. The scp shim delegates to a real OpenSSH command
//! so we can check argv, trust, exit codes and exporter reuse independently of
//! filesystem tests against the production embedded SFTP server.
use super::*;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

pub(super) fn scp_shim(fixture: &CliFixture) {
    fixture.script(
        "scp",
        r#"
printf '%s\n' "$@" > "$FIXTURE_ROOT/scp.args"
test "$1" = -s; shift
test "$1" = -F; config=$2; shift 2
if test "$1" = -r; then shift; fi
test "$1" = --; shift
case "$1" in attached-*:*) remote=$1;; *) remote=$2;; esac
alias=${remote%%:*}
exec ssh -F "$config" -T -- "$alias" 'printf expected'
"#,
    );
}

#[tokio::test]
async fn copy_cli_resolves_labels_and_ids_and_preserves_the_transfer_exit_code() {
    let fixture = CliFixture::new();
    scp_shim(&fixture);
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", http.local_addr().unwrap());
    let identity = iroh::SecretKey::generate().to_bytes();
    import_with_identity(&fixture, &origin, identity).await;
    let publisher = Endpoint::builder(presets::N0)
        .clear_ip_transports()
        .bind_addr_with_opts(
            (Ipv4Addr::LOCALHOST, 0),
            BindOpts::default().set_prefix_len(8),
        )
        .unwrap()
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .alpns(vec![SSH_ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let (index, record) = catalog(&EndpointTicket::new(publisher.addr()).to_string(), 1);
    let http_task = tokio::spawn(async move {
        respond(&mut checked_request(&http, false).await, &index, "").await;
        respond(
            &mut checked_request(&http, true).await,
            &record,
            "ETag: \"1\"\r\n",
        )
        .await;
    });
    let endpoint = publisher.clone();
    let ssh_task = tokio::spawn(async move {
        let key = russh::keys::PrivateKey::new(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[77; 32]).into(),
            "test",
        )
        .unwrap();
        for _ in 0..6 {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            assert_eq!(
                connection.remote_id(),
                iroh::SecretKey::from_bytes(&identity).public()
            );
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            let length = receive.read_u32().await.unwrap() as usize;
            assert!(length <= 8192);
            let mut bytes = vec![0; length];
            receive.read_exact(&mut bytes).await.unwrap();
            let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(request["capability"], serde_json::json!([46; 32].to_vec()));
            let public_key =
                russh::keys::PublicKey::from_openssh(request["public_key"].as_str().unwrap())
                    .unwrap();
            let response = serde_json::to_vec(&serde_json::json!({"username":"ssh-test", "host_key":key.public_key().to_openssh().unwrap()})).unwrap();
            send.write_u32(response.len() as u32).await.unwrap();
            send.write_all(&response).await.unwrap();
            if let Ok(session) = russh::server::run_stream(
                Arc::new(russh::server::Config {
                    keys: vec![key.clone()],
                    ..Default::default()
                }),
                tokio::io::join(receive, send),
                MockSsh { key: public_key },
            )
            .await
            {
                let _ = session.await;
            }
            connection.close(0u32.into(), b"test ended");
        }
    });
    let endpoint_id = publisher.id().to_string();
    for (source, destination, recursive) in [
        (
            "remote:/path with space".to_owned(),
            "-local".to_owned(),
            false,
        ),
        (
            "./local:name".to_owned(),
            "remote:destination".to_owned(),
            true,
        ),
        (format!("{endpoint_id}:/tmp/file"), ".".to_owned(), false),
    ] {
        let mut args = vec!["--use-1password", "cp"];
        if recursive {
            args.push("-r");
        }
        args.extend(["--", source.as_str(), destination.as_str()]);
        let output = fixture.run(&args).await;
        output.assert_code(7);
        assert_eq!(output.stdout, "expected");
        assert_eq!(output.stderr, "expected-error");
        let args = fs::read_to_string(fixture.path("scp.args")).unwrap();
        assert!(args.starts_with("-s\n-F\n"));
        assert!(args.contains(&format!("attached-{endpoint_id}:")));
        assert_eq!(args.contains("\n-r\n"), recursive);
        assert!(!fs::read_dir(fixture.path("tmp")).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("attached-ssh-")
        }));
    }
    timeout(DEADLINE, http_task).await.unwrap().unwrap();
    timeout(DEADLINE, ssh_task).await.unwrap().unwrap();
    publisher.close().await;
}

#[tokio::test]
async fn copy_rejects_unsupported_directions_without_unlocking_or_invoking_scp() {
    let fixture = CliFixture::new();
    fixture.script("op", "echo unexpected-unlock >&2; exit 90");
    fixture.script("scp", "touch \"$FIXTURE_ROOT/unexpected-scp\"; exit 90");
    for operands in [
        ["a", "b"],
        ["office:x", "laptop:y"],
        ["office:", "."],
        [":file", "."],
    ] {
        let output = fixture
            .run(&["--use-1password", "cp", operands[0], operands[1]])
            .await;
        output.assert_code(1);
        assert!(!output.stderr.contains("unexpected-unlock"), "{output:?}");
        assert!(!fixture.path("unexpected-scp").exists());
    }
    let help = fixture.run(&["cp", "--help"]).await;
    help.assert_code(0);
    assert!(help.stdout.contains("--recursive"));
    assert!(help.stdout.contains("HOST:PATH"));
}
