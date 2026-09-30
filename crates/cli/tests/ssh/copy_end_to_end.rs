//! Opt-in network smoke test: actual attached serve/cp/export processes and
//! system OpenSSH, not a mocked publisher or scp executable. Only credential
//! lookup and the passive encrypted-record HTTP store are disposable fixtures.
use super::*;
use attached_session_sync_protocol::account::ApiKeyScope;
use std::{collections::BTreeMap, process::Stdio, sync::Arc};
use support::RunningCli;
use tokio::{io::AsyncReadExt, sync::Mutex};

const PUBLISH_TOKEN: [u8; 32] = [48; 32];

struct Record {
    revision: u64,
    bytes: Vec<u8>,
}

struct Store {
    origin: String,
    task: tokio::task::JoinHandle<()>,
}

impl Store {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let records = Arc::new(Mutex::new(BTreeMap::<RecordId, Record>::new()));
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let headers = request(&mut stream).await;
                let mut first = headers.lines().next().unwrap().split_whitespace();
                let method = first.next().unwrap();
                let path = first.next().unwrap();
                let header = |name: &str| {
                    headers
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(key, _)| key.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value.trim())
                };
                let prefix = format!("/v1/accounts/{ACCOUNT}/records");
                let expected_token = if method == "PUT" {
                    PUBLISH_TOKEN
                } else {
                    TOKEN
                };
                assert_eq!(
                    header("authorization"),
                    Some(
                        format!("Bearer {}", ApiToken::from_bytes(expected_token).encode())
                            .as_str()
                    )
                );
                let mut records = records.lock().await;
                let (status, body, etag) = if method == "GET" && path == prefix {
                    let index = LiveRecordIndex::new(
                        records
                            .iter()
                            .map(|(id, record)| LiveRecordIndexEntry {
                                record_id: *id,
                                revision: record.revision,
                            })
                            .collect(),
                    )
                    .unwrap();
                    ("200 OK", serde_json::to_vec(&index).unwrap(), String::new())
                } else {
                    let id =
                        RecordId::parse(path.strip_prefix(&format!("{prefix}/")).unwrap()).unwrap();
                    match method {
                        "PUT" => {
                            let length =
                                header("content-length").unwrap().parse::<usize>().unwrap();
                            assert!(length < 128 * 1024);
                            let mut body = vec![0; length];
                            stream.read_exact(&mut body).await.unwrap();
                            // Store only the actual publisher's encrypted envelope;
                            // do not synthesize its identity, ticket or capability.
                            assert!(Envelope::parse_json(&body).is_ok());
                            let revision = records.get(&id).map_or(1, |record| record.revision + 1);
                            records.insert(
                                id,
                                Record {
                                    revision,
                                    bytes: body,
                                },
                            );
                            ("201 Created", vec![], format!("ETag: \"{revision}\"\r\n"))
                        }
                        "GET" => match records.get(&id) {
                            Some(record) => (
                                "200 OK",
                                record.bytes.clone(),
                                format!("ETag: \"{}\"\r\n", record.revision),
                            ),
                            None => ("404 Not Found", vec![], String::new()),
                        },
                        other => panic!("unexpected request method {other}"),
                    }
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{etag}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self { origin, task }
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn wait_for(process: &RunningCli, predicate: impl Fn() -> bool) {
    timeout(DEADLINE, async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("process did not become ready: {}", process.stderr()));
}

async fn copy(client: &CliFixture, source: &str, destination: &str, recursive: bool) {
    let mut args = vec!["--use-1password", "cp"];
    if recursive {
        args.push("-r");
    }
    args.extend(["--", source, destination]);
    let output = client.run(&args).await;
    output.assert_code(0);
}

#[tokio::test]
#[ignore = "requires public Iroh relay connectivity; exercises real serve/cp processes"]
async fn real_publisher_copy_end_to_end() {
    let store = Store::new().await;
    let client = CliFixture::new();
    let publisher = CliFixture::new();
    assert!(!client.path("bin/scp").exists());
    let identity = iroh::SecretKey::generate().to_bytes();
    import_with_identity(&client, &store.origin, identity).await;
    let publish = AccountBundle::Scoped(
        ScopedAccountBundle::from_parts(
            ServiceOrigin::parse(&store.origin).unwrap(),
            AccountId::parse(ACCOUNT).unwrap(),
            ApiKeyScope::Publish,
            ApiToken::from_bytes(PUBLISH_TOKEN),
            AccountRootKey::from_bytes(ROOT_KEY),
            Some(ConsumerIdentitySecret::from_bytes(identity).authorized_identity()),
        )
        .unwrap(),
    )
    .encode();
    fs::write(publisher.path("publish.bundle"), publish).unwrap();
    let serving = publisher.spawn(publisher.command(&[
        "--use-1password",
        "serve",
        "--bundle-file",
        "publish.bundle",
        "--host-label",
        "omarchy",
    ]));
    wait_for(&serving, || {
        serving
            .stderr()
            .contains("Serving Attached SSH tunnels as `omarchy`.")
    })
    .await;

    // Use the real discovery command; it reads the actual encrypted publication.
    let discovered = client
        .run(&["--use-1password", "sessions", "list", "--json"])
        .await;
    discovered.assert_code(0);
    let hosts: serde_json::Value = serde_json::from_str(&discovered.stdout).unwrap();
    let endpoint_id = hosts[0]["endpoint_id"].as_str().unwrap();
    assert_eq!(hosts[0]["host"], "omarchy");
    assert_eq!(endpoint_id.len(), 64);

    let payload = (0..8 * 1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    fs::write(publisher.path("somefile"), &payload).unwrap();
    copy(
        &client,
        &format!("omarchy:{}", publisher.path("somefile").display()),
        ".",
        false,
    )
    .await;
    assert_eq!(fs::read(client.path("somefile")).unwrap(), payload);
    println!("PASS: attached cp omarchy:<absolute source> .; 8 MiB download matched byte-for-byte");

    let special = "upload *[?] \\'$(touch SHOULD-NOT-EXIST)";
    fs::write(client.path(special), &payload).unwrap();
    fs::create_dir(publisher.path("incoming")).unwrap();
    copy(
        &client,
        special,
        &format!("omarchy:{}/", publisher.path("incoming").display()),
        false,
    )
    .await;
    assert_eq!(
        fs::read(publisher.path(&format!("incoming/{special}"))).unwrap(),
        payload
    );
    fs::create_dir(client.path("downloads")).unwrap();
    copy(
        &client,
        &format!(
            "omarchy:{}/{}",
            publisher.path("incoming").display(),
            special
        ),
        "downloads/",
        false,
    )
    .await;
    assert_eq!(
        fs::read(client.path(&format!("downloads/{special}"))).unwrap(),
        payload
    );
    assert!(!client.path("SHOULD-NOT-EXIST").exists());
    assert!(!publisher.path("SHOULD-NOT-EXIST").exists());
    println!(
        "PASS: 8 MiB upload/download with literal glob, backslash, quote and shell-like characters"
    );
    fs::write(client.path(special), b"replacement").unwrap();
    copy(
        &client,
        special,
        &format!("omarchy:{}/", publisher.path("incoming").display()),
        false,
    )
    .await;
    assert_eq!(
        fs::read(publisher.path(&format!("incoming/{special}"))).unwrap(),
        b"replacement"
    );
    println!("PASS: overwriting a larger remote file truncates it correctly");

    fs::create_dir_all(client.path("tree/nested/empty")).unwrap();
    fs::write(client.path("tree/file"), b"top").unwrap();
    fs::write(client.path("tree/nested/file"), b"nested\0\xff").unwrap();
    copy(
        &client,
        "tree",
        &format!("omarchy:{}", publisher.path("remote-tree").display()),
        true,
    )
    .await;
    copy(
        &client,
        &format!("{endpoint_id}:{}", publisher.path("remote-tree").display()),
        "downloaded-tree",
        true,
    )
    .await;
    assert_eq!(
        fs::read(client.path("downloaded-tree/nested/file")).unwrap(),
        b"nested\0\xff"
    );
    assert!(client.path("downloaded-tree/nested/empty").is_dir());
    println!("PASS: recursive upload/download, empty directories and stable endpoint ID selection");

    // Repeat real transfers while another real SSH session uses the exporter.
    let exporter = client.spawn(client.command(&[
        "--use-1password",
        "export-ssh-config",
        "--refresh-interval",
        "1",
    ]));
    let config = client.path("home/.ssh/attached/config");
    wait_for(&exporter, || {
        fs::read_to_string(&config)
            .is_ok_and(|config| config.contains(&format!("Host attached-{endpoint_id} ")))
    })
    .await;
    let before = fs::read_to_string(&config).unwrap();
    let mut ssh = tokio::process::Command::new("ssh");
    ssh.arg("-F")
        .arg(&config)
        .args(["-T", "--", &format!("attached-{endpoint_id}"), "cat"])
        .stdin(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    let mut active = client.spawn(ssh);
    active.write_stdin(b"before-real-copy\n").await;
    wait_for(&active, || active.stdout() == b"before-real-copy\n").await;
    copy(
        &client,
        "somefile",
        &format!("omarchy:{}", publisher.path("exporter-upload").display()),
        false,
    )
    .await;
    assert_eq!(
        fs::read(publisher.path("exporter-upload")).unwrap(),
        payload
    );
    copy(
        &client,
        &format!("omarchy:{}", publisher.path("exporter-upload").display()),
        "exporter-download",
        false,
    )
    .await;
    assert_eq!(fs::read(client.path("exporter-download")).unwrap(), payload);
    assert_eq!(fs::read_to_string(&config).unwrap(), before);
    active.write_stdin(b"after-real-copy\n").await;
    wait_for(&active, || {
        active.stdout() == b"before-real-copy\nafter-real-copy\n"
    })
    .await;
    active.close_stdin();
    active.wait().await.assert_code(0);
    println!(
        "PASS: real exporter-backed copies leave its config/keys and concurrent SSH session intact"
    );

    let missing = client
        .run(&[
            "--use-1password",
            "cp",
            &format!("omarchy:{}", publisher.path("missing").display()),
            ".",
        ])
        .await;
    assert!(!missing.status.success());
    assert!(!client.path("missing").exists());
    let no_recursive = client
        .run(&[
            "--use-1password",
            "cp",
            &format!("omarchy:{}", publisher.path("remote-tree").display()),
            "no-recursion",
        ])
        .await;
    assert!(!no_recursive.status.success());
    println!("PASS: missing sources and directories without -r return nonzero status");

    exporter.signal(rustix::process::Signal::TERM);
    exporter.wait().await.assert_code(0);
    // serve's existing graceful shutdown is Ctrl-C; the exporter also handles
    // SIGTERM. Do not confuse serve's default SIGTERM exit with a copy failure.
    serving.signal(rustix::process::Signal::INT);
    serving.wait().await.assert_code(0);
    assert!(!fs::read_dir(client.path("tmp")).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("attached-ssh-")
    }));
    println!("PASS: exporter/publisher stop cleanly and temporary broker credentials are removed");
}
