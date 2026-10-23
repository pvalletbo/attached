//! Independent real CLI processes must share one endpoint in either startup
//! order, survive one another's shutdown, and recover from a broker crash.
use super::ssh_export::{Discovery, Publisher, check_command, start, stop, wait_config};
use super::ssh_renewal::{round_trip, ssh};
use super::*;
use std::process::Stdio;
use support::RunningCli;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

fn runtime(identity: iroh::EndpointId) -> std::path::PathBuf {
    fs::canonicalize("/tmp")
        .unwrap()
        .join(format!(
            "attached-client-{}",
            rustix::process::geteuid().as_raw()
        ))
        .join(identity.to_string())
}

async fn broker_pid(identity: iroh::EndpointId) -> u32 {
    let mut socket = UnixStream::connect(runtime(identity).join("s"))
        .await
        .unwrap();
    let request = serde_json::to_vec(&serde_json::json!({
        "version": 1, "operation": {"op": "Lease", "identity": identity},
    }))
    .unwrap();
    socket.write_u32(request.len() as u32).await.unwrap();
    socket.write_all(&request).await.unwrap();
    let size = socket.read_u32().await.unwrap();
    assert!(size < 16384);
    let mut bytes = vec![0; size as usize];
    socket.read_exact(&mut bytes).await.unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    reply["pid"].as_u64().unwrap() as u32
}

async fn start_forward(fixture: &CliFixture, local: u16, remote: u16) -> RunningCli {
    let process = fixture.spawn(fixture.command(&[
        "--use-1password",
        "forward",
        "Office",
        "--local",
        &local.to_string(),
        "--remote",
        &remote.to_string(),
    ]));
    timeout(DEADLINE, async {
        while !process.stderr().contains("Forwarding ") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("forwarder not ready: {}", process.stderr()));
    process
}

async fn tcp_roundtrip(stream: &mut TcpStream, bytes: &[u8]) {
    timeout(DEADLINE, async {
        stream.write_all(bytes).await.unwrap();
        let mut response = vec![0; bytes.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, bytes);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn exporter_then_tcp_share_endpoint_and_recover_independently() {
    coexist(true, false).await;
}

#[tokio::test]
async fn tcp_then_exporter_share_endpoint_and_recover_independently() {
    coexist(false, false).await;
}

#[tokio::test]
async fn broker_resume_recovers_both_workflows_without_replacing_client_leases() {
    coexist(true, true).await;
}

async fn coexist(export_first: bool, suspend_broker: bool) {
    timeout(Duration::from_secs(60), async {
        let fixture = CliFixture::new();
        // Different HOME, TMPDIR, and credential directories must still converge
        // on the same broker when the consumer identity is the same.
        let tcp_fixture = CliFixture::new();
        let discovery = Discovery::new().await;
        let consumer = iroh::SecretKey::generate();
        import_with_identity(&fixture, &discovery.origin, consumer.to_bytes()).await;
        import_with_identity(&tcp_fixture, &discovery.origin, consumer.to_bytes()).await;
        let publisher = Publisher::new(consumer.to_bytes(), 88).await;
        publisher
            .advertise(&discovery, "Office", 1, true, 300)
            .await;
        let service = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = service.local_addr().unwrap().port();
        let cancel = CancellationToken::new();
        let echo = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let mut tasks = JoinSet::new();
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        accepted = service.accept() => {
                            let (stream, _) = accepted.unwrap();
                            tasks.spawn(async move {
                                let (mut read, mut write) = stream.into_split();
                                let _ = tokio::io::copy(&mut read, &mut write).await;
                            });
                        }
                        _ = tasks.join_next(), if !tasks.is_empty() => {},
                    }
                }
            })
        };
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let mut exporter = None;
        let mut forwarder = None;
        if export_first {
            exporter = Some(start(&fixture));
            wait_config(&fixture, |text| text.contains(" attached-office\n")).await;
        } else {
            forwarder = Some(start_forward(&tcp_fixture, address.port(), remote).await);
        }
        let first_pid = broker_pid(consumer.public()).await;
        if export_first {
            forwarder = Some(start_forward(&tcp_fixture, address.port(), remote).await);
        } else {
            exporter = Some(start(&fixture));
            wait_config(&fixture, |text| text.contains(" attached-office\n")).await;
        }
        assert_eq!(
            broker_pid(consumer.public()).await,
            first_pid,
            "second command started a competing endpoint"
        );
        use std::os::unix::fs::PermissionsExt;
        for entry in fs::read_dir(runtime(consumer.public())).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            assert!(
                ["s", "startup.lock", "owner.lock"]
                    .iter()
                    .any(|allowed| name == *allowed),
                "unexpected broker state file: {name:?}"
            );
            assert_eq!(
                entry.metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
            if name != "s" {
                assert_eq!(
                    entry.metadata().unwrap().len(),
                    0,
                    "broker persisted secret data"
                );
            }
        }
        let config = fixture.path("home/.ssh/config");
        check_command(&config, "attached-office").await;
        let mut tcp = TcpStream::connect(address).await.unwrap();
        tcp_roundtrip(&mut tcp, b"simultaneous\0\xff").await;

        if export_first {
            stop(exporter.take().unwrap(), rustix::process::Signal::TERM).await;
            tcp_roundtrip(&mut tcp, b"exporter-stopped\0\xff").await;
            assert_eq!(broker_pid(consumer.public()).await, first_pid);
            exporter = Some(start(&fixture));
            wait_config(&fixture, |text| text.contains(" attached-office\n")).await;
        } else {
            let mut active = ssh(&config, "attached-office", "cat")
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdin = active.stdin.take().unwrap();
            let mut stdout = active.stdout.take().unwrap();
            round_trip(&mut stdin, &mut stdout, b"before-forwarder-stop\n").await;
            let process = forwarder.take().unwrap();
            process.signal(rustix::process::Signal::TERM);
            process.wait().await.assert_code(0);
            round_trip(&mut stdin, &mut stdout, b"after-forwarder-stop\n").await;
            assert_eq!(broker_pid(consumer.public()).await, first_pid);
            forwarder = Some(start_forward(&tcp_fixture, address.port(), remote).await);
            drop(stdin);
            timeout(DEADLINE, active.wait()).await.unwrap().unwrap();
            tcp = TcpStream::connect(address).await.unwrap();
            tcp_roundtrip(&mut tcp, b"forwarder-restarted\0\xff").await;
        }

        // Kill or suspend only the broker. Both foreground commands stay alive;
        // new connections recover without replaying any application bytes.
        let pid = rustix::process::Pid::from_raw(first_pid as i32).unwrap();
        if suspend_broker {
            rustix::process::kill_process(pid, rustix::process::Signal::STOP).unwrap();
            tokio::time::sleep(Duration::from_secs(32)).await;
            rustix::process::kill_process(pid, rustix::process::Signal::CONT).unwrap();
        } else {
            rustix::process::kill_process(pid, rustix::process::Signal::KILL).unwrap();
        }
        let mut byte = [0; 1];
        let ended = timeout(Duration::from_secs(4), tcp.read(&mut byte))
            .await
            .unwrap();
        assert!(!matches!(ended, Ok(n) if n != 0));
        let ((), ()) = tokio::join!(check_command(&config, "attached-office"), async {
            let mut stream = TcpStream::connect(address).await.unwrap();
            tcp_roundtrip(&mut stream, b"after-broker-crash\0\xff").await;
        },);
        let recovered_pid = broker_pid(consumer.public()).await;
        if suspend_broker {
            assert_eq!(
                recovered_pid, first_pid,
                "resume replaced live client leases"
            );
        } else {
            assert_ne!(recovered_pid, first_pid);
        }
        let mut active = ssh(&config, "attached-office", "cat")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = active.stdin.take().unwrap();
        let mut stdout = active.stdout.take().unwrap();
        round_trip(&mut stdin, &mut stdout, b"recovered-ssh\n").await;
        let process = forwarder.take().unwrap();
        process.signal(rustix::process::Signal::HUP);
        process.wait().await.assert_code(0);
        round_trip(&mut stdin, &mut stdout, b"tcp-shutdown-preserves-ssh\n").await;
        check_command(&config, "attached-office").await;
        stop(exporter.take().unwrap(), rustix::process::Signal::TERM).await;
        timeout(DEADLINE, active.wait()).await.unwrap().unwrap();
        timeout(Duration::from_secs(8), async {
            while runtime(consumer.public()).join("s").exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("broker survived its last client");
        assert!(TcpStream::connect(address).await.is_err());
        cancel.cancel();
        echo.await.unwrap();
        publisher.stop().await;
        discovery.stop().await;
    })
    .await
    .expect("concurrent workflows timed out");
}
