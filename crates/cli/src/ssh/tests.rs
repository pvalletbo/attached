use super::*;
use std::{process::Stdio, sync::Arc};
use tokio::{io::AsyncWriteExt, net::TcpListener};

fn test_policy() -> state::Policy {
    state::Policy {
        consumer: [42; 32],
        uid: rustix::process::geteuid().as_raw(),
        username: "attached-test".into(),
        home: std::env::temp_dir(),
        shell: "/bin/sh".into(),
        generation: [1; 32],
        enabled: true,
    }
}

/// Test-only loopback listener to exercise an actual system OpenSSH client against
/// the same byte-stream server used on Iroh. Production has no TCP SSH listener.
async fn openssh(command: &str, input: &[u8]) -> std::process::Output {
    let temporary = crate::test_support::canonical_tempdir();
    let client = state::ephemeral_key().unwrap();
    let host = state::ephemeral_key().unwrap();
    crate::secure_state::prepare_private_dir(temporary.path()).unwrap();
    let dir = crate::secure_state::StateDir::open(temporary.path()).unwrap();
    dir.atomic_replace(
        "key",
        client
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    dir.atomic_replace(
        "known_hosts",
        format!(
            "attached-test {}\n",
            host.public_key().to_openssh().unwrap()
        )
        .as_bytes(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let token = CancellationToken::new();
    let cancel = token.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        exec::serve_stream(
            stream,
            host,
            client.public_key().clone(),
            test_policy(),
            cancel,
        )
        .await
    });
    let mut child = tokio::process::Command::new("ssh")
        .args([
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "HostKeyAlias=attached-test",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
        ])
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            temporary.path().join("known_hosts").display()
        ))
        .arg("-i")
        .arg(temporary.path().join("key"))
        .arg("-p")
        .arg(port.to_string())
        .arg("attached-test@127.0.0.1")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let bytes = input.to_vec();
    let writer = tokio::spawn(async move {
        stdin.write_all(&bytes).await.unwrap();
        drop(stdin);
    });
    let output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    writer.await.unwrap();
    token.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap();
    output
}

#[tokio::test]
async fn setup_frames_are_bounded_and_reject_unknown_fields() {
    let (mut write, mut read) = tokio::io::duplex(128);
    write.write_u32(8193).await.unwrap();
    assert!(read_frame::<_, Request>(&mut read).await.is_err());
    let bytes = br#"{"username":"user","host_key":"key","extra":true}"#;
    let (mut write, mut read) = tokio::io::duplex(128);
    write.write_u32(bytes.len() as u32).await.unwrap();
    write.write_all(bytes).await.unwrap();
    assert!(read_frame::<_, Response>(&mut read).await.is_err());
}

#[tokio::test]
async fn openssh_exec_stdout_stderr_and_exit_status() {
    let output = openssh("printf hello; printf error >&2; exit 7", b"").await;
    assert_eq!(output.stdout, b"hello");
    assert_eq!(output.stderr, b"error");
    assert_eq!(output.status.code(), Some(7));
}

#[tokio::test]
async fn openssh_script_stdin_and_eof_tail() {
    let output = openssh(
        "/bin/sh -s",
        b"cat >/dev/null <<EOF\ninput\nEOF\nprintf script-ok\n",
    )
    .await;
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(output.stdout, b"script-ok");
    let output = openssh(
        "cat; printf after-eof; printf error-after-eof >&2",
        b"input\0\xff",
    )
    .await;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"input\0\xffafter-eof");
    assert_eq!(output.stderr, b"error-after-eof");
}

#[tokio::test]
async fn openssh_large_binary_and_concurrent_connections() {
    let bytes: Arc<Vec<u8>> = Arc::new((0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect());
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..3 {
        let bytes = bytes.clone();
        tasks.spawn(async move {
            let output = openssh("cat", &bytes).await;
            assert!(output.status.success(), "{:?}", output.status);
            assert_eq!(output.stdout, *bytes);
            assert!(output.stderr.is_empty());
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
}
