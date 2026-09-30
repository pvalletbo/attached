//! Real system scp/sftp against the production embedded server, without an
//! OpenSSH server/helper, external discovery, Herdr, or persistent user files.
use super::*;
use std::{path::PathBuf, process::Stdio};
use tokio::{net::TcpListener, process::Command, task::JoinSet, time::timeout};

struct Server {
    root: tempfile::TempDir,
    config: PathBuf,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn new() -> Self {
        let root = crate::test_support::canonical_tempdir();
        let client = state::ephemeral_key().unwrap();
        let host = state::ephemeral_key().unwrap();
        crate::secure_state::prepare_private_dir(root.path()).unwrap();
        let directory = crate::secure_state::StateDir::open(root.path()).unwrap();
        directory
            .atomic_replace(
                "identity",
                client
                    .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
        directory
            .atomic_replace(
                "known_hosts",
                format!(
                    "attached-test {}\n",
                    host.public_key().to_openssh().unwrap()
                )
                .as_bytes(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = root.path().join("config");
        directory.atomic_replace("config", format!(
            "Host attached-test\n HostName 127.0.0.1\n Port {}\n User attached-test\n HostKeyAlias attached-test\n StrictHostKeyChecking yes\n UserKnownHostsFile {}\n GlobalKnownHostsFile /dev/null\n IdentityFile {}\n IdentitiesOnly yes\n IdentityAgent none\n BatchMode yes\n", listener.local_addr().unwrap().port(), root.path().join("known_hosts").display(), root.path().join("identity").display()
        ).as_bytes()).unwrap();
        let cancel = CancellationToken::new();
        let task = {
            let cancel = cancel.clone();
            let home = root.path().to_owned();
            tokio::spawn(async move {
                let mut sessions = JoinSet::new();
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        incoming = listener.accept() => {
                            let (stream, _) = incoming.unwrap();
                            let policy = state::Policy { consumer: [42; 32], uid: rustix::process::geteuid().as_raw(), username: "attached-test".into(), home: home.clone(), shell: "/bin/sh".into() };
                            sessions.spawn(exec::serve_stream(stream, host.clone(), client.public_key().clone(), policy, cancel.child_token()));
                        }
                        result = sessions.join_next(), if !sessions.is_empty() => { result.unwrap().unwrap().unwrap(); }
                    }
                }
                while let Some(result) = sessions.join_next().await {
                    result.unwrap().unwrap();
                }
            })
        };
        Self {
            root,
            config,
            cancel,
            task,
        }
    }

    async fn copy(&self, source: &str, destination: &str, recursive: bool) -> std::process::Output {
        let plan = copy::Copy::parse(source, destination, recursive).unwrap();
        let mut command = plan.command(&self.config, "attached-test");
        command
            .current_dir(self.root.path())
            .stdin(Stdio::null())
            .kill_on_drop(true);
        timeout(Duration::from_secs(20), command.output())
            .await
            .unwrap()
            .unwrap()
    }

    async fn stop(self) {
        self.cancel.cancel();
        timeout(Duration::from_secs(3), self.task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn openssh_scp_uploads_downloads_overwrites_and_handles_literal_filenames() {
    let server = Server::new().await;
    let payload = (0..2 * 1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let name = "binary *[?] \\'$(touch SHOULD-NOT-EXIST)";
    std::fs::create_dir(server.root.path().join("incoming")).unwrap();
    std::fs::create_dir(server.root.path().join("downloads")).unwrap();
    std::fs::write(server.root.path().join(name), &payload).unwrap();
    let upload = server.copy(name, "fixture:incoming/", false).await;
    assert!(upload.status.success(), "{upload:?}");
    assert_eq!(
        std::fs::read(server.root.path().join("incoming").join(name)).unwrap(),
        payload
    );
    let download = server
        .copy(&format!("fixture:incoming/{name}"), "downloads/", false)
        .await;
    assert!(download.status.success(), "{download:?}");
    assert_eq!(
        std::fs::read(server.root.path().join("downloads").join(name)).unwrap(),
        payload
    );
    assert!(!server.root.path().join("SHOULD-NOT-EXIST").exists());
    std::fs::write(server.root.path().join(name), b"replacement").unwrap();
    assert!(
        server
            .copy(name, "fixture:incoming/", false)
            .await
            .status
            .success()
    );
    assert_eq!(
        std::fs::read(server.root.path().join("incoming").join(name)).unwrap(),
        b"replacement"
    );
    assert!(
        server
            .copy("fixture:~/incoming", "downloads/", true)
            .await
            .status
            .success()
    );
    let missing = server.copy("fixture:missing", "downloads/", false).await;
    assert!(!missing.status.success());
    server.stop().await;
}

#[tokio::test]
async fn openssh_scp_recurses_and_rejects_directories_without_r() {
    let server = Server::new().await;
    let source = server.root.path().join("tree");
    std::fs::create_dir_all(source.join("nested/empty")).unwrap();
    std::fs::write(source.join("file"), b"top").unwrap();
    std::fs::write(source.join("nested/file"), b"nested\0\xff").unwrap();
    std::os::unix::fs::symlink("file", source.join("link")).unwrap();
    assert!(
        !server
            .copy("tree", "fixture:not-recursive", false)
            .await
            .status
            .success()
    );
    let upload = server.copy("tree", "fixture:uploaded", true).await;
    assert!(upload.status.success(), "{upload:?}");
    assert!(server.root.path().join("uploaded/nested/empty").is_dir());
    let download = server.copy("fixture:uploaded", "downloaded", true).await;
    assert!(download.status.success(), "{download:?}");
    assert_eq!(
        std::fs::read(server.root.path().join("downloaded/nested/file")).unwrap(),
        b"nested\0\xff"
    );
    assert_eq!(
        std::fs::read(server.root.path().join("downloaded/link")).unwrap(),
        b"top"
    );
    server.stop().await;
}

#[tokio::test]
async fn openssh_sftp_batch_supports_permissions_symlinks_rename_and_removal() {
    let server = Server::new().await;
    std::fs::write(server.root.path().join("local"), b"sftp\0\xff").unwrap();
    std::fs::write(server.root.path().join("batch"), b"mkdir directory\nput local directory/upload\nchmod 000 directory/upload\nchmod 600 directory/upload\nln -s upload directory/link\nget directory/link downloaded\nrename directory/upload directory/renamed\nrm directory/link\nrm directory/renamed\nrmdir directory\n").unwrap();
    let output = timeout(
        Duration::from_secs(20),
        Command::new("sftp")
            .args(["-q", "-b", "batch", "-F"])
            .arg(&server.config)
            .arg("attached-test")
            .current_dir(server.root.path())
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read(server.root.path().join("downloaded")).unwrap(),
        b"sftp\0\xff"
    );
    assert!(!server.root.path().join("directory").exists());
    server.stop().await;
}
