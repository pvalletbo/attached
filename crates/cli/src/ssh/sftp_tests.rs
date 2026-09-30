use super::*;
use russh_sftp::{client::SftpSession, protocol::Init};
use std::time::Duration;

#[tokio::test]
async fn filesystem_supports_binary_offsets_attributes_directories_and_links() {
    let root = crate::test_support::canonical_tempdir();
    let mut filesystem = Filesystem::new(root.path().to_owned());
    let handle = filesystem
        .open(
            1,
            "binary".into(),
            OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE,
            FileAttributes::empty(),
        )
        .await
        .unwrap()
        .handle;
    filesystem
        .write(2, handle.clone(), 3, b"binary\0\xff".to_vec())
        .await
        .unwrap();
    assert_eq!(
        filesystem
            .read(3, handle.clone(), 0, u32::MAX)
            .await
            .unwrap()
            .data,
        b"\0\0\0binary\0\xff"
    );
    let metadata = filesystem.fstat(4, handle.clone()).await.unwrap().attrs;
    assert!(metadata.is_regular());
    assert_eq!(metadata.size, Some(11));
    filesystem
        .fsetstat(
            5,
            handle.clone(),
            FileAttributes {
                size: Some(4),
                permissions: Some(0o640),
                atime: Some(100),
                mtime: Some(200),
                ..FileAttributes::empty()
            },
        )
        .await
        .unwrap();
    let metadata = filesystem.fstat(6, handle.clone()).await.unwrap().attrs;
    assert_eq!(metadata.size, Some(4));
    assert_eq!(metadata.permissions.unwrap() & 0o777, 0o640);
    assert_eq!(metadata.mtime, Some(200));
    filesystem.close(7, handle.clone()).await.unwrap();
    assert!(filesystem.read(8, handle, 0, 1).await.is_err());
    filesystem
        .mkdir(9, "directory".into(), FileAttributes::empty())
        .await
        .unwrap();
    for index in 0..100 {
        fs::write(root.path().join(format!("directory/{index}")), b"x")
            .await
            .unwrap();
    }
    let handle = filesystem
        .opendir(10, "directory".into())
        .await
        .unwrap()
        .handle;
    let mut total = 0;
    loop {
        match filesystem.readdir(11, handle.clone()).await {
            Ok(batch) => {
                assert!(batch.files.len() <= DIRECTORY_BATCH);
                total += batch.files.len();
            }
            Err(StatusCode::Eof) => break,
            other => panic!("unexpected directory result: {other:?}"),
        }
    }
    assert_eq!(total, 100);
    filesystem.close(12, handle).await.unwrap();
    filesystem
        .symlink(13, "link".into(), "binary".into())
        .await
        .unwrap();
    assert!(
        filesystem
            .lstat(14, "link".into())
            .await
            .unwrap()
            .attrs
            .is_symlink()
    );
    assert!(
        filesystem
            .stat(15, "link".into())
            .await
            .unwrap()
            .attrs
            .is_regular()
    );
    assert_eq!(
        filesystem.readlink(16, "link".into()).await.unwrap().files[0].filename,
        "binary"
    );
    assert_eq!(
        filesystem.realpath(17, "link".into()).await.unwrap().files[0].filename,
        root.path().join("binary").to_str().unwrap()
    );
    assert_eq!(
        filesystem.stat(18, "missing".into()).await.unwrap_err(),
        StatusCode::NoSuchFile
    );
}

#[tokio::test]
async fn handles_and_reads_are_bounded_and_capacity_failure_has_no_side_effects() {
    let root = crate::test_support::canonical_tempdir();
    fs::write(root.path().join("source"), vec![42; MAX_READ as usize * 2])
        .await
        .unwrap();
    let mut filesystem = Filesystem::new(root.path().to_owned());
    for _ in 0..MAX_HANDLES {
        filesystem
            .open(1, "source".into(), OpenFlags::READ, FileAttributes::empty())
            .await
            .unwrap();
    }
    assert_eq!(
        filesystem
            .read(2, "1".into(), 0, u32::MAX)
            .await
            .unwrap()
            .data
            .len(),
        MAX_READ as usize
    );
    assert_eq!(
        filesystem
            .open(
                3,
                "must-not-create".into(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::empty()
            )
            .await
            .unwrap_err(),
        StatusCode::Failure
    );
    assert!(!root.path().join("must-not-create").exists());
    assert_eq!(
        filesystem.opendir(4, ".".into()).await.unwrap_err(),
        StatusCode::Failure
    );
    filesystem.close(5, "1".into()).await.unwrap();
    filesystem
        .open(
            6,
            "allowed".into(),
            OpenFlags::WRITE | OpenFlags::CREATE,
            FileAttributes::empty(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn paths_use_home_as_cwd_not_as_a_sandbox_and_special_files_do_not_block() {
    let root = crate::test_support::canonical_tempdir();
    fs::create_dir(root.path().join("home")).await.unwrap();
    fs::write(root.path().join("outside"), b"outside")
        .await
        .unwrap();
    let mut filesystem = Filesystem::new(root.path().join("home"));
    assert!(filesystem.stat(1, "../outside".into()).await.is_ok());
    assert!(
        filesystem
            .stat(2, root.path().join("outside").to_str().unwrap().into())
            .await
            .is_ok()
    );
    assert_eq!(
        filesystem.stat(3, "bad\0path".into()).await.unwrap_err(),
        StatusCode::BadMessage
    );
    // rustix's mknodat is unavailable on macOS; use the portable POSIX tool
    // only to construct the disposable fixture, never in the SFTP service.
    assert!(
        std::process::Command::new("mkfifo")
            .arg(root.path().join("home/fifo"))
            .status()
            .unwrap()
            .success()
    );
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        filesystem.open(4, "fifo".into(), OpenFlags::READ, FileAttributes::empty()),
    )
    .await
    .unwrap();
    assert_eq!(result.unwrap_err(), StatusCode::Failure);
    assert_eq!(
        filesystem
            .open(5, ".".into(), OpenFlags::READ, FileAttributes::empty())
            .await
            .unwrap_err(),
        StatusCode::Failure
    );
}

#[tokio::test]
async fn rename_does_not_clobber_and_extensions_validate_payloads() {
    let root = crate::test_support::canonical_tempdir();
    fs::write(root.path().join("one"), b"one").await.unwrap();
    fs::write(root.path().join("two"), b"two").await.unwrap();
    let mut filesystem = Filesystem::new(root.path().to_owned());
    assert!(
        filesystem
            .rename(1, "one".into(), "two".into())
            .await
            .is_err()
    );
    assert_eq!(fs::read(root.path().join("two")).await.unwrap(), b"two");
    let payload = |values: &[&str]| {
        let mut bytes = Vec::new();
        for value in values {
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        bytes
    };
    filesystem
        .extended(
            2,
            "posix-rename@openssh.com".into(),
            payload(&["one", "two"]),
        )
        .await
        .unwrap();
    assert_eq!(fs::read(root.path().join("two")).await.unwrap(), b"one");
    let expanded = filesystem
        .extended(3, "expand-path@openssh.com".into(), payload(&["~"]))
        .await
        .unwrap();
    assert!(
        matches!(expanded, Packet::Name(name) if name.files[0].filename == root.path().to_str().unwrap())
    );
    assert_eq!(
        filesystem
            .extended(6, "unknown-extension".into(), vec![])
            .await
            .unwrap_err(),
        StatusCode::OpUnsupported
    );
    assert_eq!(
        filesystem
            .extended(4, "fsync@openssh.com".into(), vec![0, 0, 0, 20])
            .await
            .unwrap_err(),
        StatusCode::BadMessage
    );
    assert_eq!(
        filesystem
            .extended(5, "fsync@openssh.com".into(), payload(&["1", "extra"]))
            .await
            .unwrap_err(),
        StatusCode::BadMessage
    );
}

#[tokio::test]
async fn embedded_server_interoperates_with_russh_sftp_client() {
    let root = crate::test_support::canonical_tempdir();
    let (client, server) = tokio::io::duplex(128 * 1024);
    let cancel = CancellationToken::new();
    let running = tokio::spawn(serve(server, root.path().to_owned(), cancel.clone()));
    let session = SftpSession::new(client).await.unwrap();
    let payload = (0..1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let mut file = session.create("binary").await.unwrap();
    file.write_all(&payload).await.unwrap();
    file.close().await.unwrap();
    assert_eq!(session.read("binary").await.unwrap(), payload);
    assert_eq!(
        session.canonicalize(".").await.unwrap(),
        root.path().to_str().unwrap()
    );
    session.create_dir("empty").await.unwrap();
    assert!(session.read_dir("empty").await.unwrap().next().is_none());
    session.remove_dir("empty").await.unwrap();
    session.remove_file("binary").await.unwrap();
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(2), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn malformed_packets_and_initialization_close_the_session() {
    let init = Bytes::try_from(Packet::Init(Init {
        version: 3,
        extensions: HashMap::new(),
    }))
    .unwrap();
    for bytes in [
        (MAX_PACKET + 1).to_be_bytes().to_vec(),
        0_u32.to_be_bytes().to_vec(),
        vec![0, 0],
        vec![0, 0, 0, 1, 255],
        vec![0, 0, 0, 8, 1],
        Bytes::try_from(Packet::error(1, StatusCode::Ok))
            .unwrap()
            .to_vec(),
        [init.to_vec(), init.to_vec()].concat(),
    ] {
        let root = crate::test_support::canonical_tempdir();
        let (mut client, server) = tokio::io::duplex(4096);
        let running = tokio::spawn(serve(
            server,
            root.path().to_owned(),
            CancellationToken::new(),
        ));
        client.write_all(&bytes).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), running)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }
}

#[tokio::test]
async fn cancellation_interrupts_idle_and_mid_packet_requests() {
    for partial in [false, true] {
        let root = crate::test_support::canonical_tempdir();
        let (mut client, server) = tokio::io::duplex(4096);
        let cancel = CancellationToken::new();
        let running = tokio::spawn(serve(server, root.path().to_owned(), cancel.clone()));
        if partial {
            client.write_u32(100).await.unwrap();
            client.write_u8(1).await.unwrap();
        }
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
    }
}
