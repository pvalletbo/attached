use std::{
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::{Child, Command},
};

pub const DEADLINE: Duration = Duration::from_secs(30);

pub struct CliFixture {
    pub root: tempfile::TempDir,
}

impl CliFixture {
    pub fn new() -> Self {
        // Short, canonical paths also work with macOS's sockaddr_un and /var symlink.
        let base = fs::canonicalize("/tmp").unwrap();
        let root = tempfile::Builder::new()
            .prefix("at-")
            .tempdir_in(base)
            .unwrap();
        for directory in ["home", "bin", "tmp", "runtime"] {
            fs::create_dir(root.path().join(directory)).unwrap();
        }
        let fixture = Self { root };
        fixture.script("op", r#"
case "$*" in
  'item list --categories=Password --tags=com.pvalletbo.attached/encryption-password-v1 --format=json')
    printf '%s\n' '[{"id":"testitem","title":"Attached encryption password","vault":{"id":"testvault"}}]';;
  'item get testitem --vault=testvault --fields=label=password --reveal')
    printf '%s\n' 'fixture-only-encryption-password';;
  *) echo 'unexpected op invocation' >&2; exit 90;;
esac
"#);
        fixture.script(
            "herdr",
            r#"
case "$*" in
  --version) printf 'herdr 3.2.1\n';;
  *) echo 'unexpected herdr invocation' >&2; exit 91;;
esac
"#,
        );
        fixture
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    pub fn script(&self, name: &str, body: &str) {
        let path = self.path(&format!("bin/{name}"));
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_attached"));
        command
            .env_clear()
            .env("HOME", self.path("home"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("bin").display()),
            )
            .env("TMPDIR", self.path("tmp"))
            .env("XDG_RUNTIME_DIR", self.path("runtime"))
            .env("FIXTURE_ROOT", self.root.path())
            .env("NO_COLOR", "1")
            .current_dir(self.root.path())
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .process_group(0)
            .args(args);
        command
    }

    pub fn spawn(&self, mut command: Command) -> RunningCli {
        // File-backed capture cannot deadlock on a full stdout/stderr pipe.
        let stdout = tempfile::NamedTempFile::new_in(self.root.path()).unwrap();
        let stderr = tempfile::NamedTempFile::new_in(self.root.path()).unwrap();
        command.stdout(File::create(stdout.path()).unwrap());
        command.stderr(File::create(stderr.path()).unwrap());
        let child = command.spawn().unwrap();
        let pid = rustix::process::Pid::from_raw(child.id().unwrap() as i32).unwrap();
        RunningCli {
            child,
            pid,
            stdout,
            stderr,
        }
    }

    pub async fn run(&self, args: &[&str]) -> CliOutput {
        self.spawn(self.command(args)).wait().await
    }
}

pub struct RunningCli {
    child: Child,
    pid: rustix::process::Pid,
    stdout: tempfile::NamedTempFile,
    stderr: tempfile::NamedTempFile,
}

impl RunningCli {
    pub async fn wait(mut self) -> CliOutput {
        let result = tokio::time::timeout(DEADLINE, self.child.wait()).await;
        let stdout = fs::read_to_string(self.stdout.path()).unwrap();
        let stderr = fs::read_to_string(self.stderr.path()).unwrap();
        let status = result
            .unwrap_or_else(|_| panic!("CLI timed out\nstdout: {stdout}\nstderr: {stderr}"))
            .unwrap();
        CliOutput {
            status,
            stdout,
            stderr,
        }
    }
}

impl Drop for RunningCli {
    fn drop(&mut self) {
        // Include Herdr/op descendants on assertion failure or timeout.
        let _ = rustix::process::kill_process_group(self.pid, rustix::process::Signal::KILL);
    }
}

#[derive(Debug)]
pub struct CliOutput {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl CliOutput {
    pub fn assert_code(&self, code: i32) {
        assert_eq!(self.status.code(), Some(code), "{self:?}");
    }
}

pub async fn request(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    loop {
        let byte = stream
            .read_u8()
            .await
            .expect("request ended before headers");
        bytes.push(byte);
        assert!(bytes.len() <= 8192, "oversized fixture request");
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes).unwrap();
        }
    }
}

pub async fn respond(stream: &mut TcpStream, body: &[u8], etag: &str) {
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{etag}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.shutdown().await.unwrap();
}

pub fn assert_private(path: &Path) {
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
