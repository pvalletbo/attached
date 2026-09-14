use std::{
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use attached_session_sync_protocol::account::ApiKeyScope;
use attached_tunnel_protocol::HerdrVersion;
use iroh::{Endpoint, endpoint::presets};
use iroh_tickets::endpoint::EndpointTicket;
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
};

use super::{ALPN, Request, Response, SETUP_TIMEOUT, read_frame, state, write_frame};
use crate::{
    proxy,
    secure_state::{self, StateDir},
    sync,
};

/// OpenSSH invokes this helper only against an owner-only, short-lived IPC socket.
/// It never loads credentials or emits anything except SSH bytes to stdout.
pub(crate) async fn local_proxy(socket: PathBuf) -> Result<i32> {
    let stream = tokio::time::timeout(SETUP_TIMEOUT, UnixStream::connect(socket)).await??;
    let (mut read, mut write) = stream.into_split();
    // This is a dedicated helper process. Tokio's stdin uses an uncancellable
    // blocking-pool read and can prevent runtime shutdown forever when the peer
    // closes while OpenSSH still holds stdin open. A bounded ordinary thread is
    // intentionally not joined; process exit disposes of an outstanding read.
    let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
    std::thread::Builder::new()
        .name("ssh-proxy-stdin".into())
        .spawn(move || {
            use std::io::Read;
            let stdin = std::io::stdin();
            let mut stdin = stdin.lock();
            loop {
                let mut bytes = vec![0; 16 * 1024];
                let message = match stdin.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(length) => {
                        bytes.truncate(length);
                        Ok(bytes)
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => Err(error),
                };
                let failed = message.is_err();
                if sender.blocking_send(message).is_err() || failed {
                    break;
                }
            }
        })?;
    use tokio::io::AsyncWriteExt;
    let upload = async {
        while let Some(bytes) = receiver.recv().await {
            write.write_all(&bytes?).await?;
        }
        write.shutdown().await
    };
    let download = async {
        let mut stdout = tokio::io::stdout();
        tokio::io::copy(&mut read, &mut stdout).await?;
        stdout.flush().await
    };
    tokio::pin!(upload, download);
    tokio::select! {
        result = &mut upload => { result?; download.await?; },
        result = &mut download => result?,
    }
    Ok(0)
}

async fn open(
    endpoint: &Endpoint,
    attachment: &sync::state_catalog::SyncedAttachment,
    public_key: &str,
) -> Result<(
    iroh::endpoint::Connection,
    iroh::endpoint::SendStream,
    iroh::endpoint::RecvStream,
    Response,
)> {
    ensure!(
        sync::utc_now_seconds() < attachment.expires_at,
        "publisher descriptor expired; restart `attached ssh`"
    );
    let ticket = EndpointTicket::from_str(&attachment.endpoint_ticket)?;
    ensure!(
        ticket.endpoint_addr().id.as_bytes() == &attachment.endpoint_identity,
        "publisher ticket identity mismatch"
    );
    tokio::time::timeout(SETUP_TIMEOUT, async {
        let connection = endpoint.connect(ticket.endpoint_addr().clone(), ALPN).await
            .context("publisher does not support SSH or is unavailable; update Attached and enable `attached ssh-access enable` on the publisher")?;
        let (mut send, mut receive) = connection.open_bi().await?;
        write_frame(&mut send, &Request { capability: attachment.attach_capability, public_key: public_key.to_owned() }).await?;
        let response: Response = read_frame(&mut receive).await.context("publisher rejected SSH access; run `attached ssh-access enable` there")?;
        // Parsing prevents setup metadata from injecting arbitrary known_hosts entries.
        russh::keys::PublicKey::from_openssh(&response.host_key)?;
        ensure!(!response.username.is_empty() && response.username.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)), "publisher supplied an unsupported OS username");
        Ok((connection, send, receive, response))
    }).await.context("SSH publisher setup timed out")?
}

pub(crate) async fn connect(
    path: &Path,
    target: &str,
    command: Vec<String>,
    expose_config: bool,
    no_cache: bool,
    trust_new_host_key: bool,
) -> Result<i32> {
    let account = sync::state::load_account(path, ApiKeyScope::Download)?;
    // No Herdr executable or exact-version compatibility check belongs on this carrier.
    if no_cache
        || sync::state_catalog::ssh_host(path, &account, target, sync::utc_now_seconds()).is_err()
    {
        let refreshed = sync::refresh::refresh_sessions(path, HerdrVersion::new(0, 0, 0)).await?;
        for warning in refreshed.warnings {
            eprintln!("Warning: {warning}");
        }
    }
    let attachment =
        sync::state_catalog::ssh_host(path, &account, target, sync::utc_now_seconds())?;
    let consumer = iroh::SecretKey::from_bytes(
        account
            .consumer_identity_secret()
            .context("download bundle has no consumer identity")?,
    );
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(consumer)
        .bind()
        .await?;
    let result = run(
        &endpoint,
        path,
        attachment,
        command,
        expose_config,
        trust_new_host_key,
    )
    .await;
    endpoint.close().await;
    result
}

async fn run(
    endpoint: &Endpoint,
    path: &Path,
    attachment: sync::state_catalog::SyncedAttachment,
    command: Vec<String>,
    expose_config: bool,
    trust_new_host_key: bool,
) -> Result<i32> {
    // A new key per invocation. It is registered only inside each authorized Iroh
    // connection, never persisted on the publisher, and dies with that connection.
    let key = state::ephemeral_key()?;
    let public_key = key.public_key().to_openssh()?;
    let (first_connection, _, _, response) = open(endpoint, &attachment, &public_key).await?;
    let peer = first_connection.remote_id();
    first_connection.close(0u32.into(), b"SSH metadata verified");
    let host_key = russh::keys::PublicKey::from_openssh(&response.host_key)?.to_openssh()?;
    state::pin_host(
        path,
        &peer,
        &response.username,
        &host_key,
        trust_new_host_key,
    )?;

    // Short paths avoid Unix socket pathname limits. No persistent plaintext keys.
    let temporary = tempfile::Builder::new().prefix("attached-ssh-").tempdir()?;
    let runtime = temporary.path().canonicalize()?;
    secure_state::prepare_private_dir(&runtime)?;
    let directory = StateDir::open(&runtime)?;
    let encoded = key.to_openssh(russh::keys::ssh_key::LineEnding::LF)?;
    directory.atomic_replace("identity", encoded.as_bytes())?;
    let alias = format!("attached-{peer}");
    directory.atomic_replace("known_hosts", format!("{alias} {host_key}\n").as_bytes())?;
    let socket = runtime.join("proxy");
    let listener = UnixListener::bind(&socket)?;
    let config = configuration(
        &alias,
        &response.username,
        &runtime,
        &std::env::current_exe()?,
    )?;
    directory.atomic_replace("config", config.as_bytes())?;
    let config_path = runtime.join("config");
    let cancellation = tokio_util::sync::CancellationToken::new();
    let _cancel = cancellation.clone().drop_guard();
    let broker = async {
        let limit = Arc::new(Semaphore::new(8));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => break,
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let Ok(permit) = limit.clone().try_acquire_owned() else { continue; };
                    let endpoint = endpoint.clone();
                    let attachment = attachment.clone();
                    let public_key = public_key.clone();
                    let expected_username = response.username.clone();
                    let expected_host_key = host_key.clone();
                    let token = cancellation.child_token();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let (connection, send, receive, metadata) = tokio::select! {
                            result = open(&endpoint, &attachment, &public_key) => result?,
                            _ = token.cancelled() => return Ok::<_, anyhow::Error>(()),
                        };
                        let result = async {
                            ensure!(metadata.username == expected_username && russh::keys::PublicKey::from_openssh(&metadata.host_key)?.to_openssh()? == expected_host_key, "publisher SSH identity changed");
                            let (read, write) = stream.into_split();
                            proxy::copy_until_cancelled(read, write, receive, send, token).await?;
                            Ok(())
                        }.await;
                        connection.close(0u32.into(), b"OpenSSH proxy ended");
                        result
                    });
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Ok(Err(error))) = completed { eprintln!("SSH proxy failed: {error:#}"); }
                }
            }
        }
        while tasks.join_next().await.is_some() {}
        Ok::<_, anyhow::Error>(())
    };
    tokio::pin!(broker);
    if expose_config {
        // Foreground export keeps the ephemeral key unlocked. Users can point ordinary
        // OpenSSH at this file; no changes to ~/.ssh/config or background key agents.
        println!("{}", config_path.display());
        eprintln!(
            "Ready: ssh -F '{}' {alias} [command]. Keep this process running; Ctrl-C removes the configuration and invalidates its keys.",
            config_path.display()
        );
        tokio::select! {
            result = &mut broker => result?,
            result = tokio::signal::ctrl_c() => { result?; cancellation.cancel(); broker.await?; }
        }
        return Ok(0);
    }
    let mut child = tokio::process::Command::new("ssh")
        .arg("-F")
        .arg(&config_path)
        .arg("-T")
        .arg(&alias)
        .args(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("system OpenSSH client `ssh` is required")?;
    let status = tokio::select! {
        result = child.wait() => result?,
        result = &mut broker => { result?; anyhow::bail!("SSH proxy ended unexpectedly"); }
    };
    cancellation.cancel();
    broker.await?;
    Ok(status.code().unwrap_or(255))
}

fn config_path(path: &Path) -> Result<String> {
    let value = path.to_str().context("OpenSSH paths must be UTF-8")?;
    ensure!(
        !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '%' | '$' | '`' | '\\')),
        "path cannot be represented safely in OpenSSH configuration"
    );
    Ok(format!("\"{value}\""))
}
fn shell_word(path: &Path) -> Result<String> {
    let value = path.to_str().context("proxy paths must be UTF-8")?;
    ensure!(
        !value.chars().any(|c| c.is_control() || c == '%'),
        "unsafe OpenSSH ProxyCommand path"
    );
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}
fn configuration(alias: &str, username: &str, runtime: &Path, executable: &Path) -> Result<String> {
    Ok(format!(
        "Host {alias}\n    HostName {alias}\n    User {username}\n    HostKeyAlias {alias}\n    ProxyCommand {} __ssh-local-proxy {}\n    IdentityFile {}\n    UserKnownHostsFile {}\n    GlobalKnownHostsFile /dev/null\n    StrictHostKeyChecking yes\n    CheckHostIP no\n    BatchMode yes\n    IdentitiesOnly yes\n    IdentityAgent none\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    PreferredAuthentications publickey\n    ForwardAgent no\n    ClearAllForwardings yes\n    RequestTTY no\n    ControlMaster no\n    ControlPath none\n    ConnectTimeout 20\n    ServerAliveInterval 30\n    ServerAliveCountMax 3\n",
        shell_word(executable)?,
        shell_word(&runtime.join("proxy"))?,
        config_path(&runtime.join("identity"))?,
        config_path(&runtime.join("known_hosts"))?
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_openssh_config_is_strict_and_handles_spaces_and_quotes() {
        let root = crate::test_support::canonical_tempdir();
        let runtime = root.path().join("directory with spaces");
        let executable = root.path().join("Attached's binary");
        let generated =
            configuration("attached-stable-id", "account", &runtime, &executable).unwrap();
        let file = root.path().join("config");
        std::fs::write(&file, generated).unwrap();
        let output = std::process::Command::new("ssh")
            .args(["-G", "-F"])
            .arg(file)
            .arg("attached-stable-id")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let config = String::from_utf8(output.stdout).unwrap();
        for expected in [
            "user account",
            "hostname attached-stable-id",
            "stricthostkeychecking true",
            "batchmode yes",
            "identityagent none",
            "forwardagent no",
            "requesttty false",
        ] {
            assert!(
                config.lines().any(|line| line == expected),
                "missing {expected}: {config}"
            );
        }
        assert!(config.contains("Attached'\\''s binary"));
    }

    #[test]
    fn config_generation_rejects_token_expansion_and_line_injection() {
        for path in [
            "/tmp/%h",
            "/tmp/path\nHost evil",
            "/tmp/${HOME}",
            "/tmp/quote\"name",
        ] {
            assert!(
                configuration(
                    "attached-id",
                    "account",
                    Path::new(path),
                    Path::new("/bin/attached")
                )
                .is_err()
            );
        }
        assert!(shell_word(Path::new("/bin/%h")).is_err());
        assert_eq!(
            shell_word(Path::new("/bin/attached's app")).unwrap(),
            "'/bin/attached'\\''s app'"
        );
    }
}
