use std::{
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use attached_session_sync_protocol::account::ApiKeyScope;
use iroh::{Endpoint, endpoint::presets};
use iroh_tickets::endpoint::EndpointTicket;
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
};

use super::{
    ALPN, Request, Response, SETUP_TIMEOUT, descriptor::Descriptors, read_frame, state, write_frame,
};
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
    attachment: &sync::state_catalog::HostConnection,
    public_key: &str,
) -> Result<(
    iroh::endpoint::Connection,
    iroh::endpoint::SendStream,
    iroh::endpoint::RecvStream,
    Response,
)> {
    ensure!(
        sync::utc_now_seconds() < attachment.expires_at,
        "SSH publisher descriptor expired during connection setup"
    );
    let ticket = EndpointTicket::from_str(&attachment.endpoint_ticket)?;
    ensure!(
        ticket.endpoint_addr().id.as_bytes() == &attachment.endpoint_identity,
        "publisher ticket identity mismatch"
    );
    tokio::time::timeout(SETUP_TIMEOUT, async {
        let connection = endpoint.connect(ticket.endpoint_addr().clone(), ALPN).await
            .context("publisher does not support SSH or is unavailable; update Attached and run `attached serve` on the publisher")?;
        let (mut send, mut receive) = connection.open_bi().await?;
        write_frame(&mut send, &Request { capability: attachment.attach_capability, public_key: public_key.to_owned() }).await?;
        let response: Response = read_frame(&mut receive).await.context("publisher rejected SSH access; verify its publish bundle, or retry with `--no-cache` after a publisher restart")?;
        // Parsing prevents setup metadata from injecting arbitrary known_hosts entries.
        canonical_host_key(&response.host_key)?;
        ensure!(!response.username.is_empty() && response.username.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)), "publisher supplied an unsupported OS username");
        Ok((connection, send, receive, response))
    }).await.context("SSH publisher setup timed out")?
}

/// Renew only connection setup data, never replay SSH commands. No SSH bytes
/// reach the caller until setup succeeds and the caller checks the pinned host.
async fn open_current(
    endpoint: &Endpoint,
    descriptors: &Descriptors,
    account: &sync::state::AccountCredentials,
    public_key: &str,
) -> Result<(
    iroh::endpoint::Connection,
    iroh::endpoint::SendStream,
    iroh::endpoint::RecvStream,
    Response,
)> {
    tokio::time::timeout(SETUP_TIMEOUT, async {
        let attachment = descriptors.get(account, None).await?;
        match open(endpoint, &attachment, public_key).await {
            Ok(connection) => Ok(connection),
            Err(error) => {
                // A publisher restart may rotate its capability/address before
                // the old lease expires. Refresh once, sharing concurrent retries.
                let refreshed = descriptors.get(account, Some(&attachment)).await?;
                if refreshed == attachment {
                    return Err(error);
                }
                open(endpoint, &refreshed, public_key)
                    .await
                    .context("SSH setup failed after refreshing publisher discovery")
            }
        }
    })
    .await
    .context("SSH connection setup or discovery refresh timed out")?
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
    let attachment = sync::refresh::ssh_host(path, &account, target, no_cache).await?;
    let consumer = iroh::SecretKey::from_bytes(
        account
            .consumer_identity_secret()
            .context("download bundle has no consumer identity")?,
    );
    let ticket = EndpointTicket::from_str(&attachment.endpoint_ticket)?;
    let mut builder = Endpoint::builder(presets::N0).secret_key(consumer);
    if loopback_only(ticket.endpoint_addr()) {
        // A strictly local descriptor needs no public relay registration or
        // address lookup. Keep local operation (and disposable fixtures) offline.
        builder = builder
            .relay_mode(iroh::RelayMode::Disabled)
            .clear_address_lookup();
    }
    let endpoint = builder.bind().await?;
    let result = run(
        &endpoint,
        path,
        attachment,
        account,
        command,
        expose_config,
        trust_new_host_key,
    )
    .await;
    endpoint.close().await;
    result
}

pub(super) struct Broker {
    descriptors: Arc<Descriptors>,
    endpoint: Endpoint,
    account: Arc<sync::state::AccountCredentials>,
    _temporary: tempfile::TempDir,
    runtime: PathBuf,
    listener: UnixListener,
    public_key: String,
    response: Response,
    host_key: String,
    alias: String,
}

impl Broker {
    pub(super) async fn prepare(
        endpoint: &Endpoint,
        path: &Path,
        attachment: sync::state_catalog::HostConnection,
        account: Arc<sync::state::AccountCredentials>,
        trust_new_host_key: bool,
    ) -> Result<Self> {
        // A new key per invocation. It is registered only inside each authorized Iroh
        // connection, never persisted on the publisher, and dies with that connection.
        let key = state::ephemeral_key()?;
        let public_key = key.public_key().to_openssh()?;
        let descriptors = Arc::new(Descriptors::new(attachment));
        let (first_connection, _, _, response) =
            open_current(endpoint, &descriptors, &account, &public_key).await?;
        let peer = first_connection.remote_id();
        first_connection.close(0u32.into(), b"SSH metadata verified");
        let host_key = canonical_host_key(&response.host_key)?;
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
        Ok(Self {
            descriptors,
            endpoint: endpoint.clone(),
            account,
            _temporary: temporary,
            runtime,
            listener,
            public_key,
            response,
            host_key,
            alias,
        })
    }

    pub(super) fn observe(&self, connection: &sync::state_catalog::HostConnection) {
        self.descriptors.observe(connection);
    }

    pub(super) fn configuration(&self, aliases: &str) -> Result<String> {
        let config = configuration(
            &self.alias,
            &self.response.username,
            &self.runtime,
            &std::env::current_exe()?,
        )?;
        let target = aliases
            .split_whitespace()
            .next()
            .context("missing stable SSH alias")?;
        // Keep the per-broker HostKeyAlias/known_hosts pin, but expose the
        // workspace-qualified HostName to OpenSSH and discovery integrations.
        Ok(config
            .replacen(
                &format!("Host {}\n", self.alias),
                &format!("Host {aliases}\n"),
                1,
            )
            .replacen(
                &format!("HostName {}\n", self.alias),
                &format!("HostName {target}\n"),
                1,
            ))
    }

    /// Retirement stops admission, but does not interrupt established SSH streams.
    /// Global cancellation tears down both pending setup and active connections.
    pub(super) async fn serve(
        &self,
        cancellation: tokio_util::sync::CancellationToken,
        retired: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        let limit = Arc::new(Semaphore::new(8));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => break,
                _ = retired.cancelled() => break,
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    let Ok(permit) = limit.clone().try_acquire_owned() else { continue; };
                    let endpoint = self.endpoint.clone();
                    let descriptors = self.descriptors.clone();
                    let account = self.account.clone();
                    let public_key = self.public_key.clone();
                    let expected_username = self.response.username.clone();
                    let expected_host_key = self.host_key.clone();
                    let token = cancellation.child_token();
                    let retired = retired.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let (connection, send, receive, metadata) = tokio::select! {
                            biased;
                            _ = token.cancelled() => return Ok::<_, anyhow::Error>(()),
                            _ = retired.cancelled() => return Ok(()),
                            result = open_current(&endpoint, &descriptors, &account, &public_key) => result?,
                        };
                        let result = async {
                            ensure!(metadata.username == expected_username && canonical_host_key(&metadata.host_key)? == expected_host_key, "publisher SSH identity changed");
                            let (read, write) = stream.into_split();
                            if let Err(error) = proxy::copy_until_cancelled(read, write, receive, send, token).await {
                                // OpenSSH owns command/transport exit reporting. QUIC can
                                // close normally just after SSH's final exit/disconnect;
                                // do not contaminate successful command stderr with it.
                                tracing::debug!(%error, "SSH byte proxy ended");
                            }
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
        // Existing streams may keep this broker alive after its aliases retire.
        // Unlink the listening address now so stale OpenSSH configurations fail
        // promptly rather than queuing behind a listener no longer being polled.
        let _ = std::fs::remove_file(self.runtime.join("proxy"));
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

async fn run(
    endpoint: &Endpoint,
    path: &Path,
    attachment: sync::state_catalog::HostConnection,
    account: sync::state::AccountCredentials,
    command: Vec<String>,
    expose_config: bool,
    trust_new_host_key: bool,
) -> Result<i32> {
    let prepared = Broker::prepare(
        endpoint,
        path,
        attachment,
        Arc::new(account),
        trust_new_host_key,
    )
    .await?;
    let config_path = prepared.runtime.join("config");
    let alias = &prepared.alias;
    let cancellation = tokio_util::sync::CancellationToken::new();
    let _cancel = cancellation.clone().drop_guard();
    let broker = prepared.serve(
        cancellation.clone(),
        tokio_util::sync::CancellationToken::new(),
    );
    tokio::pin!(broker);
    if expose_config {
        // Foreground export keeps the ephemeral key unlocked. Users can point ordinary
        // OpenSSH at this file; no changes to ~/.ssh/config or background key agents.
        println!("{}", config_path.display());
        eprintln!(
            "Ready: ssh -F {} {alias} [command]. Keep this process running; Ctrl-C removes the configuration and invalidates its keys.",
            shell_word(&config_path)?
        );
        tokio::select! {
            result = &mut broker => result?,
            result = tokio::signal::ctrl_c() => { result?; cancellation.cancel(); broker.await?; }
        }
        return Ok(0);
    }
    let mut child = openssh_command(&config_path, alias, &command)
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

fn openssh_command(
    config: &Path,
    alias: &str,
    remote_command: &[String],
) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("ssh");
    // OpenSSH also parses options after the destination. End option parsing
    // before it so remote command arguments cannot override local SSH policy
    // or select a different local ProxyCommand.
    command
        .args(["-F"])
        .arg(config)
        .args(["-T", "--", alias])
        .args(remote_command);
    command
}

fn loopback_only(address: &iroh::EndpointAddr) -> bool {
    !address.addrs.is_empty() && address.addrs.iter().all(|address| {
        matches!(address, iroh::TransportAddr::Ip(socket) if socket.ip().is_loopback())
    })
}

fn canonical_host_key(encoded: &str) -> Result<String> {
    let parsed = russh::keys::PublicKey::from_openssh(encoded)?;
    ensure!(
        parsed.algorithm() == russh::keys::Algorithm::Ed25519,
        "unsupported publisher SSH host key algorithm"
    );
    // Comments are untrusted metadata, not part of key identity. Do not allow
    // them into known_hosts (including newlines accepted by a future parser).
    Ok(russh::keys::PublicKey::new(parsed.key_data().clone(), "").to_openssh()?)
}

pub(super) fn config_path(path: &Path) -> Result<String> {
    let value = path.to_str().context("OpenSSH paths must be UTF-8")?;
    ensure!(
        !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '%' | '$' | '`' | '\\' | '*' | '?' | '[')),
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
        "Host {alias}\n    HostName {alias}\n    CanonicalizeHostname no\n    User {username}\n    HostKeyAlias {alias}\n    ProxyCommand {} __ssh-local-proxy {}\n    IdentityFile {}\n    UserKnownHostsFile {}\n    GlobalKnownHostsFile /dev/null\n    StrictHostKeyChecking yes\n    CheckHostIP no\n    BatchMode yes\n    IdentitiesOnly yes\n    IdentityAgent none\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    PreferredAuthentications publickey\n    ForwardAgent no\n    ClearAllForwardings yes\n    RequestTTY no\n    ControlMaster no\n    ControlPath none\n    ConnectTimeout 20\n    ServerAliveInterval 30\n    ServerAliveCountMax 3\n",
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
    fn remote_command_arguments_cannot_override_local_openssh_options() {
        let root = crate::test_support::canonical_tempdir();
        let config = root.path().join("config");
        std::fs::write(
            &config,
            configuration(
                "attached-stable-id",
                "account",
                root.path(),
                Path::new("/bin/attached"),
            )
            .unwrap(),
        )
        .unwrap();
        let remote = vec![
            "-oIdentityAgent=/tmp/unwanted-agent".to_owned(),
            "-oStrictHostKeyChecking=no".to_owned(),
            "-oProxyCommand=unwanted-local-command".to_owned(),
            "argument with spaces".to_owned(),
        ];
        let command = openssh_command(&config, "attached-stable-id", &remote);
        let args = command.as_std().get_args().collect::<Vec<_>>();
        assert_eq!(args[3], "--");
        assert_eq!(args[4], "attached-stable-id");
        assert_eq!(
            args[5..],
            remote.iter().map(std::ffi::OsStr::new).collect::<Vec<_>>()
        );
        // Ask real OpenSSH to parse the production argv without connecting or
        // executing anything. These remote arguments must remain remote data.
        let output = std::process::Command::new(command.as_std().get_program())
            .arg("-G")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let effective = String::from_utf8(output.stdout).unwrap();
        assert!(effective.lines().any(|line| line == "identityagent none"));
        assert!(
            effective
                .lines()
                .any(|line| line == "stricthostkeychecking true")
        );
        assert!(!effective.contains("unwanted-local-command"));
        assert!(effective.contains("__ssh-local-proxy"));
    }

    #[test]
    fn only_strictly_loopback_descriptors_disable_public_relays() {
        let id = iroh::SecretKey::generate().public();
        let empty = iroh::EndpointAddr::new(id);
        assert!(!loopback_only(&empty));
        let local = empty
            .clone()
            .with_ip_addr("127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap());
        assert!(loopback_only(&local));
        let remote = local
            .clone()
            .with_ip_addr("192.0.2.1:1234".parse::<std::net::SocketAddr>().unwrap());
        assert!(!loopback_only(&remote));
        let relayed = local.with_relay_url("https://relay.example".parse().unwrap());
        assert!(!loopback_only(&relayed));
    }

    #[test]
    fn host_identity_discards_untrusted_key_comments() {
        let key = state::ephemeral_key().unwrap();
        let public = russh::keys::PublicKey::new(
            key.public_key().key_data().clone(),
            "untrusted publisher metadata",
        );
        let canonical = canonical_host_key(&public.to_openssh().unwrap()).unwrap();
        assert!(!canonical.contains("untrusted"));
        assert_eq!(canonical.split_whitespace().count(), 2);
        let injected = format!("{canonical} comment\nother-host key");
        if let Ok(clean) = canonical_host_key(&injected) {
            assert_eq!(clean, canonical);
        }
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
