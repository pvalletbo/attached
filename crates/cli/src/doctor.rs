//! Bounded, secret-free diagnostics. Discovery is never treated as a liveness check.
use std::{
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::Duration,
};

use anyhow::Result;
use attached_session_sync_protocol::account::ApiKeyScope;
use chrono::{DateTime, Utc};
use clap::Args;
use futures_util::{StreamExt, stream};
use serde::Serialize;
use tokio::time::timeout;

use crate::{
    client_ipc::ConnectionInfo,
    client_transport::ClientEndpoint,
    config::{Config, PasswordSource},
    local_encryption, ssh,
    sync::{self, state::AccountCredentials, state_catalog::SyncedHost},
};

#[derive(Args)]
pub(crate) struct Options {
    /// Probe one host label or stable endpoint ID; omit to probe all advertised SSH hosts.
    pub target: Option<String>,
    /// Print secret-free JSON (one JSON object per snapshot in watch mode).
    #[arg(long)]
    pub json: bool,
    /// Deadline in seconds for discovery, broker setup, and each individual live probe.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=120))]
    pub timeout: u64,
    #[arg(long, hide = true)]
    pub state_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Clone, Serialize)]
struct Check {
    name: &'static str,
    status: Level,
    message: String,
}

#[derive(Serialize)]
struct BrokerStatus {
    pid: u32,
    /// Includes the diagnostic command's own lease.
    leases: usize,
    connections: usize,
}

#[derive(Serialize)]
struct HostStatus {
    host: String,
    endpoint_id: String,
    attached_version: String,
    published_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    online: bool,
    connection: Option<ConnectionInfo>,
    failure: Option<ssh::ProbeFailure>,
    message: &'static str,
}

#[derive(Serialize)]
struct Report {
    schema_version: u8,
    checked_at: DateTime<Utc>,
    healthy: bool,
    discovery: Option<&'static str>,
    checks: Vec<Check>,
    broker: Option<BrokerStatus>,
    hosts: Vec<HostStatus>,
}

impl Report {
    fn new(checks: Vec<Check>) -> Self {
        Self {
            schema_version: 1,
            checked_at: Utc::now(),
            healthy: false,
            discovery: None,
            checks,
            broker: None,
            hosts: Vec::new(),
        }
    }

    fn check(&mut self, name: &'static str, status: Level, message: impl Into<String>) {
        self.checks.push(Check {
            name,
            status,
            message: message.into(),
        });
    }

    fn finish(&mut self) {
        self.healthy = self.checks.iter().all(|check| check.status != Level::Fail)
            && self.hosts.iter().all(|host| host.online);
    }
}

struct Context {
    path: PathBuf,
    account: AccountCredentials,
}

fn prepare(options: &Options, use_one_password: bool, doctor: bool) -> (Report, Option<Context>) {
    let mut report = Report::new(Vec::new());
    let configuration = match Config::load() {
        Ok(configuration) => configuration,
        Err(_) => {
            report.check("configuration", Level::Fail,
                "Cannot read configuration. Check ~/.config/attached/config.toml, its ownership, and permissions.");
            return (report, None);
        }
    };
    report.check("configuration", Level::Ok, "Configuration is valid.");
    if doctor {
        for tool in ["ssh", "ssh-keygen"] {
            let available = executable_available(tool);
            report.check(tool, if available { Level::Ok } else { Level::Warn },
                if available { format!("{tool} is available.") }
                else { format!("Install OpenSSH: {tool} is missing from PATH. Built-in live probes do not require it.") });
        }
    }
    // A diagnostic must fail actionably instead of waiting indefinitely for a password prompt.
    local_encryption::configure_noninteractive(true);
    if local_encryption::configure_use_one_password(
        use_one_password || configuration.password_source() == PasswordSource::OnePassword,
        configuration.one_password_item_tag(),
    )
    .is_err()
    {
        report.check(
            "credentials",
            Level::Fail,
            "Cannot initialize the password provider.",
        );
        return (report, None);
    }
    let path = options
        .state_dir
        .clone()
        .unwrap_or_else(|| configuration.config_directory().to_owned());
    match sync::state::load_account(&path, ApiKeyScope::Download) {
        Ok(account) => {
            report.check(
                "credentials",
                Level::Ok,
                "Download credentials are unlocked.",
            );
            (report, Some(Context { path, account }))
        }
        Err(_) => {
            report.check("credentials", Level::Fail,
                "Cannot unlock download credentials. Create/import a download account, then set ATTACHED_ENCRYPTION_PASSWORD or use an unlocked 1Password CLI. Run end-to-end checks on a consumer, not a publish-only host.");
            (report, None)
        }
    }
}

fn executable_available(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|path| {
            std::fs::metadata(path.join(name)).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
    })
}

/// An endpoint ID must not fall back to a mutable label; duplicate labels fail closed.
fn select_hosts(hosts: Vec<SyncedHost>, target: Option<&str>) -> Result<Vec<SyncedHost>> {
    let Some(target) = target else {
        return Ok(hosts);
    };
    let identity = target.parse::<iroh::EndpointId>().ok();
    let selected: Vec<_> = hosts
        .into_iter()
        .filter(|host| match identity {
            Some(identity) => host.target == identity.to_string(),
            None => host.host == target,
        })
        .collect();
    anyhow::ensure!(selected.len() == 1, "target missing or ambiguous");
    Ok(selected)
}

async fn snapshot(
    options: &Options,
    base: &Report,
    context: Option<&Context>,
    endpoint: &mut Option<ClientEndpoint>,
) -> Report {
    let mut report = Report::new(base.checks.clone());
    let Some(context) = context else {
        report.finish();
        return report;
    };
    let deadline = Duration::from_secs(options.timeout);
    let refreshed = timeout(deadline, sync::refresh::refresh_hosts(&context.path)).await;
    match refreshed {
        Ok(Ok(refreshed)) => {
            report.discovery = Some("refreshed");
            report.check(
                "discovery",
                Level::Ok,
                "Authenticated discovery refresh succeeded.",
            );
            if !refreshed.warnings.is_empty() {
                report.check("discovery_records", Level::Warn,
                    "Some discovery records were discarded, unavailable, or recovered. Check publishers and their clocks.");
            }
        }
        _ => {
            report.discovery = Some("cached");
            report.check("discovery", Level::Fail,
                "Discovery refresh failed or timed out. Check network access, service availability, and account credentials. Probing only unexpired cached advertisements.");
        }
    }
    let hosts = match sync::state_catalog::all_ssh_hosts(
        &context.path,
        &context.account,
        sync::utc_now_seconds(),
    ) {
        Ok(hosts) => hosts,
        Err(_) => {
            report.check(
                "catalog",
                Level::Fail,
                "Cannot read the encrypted host catalog; check local state and retry.",
            );
            report.finish();
            return report;
        }
    };
    let hosts = match select_hosts(hosts, options.target.as_deref()) {
        Ok(hosts) => hosts,
        Err(_) => {
            report.check("target", Level::Fail,
                "Host not found or label is ambiguous. Use sessions list and select a stable endpoint ID.");
            report.finish();
            return report;
        }
    };
    if hosts.is_empty() {
        report.check(
            "hosts",
            Level::Warn,
            "No unexpired SSH publishers are advertised. Run attached serve on a publisher.",
        );
    }
    if endpoint.is_none()
        && let Some(secret) = context.account.consumer_identity_secret()
        && let Ok(Ok(ready)) = timeout(
            deadline,
            ClientEndpoint::new(iroh::SecretKey::from_bytes(secret)),
        )
        .await
    {
        *endpoint = Some(ready);
    }
    if let Some(endpoint) = endpoint.as_ref()
        && let Ok(Ok((pid, leases, connections))) = timeout(deadline, endpoint.status()).await
    {
        report.broker = Some(BrokerStatus {
            pid,
            leases,
            connections,
        });
        report.check(
            "broker",
            Level::Ok,
            "Shared network broker is responsive (counts include this diagnostic lease).",
        );
    } else {
        report.check("broker", Level::Fail,
            "Network broker is unavailable or incompatible. Stop older Attached client commands and retry; inspect local runtime permissions.");
    }
    let endpoint = endpoint.as_ref();
    report.hosts = stream::iter(hosts)
        .map(|host| async move {
            let attachment = sync::state_catalog::host(
                &context.path,
                &context.account,
                &host.target,
                sync::utc_now_seconds(),
            )
            .ok();
            let result = match (endpoint, attachment.as_ref()) {
                (Some(endpoint), Some(attachment)) => {
                    timeout(deadline, ssh::probe(endpoint, &context.path, attachment))
                        .await
                        .unwrap_or(Err(ssh::ProbeFailure::TimedOut))
                }
                _ => Err(ssh::ProbeFailure::Unavailable),
            };
            let [major, minor, patch] = host.attached_version;
            let (connection, failure, message) = match result {
                Ok(info) => (
                    Some(info),
                    None,
                    "Live SSH authentication succeeded; no remote command was executed.",
                ),
                Err(failure) => (None, Some(failure), failure.advice()),
            };
            HostStatus {
                host: host.host,
                endpoint_id: host.target,
                attached_version: format!("{major}.{minor}.{patch}"),
                published_at: host.published_at,
                expires_at: attachment.as_ref().map(|host| host.expires_at),
                online: failure.is_none(),
                connection,
                failure,
                message,
            }
        })
        .buffered(8)
        .collect()
        .await;
    report.finish();
    report
}

fn render(report: &Report, json: bool, writer: &mut impl Write) -> Result<()> {
    if json {
        serde_json::to_writer(&mut *writer, report)?;
        writeln!(writer)?;
    } else {
        writeln!(
            writer,
            "Attached status — {} — {}",
            report.checked_at.to_rfc3339(),
            if report.healthy {
                "healthy"
            } else {
                "needs attention"
            }
        )?;
        for check in &report.checks {
            writeln!(
                writer,
                "[{:?}] {}: {}",
                check.status, check.name, check.message
            )?;
        }
        if let Some(broker) = &report.broker {
            writeln!(
                writer,
                "Broker PID {}: {} leases, {} connections",
                broker.pid, broker.leases, broker.connections
            )?;
        }
        for host in &report.hosts {
            let status = if host.online {
                "ONLINE".to_owned()
            } else {
                format!(
                    "{:?}",
                    host.failure.unwrap_or(ssh::ProbeFailure::Unavailable)
                )
            };
            let path = host
                .connection
                .as_ref()
                .map(|info| format!("{:?}", info.path))
                .unwrap_or_else(|| "—".into());
            let rtt = host
                .connection
                .as_ref()
                .and_then(|info| info.rtt_ms)
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "—".into());
            // Host labels are authenticated, but still untrusted terminal input.
            let label: String = host.host.chars().flat_map(char::escape_default).collect();
            writeln!(
                writer,
                "{label} ({})  {status}  path={path}  RTT={rtt}",
                host.endpoint_id
            )?;
            writeln!(
                writer,
                "  Last advertised: {} (not a liveness check). {}",
                host.published_at
                    .map(|time| time.to_rfc3339())
                    .unwrap_or_else(|| "unknown".into()),
                host.message
            )?;
        }
    }
    writer.flush()?;
    Ok(())
}

pub(crate) async fn run(
    options: &Options,
    use_one_password: bool,
    doctor: bool,
    watch: bool,
    interval: u64,
) -> Result<i32> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let shutdown = async {
        tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {}, _ = hangup.recv() => {} }
    };
    tokio::pin!(shutdown);
    let (base, context) = prepare(options, use_one_password, doctor);
    let mut endpoint = None;
    let result = async {
        loop {
            let report = tokio::select! {
                report = snapshot(options, &base, context.as_ref(), &mut endpoint) => report,
                _ = &mut shutdown => return Ok(0),
            };
            render(&report, options.json, &mut io::stdout().lock())?;
            if !watch {
                return Ok(i32::from(!report.healthy));
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {},
                _ = &mut shutdown => return Ok(0),
            }
        }
    }
    .await;
    if let Some(endpoint) = endpoint {
        endpoint.close().await;
    }
    result
}

#[cfg(test)]
#[path = "doctor_tests.rs"]
mod tests;
