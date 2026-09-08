//! Freedesktop notification actions stay live for the watcher's lifetime, not
//! just for a short-lived `notify-send --wait` subprocess. One notice per session
//! is replaced in place; outstanding action mappings are bounded.
use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use futures_util::StreamExt;
use tokio::{sync::Mutex, task::JoinHandle, time::timeout};
use zbus::{Connection, zvariant::Value};

use super::{Launch, Notice, escape_markup, text};

const MAX_PENDING: usize = 128;

#[zbus::proxy(
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications",
    interface = "org.freedesktop.Notifications"
)]
trait Notifications {
    fn get_capabilities(&self) -> zbus::Result<Vec<String>>;
    #[allow(clippy::too_many_arguments)] // Standard freedesktop D-Bus signature.
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: std::collections::HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;
    fn close_notification(&self, id: u32) -> zbus::Result<()>;
    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: &str) -> zbus::Result<()>;
    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

#[derive(Default)]
struct Pending(BTreeMap<u32, String>);

impl Pending {
    fn id_for(&self, target: &str) -> u32 {
        self.0
            .iter()
            .find_map(|(id, value)| (value == target).then_some(*id))
            .unwrap_or(0)
    }
    fn insert(&mut self, id: u32, target: &str) {
        self.0.retain(|_, value| value != target);
        self.0.insert(id, target.to_owned());
    }
}

pub struct Linux {
    connection: Connection,
    pending: Arc<Mutex<Pending>>,
    actions: JoinHandle<()>,
}

impl Drop for Linux {
    fn drop(&mut self) {
        self.actions.abort();
    }
}

impl Linux {
    pub async fn connect(launch: Launch) -> Result<Self> {
        let connection = timeout(Duration::from_secs(5), Connection::session())
            .await
            .context("desktop D-Bus connection timed out")?
            .context("notifications require a graphical user's D-Bus session (or use --print)")?;
        Self::from_connection(connection, launch).await
    }

    async fn from_connection(connection: Connection, launch: Launch) -> Result<Self> {
        let proxy = NotificationsProxy::new(&connection).await?;
        let capabilities = timeout(Duration::from_secs(5), proxy.get_capabilities())
            .await
            .context("desktop notification service timed out")??;
        ensure!(
            capabilities.iter().any(|s| s == "actions"),
            "desktop notification daemon does not support clickable actions (use --print for diagnostics)"
        );
        // Install signal matches before posting the first notification.
        let mut actions = proxy.receive_action_invoked().await?;
        let mut closed = proxy.receive_notification_closed().await?;
        let pending = Arc::new(Mutex::new(Pending::default()));
        let mappings = pending.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    signal = actions.next() => {
                        let Some(signal) = signal else { break; };
                        let Ok(args) = signal.args() else { continue; };
                        if args.action_key != "default" { continue; }
                        let target = mappings.lock().await.0.remove(&args.id);
                        if let Some(target) = target
                            && let Err(error) = launch.open(&target).await
                        { tracing::warn!(%error, "notification click could not open terminal"); }
                    }
                    signal = closed.next() => {
                        let Some(signal) = signal else { break; };
                        if let Ok(args) = signal.args() { mappings.lock().await.0.remove(&args.id); }
                    }
                }
            }
            tracing::warn!("desktop action stream stopped; restart notifications watch");
        });
        Ok(Self {
            connection,
            pending,
            actions: task,
        })
    }

    pub async fn show(&self, target: &str, notice: &Notice) -> Result<()> {
        ensure!(
            !self.actions.is_finished(),
            "desktop action listener stopped; restart notifications watch"
        );
        timeout(Duration::from_secs(5), async {
            let proxy = NotificationsProxy::new(&self.connection).await?;
            // Keep the mapping lock through Notify so an immediate action cannot
            // arrive before its ID is associated with the verified session target.
            let mut pending = self.pending.lock().await;
            let replace = pending.id_for(target);
            if replace == 0
                && pending.0.len() >= MAX_PENDING
                && let Some((id, _)) = pending.0.pop_first()
            {
                let _ = proxy.close_notification(id).await;
            }
            let summary = format!("{} — {}", text(target, 160), notice.title);
            let body = escape_markup(&notice.body);
            let id = proxy
                .notify(
                    "Attached",
                    replace,
                    "utilities-terminal",
                    &summary,
                    &body,
                    &["default", "Attach"],
                    std::collections::HashMap::new(),
                    0,
                )
                .await?;
            pending.insert(id, target);
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("desktop notification service timed out")?
    }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod bus_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacements_and_actions_keep_one_mapping_per_session() {
        let mut pending = Pending::default();
        pending.insert(1, "host/work");
        pending.insert(2, "host/other");
        assert_eq!(pending.id_for("host/work"), 1);
        pending.insert(3, "host/work");
        assert_eq!(pending.0.len(), 2);
        assert!(!pending.0.contains_key(&1));
        assert_eq!(pending.0.remove(&3).as_deref(), Some("host/work"));
        assert_eq!(pending.id_for("host/work"), 0);
    }
}
