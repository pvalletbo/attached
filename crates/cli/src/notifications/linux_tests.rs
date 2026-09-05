use super::*;
use std::{os::unix::fs::PermissionsExt, process::Stdio};
use tokio::io::AsyncBufReadExt;
use zbus::{interface, object_server::SignalEmitter, zvariant::OwnedValue};

#[derive(Debug)]
struct Posted {
    replace: u32,
    body: String,
    actions: Vec<String>,
    expiry: i32,
}

struct MockNotifications(Arc<Mutex<Vec<Posted>>>);

#[interface(name = "org.freedesktop.Notifications")]
impl MockNotifications {
    fn get_capabilities(&self) -> Vec<String> {
        vec!["actions".into(), "body-markup".into()]
    }
    #[allow(clippy::too_many_arguments)]
    async fn notify(
        &self,
        _app_name: &str,
        replaces_id: u32,
        _app_icon: &str,
        _summary: &str,
        body: &str,
        actions: Vec<String>,
        _hints: std::collections::HashMap<String, OwnedValue>,
        expire_timeout: i32,
    ) -> u32 {
        self.0.lock().await.push(Posted {
            replace: replaces_id,
            body: body.into(),
            actions,
            expiry: expire_timeout,
        });
        42
    }
    fn close_notification(&self, _id: u32) {}
    #[zbus(signal)]
    async fn action_invoked(
        emitter: &SignalEmitter<'_>,
        id: u32,
        action_key: &str,
    ) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn notification_closed(
        emitter: &SignalEmitter<'_>,
        id: u32,
        reason: u32,
    ) -> zbus::Result<()>;
}

#[tokio::test]
#[ignore = "requires dbus-daemon; starts a private test bus, not the user's desktop"]
async fn private_dbus_notification_click_replacement_and_dismissal() {
    timeout(Duration::from_secs(15), async {
        let mut daemon = tokio::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut address = String::new();
        tokio::io::BufReader::new(daemon.stdout.take().unwrap())
            .read_line(&mut address)
            .await
            .unwrap();
        let posted = Arc::new(Mutex::new(Vec::new()));
        let service = zbus::connection::Builder::address(address.trim())
            .unwrap()
            .name("org.freedesktop.Notifications")
            .unwrap()
            .serve_at(
                "/org/freedesktop/Notifications",
                MockNotifications(posted.clone()),
            )
            .unwrap()
            .build()
            .await
            .unwrap();
        let connection = zbus::connection::Builder::address(address.trim())
            .unwrap()
            .build()
            .await
            .unwrap();
        let root = crate::test_support::canonical_tempdir();
        let terminal = root.path().join("terminal");
        let output = root.path().join("argv");
        std::fs::write(
            &terminal,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\n",
                output.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&terminal, std::fs::Permissions::from_mode(0o700)).unwrap();
        let launch = Launch {
            attached: "/tmp/attached with spaces".into(),
            state_dir: root.path().into(),
            herdr_bin: "/tmp/herdr".into(),
            terminal: Some(terminal),
            one_password: true,
        };
        let linux = Linux::from_connection(connection, launch).await.unwrap();
        let notice = Notice {
            title: "pi finished".into(),
            body: "<b>not markup</b>".into(),
        };
        linux.show("host/work", &notice).await.unwrap();
        linux.show("host/work", &notice).await.unwrap();
        {
            let posted = posted.lock().await;
            assert_eq!(posted.len(), 2);
            assert_eq!(posted[0].replace, 0);
            assert_eq!(posted[1].replace, 42);
            assert_eq!(posted[1].actions, ["default", "Attach"]);
            assert_eq!(
                posted[1].expiry, 0,
                "click must remain usable when user returns later"
            );
            assert_eq!(posted[1].body, "&lt;b&gt;not markup&lt;/b&gt;");
        }
        let interface = service
            .object_server()
            .interface::<_, MockNotifications>("/org/freedesktop/Notifications")
            .await
            .unwrap();
        let emitter = interface.signal_emitter();
        MockNotifications::action_invoked(emitter, 900, "default")
            .await
            .unwrap();
        MockNotifications::action_invoked(emitter, 42, "unrecognized")
            .await
            .unwrap();
        MockNotifications::notification_closed(emitter, 42, 2)
            .await
            .unwrap();
        // Wait for dismissal mapping to be removed before reusing the daemon's ID.
        while linux.pending.lock().await.id_for("host/work") != 0 {
            tokio::task::yield_now().await;
        }
        MockNotifications::action_invoked(emitter, 42, "default")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !output.exists(),
            "dismissed/unknown actions must not open terminals"
        );
        linux.show("host/work", &notice).await.unwrap();
        MockNotifications::action_invoked(emitter, 42, "default")
            .await
            .unwrap();
        for _ in 0..100 {
            if output.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let argv = std::fs::read_to_string(&output).unwrap();
        assert!(argv.starts_with("-e\n/tmp/attached with spaces\nattach\n"));
        assert!(argv.contains("--state-dir\n"));
        assert!(argv.contains("--use-1password\n"));
        assert!(argv.ends_with("--\nhost/work\n"));
        MockNotifications::action_invoked(emitter, 42, "default")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::fs::read_to_string(&output).unwrap(),
            argv,
            "repeated action must not launch twice"
        );
        drop(linux);
        daemon.kill().await.unwrap();
        daemon.wait().await.unwrap();
    })
    .await
    .unwrap();
}
