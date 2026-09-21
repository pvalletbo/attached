//! Real local Worker deployment; no API mocks or production fallback.
use std::{path::Path, time::Duration};

use anyhow::{Result, bail, ensure};
use tokio::time::Instant;

use crate::{
    docker::{Executor, Spec, checked},
    smoke::Smoke,
};

pub(crate) const LOCAL_SERVICE: &str = "http://127.0.0.1:8787";

pub(crate) fn local_config(mut config: toml::Table) -> Result<String> {
    // Keep the actual migrations, rate-limit bindings and compatibility flags.
    // Omit deployment metadata and startup compilation/reload of prebuilt WASM.
    for field in ["build", "routes", "env"] {
        config.remove(field);
    }
    config.insert("name".into(), "attached-e2e-local".into());
    Ok(serde_json::to_string(&config)?)
}

pub(crate) fn print_config(path: &Path) -> Result<()> {
    println!(
        "{}",
        local_config(toml::from_str(&std::fs::read_to_string(path)?)?)?
    );
    Ok(())
}

pub(crate) async fn health(service: &str) -> Result<()> {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .get(format!("{service}/healthz"))
        .send()
        .await?;
    ensure!(
        response.status() == 204,
        "unexpected backend health status: {}",
        response.status()
    );
    Ok(())
}

impl<E: Executor> Smoke<E> {
    pub fn local_backend(&self) -> bool {
        self.options.service.is_empty()
    }
    pub fn service(&self) -> &str {
        if self.local_backend() {
            LOCAL_SERVICE
        } else {
            &self.options.service
        }
    }
    fn backend_image(&self) -> String {
        format!("{}-backend", self.image)
    }

    pub async fn build_backend(&mut self) -> Result<()> {
        let image = self.backend_image();
        self.images.push(image.clone());
        checked(
            &self.executor,
            Spec::new(&[
                "build",
                "--force-rm",
                "--file",
                &self.root.join("e2e/Dockerfile.backend").to_string_lossy(),
                "--tag",
                &image,
                "--label",
                &self.label,
                &self.root.to_string_lossy(),
            ])
            .stream()
            .seconds(2400),
        )
        .await?;
        Ok(())
    }

    pub async fn start_backend(&mut self, client: &str, publisher: &str) -> Result<()> {
        let name = format!("{}-backend", self.prefix);
        self.containers.push(name.clone());
        checked(
            &self.executor,
            Spec::new(&[
                "create",
                "--name",
                &name,
                "--label",
                &self.label,
                "--network",
                &self.networks[0],
                "--network-alias",
                "backend",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "256",
                "--memory",
                "512m",
                "--init",
                "--tmpfs",
                "/home/node:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700",
                "--tmpfs",
                "/state:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700",
                "--tmpfs",
                "/app/worker/.wrangler:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,mode=1777",
                &self.backend_image(),
            ]),
        )
        .await?;
        checked(
            &self.executor,
            Spec::new(&[
                "network",
                "connect",
                "--alias",
                "backend",
                &self.networks[1],
                &name,
            ]),
        )
        .await?;
        checked(&self.executor, Spec::new(&["start", &name])).await?;
        for machine in [client, publisher] {
            // Preserve the CLI's HTTP-loopback policy without a CA override,
            // shared network namespace, or exposed host port.
            checked(
                &self.executor,
                Spec::new(&[
                    "exec",
                    "--detach",
                    machine,
                    "socat",
                    "TCP4-LISTEN:8787,bind=127.0.0.1,reuseaddr,fork",
                    "TCP:backend:8787",
                ]),
            )
            .await?;
            self.wait_for_backend(machine, Duration::from_secs(90))
                .await?;
        }
        println!("PASS: local Worker is healthy from both containers");
        Ok(())
    }

    async fn wait_for_backend(&self, machine: &str, duration: Duration) -> Result<()> {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            let result = self
                .executor
                .execute(
                    Spec::new(&[
                        "exec",
                        machine,
                        "attached-e2e",
                        "__machine",
                        "health",
                        "--service",
                        self.service(),
                    ])
                    .seconds(5),
                )
                .await?;
            if result.code == 0 {
                return Ok(());
            }
            let running = self
                .executor
                .execute(Spec::new(&[
                    "inspect",
                    "--format",
                    "{{.State.Running}}",
                    &format!("{}-backend", self.prefix),
                ]))
                .await?;
            ensure!(
                String::from_utf8_lossy(&running.stdout).trim() == "true",
                "local backend exited before becoming healthy"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("local backend not healthy from {machine} before the deadline")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        docker::tests::{Fake, reply},
        smoke::Options,
    };

    fn smoke() -> Smoke<Fake> {
        Smoke::new(
            Fake::default(),
            Options {
                service: String::new(),
                release: None,
                archive: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn config_preserves_real_bindings_without_startup_build_or_deployment_metadata() {
        let original = include_str!("../../session-sync-worker/wrangler.toml");
        let config: toml::Table = toml::from_str(original).unwrap();
        let before = serde_json::to_value(&config).unwrap();
        let after: serde_json::Value =
            serde_json::from_str(&local_config(config).unwrap()).unwrap();
        for field in [
            "main",
            "compatibility_date",
            "durable_objects",
            "ratelimits",
            "migrations",
        ] {
            assert_eq!(before[field], after[field]);
            assert!(!after[field].is_null());
        }
        for removed in ["build", "routes", "env"] {
            assert!(after.get(removed).is_none());
        }
        assert_eq!(after["name"], "attached-e2e-local");
    }

    #[tokio::test]
    async fn local_backend_is_default_with_fresh_tmpfs_and_two_networks() {
        let mut test = smoke();
        assert!(test.local_backend());
        assert_eq!(test.service(), LOCAL_SERVICE);
        test.networks = vec!["client-net".into(), "publisher-net".into()];
        test.start_backend("client", "publisher").await.unwrap();
        let calls = test.executor.calls.lock().unwrap();
        let args = &calls[0].args;
        assert!(args.contains(&"--read-only".into()));
        assert!(args.contains(&"/state:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700".into()));
        assert!(!args.contains(&"--publish".into()));
        assert!(!args.contains(&"--volume".into()));
        assert!(calls[1].args.contains(&"publisher-net".into()));
        for call in calls.iter().filter(|c| c.args.contains(&"socat".into())) {
            assert!(
                call.args
                    .contains(&"TCP4-LISTEN:8787,bind=127.0.0.1,reuseaddr,fork".into())
            );
        }
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.args.contains(&"health".into()))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn explicit_external_service_never_builds_or_starts_local_backend() {
        let mut test = smoke();
        test.options.service = "https://test.example".into();
        assert!(!test.local_backend());
        test.build().await.unwrap();
        test.exercise().await.unwrap();
        let calls = test.executor.calls.lock().unwrap();
        assert!(calls.iter().all(|s| {
            !s.args
                .iter()
                .any(|arg| arg.ends_with("Dockerfile.backend") || arg.ends_with("-backend"))
        }));
    }

    #[tokio::test]
    async fn backend_failure_prevents_account_creation_and_does_not_fall_back() {
        let mut test = smoke();
        // Six calls create the two machines; fail the backend's creation next.
        test.executor
            .replies
            .lock()
            .unwrap()
            .extend((0..6).map(|_| reply(0, "")).chain([reply(1, "")]));
        assert!(test.exercise().await.is_err());
        assert_eq!(test.service(), LOCAL_SERVICE);
        assert!(
            test.executor
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|s| !s.args.contains(&"__machine".into()))
        );
        test.cleanup().await.unwrap();
        assert!(
            test.executor
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|s| s.args[0] == "rm" && s.args.last().unwrap().ends_with("-backend"))
        );
    }

    #[tokio::test]
    async fn backend_build_failure_is_registered_for_cleanup() {
        let mut test = smoke();
        test.executor
            .replies
            .lock()
            .unwrap()
            .push_back(reply(1, ""));
        assert!(test.build_backend().await.is_err());
        test.cleanup().await.unwrap();
        assert_eq!(
            test.executor.calls.lock().unwrap().last().unwrap().args,
            ["image", "rm", &test.backend_image()]
        );
    }

    #[tokio::test]
    async fn backend_early_exit_and_deadline_fail_without_waiting_forever() {
        let test = smoke();
        test.executor
            .replies
            .lock()
            .unwrap()
            .extend([reply(1, ""), reply(0, "false\n")]);
        assert!(
            test.wait_for_backend("client", Duration::from_secs(90))
                .await
                .unwrap_err()
                .to_string()
                .contains("exited")
        );
        assert!(
            test.wait_for_backend("client", Duration::ZERO)
                .await
                .unwrap_err()
                .to_string()
                .contains("deadline")
        );
    }

    #[tokio::test]
    async fn health_requires_204_and_never_follows_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for status in ["204 No Content", "200 OK", "302 Found", "503 Unavailable"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let service = format!("http://{}", listener.local_addr().unwrap());
            let redirect = format!("{service}/unexpected");
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = [0; 4096];
                let count = stream.read(&mut bytes).await.unwrap();
                assert!(bytes[..count].starts_with(b"GET /healthz "));
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nLocation: {redirect}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                drop(stream);
                if status.starts_with("302") {
                    assert!(
                        tokio::time::timeout(Duration::from_millis(100), listener.accept())
                            .await
                            .is_err(),
                        "health probe followed a redirect"
                    );
                }
            });
            assert_eq!(health(&service).await.is_ok(), status.starts_with("204"));
            server.await.unwrap();
        }
    }
}
