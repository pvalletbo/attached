use std::{future::Future, path::PathBuf, time::Duration};

use anyhow::{Result, bail, ensure};
use clap::Args;
use tokio::time::Instant;

use crate::{
    docker::{Executor, Spec, checked},
    random_secret,
    release::{candidate_context, validate_version},
};

pub(crate) const LABEL: &str = "io.attached.e2e-run";
#[cfg(test)]
pub(crate) const PRODUCTION: &str = "https://herdr.attached.sh";

#[derive(Args)]
pub(crate) struct Options {
    /// External backend origin; omitted = deploy a disposable local Worker.
    #[arg(long, default_value = "")]
    pub service: String,
    /// Official stable version (e.g. 0.3.5); omitted = build the current checkout.
    #[arg(long, value_parser = validate_version)]
    pub release: Option<String>,
    /// Candidate Linux .tar.xz with adjacent .sha256; do not rebuild/download the CLI.
    #[arg(long, conflicts_with = "release")]
    pub archive: Option<PathBuf>,
}

pub(crate) struct Smoke<E> {
    pub executor: E,
    pub options: Options,
    pub root: PathBuf,
    pub prefix: String,
    pub image: String,
    pub label: String,
    pub containers: Vec<String>,
    pub networks: Vec<String>,
    pub images: Vec<String>,
}

impl<E: Executor> Smoke<E> {
    pub fn new(executor: E, options: Options) -> Result<Self> {
        let id = random_secret()?;
        Ok(Self {
            executor,
            options,
            root: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .canonicalize()?,
            prefix: format!("attached-e2e-{id}"),
            image: format!("attached-e2e:{id}"),
            label: format!("{LABEL}={id}"),
            containers: vec![],
            networks: vec![],
            images: vec![],
        })
    }

    pub async fn build(&mut self) -> Result<()> {
        // Reject bad candidates before creating any Docker resources.
        let candidate = if let Some(archive) = &self.options.archive {
            Some(candidate_context(archive, &self.image).await?)
        } else {
            None
        };
        self.images.push(self.image.clone());
        let dockerfile = self.root.join("e2e/Dockerfile");
        let mut spec = Spec::new(&[
            "build",
            "--force-rm",
            "--file",
            &dockerfile.to_string_lossy(),
            "--tag",
            &self.image,
            "--label",
            &self.label,
            "--target",
            if self.options.archive.is_some() {
                "runtime"
            } else if self.options.release.is_some() {
                "release"
            } else {
                "source"
            },
        ])
        .stream()
        .seconds(2400);
        if let Some(version) = &self.options.release {
            spec.args
                .extend(["--build-arg".into(), format!("ATTACHED_VERSION={version}")]);
        }
        spec.args.push(self.root.to_string_lossy().into_owned());
        checked(&self.executor, spec).await?;
        if let Some(context) = candidate {
            checked(
                &self.executor,
                Spec::new(&[
                    "build",
                    "--force-rm",
                    "--tag",
                    &self.image,
                    "--label",
                    &self.label,
                    "-",
                ])
                .input(context)
                .stream()
                .seconds(120),
            )
            .await?;
        }
        let version_container = format!("{}-version", self.prefix);
        self.containers.push(version_container.clone());
        let output = checked(
            &self.executor,
            Spec::new(&[
                "run",
                "--rm",
                "--name",
                &version_container,
                "--label",
                &self.label,
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                &self.image,
                "attached",
                "--version",
            ]),
        )
        .await?;
        let version = String::from_utf8(output.stdout)?;
        let version = version.trim();
        ensure!(
            version.starts_with("attached ")
                && self
                    .options
                    .release
                    .as_ref()
                    .is_none_or(|expected| version == format!("attached {expected}")),
            "unexpected binary version: {version:?}"
        );
        println!("Testing {version} against {}", self.service());
        if self.local_backend() {
            self.build_backend().await?;
        }
        Ok(())
    }

    pub async fn create_machine(&mut self, role: &str) -> Result<String> {
        let name = format!("{}-{role}", self.prefix);
        let network = format!("{name}-net");
        // Register unique names before creation in case the daemon accepts a
        // request but the Docker client times out or gets interrupted.
        self.networks.push(network.clone());
        checked(
            &self.executor,
            Spec::new(&["network", "create", "--label", &self.label, &network]),
        )
        .await?;
        self.containers.push(name.clone());
        checked(
            &self.executor,
            Spec::new(&[
                "create",
                "--name",
                &name,
                "--hostname",
                &format!("e2e-{role}"),
                "--label",
                &self.label,
                "--network",
                &network,
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
                "/home/attached:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,mode=1777",
                "--tmpfs",
                "/var/tmp:rw,nosuid,nodev,mode=1777",
                &self.image,
                "sleep",
                "600",
            ]),
        )
        .await?;
        checked(&self.executor, Spec::new(&["start", &name])).await?;
        Ok(name)
    }

    async fn machine(&self, container: &str, args: &[&str]) -> Result<()> {
        let mut spec = Spec::new(&["exec", container, "attached-e2e", "__machine"])
            .stream()
            .seconds(200);
        spec.args.extend(args.iter().map(|arg| (*arg).to_owned()));
        checked(&self.executor, spec).await?;
        Ok(())
    }

    async fn transfer_bundle(&self, client: &str, publisher: &str) -> Result<()> {
        let bundle = checked(
            &self.executor,
            Spec::new(&["exec", client, "cat", "/home/attached/publish.bundle"]),
        )
        .await?
        .stdout;
        // The portable credential crosses the host only in memory/stdin, never
        // a file, argument, environment variable, image layer, or diagnostic.
        checked(
            &self.executor,
            Spec::new(&[
                "exec",
                "--interactive",
                publisher,
                "sh",
                "-c",
                "umask 077; cat > /home/attached/publish.bundle",
            ])
            .input(bundle),
        )
        .await?;
        checked(
            &self.executor,
            Spec::new(&["exec", client, "rm", "/home/attached/publish.bundle"]),
        )
        .await?;
        Ok(())
    }

    async fn wait_for_publisher(&self, publisher: &str, duration: Duration) -> Result<()> {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            if self
                .executor
                .execute(Spec::new(&[
                    "exec",
                    publisher,
                    "test",
                    "-f",
                    "/home/attached/ready",
                ]))
                .await?
                .code
                == 0
            {
                return Ok(());
            }
            ensure!(
                self.executor
                    .execute(Spec::new(&[
                        "exec",
                        publisher,
                        "test",
                        "-f",
                        "/home/attached/failed"
                    ]))
                    .await?
                    .code
                    != 0,
                "publisher startup failed"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("publisher did not become ready before the deadline")
    }

    pub async fn exercise(&mut self) -> Result<()> {
        let client = self.create_machine("client").await?;
        let publisher = self.create_machine("publisher").await?;
        if self.local_backend() {
            self.start_backend(&client, &publisher).await?;
        }
        self.machine(&client, &["create", "--service", self.service()])
            .await?;
        self.machine(&client, &["export"]).await?;
        self.transfer_bundle(&client, &publisher).await?;
        let proof = random_secret()?;
        checked(&self.executor, Spec::new(&["exec", "--detach", &publisher, "sh", "-c",
            "attached-e2e __machine serve --proof \"$1\" > /home/attached/publisher.log 2>&1 || touch /home/attached/failed",
            "sh", &proof])).await?;
        self.wait_for_publisher(&publisher, Duration::from_secs(130))
            .await?;
        self.machine(&client, &["verify", "--proof", &proof])
            .await?;
        println!("PASS: account creation -> bundle publishing -> remote SSH");
        Ok(())
    }

    pub async fn diagnostics(&self) {
        for container in &self.containers {
            if container.ends_with("-publisher") {
                let _ = self
                    .executor
                    .execute(
                        Spec::new(&[
                            "exec",
                            container,
                            "tail",
                            "-c",
                            "8000",
                            "/home/attached/publisher.log",
                        ])
                        .stream(),
                    )
                    .await;
            } else if container.ends_with("-backend") {
                let _ = self
                    .executor
                    .execute(Spec::new(&["logs", "--tail", "50", container]).stream())
                    .await;
            }
        }
    }

    pub async fn cleanup(&self) -> Result<()> {
        let mut specs: Vec<_> = self
            .containers
            .iter()
            .rev()
            .map(|name| Spec::new(&["rm", "--force", name]))
            .collect();
        specs.extend(
            self.networks
                .iter()
                .rev()
                .map(|name| Spec::new(&["network", "rm", name])),
        );
        specs.extend(
            self.images
                .iter()
                .rev()
                .map(|name| Spec::new(&["image", "rm", name])),
        );
        let mut failures = Vec::new();
        for spec in specs {
            let name = spec.args.last().cloned().unwrap_or_default();
            let result = self.executor.execute(spec).await;
            let removed = match result {
                Ok(result) => {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    result.code == 0
                        || [
                            "No such container",
                            "No such image",
                            &format!("network {name} not found"),
                        ]
                        .iter()
                        .any(|message| stderr.contains(message))
                }
                Err(_) => false,
            };
            if !removed {
                failures.push(name);
            }
        }
        ensure!(
            failures.is_empty(),
            "could not clean up: {}",
            failures.join(", ")
        );
        Ok(())
    }

    pub async fn run_until(&mut self, cancellation: impl Future<Output = ()>) -> Result<()> {
        println!("Run label: {}", self.label);
        if self.local_backend() {
            println!("Local backend: all account/record state will be destroyed at exit.");
        } else {
            println!("External backend: creates one account which cannot be deleted by this test.");
        }
        let result = tokio::select! {
            result = async {
                checked(&self.executor, Spec::new(&["info"])).await?;
                self.build().await?;
                self.exercise().await
            } => result,
            () = cancellation => Err(anyhow::anyhow!("E2E interrupted")),
        };
        self.diagnostics().await;
        let cleanup = self.cleanup().await;
        if let Err(error) = &cleanup {
            eprintln!("Cleanup failed: {error:#}");
        }
        result?;
        cleanup
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::tests::{Fake, reply};

    fn smoke() -> Smoke<Fake> {
        Smoke::new(
            Fake::default(),
            Options {
                service: PRODUCTION.into(),
                release: None,
                archive: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn external_fixture_and_resources_are_unique() {
        let first = smoke();
        let second = smoke();
        assert_eq!(first.options.service, PRODUCTION);
        assert_ne!(first.prefix, second.prefix);
    }

    #[tokio::test]
    async fn containers_are_disposable_with_no_host_ports_or_state_mounts() {
        let mut test = smoke();
        test.create_machine("client").await.unwrap();
        test.create_machine("publisher").await.unwrap();
        assert_ne!(test.networks[0], test.networks[1]);
        for spec in test
            .executor
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.args[0] == "create")
        {
            for required in ["--read-only", "--cap-drop", "--tmpfs", "--init"] {
                assert!(spec.args.iter().any(|s| s == required));
            }
            for forbidden in [
                "--volume",
                "-v",
                "--mount",
                "--publish",
                "-p",
                "--privileged",
            ] {
                assert!(!spec.args.iter().any(|s| s == forbidden));
            }
            assert!(
                spec.args
                    .iter()
                    .any(|s| s == "/home/attached:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700")
            );
        }
    }

    #[tokio::test]
    async fn bundles_only_cross_memory_and_stdin() {
        let test = smoke();
        test.executor
            .replies
            .lock()
            .unwrap()
            .push_back(reply(0, "secret bundle"));
        test.transfer_bundle("client", "publisher").await.unwrap();
        let calls = test.executor.calls.lock().unwrap();
        assert!(!calls[0].stream);
        assert_eq!(calls[1].input.as_deref(), Some(b"secret bundle".as_slice()));
        assert!(
            calls
                .iter()
                .all(|s| !s.args.join(" ").contains("secret bundle"))
        );
        assert_eq!(
            calls[2].args,
            ["exec", "client", "rm", "/home/attached/publish.bundle"]
        );
    }

    #[tokio::test]
    async fn cleanup_attempts_all_resources_after_one_failure() {
        let mut test = smoke();
        test.containers = vec!["client".into(), "publisher".into()];
        test.networks = vec!["client-net".into(), "publisher-net".into()];
        test.images.push(test.image.clone());
        test.executor
            .replies
            .lock()
            .unwrap()
            .push_back(Err(anyhow::anyhow!("timeout")));
        assert!(
            test.cleanup()
                .await
                .unwrap_err()
                .to_string()
                .contains("publisher")
        );
        assert_eq!(test.executor.calls.lock().unwrap().len(), 5);
    }

    #[tokio::test]
    async fn partial_creation_cleanup_tolerates_absent_resources() {
        let mut test = smoke();
        test.containers.push("absent".into());
        test.executor
            .replies
            .lock()
            .unwrap()
            .push_back(Ok(crate::process::Reply {
                code: 1,
                stderr: b"No such container".to_vec(),
                ..Default::default()
            }));
        test.cleanup().await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_cleans_even_an_in_progress_build() {
        let mut test = smoke();
        test.executor.hang_build = true;
        let error = test
            .run_until(tokio::time::sleep(Duration::from_millis(20)))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("interrupted"));
        let calls = test.executor.calls.lock().unwrap();
        assert_eq!(calls.last().unwrap().args, ["image", "rm", &test.image]);
    }

    #[tokio::test]
    async fn failed_build_cleans_without_creating_accounts() {
        let mut test = smoke();
        test.executor
            .replies
            .lock()
            .unwrap()
            .extend([reply(0, ""), reply(1, "")]);
        assert!(test.run_until(std::future::pending()).await.is_err());
        let calls = test.executor.calls.lock().unwrap();
        assert_eq!(calls.last().unwrap().args[0], "image");
        assert!(calls.iter().all(|s| s.args[0] != "exec"));
    }

    #[tokio::test]
    async fn ssh_failure_cleans_containers_networks_and_image() {
        let mut test = smoke();
        test.executor.fail_ssh = true;
        assert!(
            test.run_until(std::future::pending())
                .await
                .unwrap_err()
                .to_string()
                .contains("SSH failure")
        );
        let calls = test.executor.calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|s| s.args[0] == "rm").count(), 3);
        assert_eq!(
            calls
                .iter()
                .filter(|s| s.args.starts_with(&["network".into(), "rm".into()]))
                .count(),
            2
        );
        assert_eq!(calls.last().unwrap().args, ["image", "rm", &test.image]);
    }

    #[tokio::test]
    async fn readiness_failure_and_deadline_are_observed() {
        let test = smoke();
        test.executor
            .replies
            .lock()
            .unwrap()
            .extend([reply(1, ""), reply(0, "")]);
        assert!(
            test.wait_for_publisher("publisher", Duration::from_secs(10))
                .await
                .unwrap_err()
                .to_string()
                .contains("startup failed")
        );
        assert!(
            test.wait_for_publisher("publisher", Duration::ZERO)
                .await
                .unwrap_err()
                .to_string()
                .contains("deadline")
        );
    }

    #[tokio::test]
    async fn exact_release_version_is_checked_before_account_creation() {
        let mut test = smoke();
        test.options.release = Some("0.3.5".into());
        test.executor
            .replies
            .lock()
            .unwrap()
            .extend([reply(0, ""), reply(0, "attached 0.3.4\n")]);
        assert!(
            test.build()
                .await
                .unwrap_err()
                .to_string()
                .contains("unexpected binary version")
        );
        assert_eq!(test.containers.len(), 1); // version probe is tracked, even on failure
        assert!(
            test.executor.calls.lock().unwrap()[0]
                .args
                .contains(&"ATTACHED_VERSION=0.3.5".to_owned())
        );
    }

    #[tokio::test]
    async fn backend_override_and_full_flow_create_account_exactly_once() {
        let mut test = smoke();
        test.options.service = "https://test.example".into();
        test.exercise().await.unwrap();
        let calls = test.executor.calls.lock().unwrap();
        let actions: Vec<_> = calls
            .iter()
            .filter(|s| s.args.iter().any(|a| a == "__machine"))
            .collect();
        assert_eq!(actions.iter().filter(|s| s.args[4] == "create").count(), 1);
        assert!(actions[0].args.contains(&"https://test.example".into()));
        assert_eq!(actions[1].args[4], "export");
        assert_eq!(actions[2].args[4], "verify");
    }
}
