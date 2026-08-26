use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use attached_tunnel_protocol::{
    CapabilitySecret, HerdrVersion, TUNNEL_ALPN, UPGRADE_ALPN, UpgradeResponse,
    read_upgrade_request, write_upgrade_response,
};
use iroh::{Endpoint, endpoint::presets};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, Semaphore, watch},
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    diagnostics::next_connection_id,
    herdr_version, identity,
    session::{self, Session},
    sync::{publisher, state},
    tunnel,
};

const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(5);
const PUBLISH_INTERVAL: Duration = Duration::from_secs(30);
const MAX_PENDING_CONNECTIONS: usize = 16;
const MAX_AUTHENTICATED_CONNECTIONS: usize = 16;

async fn run_registered_lifecycle<Lifecycle, LifecycleFuture>(
    registry_dir: &std::path::Path,
    endpoint_identity: [u8; 32],
    lifecycle: Lifecycle,
) -> Result<()>
where
    Lifecycle: FnOnce() -> LifecycleFuture,
    LifecycleFuture: std::future::Future<Output = Result<()>>,
{
    let active_endpoint = crate::endpoint_registry::register(registry_dir, endpoint_identity)
        .context("could not register the live local endpoint")?;
    let result = lifecycle().await;
    drop(active_endpoint);
    result
}

pub async fn serve(
    state_dir: PathBuf,
    herdr_bin: PathBuf,
    host_label: Option<String>,
) -> Result<()> {
    state::load_account(
        &state_dir,
        attached_session_sync_protocol::account::ApiKeyScope::Publish,
    )
    .context("`serve` requires a publish account bundle")?;

    let key = identity::load_or_create(&state_dir)?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(key)
        .alpns(vec![TUNNEL_ALPN.to_vec(), UPGRADE_ALPN.to_vec()])
        .bind()
        .await
        .context("failed to bind the Iroh endpoint")?;
    endpoint.online().await;

    let registry_dir = crate::endpoint_registry::default_dir()
        .context("could not locate the live local endpoint registry")?;
    let bootstrap_lock_dir = registry_dir.clone();
    run_registered_lifecycle(
        &registry_dir,
        *endpoint.addr().id.as_bytes(),
        || async move {
            let initial_version = herdr_version::query(&herdr_bin)
                .context("could not determine the local Herdr version")?;
            session::ensure_active(bootstrap_lock_dir, herdr_bin.clone())
                .await
                .context("could not ensure an active Herdr session before serving")?;
            let (version, published_versions) = watch::channel(initial_version);
            let capability = CapabilitySecret::generate();
            let host_label =
                host_label.unwrap_or_else(|| publisher::default_host_label(&endpoint.addr()));
            let publication = Arc::new(Mutex::new(
                publisher::Publisher::load(&state_dir, *endpoint.addr().id.as_bytes())
                    .context("could not initialize the session publisher")?,
            ));

            publish_sessions(
                &publication,
                &herdr_bin,
                &host_label,
                &endpoint,
                &capability,
                initial_version,
            )
            .await
            .context("could not publish the initial session catalog")?;

            eprintln!("Serving synchronized Herdr sessions as `{host_label}`.");
            let publisher = tokio::spawn(run_publisher(
                publication,
                herdr_bin.clone(),
                host_label,
                endpoint.clone(),
                capability.clone(),
                published_versions,
            ));
            let result = serve_endpoint(&endpoint, herdr_bin, capability, version).await;

            publisher.abort();
            let _ = publisher.await;
            endpoint.close().await;
            result
        },
    )
    .await
}

async fn run_publish_loop<Publish, PublishFuture>(
    mut version: watch::Receiver<HerdrVersion>,
    interval: Duration,
    mut publish: Publish,
) where
    Publish: FnMut(HerdrVersion) -> PublishFuture,
    PublishFuture: std::future::Future<Output = Result<()>>,
{
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            changed = version.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
        let published_version = *version.borrow_and_update();
        if let Err(error) = publish(published_version).await {
            warn!(error = %error, "session catalog publication failed");
        }
    }
}

async fn run_publisher(
    publication: Arc<Mutex<publisher::Publisher>>,
    herdr_bin: PathBuf,
    host_label: String,
    endpoint: Endpoint,
    capability: CapabilitySecret,
    version: watch::Receiver<HerdrVersion>,
) {
    run_publish_loop(version, PUBLISH_INTERVAL, move |published_version| {
        let publication = publication.clone();
        let herdr_bin = herdr_bin.clone();
        let host_label = host_label.clone();
        let endpoint = endpoint.clone();
        let capability = capability.clone();
        async move {
            publish_sessions(
                &publication,
                &herdr_bin,
                &host_label,
                &endpoint,
                &capability,
                published_version,
            )
            .await
        }
    })
    .await;
}

async fn publish_sessions(
    publication: &Arc<Mutex<publisher::Publisher>>,
    herdr_bin: &std::path::Path,
    host_label: &str,
    endpoint: &Endpoint,
    capability: &CapabilitySecret,
    version: HerdrVersion,
) -> Result<()> {
    let sessions = session::discover_active(herdr_bin.to_owned()).await?;
    let names = sessions
        .into_iter()
        .map(|session| session.name().to_owned())
        .collect();
    match publication
        .lock()
        .await
        .publish_snapshot(host_label, endpoint.addr(), capability, version, names)
        .await?
    {
        publisher::PublishOutcome::Unchanged => {}
        publisher::PublishOutcome::Published { revision } => {
            info!(revision, "published encrypted session catalog");
        }
    }
    Ok(())
}

async fn resolve_session(herdr_bin: PathBuf, name: String) -> Result<Session> {
    let sessions = session::discover_active(herdr_bin).await?;
    let session = sessions
        .into_iter()
        .find(|session| session.name() == name)
        .with_context(|| format!("Herdr session `{name}` is not running"))?;
    session.validate()?;
    Ok(session)
}

fn perform_upgrade(
    herdr_bin: &std::path::Path,
    requested_version: HerdrVersion,
    version: &watch::Sender<HerdrVersion>,
    updater: Arc<Semaphore>,
) -> UpgradeResponse {
    let current = *version.borrow();
    if (
        requested_version.major(),
        requested_version.minor(),
        requested_version.patch(),
    ) <= (current.major(), current.minor(), current.patch())
    {
        return UpgradeResponse::Failed(
            "remote Herdr is already at or newer than the requested version".to_owned(),
        );
    }
    let Ok(_permit) = updater.try_acquire_owned() else {
        return UpgradeResponse::Busy;
    };
    match herdr_version::update(herdr_bin) {
        Ok(installed) => {
            // The executable changed even when its channel did not produce the requested
            // release, so refresh every consumer before deciding whether attach may proceed.
            version.send_replace(installed);
            if installed == requested_version {
                UpgradeResponse::Updated(installed)
            } else {
                UpgradeResponse::Failed(
                    "remote Herdr update did not install the required version".to_owned(),
                )
            }
        }
        Err(_error) => {
            // An updater can fail after replacing the executable. Refresh opportunistically;
            // failure to query never permits attachment. Child output and the error chain stay
            // process-local and are deliberately not logged or placed on the wire.
            if let Ok(installed) = herdr_version::query(herdr_bin) {
                version.send_replace(installed);
            }
            UpgradeResponse::Failed("remote Herdr update failed".to_owned())
        }
    }
}

async fn process_upgrade_stream<R, W, Resolve, ResolveFuture, Update>(
    receive: &mut R,
    send: &mut W,
    capability: &CapabilitySecret,
    framing_timeout: Duration,
    resolve: Resolve,
    update: Update,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    Resolve: FnOnce(String) -> ResolveFuture,
    ResolveFuture: std::future::Future<Output = Result<()>>,
    Update: FnOnce(HerdrVersion) -> UpgradeResponse,
{
    let request = timeout(framing_timeout, read_upgrade_request(receive, capability))
        .await
        .context("upgrade request frame timed out")??;
    // Authentication is complete before session resolution or update execution.
    resolve(request.session).await?;
    timeout(
        framing_timeout,
        write_upgrade_response(send, update(request.requested_version)),
    )
    .await
    .context("upgrade response frame timed out")?
}

async fn serve_upgrade_connection(
    connection: iroh::endpoint::Connection,
    capability: &CapabilitySecret,
    herdr_bin: PathBuf,
    version: watch::Sender<HerdrVersion>,
    updater: Arc<Semaphore>,
) -> Result<()> {
    let (mut send, mut receive) = timeout(AUTHENTICATION_TIMEOUT, connection.accept_bi())
        .await
        .context("upgrade request handshake timed out")??;
    process_upgrade_stream(
        &mut receive,
        &mut send,
        capability,
        AUTHENTICATION_TIMEOUT,
        |session| async {
            resolve_session(herdr_bin.clone(), session)
                .await
                .map(|_| ())
        },
        |requested_version| {
            tokio::task::block_in_place(|| {
                perform_upgrade(&herdr_bin, requested_version, &version, updater)
            })
        },
    )
    .await
}

async fn shutdown_connections(connections: &mut JoinSet<Result<()>>) {
    // Admission has stopped and tunnel cancellation has been signalled. Drain every accepted
    // connection so fixed updater work remains owned until bounded_process completes or kills
    // and reaps its process group at the hard deadline.
    while connections.join_next().await.is_some() {}
}

async fn serve_endpoint(
    endpoint: &Endpoint,
    herdr_bin: PathBuf,
    capability: CapabilitySecret,
    version: watch::Sender<HerdrVersion>,
) -> Result<()> {
    let pending = Arc::new(Semaphore::new(MAX_PENDING_CONNECTIONS));
    let authenticated = Arc::new(Semaphore::new(MAX_AUTHENTICATED_CONNECTIONS));
    let updater = Arc::new(Semaphore::new(1));
    let cancellation = CancellationToken::new();
    let mut connections = JoinSet::new();
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    let result = loop {
        tokio::select! {
            result = &mut shutdown => break result.context("failed to listen for Ctrl-C"),
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break Err(anyhow!("Iroh endpoint stopped accepting connections"));
                };
                let Ok(pending_permit) = pending.clone().try_acquire_owned() else {
                    drop(incoming);
                    continue;
                };
                let connection_id = next_connection_id();
                let herdr_bin = herdr_bin.clone();
                let capability = capability.clone();
                let authenticated = authenticated.clone();
                let updater = updater.clone();
                let version = version.clone();
                let child_cancellation = cancellation.child_token();
                connections.spawn(async move {
                    let result = async {
                        let connection = timeout(AUTHENTICATION_TIMEOUT, incoming)
                            .await
                            .context("Iroh connection handshake timed out")??;
                        if connection.alpn() == UPGRADE_ALPN {
                            return serve_upgrade_connection(
                                connection,
                                &capability,
                                herdr_bin,
                                version,
                                updater,
                            )
                            .await;
                        }
                        if connection.alpn() != TUNNEL_ALPN {
                            bail!("unsupported tunnel protocol");
                        }
                        let advertised_version = *version.borrow();
                        tunnel::serve_connection(
                            connection,
                            connection_id,
                            &capability,
                            advertised_version,
                            child_cancellation,
                            move |name| resolve_session(herdr_bin, name),
                            move || {
                                drop(pending_permit);
                                authenticated
                                    .try_acquire_owned()
                                    .context("authenticated connection capacity is exhausted")
                            },
                        )
                        .await
                    }
                    .await;
                    if let Err(error) = result {
                        warn!(connection_id, error = %error, "Iroh connection rejected");
                    }
                    Ok::<_, anyhow::Error>(())
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(error = %error, "Iroh connection task failed");
                }
            }
        }
    };

    cancellation.cancel();
    shutdown_connections(&mut connections).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use attached_tunnel_protocol::{read_upgrade_response, write_upgrade_request};
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicUsize, Ordering},
    };

    fn fake_herdr(root: &std::path::Path, version: &str) -> PathBuf {
        let path = root.join("herdr");
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nif [ \"$1\" = update ]; then printf updated > '{}/updated'; exit 0; fi\nif [ \"$1\" = --version ]; then printf 'herdr {}\\n'; exit 0; fi\nexit 9\n",
                root.display(), version
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[tokio::test]
    async fn endpoint_registration_is_held_for_serving_lifetime() {
        tokio::time::timeout(Duration::from_secs(1), async {
            let root = crate::test_support::canonical_tempdir();
            let registry = root.path().join("registry-user/live-endpoints");
            let identity = [0x44; 32];

            run_registered_lifecycle(&registry, identity, || async {
                assert!(
                    crate::endpoint_registry::is_active(&registry, identity).unwrap(),
                    "registry was inactive during initial publication"
                );
                tokio::task::yield_now().await;
                assert!(
                    crate::endpoint_registry::is_active(&registry, identity).unwrap(),
                    "registry was inactive while serving"
                );
                tokio::task::yield_now().await;
                assert!(
                    crate::endpoint_registry::is_active(&registry, identity).unwrap(),
                    "registry was inactive during endpoint shutdown"
                );
                Ok(())
            })
            .await
            .unwrap();

            assert!(!crate::endpoint_registry::is_active(&registry, identity).unwrap());
        })
        .await
        .expect("endpoint registration lifecycle scenario timed out");
    }

    #[test]
    fn successful_update_command_refreshes_in_memory_and_published_version() {
        let root = tempfile::tempdir().unwrap();
        let executable = fake_herdr(root.path(), "1.2.3");
        let (advertised, mut published) = watch::channel(HerdrVersion::new(1, 2, 2));
        assert_eq!(
            perform_upgrade(
                &executable,
                HerdrVersion::new(1, 2, 3),
                &advertised,
                Arc::new(Semaphore::new(1)),
            ),
            UpgradeResponse::Updated(HerdrVersion::new(1, 2, 3))
        );
        assert_eq!(*advertised.borrow(), HerdrVersion::new(1, 2, 3));
        assert!(published.has_changed().unwrap());
        assert_eq!(*published.borrow_and_update(), HerdrVersion::new(1, 2, 3));

        let mismatched = fake_herdr(root.path(), "1.2.4");
        let (advertised, mut published) = watch::channel(HerdrVersion::new(1, 2, 2));
        let response = perform_upgrade(
            &mismatched,
            HerdrVersion::new(1, 2, 3),
            &advertised,
            Arc::new(Semaphore::new(1)),
        );
        assert_eq!(
            response,
            UpgradeResponse::Failed(
                "remote Herdr update did not install the required version".to_owned()
            )
        );
        assert_eq!(*advertised.borrow(), HerdrVersion::new(1, 2, 4));
        assert!(published.has_changed().unwrap());
        assert_eq!(*published.borrow_and_update(), HerdrVersion::new(1, 2, 4));
    }

    #[test]
    fn equal_or_older_requested_version_never_executes_remote_update() {
        for requested in [HerdrVersion::new(1, 2, 3), HerdrVersion::new(1, 2, 2)] {
            let root = tempfile::tempdir().unwrap();
            let executable = fake_herdr(root.path(), "9.9.9");
            let (advertised, _) = watch::channel(HerdrVersion::new(1, 2, 3));

            assert_eq!(
                perform_upgrade(
                    &executable,
                    requested,
                    &advertised,
                    Arc::new(Semaphore::new(1)),
                ),
                UpgradeResponse::Failed(
                    "remote Herdr is already at or newer than the requested version".to_owned()
                )
            );
            assert!(
                !root.path().join("updated").exists(),
                "server executed the updater for requested {requested}"
            );
            assert_eq!(*advertised.borrow(), HerdrVersion::new(1, 2, 3));
        }
    }

    #[test]
    fn concurrent_upgrade_is_rejected_before_command_execution() {
        let root = tempfile::tempdir().unwrap();
        let executable = fake_herdr(root.path(), "1.2.3");
        let updater = Arc::new(Semaphore::new(1));
        let _held = updater.clone().try_acquire_owned().unwrap();
        let (advertised, _) = watch::channel(HerdrVersion::new(1, 2, 2));
        assert_eq!(
            perform_upgrade(
                &executable,
                HerdrVersion::new(1, 2, 3),
                &advertised,
                updater,
            ),
            UpgradeResponse::Busy
        );
        assert!(!root.path().join("updated").exists());
    }

    #[test]
    fn updater_child_diagnostics_are_never_exposed_on_the_wire() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("secret-herdr");
        let secret = "TOKEN=wire-secret https://user:pass@example.test /srv/private/herdr";
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\nif [ \"$1\" = update ]; then printf '%s' '{secret}' >&2; exit 7; fi\nprintf 'herdr 1.2.2\\n'\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let (advertised, _) = watch::channel(HerdrVersion::new(1, 2, 2));

        let response = perform_upgrade(
            &executable,
            HerdrVersion::new(1, 2, 3),
            &advertised,
            Arc::new(Semaphore::new(1)),
        );
        assert_eq!(
            response,
            UpgradeResponse::Failed("remote Herdr update failed".to_owned())
        );
        let wire = format!("{response:?}");
        assert!(!wire.contains("wire-secret"), "{wire}");
        assert!(!wire.contains("example.test"), "{wire}");
        assert!(!wire.contains("/srv/private"), "{wire}");
        assert!(!wire.contains("secret-herdr"), "{wire}");
    }

    #[tokio::test]
    async fn changed_version_invokes_publisher_and_periodic_retry() {
        tokio::time::timeout(Duration::from_secs(1), async {
            let (version, receiver) = watch::channel(HerdrVersion::new(1, 2, 2));
            let (published, mut publications) = tokio::sync::mpsc::unbounded_channel();
            let publisher = tokio::spawn(run_publish_loop(
                receiver,
                Duration::from_millis(30),
                move |observed| {
                    let published = published.clone();
                    async move {
                        published.send(observed).unwrap();
                        Ok(())
                    }
                },
            ));

            version.send_replace(HerdrVersion::new(1, 2, 3));
            assert_eq!(
                publications.recv().await.unwrap(),
                HerdrVersion::new(1, 2, 3)
            );
            assert_eq!(
                publications.recv().await.unwrap(),
                HerdrVersion::new(1, 2, 3),
                "periodic publication retry was not retained"
            );
            publisher.abort();
            let _ = publisher.await;
        })
        .await
        .expect("publisher action scenario timed out");
    }

    #[tokio::test]
    async fn accepted_updater_work_remains_owned_during_shutdown() {
        tokio::time::timeout(Duration::from_secs(1), async {
            let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let task_completed = completed.clone();
            let mut connections = JoinSet::new();
            connections.spawn(async move {
                tokio::time::sleep(Duration::from_millis(30)).await;
                task_completed.store(true, Ordering::SeqCst);
                Ok(())
            });

            shutdown_connections(&mut connections).await;
            assert!(completed.load(Ordering::SeqCst));
        })
        .await
        .expect("shutdown ownership scenario timed out");
    }

    #[tokio::test]
    async fn invalid_capability_never_resolves_session_or_executes_update() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let expected = CapabilitySecret::from_bytes([1; 32]);
            let supplied = CapabilitySecret::from_bytes([2; 32]);
            let calls = Arc::new(AtomicUsize::new(0));
            let (client, server) = tokio::io::duplex(512);
            let (_client_receive, mut client_send) = tokio::io::split(client);
            let (mut server_receive, mut server_send) = tokio::io::split(server);
            let server_calls = calls.clone();

            let client = write_upgrade_request(
                &mut client_send,
                "work",
                &supplied,
                HerdrVersion::new(1, 2, 3),
            );
            let server = process_upgrade_stream(
                &mut server_receive,
                &mut server_send,
                &expected,
                Duration::from_secs(1),
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                },
                |_| {
                    server_calls.fetch_add(1, Ordering::SeqCst);
                    UpgradeResponse::Busy
                },
            );
            let (client_result, server_result) = tokio::join!(client, server);
            client_result.unwrap();
            assert!(server_result.unwrap_err().to_string().contains("denied"));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        })
        .await
        .expect("invalid-capability duplex scenario timed out");
    }

    #[tokio::test]
    async fn authenticated_upgrade_stream_binds_session_and_requested_version() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let capability = CapabilitySecret::from_bytes([3; 32]);
            let (client, server) = tokio::io::duplex(512);
            let (mut client_receive, mut client_send) = tokio::io::split(client);
            let (mut server_receive, mut server_send) = tokio::io::split(server);
            let requested = HerdrVersion::new(4, 5, 6);

            let client = async {
                write_upgrade_request(&mut client_send, "work", &capability, requested).await?;
                read_upgrade_response(&mut client_receive).await
            };
            let server = process_upgrade_stream(
                &mut server_receive,
                &mut server_send,
                &capability,
                Duration::from_secs(1),
                |session| async move {
                    anyhow::ensure!(session == "work", "wrong session");
                    Ok(())
                },
                |version| {
                    assert_eq!(version, requested);
                    UpgradeResponse::Updated(version)
                },
            );
            let (response, ()) = tokio::try_join!(client, server).unwrap();
            assert_eq!(response, UpgradeResponse::Updated(requested));
        })
        .await
        .expect("authenticated duplex scenario timed out");
    }
}
