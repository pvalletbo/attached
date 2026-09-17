use anyhow::{Context, Result, anyhow, bail, ensure};
use attached_tunnel_protocol::{
    ATTACHED_UPDATE_ALPN, AttachedUpdateResponse, AttachedVersion, CapabilitySecret,
    UpdateOperationId, read_attached_update_response, write_attached_update_confirm_request,
    write_attached_update_start_request,
};
use iroh::{Endpoint, endpoint::presets};
use std::time::Duration;
use tokio::time::{sleep, timeout, timeout_at};
const ATTACHED_UPDATE_START_TIMEOUT: Duration = Duration::from_secs(150);
const ATTACHED_UPDATE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ATTACHED_RECONNECT_TIMEOUT: Duration = Duration::from_secs(60);
async fn bind_client_endpoint(local_identity: &iroh::SecretKey) -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(local_identity.clone())
        .bind()
        .await
        .context("could not bind persistent local Iroh identity")
}

pub async fn request_attached_update(
    endpoint_addr: iroh::EndpointAddr,
    local_identity: &iroh::SecretKey,
    capability: &CapabilitySecret,
) -> Result<AttachedVersion> {
    let endpoint = bind_client_endpoint(local_identity)
        .await
        .context("could not initialize the local Attached update endpoint")?;
    let result = request_attached_update_on_endpoint(&endpoint, endpoint_addr, capability).await;
    endpoint.close().await;
    result
}

async fn request_attached_update_on_endpoint(
    endpoint: &Endpoint,
    endpoint_addr: iroh::EndpointAddr,
    capability: &CapabilitySecret,
) -> Result<AttachedVersion> {
    let initial = timeout(
        ATTACHED_UPDATE_START_TIMEOUT,
        exchange_attached_update_start(endpoint, endpoint_addr.clone(), capability),
    )
    .await
    .context("remote Attached update preparation timed out")??;
    match initial {
        AttachedUpdateResponse::Current(version) | AttachedUpdateResponse::Committed(version) => {
            Ok(version)
        }
        AttachedUpdateResponse::Restarting {
            operation_id,
            version,
            reconnect_timeout_secs,
        } => {
            let reconnect_timeout = Duration::from_secs(u64::from(reconnect_timeout_secs));
            ensure!(
                !reconnect_timeout.is_zero() && reconnect_timeout <= MAX_ATTACHED_RECONNECT_TIMEOUT,
                "remote Attached returned an invalid reconnect deadline"
            );
            eprintln!("Remote Attached {version} is prepared; waiting for the server to restart…");
            confirm_attached_candidate(
                endpoint,
                endpoint_addr,
                capability,
                operation_id,
                version,
                reconnect_timeout,
            )
            .await
        }
        AttachedUpdateResponse::Failed(message) => bail!("{message}"),
        AttachedUpdateResponse::Busy => {
            bail!("a remote Attached update is already in progress; retry later")
        }
        AttachedUpdateResponse::Waiting => {
            bail!("remote Attached returned an unexpected waiting response")
        }
    }
}

async fn exchange_attached_update_start(
    endpoint: &Endpoint,
    endpoint_addr: iroh::EndpointAddr,
    capability: &CapabilitySecret,
) -> Result<AttachedUpdateResponse> {
    let connection = endpoint
        .connect(endpoint_addr, ATTACHED_UPDATE_ALPN)
        .await
        .context("could not connect to the remote Attached update service")?;
    let (mut send, mut receive) = connection.open_bi().await?;
    write_attached_update_start_request(&mut send, capability).await?;
    read_attached_update_response(&mut receive).await
}

async fn exchange_attached_update_confirm(
    endpoint: &Endpoint,
    endpoint_addr: iroh::EndpointAddr,
    capability: &CapabilitySecret,
    operation_id: UpdateOperationId,
    version: AttachedVersion,
) -> Result<AttachedUpdateResponse> {
    let connection = endpoint
        .connect(endpoint_addr, ATTACHED_UPDATE_ALPN)
        .await?;
    let (mut send, mut receive) = connection.open_bi().await?;
    write_attached_update_confirm_request(&mut send, capability, operation_id, version).await?;
    read_attached_update_response(&mut receive).await
}

async fn confirm_attached_candidate(
    endpoint: &Endpoint,
    endpoint_addr: iroh::EndpointAddr,
    capability: &CapabilitySecret,
    operation_id: UpdateOperationId,
    version: AttachedVersion,
    reconnect_timeout: Duration,
) -> Result<AttachedVersion> {
    let deadline = tokio::time::Instant::now() + reconnect_timeout;
    let mut delay = Duration::from_millis(100);
    let mut last_error = None;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            let detail = last_error.map_or_else(
                || "the replacement server did not answer".to_owned(),
                |error: anyhow::Error| error.to_string(),
            );
            bail!("timed out confirming remote Attached {version} after restart: {detail}");
        }
        let attempt_deadline = (now + ATTACHED_UPDATE_ATTEMPT_TIMEOUT).min(deadline);
        match timeout_at(
            attempt_deadline,
            exchange_attached_update_confirm(
                endpoint,
                endpoint_addr.clone(),
                capability,
                operation_id,
                version,
            ),
        )
        .await
        {
            Ok(Ok(AttachedUpdateResponse::Committed(installed))) => {
                ensure!(
                    installed == version,
                    "replacement server reported Attached {installed}, expected {version}"
                );
                return Ok(installed);
            }
            Ok(Ok(AttachedUpdateResponse::Current(installed))) if installed == version => {
                return Ok(installed);
            }
            Ok(Ok(AttachedUpdateResponse::Failed(message))) => bail!("{message}"),
            Ok(Ok(AttachedUpdateResponse::Busy | AttachedUpdateResponse::Waiting)) => {}
            Ok(Ok(response)) => {
                last_error = Some(anyhow!("unexpected confirmation response {response:?}"));
            }
            Ok(Err(error)) => last_error = Some(error),
            Err(error) => last_error = Some(error.into()),
        }
        sleep(delay.min(deadline.saturating_duration_since(tokio::time::Instant::now()))).await;
        delay = (delay * 2).min(Duration::from_secs(1));
    }
}

#[cfg(test)]
#[path = "remote_update_tests.rs"]
mod tests;
