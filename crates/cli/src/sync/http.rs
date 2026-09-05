use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use attached_session_sync_protocol::{
    account::{ApiKeyScope, RecordId, ServiceOrigin},
    api::{
        CACHE_CONTROL_VALUE, CreateAccountResponse, Envelope, ErrorDto, LiveRecordIndex,
        parse_live_record_index,
    },
    limits::MAX_API_BODY_BYTES,
};
use futures_util::StreamExt as _;
use reqwest::{
    Client, Response, StatusCode,
    header::{self, HeaderValue},
    redirect::Policy,
};

use super::state::AccountCredentials;

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ERROR_BODY_BYTES: usize = 4096;

pub struct FetchedRecord {
    pub envelope: Envelope,
    pub revision: u64,
}

pub struct SyncHttpClient {
    client: Client,
}

impl SyncHttpClient {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("could not initialize synchronization HTTP client")?;
        Ok(Self { client })
    }

    pub async fn create_account(
        &self,
        service_origin: &ServiceOrigin,
    ) -> Result<CreateAccountResponse> {
        let response = self
            .client
            .post(format!("{}/v1/accounts", service_origin.as_str()))
            .send()
            .await
            .context("could not create synchronization account")?;
        if response.status() != StatusCode::CREATED {
            return Err(service_error(response).await);
        }
        ensure_json(&response)?;
        ensure!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .is_some_and(|value| value.as_bytes() == CACHE_CONTROL_VALUE.as_bytes()),
            "account-creation response is not marked no-store"
        );
        let body = bounded_response(response, MAX_API_BODY_BYTES).await?;
        CreateAccountResponse::parse_json(&body)
            .map_err(|_| anyhow::anyhow!("invalid account-creation response"))
    }

    #[tracing::instrument(name = "http_list_records", level = "debug", skip_all)]
    pub async fn list_records(&self, account: &AccountCredentials) -> Result<LiveRecordIndex> {
        ensure!(
            account.api_key_scope() == ApiKeyScope::Download,
            "a download API key is required to list synchronized records"
        );
        let response = self
            .client
            .get(format!(
                "{}/v1/accounts/{}/records",
                account.service_origin(),
                account.account_id()
            ))
            .header(header::AUTHORIZATION, authorization(account)?)
            .send()
            .await
            .context("could not fetch synchronized record index")?;
        if response.status() != StatusCode::OK {
            return Err(service_error(response).await);
        }
        ensure_json(&response)?;
        let body = bounded_response(response, MAX_API_BODY_BYTES).await?;
        parse_live_record_index(&body).map_err(|_| anyhow::anyhow!("invalid live-record index"))
    }

    #[tracing::instrument(name = "http_get_record", level = "debug", skip_all)]
    pub async fn get_record(
        &self,
        account: &AccountCredentials,
        record_id: RecordId,
    ) -> Result<Option<FetchedRecord>> {
        ensure!(
            account.api_key_scope() == ApiKeyScope::Download,
            "a download API key is required to fetch synchronized records"
        );
        let response = self
            .client
            .get(format!(
                "{}/v1/accounts/{}/records/{}",
                account.service_origin(),
                account.account_id(),
                record_id
            ))
            .header(header::AUTHORIZATION, authorization(account)?)
            .send()
            .await
            .context("could not fetch synchronized record")?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status() != StatusCode::OK {
            return Err(service_error(response).await);
        }
        ensure_json(&response)?;
        let revision = response_revision(&response)?;
        let body = bounded_response(response, MAX_API_BODY_BYTES).await?;
        let envelope = Envelope::parse_json(&body)
            .map_err(|_| anyhow::anyhow!("invalid synchronized record envelope"))?;
        Ok(Some(FetchedRecord { envelope, revision }))
    }

    pub async fn put_record(
        &self,
        account: &AccountCredentials,
        record_id: RecordId,
        envelope: &Envelope,
    ) -> Result<u64> {
        ensure!(
            account.api_key_scope() == ApiKeyScope::Publish,
            "a publish API key is required to publish synchronized records"
        );
        let body = serde_json::to_vec(envelope).context("could not encode encrypted record")?;
        let response = self
            .client
            .put(format!(
                "{}/v1/accounts/{}/records/{}",
                account.service_origin(),
                account.account_id(),
                record_id
            ))
            .header(header::AUTHORIZATION, authorization(account)?)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .context("could not publish synchronized record")?;
        if !matches!(
            response.status(),
            StatusCode::CREATED | StatusCode::NO_CONTENT
        ) {
            return Err(anyhow::anyhow!(
                "synchronization service returned HTTP {}",
                response.status()
            ));
        }
        response_revision(&response)
    }
}

fn authorization(account: &AccountCredentials) -> Result<HeaderValue> {
    let value = account.bearer_value();
    let mut header = HeaderValue::from_bytes(value.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid synchronization credential"))?;
    header.set_sensitive(true);
    Ok(header)
}

fn response_revision(response: &reqwest::Response) -> Result<u64> {
    let value = response
        .headers()
        .get(header::ETAG)
        .context("synchronization response is missing ETag")?
        .to_str()
        .context("synchronization response has an invalid ETag")?;
    let digits = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .context("synchronization response has a malformed ETag")?;
    ensure!(
        !digits.is_empty()
            && digits != "0"
            && !(digits.len() > 1 && digits.starts_with('0'))
            && digits.bytes().all(|byte| byte.is_ascii_digit()),
        "synchronization response has a non-canonical ETag"
    );
    let revision = digits.parse::<u64>().context("ETag revision overflow")?;
    ensure!(revision <= i64::MAX as u64, "ETag revision overflow");
    Ok(revision)
}

fn ensure_json(response: &Response) -> Result<()> {
    ensure!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|value| value.as_bytes() == b"application/json"),
        "synchronization service returned an unexpected content type"
    );
    Ok(())
}

#[tracing::instrument(name = "http_read_body", level = "debug", skip_all)]
async fn bounded_response(response: Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("synchronization response exceeds {limit} bytes");
    }
    let mut stream = response.bytes_stream();
    let mut output = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("could not read synchronization response")?;
        let next = output
            .len()
            .checked_add(chunk.len())
            .context("synchronization response length overflow")?;
        ensure!(
            next <= limit,
            "synchronization response exceeds {limit} bytes"
        );
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

async fn service_error(response: Response) -> anyhow::Error {
    let status = response.status();
    let code = if response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes() == b"application/json")
    {
        bounded_response(response, MAX_ERROR_BODY_BYTES)
            .await
            .ok()
            .and_then(|body| serde_json::from_slice::<ErrorDto>(&body).ok())
            .map(|error| format!(" ({:?})", error.code))
            .unwrap_or_default()
    } else {
        String::new()
    };
    anyhow::anyhow!("synchronization service returned HTTP {status}{code}")
}
