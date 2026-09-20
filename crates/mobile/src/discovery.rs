//! Stateless encrypted discovery. No credentials, tickets or capabilities touch disk.
use std::time::Duration;

use anyhow::{Result, bail, ensure};
use attached_session_sync_protocol::{
    account::{AccountBundle, AccountId, ApiKeyScope, ApiToken},
    api::{Envelope, parse_live_record_index},
    crypto::{self, OpenedHostAccessDescriptor, VerificationContext},
    limits::MAX_API_BODY_BYTES,
};
use futures_util::{StreamExt, stream};
use reqwest::{Client, Response, StatusCode, header, redirect};
use zeroize::Zeroizing;

pub(crate) struct Account {
    pub origin: String,
    pub id: AccountId,
    pub token: ApiToken,
    pub root: Zeroizing<[u8; 32]>,
    pub consumer: Zeroizing<[u8; 32]>,
}

impl Account {
    pub fn parse(encoded: String) -> Result<Self> {
        let encoded = Zeroizing::new(encoded);
        // A mobile device only needs a download bundle. Do not import owner or
        // publisher credentials into an app which cannot make use of them.
        let AccountBundle::Scoped(bundle) = AccountBundle::parse(encoded.trim().as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid download bundle"))?
        else {
            bail!("export a download bundle with attached account export --type download")
        };
        ensure!(
            bundle.api_key_scope() == ApiKeyScope::Download,
            "download bundle required"
        );
        let consumer = Zeroizing::new(
            *bundle
                .consumer_identity_secret()
                .ok_or_else(|| anyhow::anyhow!("consumer identity missing"))?
                .as_bytes(),
        );
        Ok(bundle.consume(|origin, id, token, root| Self {
            origin: origin.as_str().to_owned(),
            id,
            token: ApiToken::from_bytes(*token),
            root: Zeroizing::new(*root),
            consumer,
        }))
    }
}

pub(crate) fn http_client() -> Result<Client> {
    Ok(Client::builder()
        .redirect(redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?)
}

async fn get(client: &Client, account: &Account, path: &str) -> Result<Response> {
    let bearer = Zeroizing::new(format!("Bearer {}", account.token.encode()));
    let mut authorization = header::HeaderValue::from_bytes(bearer.as_bytes())?;
    authorization.set_sensitive(true);
    Ok(client
        .get(format!(
            "{}/v1/accounts/{}{path}",
            account.origin, account.id
        ))
        .header(header::AUTHORIZATION, authorization)
        .send()
        .await?)
}

async fn body(response: Response) -> Result<Vec<u8>> {
    ensure!(
        response.status() == StatusCode::OK,
        "discovery request failed"
    );
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    ensure!(
        content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json"),
        "invalid discovery response"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= MAX_API_BODY_BYTES as u64),
        "discovery body too large"
    );
    let mut chunks = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk?;
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_API_BODY_BYTES,
            "discovery body too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(crate) async fn discover(
    client: &Client,
    account: &Account,
) -> Result<Vec<OpenedHostAccessDescriptor>> {
    let index = parse_live_record_index(&body(get(client, account, "/records").await?).await?)
        .map_err(|_| anyhow::anyhow!("invalid record index"))?;
    let records = stream::iter(index.records)
        .map(|entry| async move {
            let response = get(client, account, &format!("/records/{}", entry.record_id)).await?;
            if response.status() == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            let envelope = Envelope::parse_json(&body(response).await?)
                .map_err(|_| anyhow::anyhow!("invalid record envelope"))?;
            let envelope = crypto::Envelope::new(envelope.nonce, envelope.ciphertext)
                .map_err(|_| anyhow::anyhow!("invalid encrypted record"))?;
            let context = VerificationContext {
                account_id: *account.id.as_bytes(),
                record_id: *entry.record_id.as_bytes(),
                now: chrono::Utc::now(),
            };
            // One stale/corrupt record must not hide other valid Hosts. The shared
            // protocol verifies AEAD, endpoint tickets, timestamps and size limits.
            Ok::<_, anyhow::Error>(
                crypto::open_host_access_descriptor(&envelope, &account.root, &context).ok(),
            )
        })
        .buffer_unordered(8)
        .collect::<Vec<_>>()
        .await;
    let mut accepted = Vec::new();
    for result in records {
        if let Some(record) = result? {
            accepted.push(record);
        }
    }
    Ok(accepted)
}
