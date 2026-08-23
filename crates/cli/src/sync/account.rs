use std::path::Path;

use anyhow::{Context as _, Result};
use attached_session_sync_protocol::account::{ApiKeyScope, ServiceOrigin};

use super::{http::SyncHttpClient, state};

pub async fn create(state_dir: &Path, service_origin: &str) -> Result<String> {
    let service_origin = ServiceOrigin::parse(service_origin)
        .map_err(|_| anyhow::anyhow!("invalid sync service origin"))?;
    state::ensure_account_slot_available(state_dir)?;
    let response = SyncHttpClient::new()?
        .create_account(&service_origin)
        .await?;
    state::install_created_account(state_dir, service_origin, response).context(
        "the service created the account, but its credentials could not be saved locally; create another account",
    )
}

pub fn import(state_dir: &Path, bundle: &[u8]) -> Result<()> {
    state::import_account(state_dir, bundle)
}

pub fn export(state_dir: &Path, scope: ApiKeyScope) -> Result<String> {
    state::export_account(state_dir, scope)
}
