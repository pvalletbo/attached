use attached_session_sync_protocol::account::{AccountId, ApiToken};
use uuid::Uuid;

pub(crate) struct IssuedAccount {
    pub(crate) account_id: AccountId,
    pub(crate) publish_token: ApiToken,
    pub(crate) download_token: ApiToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IssuanceError {
    EntropyUnavailable,
}

pub(crate) fn issue() -> Result<IssuedAccount, IssuanceError> {
    let account_id = AccountId::from(Uuid::now_v7());
    let (publish_token, download_token) = distinct_tokens()?;
    Ok(IssuedAccount {
        account_id,
        publish_token,
        download_token,
    })
}

fn distinct_tokens() -> Result<(ApiToken, ApiToken), IssuanceError> {
    loop {
        let mut bytes = [0_u8; 64];
        getrandom::fill(&mut bytes).map_err(|_| IssuanceError::EntropyUnavailable)?;
        let publish = ApiToken::from_bytes(
            bytes[..32]
                .try_into()
                .expect("a 32-byte token slice has a fixed length"),
        );
        let download = ApiToken::from_bytes(
            bytes[32..]
                .try_into()
                .expect("a 32-byte token slice has a fixed length"),
        );
        if publish.service_hash() != download.service_hash() {
            return Ok((publish, download));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuance_creates_uuid_v7_accounts_with_distinct_tokens() {
        let first = issue().expect("first issuance");
        let second = issue().expect("second issuance");
        assert!(first.account_id.is_uuid_v7());
        assert!(second.account_id.is_uuid_v7());
        assert_ne!(first.account_id, second.account_id);
        assert_ne!(
            first.publish_token.service_hash(),
            first.download_token.service_hash()
        );
    }
}
