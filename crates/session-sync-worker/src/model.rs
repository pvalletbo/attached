use attached_session_sync_protocol::{
    account::{AccountId, ApiKeyScope},
    api::Envelope,
    limits::MAX_CIPHERTEXT_BYTES,
};

pub(crate) const ENCODED_ACCOUNT_BYTES: usize = 80;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MutationOutcome {
    Created { revision: u64 },
    Updated { revision: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MutationError {
    InvalidRequest,
    LiveQuotaExceeded,
    RevisionOverflow,
    InvalidStorage,
}

#[derive(Clone)]
pub(crate) struct StoredAccount {
    account_id: [u8; 16],
    publish_api_token_hash: [u8; 32],
    download_api_token_hash: [u8; 32],
}

impl StoredAccount {
    pub(crate) fn new(
        account_id: AccountId,
        publish_api_token_hash: [u8; 32],
        download_api_token_hash: [u8; 32],
    ) -> Result<Self, MutationError> {
        let account = Self {
            account_id: *account_id.as_bytes(),
            publish_api_token_hash,
            download_api_token_hash,
        };
        account.validate()?;
        Ok(account)
    }

    pub(crate) fn account_id(&self) -> AccountId {
        AccountId::from_bytes(self.account_id)
    }

    pub(crate) fn authenticate(&self, supplied_hash: &[u8; 32], scope: ApiKeyScope) -> bool {
        let expected = match scope {
            ApiKeyScope::Publish => &self.publish_api_token_hash,
            ApiKeyScope::Download => &self.download_api_token_hash,
        };
        expected == supplied_hash
    }

    pub(crate) fn encode(&self) -> [u8; ENCODED_ACCOUNT_BYTES] {
        let mut encoded = [0_u8; ENCODED_ACCOUNT_BYTES];
        encoded[..16].copy_from_slice(&self.account_id);
        encoded[16..48].copy_from_slice(&self.publish_api_token_hash);
        encoded[48..].copy_from_slice(&self.download_api_token_hash);
        encoded
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, MutationError> {
        if encoded.len() != ENCODED_ACCOUNT_BYTES {
            return Err(MutationError::InvalidStorage);
        }
        Self::new(
            AccountId::from_bytes(
                encoded[..16]
                    .try_into()
                    .expect("validated account ID slice has a fixed length"),
            ),
            encoded[16..48]
                .try_into()
                .expect("validated publish hash slice has a fixed length"),
            encoded[48..]
                .try_into()
                .expect("validated download hash slice has a fixed length"),
        )
    }

    pub(crate) fn storage_parts(&self) -> ([u8; 16], [u8; 32], [u8; 32]) {
        (
            self.account_id,
            self.publish_api_token_hash,
            self.download_api_token_hash,
        )
    }

    fn validate(&self) -> Result<(), MutationError> {
        if !self.account_id().is_uuid_v7()
            || self.publish_api_token_hash == self.download_api_token_hash
        {
            Err(MutationError::InvalidStorage)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone)]
pub(crate) struct StoredRecord {
    revision: u64,
    envelope_nonce: [u8; 24],
    envelope_ciphertext: Vec<u8>,
}

impl StoredRecord {
    pub(crate) fn from_storage(
        revision: u64,
        envelope_nonce: [u8; 24],
        envelope_ciphertext: Vec<u8>,
    ) -> Result<Self, MutationError> {
        let record = Self {
            revision,
            envelope_nonce,
            envelope_ciphertext,
        };
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn nonce(&self) -> &[u8; 24] {
        &self.envelope_nonce
    }

    pub(crate) fn ciphertext(&self) -> &[u8] {
        &self.envelope_ciphertext
    }

    pub(crate) fn into_envelope(self) -> (Envelope, u64) {
        // Construction validates the private fields, so moving them cannot
        // introduce an invalid envelope or require another ciphertext copy.
        let envelope = Envelope {
            envelope_version: 1,
            nonce: self.envelope_nonce,
            ciphertext: self.envelope_ciphertext,
        };
        (envelope, self.revision)
    }

    fn validate(&self) -> Result<(), MutationError> {
        if self.revision == 0
            || self.revision > i64::MAX as u64
            || self.envelope_ciphertext.len() > MAX_CIPHERTEXT_BYTES
        {
            Err(MutationError::InvalidStorage)
        } else {
            Ok(())
        }
    }
}

pub(crate) fn put(
    current: Option<&StoredRecord>,
    envelope: Envelope,
) -> Result<(StoredRecord, MutationOutcome), MutationError> {
    if envelope.envelope_version != 1 {
        return Err(MutationError::InvalidRequest);
    }
    let (revision, outcome) = match current {
        Some(record) => {
            let revision = next_revision(record.revision)?;
            (revision, MutationOutcome::Updated { revision })
        }
        None => (1, MutationOutcome::Created { revision: 1 }),
    };
    let record = StoredRecord::from_storage(revision, envelope.nonce, envelope.ciphertext)?;
    Ok((record, outcome))
}

fn next_revision(revision: u64) -> Result<u64, MutationError> {
    revision
        .checked_add(1)
        .filter(|revision| *revision <= i64::MAX as u64)
        .ok_or(MutationError::RevisionOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> StoredAccount {
        let mut id = [0_u8; 16];
        id[0..6].copy_from_slice(&1_700_000_000_000_u64.to_be_bytes()[2..]);
        id[6] = 0x70;
        id[8] = 0x80;
        StoredAccount::new(AccountId::from_bytes(id), [1; 32], [2; 32]).expect("account")
    }

    fn envelope(value: u8) -> Envelope {
        Envelope::new([value; 24], vec![value; 32]).expect("envelope")
    }

    #[test]
    fn unconditional_put_creates_then_replaces() {
        let (first, created) = put(None, envelope(3)).expect("create");
        assert_eq!(created, MutationOutcome::Created { revision: 1 });

        let replacement = envelope(4);
        let allocation = replacement.ciphertext.as_ptr();
        let (second, updated) = put(Some(&first), replacement).expect("update");
        assert_eq!(updated, MutationOutcome::Updated { revision: 2 });
        assert_eq!(
            second.ciphertext().as_ptr(),
            allocation,
            "PUT copied ciphertext"
        );
        let (envelope, revision) = second.into_envelope();
        assert_eq!(revision, 2);
        assert_eq!(envelope.nonce, [4; 24]);
        assert_eq!(envelope.ciphertext, vec![4; 32]);
        assert_eq!(
            envelope.ciphertext.as_ptr(),
            allocation,
            "ciphertext was copied"
        );
        assert_eq!(
            first.revision(),
            1,
            "replacement mutated the previous record"
        );
    }

    #[test]
    fn account_transport_encoding_is_fixed_and_validated() {
        let account = account();
        let encoded = account.encode();
        let decoded = StoredAccount::decode(&encoded).expect("decode account");
        assert_eq!(decoded.account_id(), account.account_id());

        assert!(StoredAccount::decode(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn stored_records_validate_bounds_before_exposing_an_envelope() {
        for revision in [0, i64::MAX as u64 + 1, u64::MAX] {
            assert_eq!(
                StoredRecord::from_storage(revision, [0; 24], Vec::new()).err(),
                Some(MutationError::InvalidStorage)
            );
        }
        assert_eq!(
            StoredRecord::from_storage(1, [0; 24], vec![0; MAX_CIPHERTEXT_BYTES + 1]).err(),
            Some(MutationError::InvalidStorage)
        );
        for length in [0, MAX_CIPHERTEXT_BYTES] {
            let record =
                StoredRecord::from_storage(i64::MAX as u64, [5; 24], vec![7; length]).unwrap();
            let (envelope, revision) = record.into_envelope();
            assert_eq!(revision, i64::MAX as u64);
            assert_eq!(envelope, Envelope::new([5; 24], vec![7; length]).unwrap());
        }
    }

    #[test]
    fn updates_validate_public_envelope_fields() {
        let mut invalid = envelope(1);
        invalid.envelope_version = 2;
        assert_eq!(
            put(None, invalid).err(),
            Some(MutationError::InvalidRequest)
        );
        let invalid = Envelope {
            envelope_version: 1,
            nonce: [0; 24],
            ciphertext: vec![0; MAX_CIPHERTEXT_BYTES + 1],
        };
        assert_eq!(
            put(None, invalid).err(),
            Some(MutationError::InvalidStorage)
        );
    }

    #[test]
    fn record_revision_cannot_exceed_sqlite_integer_range() {
        let current = StoredRecord::from_storage(i64::MAX as u64, [3; 24], vec![4; 32])
            .expect("maximum revision");
        assert!(matches!(
            put(Some(&current), envelope(5)),
            Err(MutationError::RevisionOverflow)
        ));
    }
}
