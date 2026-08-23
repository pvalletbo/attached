use attached_session_sync_protocol::{
    account::RecordId,
    api::{Envelope, LiveRecordIndex, LiveRecordIndexEntry},
    limits::{MAX_CIPHERTEXT_BYTES, MAX_LIVE_RECORDS},
};
use worker::{SqlCursor, SqlStorageValue, Storage};

use crate::model::{self, MutationError, MutationOutcome, StoredAccount, StoredRecord};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InitializeOutcome {
    Created,
    AlreadyExists,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StoreError {
    Unavailable,
}

fn initialize_schema(storage: &Storage) -> Result<(), StoreError> {
    let schema = format!(
        r#"
        CREATE TABLE IF NOT EXISTS account_state (
            singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
            account_id BLOB NOT NULL CHECK (length(account_id) = 16),
            publish_api_token_hash BLOB NOT NULL
                CHECK (length(publish_api_token_hash) = 32),
            download_api_token_hash BLOB NOT NULL
                CHECK (length(download_api_token_hash) = 32),
            CHECK (publish_api_token_hash <> download_api_token_hash)
        ) STRICT, WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS records (
            record_id BLOB NOT NULL PRIMARY KEY CHECK (length(record_id) = 16),
            revision INTEGER NOT NULL CHECK (revision > 0),
            envelope_nonce BLOB NOT NULL CHECK (length(envelope_nonce) = 24),
            envelope_ciphertext BLOB NOT NULL
                CHECK (length(envelope_ciphertext) <= {MAX_CIPHERTEXT_BYTES})
        ) STRICT, WITHOUT ROWID;

        CREATE TRIGGER IF NOT EXISTS records_live_quota
        BEFORE INSERT ON records
        WHEN (SELECT COUNT(*) FROM records) >= {MAX_LIVE_RECORDS}
        BEGIN
            SELECT RAISE(ABORT, 'live record quota exceeded');
        END;
        "#,
    );
    storage
        .sql()
        .exec(&schema, None)
        .map_err(|_| StoreError::Unavailable)?;
    Ok(())
}

pub(crate) fn initialize(
    storage: &Storage,
    account: &StoredAccount,
) -> Result<InitializeOutcome, StoreError> {
    // Keep DDL on the private initialization path. Creating tables in the
    // constructor would persist an empty database for every guessed account ID.
    initialize_schema(storage)?;
    let (account_id, publish_hash, download_hash) = account.storage_parts();
    let cursor = storage
        .sql()
        .exec(
            "INSERT INTO account_state (\
                 singleton, account_id, publish_api_token_hash, download_api_token_hash\
             ) VALUES (1, ?, ?, ?) \
             ON CONFLICT (singleton) DO NOTHING \
             RETURNING CAST(singleton AS TEXT)",
            Some(vec![
                SqlStorageValue::Blob(account_id.to_vec()),
                SqlStorageValue::Blob(publish_hash.to_vec()),
                SqlStorageValue::Blob(download_hash.to_vec()),
            ]),
        )
        .map_err(|_| StoreError::Unavailable)?;
    match optional_row(cursor)? {
        Some(row) => {
            let singleton = single_text(row)?;
            if singleton == "1" {
                Ok(InitializeOutcome::Created)
            } else {
                Err(StoreError::Unavailable)
            }
        }
        None => Ok(InitializeOutcome::AlreadyExists),
    }
}

pub(crate) fn load_account(storage: &Storage) -> Result<Option<StoredAccount>, StoreError> {
    if !schema_exists(storage)? {
        return Ok(None);
    }
    let cursor = storage
        .sql()
        .exec(
            "SELECT account_id, publish_api_token_hash, download_api_token_hash \
             FROM account_state WHERE singleton = 1",
            None,
        )
        .map_err(|_| StoreError::Unavailable)?;
    optional_row(cursor)?.map(parse_account).transpose()
}

pub(crate) fn load_index(storage: &Storage) -> Result<LiveRecordIndex, StoreError> {
    let cursor = storage
        .sql()
        .exec(
            "SELECT record_id, CAST(revision AS TEXT) \
             FROM records ORDER BY record_id LIMIT ?",
            Some(vec![SqlStorageValue::Integer(
                i64::try_from(MAX_LIVE_RECORDS + 1).map_err(|_| StoreError::Unavailable)?,
            )]),
        )
        .map_err(|_| StoreError::Unavailable)?;
    let mut records = Vec::new();
    for row in cursor.raw() {
        let [record_id, revision]: [SqlStorageValue; 2] = row
            .map_err(|_| StoreError::Unavailable)?
            .try_into()
            .map_err(|_| StoreError::Unavailable)?;
        records.push(LiveRecordIndexEntry {
            record_id: RecordId::from_bytes(fixed_blob(record_id)?),
            revision: revision_text(revision)?,
        });
        if records.len() > MAX_LIVE_RECORDS {
            return Err(StoreError::Unavailable);
        }
    }
    LiveRecordIndex::new(records).map_err(|_| StoreError::Unavailable)
}

pub(crate) fn load_record(
    storage: &Storage,
    record_id: RecordId,
) -> Result<Option<StoredRecord>, StoreError> {
    let cursor = storage
        .sql()
        .exec(
            "SELECT CAST(revision AS TEXT), envelope_nonce, envelope_ciphertext \
             FROM records WHERE record_id = ?",
            Some(vec![SqlStorageValue::Blob(record_id.as_bytes().to_vec())]),
        )
        .map_err(|_| StoreError::Unavailable)?;
    optional_row(cursor)?.map(parse_record).transpose()
}

pub(crate) fn put_record(
    storage: &Storage,
    record_id: RecordId,
    envelope: Envelope,
) -> Result<Result<MutationOutcome, MutationError>, StoreError> {
    let current = load_record(storage, record_id)?;
    let live_records = live_record_count(storage)?;
    if live_records > MAX_LIVE_RECORDS {
        return Err(StoreError::Unavailable);
    }
    if current.is_none() && live_records == MAX_LIVE_RECORDS {
        return Ok(Err(MutationError::LiveQuotaExceeded));
    }
    let (record, outcome) = match model::put(current.as_ref(), &envelope) {
        Ok(value) => value,
        Err(error) => return Ok(Err(error)),
    };

    // SQL storage calls are synchronous. With no intervening await, Durable
    // Objects commit the read/check/write sequence as one implicit transaction.
    let cursor = match outcome {
        MutationOutcome::Created { .. } => storage.sql().exec(
            "INSERT INTO records (\
                 record_id, revision, envelope_nonce, envelope_ciphertext\
             ) SELECT ?, 1, ?, ? \
             WHERE EXISTS (SELECT 1 FROM account_state WHERE singleton = 1) \
             RETURNING CAST(revision AS TEXT)",
            Some(vec![
                SqlStorageValue::Blob(record_id.as_bytes().to_vec()),
                SqlStorageValue::Blob(record.nonce().to_vec()),
                SqlStorageValue::Blob(record.ciphertext().to_vec()),
            ]),
        ),
        MutationOutcome::Updated { .. } => storage.sql().exec(
            "UPDATE records \
             SET revision = revision + 1, envelope_nonce = ?, envelope_ciphertext = ? \
             WHERE record_id = ? AND revision < 9223372036854775807 \
             RETURNING CAST(revision AS TEXT)",
            Some(vec![
                SqlStorageValue::Blob(record.nonce().to_vec()),
                SqlStorageValue::Blob(record.ciphertext().to_vec()),
                SqlStorageValue::Blob(record_id.as_bytes().to_vec()),
            ]),
        ),
    }
    .map_err(|_| StoreError::Unavailable)?;

    let stored_revision = optional_row(cursor)?
        .ok_or(StoreError::Unavailable)
        .and_then(|row| revision_text(single_value(row)?))?;
    if stored_revision != record.revision() {
        return Err(StoreError::Unavailable);
    }
    Ok(Ok(outcome))
}

fn schema_exists(storage: &Storage) -> Result<bool, StoreError> {
    let cursor = storage
        .sql()
        .exec(
            "SELECT name FROM sqlite_schema \
             WHERE type = 'table' AND name = 'account_state'",
            None,
        )
        .map_err(|_| StoreError::Unavailable)?;
    match optional_row(cursor)? {
        Some(row) => Ok(single_text(row)? == "account_state"),
        None => Ok(false),
    }
}

fn live_record_count(storage: &Storage) -> Result<usize, StoreError> {
    let cursor = storage
        .sql()
        .exec("SELECT CAST(COUNT(*) AS TEXT) FROM records", None)
        .map_err(|_| StoreError::Unavailable)?;
    let count = single_text(required_row(cursor)?)?
        .parse::<usize>()
        .map_err(|_| StoreError::Unavailable)?;
    Ok(count)
}

fn parse_account(row: Vec<SqlStorageValue>) -> Result<StoredAccount, StoreError> {
    let [account_id, publish_hash, download_hash]: [SqlStorageValue; 3] =
        row.try_into().map_err(|_| StoreError::Unavailable)?;
    StoredAccount::new(
        attached_session_sync_protocol::account::AccountId::from_bytes(fixed_blob(account_id)?),
        fixed_blob(publish_hash)?,
        fixed_blob(download_hash)?,
    )
    .map_err(|_| StoreError::Unavailable)
}

fn parse_record(row: Vec<SqlStorageValue>) -> Result<StoredRecord, StoreError> {
    let [revision, nonce, ciphertext]: [SqlStorageValue; 3] =
        row.try_into().map_err(|_| StoreError::Unavailable)?;
    StoredRecord::from_storage(
        revision_text(revision)?,
        fixed_blob(nonce)?,
        variable_blob(ciphertext)?,
    )
    .map_err(|_| StoreError::Unavailable)
}

fn revision_text(value: SqlStorageValue) -> Result<u64, StoreError> {
    revision_text_value(text(value)?)
}

fn revision_text_value(value: String) -> Result<u64, StoreError> {
    value
        .parse::<u64>()
        .ok()
        .filter(|revision| *revision > 0 && *revision <= i64::MAX as u64)
        .ok_or(StoreError::Unavailable)
}

fn fixed_blob<const N: usize>(value: SqlStorageValue) -> Result<[u8; N], StoreError> {
    variable_blob(value)?
        .try_into()
        .map_err(|_| StoreError::Unavailable)
}

fn variable_blob(value: SqlStorageValue) -> Result<Vec<u8>, StoreError> {
    match value {
        SqlStorageValue::Blob(bytes) => Ok(bytes),
        _ => Err(StoreError::Unavailable),
    }
}

fn text(value: SqlStorageValue) -> Result<String, StoreError> {
    match value {
        SqlStorageValue::String(value) => Ok(value),
        _ => Err(StoreError::Unavailable),
    }
}

fn optional_row(cursor: SqlCursor) -> Result<Option<Vec<SqlStorageValue>>, StoreError> {
    let mut rows = cursor.raw();
    let first = rows
        .next()
        .transpose()
        .map_err(|_| StoreError::Unavailable)?;
    if rows
        .next()
        .transpose()
        .map_err(|_| StoreError::Unavailable)?
        .is_some()
    {
        return Err(StoreError::Unavailable);
    }
    Ok(first)
}

fn required_row(cursor: SqlCursor) -> Result<Vec<SqlStorageValue>, StoreError> {
    optional_row(cursor)?.ok_or(StoreError::Unavailable)
}

fn single_value(row: Vec<SqlStorageValue>) -> Result<SqlStorageValue, StoreError> {
    let [value] = row.try_into().map_err(|_| StoreError::Unavailable)?;
    Ok(value)
}

fn single_text(row: Vec<SqlStorageValue>) -> Result<String, StoreError> {
    text(single_value(row)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_revisions_are_decoded_without_javascript_numbers() {
        assert_eq!(
            revision_text(SqlStorageValue::String(i64::MAX.to_string())),
            Ok(i64::MAX as u64)
        );
        assert!(revision_text(SqlStorageValue::String((i64::MAX as u64 + 1).to_string())).is_err());
    }
}
