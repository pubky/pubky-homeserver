use pubky_common::crypto::PublicKey;
use sea_query::Iden;
use sqlx::{postgres::PgRow, FromRow, Row};

use crate::{
    persistence::sql::{entities::user::UserIden, entry::EntryIden},
    shared::webdav::{EntryPath, StoragePath},
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EntryEntity {
    pub id: i64,
    pub user_id: i32,
    pub path: EntryPath,
    pub content_hash: pubky_common::crypto::Hash,
    pub content_length: u64,
    pub content_type: String,
    pub modified_at: sqlx::types::chrono::NaiveDateTime,
    pub created_at: sqlx::types::chrono::NaiveDateTime,
}

impl FromRow<'_, PgRow> for EntryEntity {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        let id: i64 = row.try_get(EntryIden::Id.to_string().as_str())?;
        let user_id: i32 = row.try_get(EntryIden::User.to_string().as_str())?;
        let user_pubkey: String = row.try_get(UserIden::PublicKey.to_string().as_str())?;
        let user_pubkey: PublicKey = user_pubkey
            .parse()
            .map_err(|e: pkarr::errors::PublicKeyError| sqlx::Error::Decode(e.into()))?;
        let path: String = row.try_get(EntryIden::Path.to_string().as_str())?;
        let storage_path = StoragePath::new(&path).map_err(|e| sqlx::Error::Decode(e.into()))?;
        let entry_path = EntryPath::new(user_pubkey, storage_path);
        let content_hash_vec: Vec<u8> = row.try_get(EntryIden::ContentHash.to_string().as_str())?;

        // Ensure content_hash is exactly 32 bytes
        let content_hash: [u8; 32] = content_hash_vec
            .try_into()
            .map_err(|_| sqlx::Error::Decode("Content hash must be exactly 32 bytes".into()))?;
        let content_hash = pubky_common::crypto::Hash::from_bytes(content_hash);
        let content_length: i64 = row.try_get(EntryIden::ContentLength.to_string().as_str())?;
        let content_type: String = row.try_get(EntryIden::ContentType.to_string().as_str())?;
        let modified_at: sqlx::types::chrono::NaiveDateTime =
            row.try_get(EntryIden::ModifiedAt.to_string().as_str())?;
        let created_at: sqlx::types::chrono::NaiveDateTime =
            row.try_get(EntryIden::CreatedAt.to_string().as_str())?;
        Ok(EntryEntity {
            id,
            user_id,
            path: entry_path,
            content_hash,
            content_length: content_length as u64,
            content_type,
            modified_at,
            created_at,
        })
    }
}
