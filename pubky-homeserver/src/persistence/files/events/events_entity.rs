use pubky_common::crypto::Hash;
use pubky_common::crypto::PublicKey;
use pubky_common::events::{EventCursor, EventType};
use sea_query::Iden;
use sqlx::{postgres::PgRow, types::chrono::NaiveDateTime, FromRow, Row};

use crate::{
    persistence::{files::events::events_repository::EventIden, sql::user::UserIden},
    shared::webdav::{EntryPath, StoragePath},
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EventEntity {
    pub id: u64,
    pub user_id: i32,
    pub user_pubkey: PublicKey,
    pub event_type: EventType,
    pub path: EntryPath,
    pub created_at: NaiveDateTime,
}

impl EventEntity {
    pub fn cursor(&self) -> EventCursor {
        EventCursor::new(self.id)
    }

    /// Full `pubky://` URI of this event's resource, e.g. `pubky://<z32>/pub/file.txt`.
    pub(crate) fn pubky_uri(&self) -> String {
        format!("pubky://{}{}", self.user_pubkey.z32(), self.path.path())
    }

    /// Multiline SSE `data:` payload (path, `cursor:`, and `content_hash:` for PUTs) shared by the
    /// public and admin event streams. Each line is prefixed with `data: ` by the SSE layer.
    pub(crate) fn to_sse_data(&self) -> String {
        let mut lines = vec![self.pubky_uri(), format!("cursor: {}", self.cursor())];
        if let Some(hash) = self.event_type.content_hash() {
            let hash_base64 =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash.as_bytes());
            lines.push(format!("content_hash: {hash_base64}"));
        }
        lines.join("\n")
    }
}

impl FromRow<'_, PgRow> for EventEntity {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        let id: i64 = row.try_get(EventIden::Id.to_string().as_str())?;
        let id = id as u64;
        let user_id: i32 = row.try_get(EventIden::User.to_string().as_str())?;
        let user_public_key: String = row.try_get(UserIden::PublicKey.to_string().as_str())?;
        let user_pubkey =
            PublicKey::try_from_z32(&user_public_key).map_err(|e| sqlx::Error::Decode(e.into()))?;
        let event_type_str: String = row.try_get(EventIden::Type.to_string().as_str())?;
        let path: String = row.try_get(EventIden::Path.to_string().as_str())?;
        let path = StoragePath::new(&path).map_err(|e| sqlx::Error::Decode(e.into()))?;
        let created_at: NaiveDateTime = row.try_get(EventIden::CreatedAt.to_string().as_str())?;

        let content_hash_bytes: Option<Vec<u8>> =
            row.try_get(EventIden::ContentHash.to_string().as_str())?;

        let content_hash = content_hash_bytes.and_then(|bytes| {
            let hash_bytes: [u8; 32] = bytes.try_into().ok()?;
            Some(Hash::from_bytes(hash_bytes))
        });

        let event_type = match event_type_str.as_str() {
            "PUT" => {
                let hash = content_hash.unwrap_or_else(|| {
                    // This should never happen after m20251014 migration runs.
                    tracing::error!(
                        "PUT event {} has NULL content_hash - this indicates a database issue. Using zero hash as fallback.",
                        id
                    );
                    Hash::from_bytes([0; 32])
                });
                EventType::Put { content_hash: hash }
            }
            "DEL" => EventType::Delete,
            other => {
                return Err(sqlx::Error::Decode(
                    format!("Invalid event type: {}", other).into(),
                ))
            }
        };

        let entry_path = EntryPath::new(user_pubkey.clone(), path);
        Ok(EventEntity {
            id,
            event_type,
            user_id,
            user_pubkey,
            path: entry_path,
            created_at,
        })
    }
}
