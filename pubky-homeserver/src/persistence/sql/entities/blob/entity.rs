use sqlx::{postgres::PgRow, FromRow, Row};

/// One worker's ownership of a queued backend deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobGarbageEntity {
    pub blob_key: String,
    pub(super) claim_token: String,
}

impl FromRow<'_, PgRow> for BlobGarbageEntity {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            blob_key: row.try_get("blob_key")?,
            claim_token: row.try_get("claim_token")?,
        })
    }
}
