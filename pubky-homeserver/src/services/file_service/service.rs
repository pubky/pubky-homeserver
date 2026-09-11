use crate::{
    persistence::{
        files::{events::EventsService, FileIoError, OpendalService},
        sql::{entities::blob::BlobRepository, entry::EntryEntity, SqlDb},
    },
    services::user_service::UserService,
    ConfigToml,
};
#[cfg(test)]
use crate::{shared::webdav::EntryPath, AppContext};
#[cfg(test)]
use bytes::Bytes;
#[cfg(test)]
use futures_util::StreamExt;
#[cfg(test)]
use opendal::Buffer;
use std::path::Path;

/// Coordinates logical file entries in PostgreSQL with immutable backend blobs.
#[derive(Debug, Clone)]
pub struct FileService {
    pub(crate) opendal: OpendalService,
    pub(crate) db: SqlDb,
    pub(super) events_service: EventsService,
    pub(super) user_service: UserService,
    pub(super) default_storage_mb: Option<u64>,
    pub(super) blob_prefix: String,
}

impl FileService {
    pub fn new(
        opendal_service: OpendalService,
        db: SqlDb,
        events_service: EventsService,
        user_service: UserService,
        default_storage_mb: Option<u64>,
        blob_prefix: String,
    ) -> Self {
        Self {
            opendal: opendal_service,
            db,
            events_service,
            user_service,
            default_storage_mb,
            blob_prefix,
        }
    }

    pub async fn new_from_config(
        config: &ConfigToml,
        data_directory: &Path,
        db: SqlDb,
        events_service: EventsService,
        user_service: crate::services::user_service::UserService,
    ) -> Result<Self, FileIoError> {
        let opendal_service = OpendalService::new_from_config(&config.storage, data_directory)?;
        let namespace = BlobRepository::storage_namespace(&mut db.pool().into()).await?;
        Ok(Self::new(
            opendal_service,
            db,
            events_service,
            user_service,
            config.storage.default_quota_mb,
            format!("__pubky/blobs/{namespace}/"),
        ))
    }

    pub(super) fn backend_key(entry: &EntryEntity) -> String {
        entry
            .blob_key
            .clone()
            .unwrap_or_else(|| entry.path.as_str().to_string())
    }
}

#[cfg(test)]
impl FileService {
    pub fn new_from_context(context: &AppContext) -> Result<Self, FileIoError> {
        let opendal_service = OpendalService::new(context)?;
        Ok(Self::new(
            opendal_service,
            context.sql_db.clone(),
            context.events_service.clone(),
            context.user_service.clone(),
            context.config_toml.storage.default_quota_mb,
            context.file_service.blob_prefix.clone(),
        ))
    }

    /// Get the content of a file as bytes.
    /// Errors if the file does not exist.
    pub async fn get(&self, path: &EntryPath) -> Result<Bytes, FileIoError> {
        let mut stream = self.get_stream(path).await?;
        let mut collected_data = Vec::new();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            collected_data.extend_from_slice(&chunk);
        }

        Ok(Bytes::from(collected_data))
    }

    /// Write a complete file through the streamed storage path.
    pub async fn write(&self, path: &EntryPath, data: Buffer) -> Result<EntryEntity, FileIoError> {
        let stream = futures_util::stream::iter(vec![Ok(Bytes::from(data.to_vec()))]);
        let entry = self.write_stream(path, stream).await?;
        Ok(entry)
    }
}

#[cfg(test)]
mod tests;
