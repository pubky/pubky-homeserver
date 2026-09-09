use crate::{
    persistence::{
        files::{FileIoError, FileStream},
        sql::{
            entry::{EntryEntity, EntryRepository},
            UnifiedExecutor,
        },
    },
    shared::webdav::EntryPath,
};
use bytes::Bytes;

use super::FileService;

impl FileService {
    /// Get the metadata of a file.
    pub async fn get_info(
        &self,
        path: &EntryPath,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<EntryEntity, FileIoError> {
        match EntryRepository::get_by_path(path, executor).await {
            Ok(entry) => Ok(entry),
            Err(sqlx::Error::RowNotFound) => Err(FileIoError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// Get the content of a file as a stream of bytes.
    /// The stream is chunked.
    /// Errors if the file does not exist.
    #[cfg(test)]
    pub async fn get_stream(&self, path: &EntryPath) -> Result<FileStream, FileIoError> {
        let entry = self.get_info(path, &mut self.db.pool().into()).await?;
        self.get_entry_stream(&entry).await
    }

    /// Get the content selected by an already-loaded logical entry.
    /// Reads may fail if cleanup removes the blob after its retention period.
    pub(crate) async fn get_entry_stream(
        &self,
        entry: &EntryEntity,
    ) -> Result<FileStream, FileIoError> {
        self.opendal
            .get_stream_by_key(&Self::backend_key(entry))
            .await
    }

    /// Read one byte range selected by an already-loaded logical entry.
    pub(crate) async fn get_entry_range(
        &self,
        entry: &EntryEntity,
        range: std::ops::Range<u64>,
    ) -> Result<Bytes, FileIoError> {
        self.opendal
            .get_range_by_key(&Self::backend_key(entry), range)
            .await
    }
}
