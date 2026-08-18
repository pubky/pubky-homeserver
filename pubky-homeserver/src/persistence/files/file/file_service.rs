#[cfg(test)]
use crate::AppContext;
use crate::{
    persistence::{
        files::events::EventsService,
        sql::{
            entry::{EntryEntity, EntryRepository},
            SqlDb, UnifiedExecutor,
        },
    },
    shared::webdav::EntryPath,
    ConfigToml,
};
use bytes::Bytes;
use futures_util::Stream;
#[cfg(test)]
use futures_util::StreamExt;
#[cfg(test)]
use opendal::Buffer;
use std::path::Path;

use super::super::{FileIoError, FileStream, OpendalService, WriteStreamError};

/// The file service creates an abstraction layer over the SqlDb and OpenDAL services.
/// This way, files can be managed in a unified way.
#[derive(Debug, Clone)]
pub struct FileService {
    pub(crate) opendal: OpendalService,
    pub(crate) db: SqlDb,
}

impl FileService {
    pub fn new(opendal_service: OpendalService, db: SqlDb) -> Self {
        Self {
            opendal: opendal_service,
            db,
        }
    }

    pub fn new_from_config(
        config: &ConfigToml,
        data_directory: &Path,
        db: SqlDb,
        events_service: EventsService,
        user_service: crate::services::user_service::UserService,
    ) -> Result<Self, FileIoError> {
        let opendal_service = OpendalService::new_from_config(
            &config.storage,
            data_directory,
            db.clone(),
            events_service,
            user_service,
        )?;
        Ok(Self::new(opendal_service, db))
    }

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
    pub async fn get_stream(&self, path: &EntryPath) -> Result<FileStream, FileIoError> {
        let stream: FileStream = self.opendal.get_stream(path).await?;
        Ok(stream)
    }

    /// Write a file to the database and storage depending on the selected target location.
    pub async fn write_stream(
        &self,
        path: &EntryPath,
        stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
    ) -> Result<EntryEntity, FileIoError> {
        self.opendal.write_stream(path, stream).await?;
        match EntryRepository::get_by_path(path, &mut self.db.pool().into()).await {
            Ok(entry) => Ok(entry),
            Err(sqlx::Error::RowNotFound) => Err(FileIoError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete a file.
    pub async fn delete(&self, path: &EntryPath) -> Result<(), FileIoError> {
        if !self.opendal.exists(path).await? {
            return Err(FileIoError::NotFound);
        }
        self.opendal.delete(path).await?;
        Ok(())
    }

    /// Delete a file bypassing write-path restrictions.
    /// Used by the admin `/webdav` REST delete route; the `/dav` WebDAV handler
    /// already uses `admin_operator` directly and does not need this.
    pub async fn admin_delete(&self, path: &EntryPath) -> Result<(), FileIoError> {
        if !self.opendal.exists(path).await? {
            return Err(FileIoError::NotFound);
        }
        self.opendal.admin_delete(path).await?;
        Ok(())
    }

    /// Copy a file from `from` to `to` (same tenant).
    ///
    /// Composed from `get_stream` + `write_stream` so that write finalization
    /// (quota, entry upsert, PUT event) runs for the destination. Overwrites
    /// the destination if it exists.
    pub async fn copy(&self, from: &EntryPath, to: &EntryPath) -> Result<EntryEntity, FileIoError> {
        use futures_util::StreamExt;
        let stream = self
            .get_stream(from)
            .await?
            .map(|chunk| chunk.map_err(|e| WriteStreamError::Other(e.into())));
        self.write_stream(to, stream).await
    }

    /// Move a file from `from` to `to` (same tenant).
    ///
    /// Composed from `copy` + `delete` so that finalization runs for both the
    /// destination (PUT event, quota increase) and the source (DEL event,
    /// quota decrease).
    pub async fn move_file(
        &self,
        from: &EntryPath,
        to: &EntryPath,
    ) -> Result<EntryEntity, FileIoError> {
        let entry = self.copy(from, to).await?;
        self.delete(from).await?;
        Ok(entry)
    }

    /// Recursively delete a folder and all its descendants.
    ///
    /// Lists the folder's entries page by page and deletes each file
    /// individually, so every file goes through delete finalization (entry
    /// removal, quota decrease, DEL event). Synchronous: for very large trees
    /// the caller may run into an HTTP timeout.
    ///
    /// Deleting a non-existing or empty folder will NOT return an error.
    pub async fn delete_folder(&self, path: &EntryPath) -> Result<(), FileIoError> {
        const PAGE_SIZE: u16 = 1000;
        // No cursor: deleted entries disappear from subsequent pages, so
        // re-listing from the start eventually drains the folder.
        loop {
            let page = EntryRepository::list_deep(
                path,
                Some(PAGE_SIZE),
                None,
                false,
                &mut self.db.pool().into(),
            )
            .await?;
            if page.is_empty() {
                return Ok(());
            }
            for entry_path in page {
                // Unconditional delete: finalization removes the SQL row even
                // when the blob is already gone, so every listed entry makes
                // progress and the loop always terminates.
                self.opendal.delete(&entry_path).await?;
            }
        }
    }
}

#[cfg(test)]
impl FileService {
    pub fn new_from_context(context: &AppContext) -> Result<Self, FileIoError> {
        let opendal_service = OpendalService::new(context)?;
        Ok(Self::new(opendal_service, context.sql_db.clone()))
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

    /// Write a file to the database and storage depending on the selected target location.
    pub async fn write(&self, path: &EntryPath, data: Buffer) -> Result<EntryEntity, FileIoError> {
        let stream = futures_util::stream::iter(vec![Ok(Bytes::from(data.to_vec()))]);
        let entry = self.write_stream(path, stream).await?;
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use crate::{services::user_service::FILE_METADATA_SIZE, shared::webdav::StoragePath};
    use futures_lite::StreamExt;

    use super::*;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_write_get_delete_db_and_opendal() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();

        let user = user_service.create(&pubkey).await.unwrap();

        // User should not have any data usage yet
        assert_eq!(user.used_bytes, 0);

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());

        // Test getting a non-existent file
        match file_service.get_stream(&path).await {
            Ok(_) => panic!("Should error for non-existent file"),
            Err(FileIoError::NotFound) => {}
            Err(e) => panic!("Should error for non-existent file: {}", e),
        };

        // Test data
        let test_data = b"Hello, world! This is test data for the get method.";
        let chunks = vec![Ok(Bytes::from(test_data.as_slice()))];
        let stream = futures_util::stream::iter(chunks);

        file_service.write_stream(&path, stream).await.unwrap();
        let user = user_service.get(&pubkey).await.unwrap();
        assert_eq!(
            user.used_bytes,
            test_data.len() as u64 + FILE_METADATA_SIZE,
            "Data usage should be the size of the file"
        );

        // Get the file content and verify
        let mut stream = file_service
            .get_stream(&path)
            .await
            .expect("File should exist");
        let mut collected_data = Vec::new();
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.unwrap();
            collected_data.extend_from_slice(&chunk);
        }

        assert_eq!(
            collected_data,
            test_data.to_vec(),
            "Content should match original data"
        );

        file_service.delete(&path).await.unwrap();
        let result = file_service.get_stream(&path).await;
        assert!(result.is_err(), "Should error for deleted file");
        let user = user_service.get(&pubkey).await.unwrap();
        assert_eq!(
            user.used_bytes, 0,
            "Data usage should be 0 after deleting file"
        );

        // Test OpenDal location
        let path = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/test_opendal.txt").unwrap(),
        );
        let chunks = vec![Ok(Bytes::from(test_data.as_slice()))];
        let stream = futures_util::stream::iter(chunks);
        file_service.write_stream(&path, stream).await.unwrap();
        let user = user_service.get(&pubkey).await.unwrap();
        assert_eq!(
            user.used_bytes,
            test_data.len() as u64 + FILE_METADATA_SIZE,
            "Data usage should be the size of the file"
        );

        // Get the file content and verify
        let mut stream = file_service
            .get_stream(&path)
            .await
            .expect("File should exist");
        let mut collected_data = Vec::new();
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.unwrap();
            collected_data.extend_from_slice(&chunk);
        }

        assert_eq!(
            collected_data,
            test_data.to_vec(),
            "Content should match original data for OpenDal location"
        );

        // Clean up
        file_service.delete(&path).await.unwrap();
        let result = file_service.get_stream(&path).await;
        assert!(result.is_err(), "Should error for deleted file");
        let user = user_service.get(&pubkey).await.unwrap();
        assert_eq!(
            user.used_bytes, 0,
            "Data usage should be 0 after deleting file"
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_write_get_basic() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create(&pubkey).await.unwrap();

        let test_data = b"Hello, world!";
        let buffer = Buffer::from(test_data.as_slice());

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
        file_service.write(&path, buffer.clone()).await.unwrap();
        let content = file_service.get(&path).await.unwrap();
        assert_eq!(content.as_ref(), test_data);

        // Test OpenDal
        let opendal_path = EntryPath::new(pubkey, StoragePath::new("/test_opendal.txt").unwrap());
        file_service.write(&opendal_path, buffer).await.unwrap();
        let content = file_service.get(&opendal_path).await.unwrap();
        assert_eq!(content.as_ref(), test_data);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_data_usage_update_basic() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create_with_quota_mb(&pubkey, 1).await;

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
        let test_data = vec![1u8; 1024];
        let buffer = Buffer::from(test_data.clone());

        file_service.write(&path, buffer).await.unwrap();
        let user = user_service.get(&pubkey).await.unwrap();
        assert_eq!(user.used_bytes, test_data.len() as u64 + FILE_METADATA_SIZE);

        // Delete the file and check if the data usage is updated correctly.
        file_service.delete(&path).await.unwrap();
        let user = user_service.get(&pubkey).await.unwrap();
        assert_eq!(user.used_bytes, 0);
    }

    /// Override and existing entry and check if the data usage is updated correctly.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_data_usage_override_existing_entry() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create_with_quota_mb(&pubkey, 1).await;

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
        let test_data = vec![1u8; 1024];
        let buffer = Buffer::from(test_data.clone());

        file_service.write(&path, buffer).await.unwrap();

        let test_data2 = vec![2u8; 1024];
        let buffer2 = Buffer::from(test_data2.clone());
        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());

        file_service.write(&path, buffer2).await.unwrap();

        assert_eq!(
            user_service.get(&pubkey).await.unwrap().used_bytes,
            test_data2.len() as u64 + FILE_METADATA_SIZE
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_rejects_descendant_when_exact_file_exists() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let db = context.sql_db.clone();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create(&pubkey).await.unwrap();

        let exact_path = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/app/foo").unwrap());
        let descendant_path = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/app/foo/bar.json").unwrap(),
        );

        file_service
            .write(&exact_path, Buffer::from(vec![1; 10]))
            .await
            .unwrap();
        let err = file_service
            .write(&descendant_path, Buffer::from(vec![2; 10]))
            .await
            .expect_err("descendant write should be rejected");

        assert!(matches!(err, FileIoError::PathCollision));
        file_service
            .get_info(&descendant_path, &mut db.pool().into())
            .await
            .expect_err("Rejected descendant should not create metadata");
        file_service
            .get(&descendant_path)
            .await
            .expect_err("Rejected descendant should not create a blob");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_rejects_exact_file_when_descendant_exists() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let db = context.sql_db.clone();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create(&pubkey).await.unwrap();

        let exact_path = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/app/foo").unwrap());
        let descendant_path =
            EntryPath::new(pubkey, StoragePath::new("/pub/app/foo/bar.json").unwrap());

        file_service
            .write(&descendant_path, Buffer::from(vec![1; 10]))
            .await
            .unwrap();
        let err = file_service
            .write(&exact_path, Buffer::from(vec![2; 10]))
            .await
            .expect_err("exact-file write should be rejected");

        assert!(matches!(err, FileIoError::PathCollision));
        file_service
            .get_info(&exact_path, &mut db.pool().into())
            .await
            .expect_err("Rejected exact file should not create metadata");
        file_service
            .get(&exact_path)
            .await
            .expect_err("Rejected exact file should not create a blob");
    }

    /// Write a file that is exactly at the quota and check if the data usage is updated correctly.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_data_usage_exactly_to_quota() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create_with_quota_mb(&pubkey, 1).await;

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
        let test_data = vec![1u8; 1024 * 1024 - FILE_METADATA_SIZE as usize];
        let buffer = Buffer::from(test_data.clone());

        file_service.write(&path, buffer).await.unwrap();

        assert_eq!(
            user_service.get(&pubkey).await.unwrap().used_bytes,
            test_data.len() as u64 + FILE_METADATA_SIZE
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_data_usage_above_quota() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create_with_quota_mb(&pubkey, 1).await;

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
        let test_data = vec![1u8; 1024 * 1024 + 1];
        let buffer = Buffer::from(test_data.clone());

        match file_service.write(&path, buffer).await {
            Ok(_) => panic!("Should error for file above quota"),
            Err(FileIoError::DiskSpaceQuotaExceeded) => {} // All good
            Err(e) => {
                panic!("Should error for file above quota: {:?}", e);
            }
        }

        assert_eq!(user_service.get(&pubkey).await.unwrap().used_bytes, 0);
    }

    /// Override and existing entry and check if the data usage is updated correctly.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_data_usage_override_existing_above_quota() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create_with_quota_mb(&pubkey, 1).await;

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
        let test_data = vec![1u8; 1024];
        let buffer = Buffer::from(test_data.clone());

        file_service.write(&path, buffer).await.unwrap();

        let test_data2 = vec![2u8; 1024 * 1024 + 1];
        let buffer2 = Buffer::from(test_data2.clone());
        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());

        match file_service.write(&path, buffer2).await {
            Ok(_) => panic!("Should error for file above quota"),
            Err(FileIoError::DiskSpaceQuotaExceeded) => {} // All good
            Err(e) => {
                panic!("Should error for file above quota: {:?}", e);
            }
        }

        assert_eq!(
            user_service.get(&pubkey).await.unwrap().used_bytes,
            test_data.len() as u64 + FILE_METADATA_SIZE
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_copy_file() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create(&pubkey).await.unwrap();

        let from = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/app/from.txt").unwrap(),
        );
        let to = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/app/to.txt").unwrap());
        let data = Buffer::from(b"copy me".as_slice());

        file_service.write(&from, data.clone()).await.unwrap();
        file_service.copy(&from, &to).await.unwrap();

        // Source untouched, destination has the content.
        assert_eq!(
            file_service.get(&from).await.unwrap(),
            data.to_vec().as_slice()
        );
        assert_eq!(
            file_service.get(&to).await.unwrap(),
            data.to_vec().as_slice()
        );

        // Quota counts both files.
        let per_file = data.len() as u64 + FILE_METADATA_SIZE;
        assert_eq!(
            user_service.get(&pubkey).await.unwrap().used_bytes,
            per_file * 2
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_copy_missing_source_is_not_found() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create(&pubkey).await.unwrap();

        let from = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/app/none.txt").unwrap(),
        );
        let to = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/app/to.txt").unwrap());

        let err = file_service
            .copy(&from, &to)
            .await
            .expect_err("missing source");
        assert!(matches!(err, FileIoError::NotFound));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_move_file() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create(&pubkey).await.unwrap();

        let from = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/app/from.txt").unwrap(),
        );
        let to = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/app/to.txt").unwrap());
        let data = Buffer::from(b"move me".as_slice());

        file_service.write(&from, data.clone()).await.unwrap();
        file_service.move_file(&from, &to).await.unwrap();

        // Source gone, destination has the content.
        file_service
            .get(&from)
            .await
            .expect_err("source should be deleted after move");
        assert_eq!(
            file_service.get(&to).await.unwrap(),
            data.to_vec().as_slice()
        );

        // Quota counts only the destination file.
        assert_eq!(
            user_service.get(&pubkey).await.unwrap().used_bytes,
            data.len() as u64 + FILE_METADATA_SIZE
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_delete_folder_recursive() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create(&pubkey).await.unwrap();

        let data = Buffer::from(b"x".as_slice());
        let inside = [
            "/pub/app/folder/a.txt",
            "/pub/app/folder/sub/b.txt",
            "/pub/app/folder/sub/deep/c.txt",
        ];
        let outside = "/pub/app/other.txt";
        for p in inside.iter().chain([outside].iter()) {
            let path = EntryPath::new(pubkey.clone(), StoragePath::new(p).unwrap());
            file_service.write(&path, data.clone()).await.unwrap();
        }
        assert_eq!(
            user_service.get(&pubkey).await.unwrap().used_bytes,
            4 * (data.len() as u64 + FILE_METADATA_SIZE)
        );

        let folder = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/app/folder/").unwrap(),
        );
        file_service.delete_folder(&folder).await.unwrap();

        for p in inside {
            let path = EntryPath::new(pubkey.clone(), StoragePath::new(p).unwrap());
            file_service
                .get(&path)
                .await
                .expect_err("folder contents should be deleted");
        }
        let outside_path = EntryPath::new(pubkey.clone(), StoragePath::new(outside).unwrap());
        assert_eq!(
            file_service.get(&outside_path).await.unwrap(),
            data.to_vec().as_slice(),
            "files outside the folder must remain"
        );
        assert_eq!(
            user_service.get(&pubkey).await.unwrap().used_bytes,
            data.len() as u64 + FILE_METADATA_SIZE
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_delete_folder_empty_or_missing_is_ok() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create(&pubkey).await.unwrap();

        let folder = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/app/none/").unwrap());
        file_service
            .delete_folder(&folder)
            .await
            .expect("deleting a missing folder should be a no-op");
    }
}
