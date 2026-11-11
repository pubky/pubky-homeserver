#[cfg(test)]
use crate::AppContext;
use crate::{
    persistence::{
        files::write_finalization_layer::{resolve_storage_max_bytes, would_exceed_limit},
        sql::{
            entry::{EntryEntity, EntryRepository},
            user::UserEntity,
            SqlDb,
        },
    },
    services::{events_service::EventsService, user_service::FILE_METADATA_SIZE},
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
    /// The storage limit for users without their own, in megabytes. `None` is unlimited.
    default_storage_mb: Option<u64>,
}

impl FileService {
    pub fn new(
        opendal_service: OpendalService,
        db: SqlDb,
        default_storage_mb: Option<u64>,
    ) -> Self {
        Self {
            opendal: opendal_service,
            db,
            default_storage_mb,
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
        Ok(Self::new(
            opendal_service,
            db,
            config.storage.default_quota_mb,
        ))
    }

    /// Get the metadata of a file.
    pub async fn get_info(&self, path: &EntryPath) -> Result<EntryEntity, FileIoError> {
        match EntryRepository::get_by_path(path, &mut self.db.pool().into()).await {
            Ok(entry) => Ok(entry),
            Err(sqlx::Error::RowNotFound) => Err(FileIoError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// List the entries under `dir`, as paths, in path order.
    ///
    /// `shallow` lists the direct children only, with sub-directories as
    /// paths ending in `/`; otherwise every file below `dir` is listed.
    /// `cursor` is the path to continue after. Errors with
    /// [`FileIoError::NotFound`] when nothing is stored under `dir`.
    pub async fn list(
        &self,
        dir: &EntryPath,
        limit: Option<u16>,
        cursor: Option<EntryPath>,
        reverse: bool,
        shallow: bool,
    ) -> Result<Vec<EntryPath>, FileIoError> {
        let mut executor = self.db.pool().into();
        if !EntryRepository::contains_directory(dir, &mut executor).await? {
            return Err(FileIoError::NotFound);
        }
        let entries = if shallow {
            EntryRepository::list_shallow(dir, limit, cursor, reverse, &mut executor).await?
        } else {
            EntryRepository::list_deep(dir, limit, cursor, reverse, &mut executor).await?
        };
        Ok(entries)
    }

    /// Reject a write of `content_length` bytes to `path` up front when it
    /// would exceed the user's storage quota, so the body need not be read
    /// first. The write path enforces the quota again on the actual bytes.
    ///
    /// Passes when there is no size hint, no quota, or the hint fits.
    pub async fn check_size_hint(
        &self,
        user: &UserEntity,
        content_length: Option<u64>,
        path: &EntryPath,
    ) -> Result<(), FileIoError> {
        let Some(content_length) = content_length else {
            return Ok(());
        };

        let existing_entry = self.get_info(path).await.ok();
        let existing_entry_bytes = existing_entry.as_ref().map_or(0, |e| e.content_length);
        let is_new_file = existing_entry.is_none();

        let mut bytes_delta = content_length as i64 - existing_entry_bytes as i64;
        if is_new_file {
            bytes_delta += FILE_METADATA_SIZE as i64;
        }

        let max_bytes = resolve_storage_max_bytes(user, self.default_storage_mb);
        if would_exceed_limit(user.used_bytes, bytes_delta, max_bytes) {
            return Err(FileIoError::DiskSpaceQuotaExceeded);
        }
        Ok(())
    }

    /// The size of the stored blob, for the `Content-Length` of a response
    /// that serves it.
    ///
    /// The entry row also records a length, but a database failure after
    /// publication leaves the row describing the previous content (see the
    /// [`files`](crate::persistence::files) module docs). A response sized
    /// from the row would then cut the body short, so `GET` and `HEAD` report
    /// the blob's size instead. Errors if the file does not exist.
    pub async fn blob_length(&self, path: &EntryPath) -> Result<u64, FileIoError> {
        self.opendal.blob_length(path).await
    }

    /// The size of the stored blob and a stream of its bytes, sized by one
    /// `stat` so a response's `Content-Length` and body agree. See
    /// [`Self::blob_length`] for why the size is not the entry row's.
    /// Errors if the file does not exist.
    pub async fn get_sized_stream(
        &self,
        path: &EntryPath,
    ) -> Result<(u64, FileStream), FileIoError> {
        self.opendal.get_sized_stream(path).await
    }

    /// Write a file to the database and storage depending on the selected target location.
    pub async fn write_stream(
        &self,
        path: &EntryPath,
        stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
    ) -> Result<EntryEntity, FileIoError> {
        self.opendal.write_stream(path, stream).await?;
        self.get_info(path).await
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
}

#[cfg(test)]
impl FileService {
    pub fn new_from_context(context: &AppContext) -> Result<Self, FileIoError> {
        let opendal_service = OpendalService::new(context)?;
        Ok(Self::new(
            opendal_service,
            context.sql_db.clone(),
            context.config_toml.storage.default_quota_mb,
        ))
    }

    /// Get the content of a file as a stream of bytes.
    /// The stream is chunked.
    /// Errors if the file does not exist.
    pub async fn get_stream(&self, path: &EntryPath) -> Result<FileStream, FileIoError> {
        self.opendal.get_stream(path).await
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
            .get_info(&descendant_path)
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
            .get_info(&exact_path)
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
    async fn test_list_shallow_deep_and_missing_directory() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&pubkey).await.unwrap();

        let path = |p: &str| EntryPath::new(pubkey.clone(), StoragePath::new(p).unwrap());
        for file in ["/pub/app/a.txt", "/pub/app/sub/b.txt"] {
            file_service
                .write(&path(file), Buffer::from(b"x".as_slice()))
                .await
                .unwrap();
        }

        let dir = path("/pub/app/");
        let shallow = file_service
            .list(&dir, None, None, false, true)
            .await
            .unwrap();
        assert_eq!(
            shallow
                .iter()
                .map(|e| e.path().as_str())
                .collect::<Vec<_>>(),
            ["/pub/app/a.txt", "/pub/app/sub/"]
        );
        let deep = file_service
            .list(&dir, None, None, false, false)
            .await
            .unwrap();
        assert_eq!(
            deep.iter().map(|e| e.path().as_str()).collect::<Vec<_>>(),
            ["/pub/app/a.txt", "/pub/app/sub/b.txt"]
        );

        match file_service
            .list(&path("/pub/missing/"), None, None, false, true)
            .await
        {
            Err(FileIoError::NotFound) => {}
            other => panic!("a directory with no entries should be NotFound: {other:?}"),
        }
    }

    /// Build the args and call `check_size_hint` for a path under `user`.
    async fn check_hint(
        file_service: &FileService,
        user: &UserEntity,
        path: &str,
        size_hint: Option<u64>,
    ) -> Result<(), FileIoError> {
        let entry_path = EntryPath::new(user.public_key.clone(), StoragePath::new(path).unwrap());
        file_service
            .check_size_hint(user, size_hint, &entry_path)
            .await
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_no_size_hint_always_ok() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pk = pubky_common::crypto::Keypair::random().public_key();
        let user = context.user_service.create_with_quota_mb(&pk, 1).await;

        // No size hint → always OK regardless of quota
        check_hint(&file_service, &user, "/test.txt", None)
            .await
            .expect("no size hint should always pass");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_new_file_accounts_for_metadata_overhead() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pk = pubky_common::crypto::Keypair::random().public_key();
        let user = context.user_service.create_with_quota_mb(&pk, 1).await;

        let one_mb = 1024u64 * 1024;
        let max_content = one_mb - FILE_METADATA_SIZE;

        // Exactly at limit: content + metadata == quota → OK
        check_hint(&file_service, &user, "/test.txt", Some(max_content))
            .await
            .expect("content + metadata exactly at quota should pass");

        // One byte over: content + metadata > quota → fail
        match check_hint(&file_service, &user, "/test.txt", Some(max_content + 1)).await {
            Err(FileIoError::DiskSpaceQuotaExceeded) => {}
            other => panic!("content + metadata one byte over quota should fail: {other:?}"),
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_unlimited_quota_allows_anything() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        // No system default → unlimited for Default users
        let pk = pubky_common::crypto::Keypair::random().public_key();
        let user = context.user_service.create(&pk).await.unwrap();

        // Even a huge hint should pass with unlimited quota
        check_hint(
            &file_service,
            &user,
            "/test.txt",
            Some(10 * 1024 * 1024 * 1024),
        )
        .await
        .expect("unlimited quota should accept any size");
    }
}
