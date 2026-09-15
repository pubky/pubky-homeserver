//! Database-backed WebDAV view over logical homeserver files.
//!
//! Directories are derived from file paths; empty directories are not persisted.

use std::{
    collections::HashMap,
    fmt,
    io::SeekFrom,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::{Buf, Bytes};
use dav_server::{
    davpath::DavPath,
    fs::{
        DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsFuture, FsStream, OpenOptions,
        ReadDirMeta,
    },
};
use futures_util::{FutureExt, StreamExt};

use crate::{
    persistence::{files::FileIoError, sql::entry::EntryEntity},
    services::file_service::FileService,
    shared::webdav::{EntryPath, StoragePath},
};

const DAV_READ_AHEAD_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub(crate) struct AdminDavFileSystem {
    file_service: FileService,
}

impl AdminDavFileSystem {
    pub(crate) fn new(file_service: FileService) -> Self {
        Self { file_service }
    }

    fn path_string(path: &DavPath) -> Result<String, FsError> {
        String::from_utf8(path.as_bytes().to_vec())
            .map(|path| path.trim_matches('/').to_string())
            .map_err(|_| FsError::GeneralFailure)
    }

    fn entry_path(path: &DavPath) -> Result<EntryPath, FsError> {
        let path = Self::path_string(path)?;
        EntryPath::from_str(&path).map_err(|_| FsError::NotFound)
    }

    pub(crate) fn file_entry_path(path: &DavPath) -> Result<EntryPath, FsError> {
        if path.as_bytes().ends_with(b"/") {
            return Err(FsError::NotImplemented);
        }
        let entry_path = Self::entry_path(path)?;
        if entry_path.path().is_file() {
            Ok(entry_path)
        } else {
            Err(FsError::NotImplemented)
        }
    }

    pub(crate) fn directory_entry_path(path: &DavPath) -> Result<EntryPath, FsError> {
        let path_string = Self::path_string(path)?;
        if path_string.is_empty() {
            return Err(FsError::Forbidden);
        }
        if path_string.contains('/') {
            return EntryPath::from_str(&path_string).map_err(|_| FsError::NotFound);
        }
        let pubkey = pubky_common::crypto::PublicKey::try_from_z32(&path_string)
            .map_err(|_| FsError::NotFound)?;
        Ok(EntryPath::new(
            pubkey,
            StoragePath::new("/").map_err(|_| FsError::NotFound)?,
        ))
    }

    pub(crate) async fn metadata_for_path(
        &self,
        path: &DavPath,
    ) -> Result<AdminDavMetadata, FsError> {
        let directory_requested = path.as_bytes().ends_with(b"/");
        let path_string = Self::path_string(path)?;
        if path_string.is_empty() {
            return Ok(AdminDavMetadata::directory());
        }

        if !path_string.contains('/') {
            let exists = self
                .file_service
                .admin_users()
                .await
                .map_err(map_file_error)?
                .into_iter()
                .any(|user| user == path_string);
            return if exists {
                Ok(AdminDavMetadata::directory())
            } else {
                Err(FsError::NotFound)
            };
        }

        let entry_path = EntryPath::from_str(&path_string).map_err(|_| FsError::NotFound)?;
        if !directory_requested {
            match self
                .file_service
                .get_info(&entry_path, &mut self.file_service.db.pool().into())
                .await
            {
                Ok(entry) => return Ok(AdminDavMetadata::file(&entry)),
                Err(FileIoError::NotFound) => {}
                Err(error) => return Err(map_file_error(error)),
            }
        }
        if self
            .file_service
            .contains_directory(&entry_path)
            .await
            .map_err(map_file_error)?
        {
            Ok(AdminDavMetadata::directory())
        } else {
            Err(FsError::NotFound)
        }
    }
}

impl DavFileSystem for AdminDavFileSystem {
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        async move {
            if options.write || options.append {
                return Err(FsError::Forbidden);
            }
            let entry_path = Self::file_entry_path(path)?;
            let entry = self
                .file_service
                .get_info(&entry_path, &mut self.file_service.db.pool().into())
                .await
                .map_err(map_file_error)?;
            Ok(Box::new(AdminDavFile {
                file_service: self.file_service.clone(),
                entry,
                position: 0,
                buffer: Bytes::new(),
            }) as Box<dyn DavFile>)
        }
        .boxed()
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        async move {
            let path_string = Self::path_string(path)?;
            let entries = if path_string.is_empty() {
                self.file_service
                    .admin_users()
                    .await
                    .map_err(map_file_error)?
                    .into_iter()
                    .map(|name| AdminDavDirEntry {
                        name,
                        metadata: AdminDavMetadata::directory(),
                    })
                    .collect()
            } else {
                let base = Self::directory_entry_path(path)?;
                let children = self
                    .file_service
                    .list_shallow_all(&base)
                    .await
                    .map_err(map_file_error)?;
                let files = children
                    .iter()
                    .filter(|child| child.path().is_file())
                    .cloned()
                    .collect::<Vec<_>>();
                let mut file_metadata = self
                    .file_service
                    .get_info_many(&files)
                    .await
                    .map_err(map_file_error)?
                    .into_iter()
                    .map(|entry| {
                        (
                            entry.path.path().as_str().to_string(),
                            AdminDavMetadata::file(&entry),
                        )
                    })
                    .collect::<HashMap<_, _>>();
                let mut entries = Vec::new();
                for child in children {
                    let name = child
                        .path()
                        .as_str()
                        .trim_end_matches('/')
                        .rsplit('/')
                        .next()
                        .unwrap_or_default()
                        .to_string();
                    let is_directory = child.path().is_directory();
                    let metadata = if is_directory {
                        AdminDavMetadata::directory()
                    } else {
                        file_metadata
                            .remove(child.path().as_str())
                            .ok_or(FsError::NotFound)?
                    };
                    entries.push(AdminDavDirEntry { name, metadata });
                }
                entries
            };

            Ok(futures_util::stream::iter(
                entries
                    .into_iter()
                    .map(|entry| Ok(Box::new(entry) as Box<dyn DavDirEntry>)),
            )
            .boxed())
        }
        .boxed()
    }

    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        async move {
            self.metadata_for_path(path)
                .await
                .map(|metadata| Box::new(metadata) as Box<dyn DavMetaData>)
        }
        .boxed()
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            self.file_service
                .admin_delete(&Self::file_entry_path(path)?)
                .await
                .map_err(map_file_error)
        }
        .boxed()
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            let entry_path = Self::directory_entry_path(path)?;
            if self
                .file_service
                .contains_directory(&entry_path)
                .await
                .map_err(map_file_error)?
            {
                Err(FsError::Forbidden)
            } else {
                Ok(())
            }
        }
        .boxed()
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            match self.metadata_for_path(path).await {
                Ok(_) => Err(FsError::Exists),
                // Recursive COPY uses this callback before writing the files that make the
                // implicit directory visible. External MKCOL requests are rejected by the route.
                Err(FsError::NotFound) => Ok(()),
                Err(error) => Err(error),
            }
        }
        .boxed()
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            self.file_service
                .admin_copy(&Self::file_entry_path(from)?, &Self::file_entry_path(to)?)
                .await
                .map_err(map_file_error)
        }
        .boxed()
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            if from.as_bytes().ends_with(b"/") {
                self.file_service
                    .admin_rename_directory(
                        &Self::directory_entry_path(from)?,
                        &Self::directory_entry_path(to)?,
                    )
                    .await
                    .map_err(map_file_error)
            } else {
                self.file_service
                    .admin_rename(&Self::file_entry_path(from)?, &Self::file_entry_path(to)?)
                    .await
                    .map_err(map_file_error)
            }
        }
        .boxed()
    }
}

struct AdminDavFile {
    file_service: FileService,
    entry: EntryEntity,
    position: u64,
    buffer: Bytes,
}

impl fmt::Debug for AdminDavFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminDavFile")
            .field("entry_path", &self.entry.path)
            .finish()
    }
}

impl DavFile for AdminDavFile {
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        async move { Ok(Box::new(AdminDavMetadata::file(&self.entry)) as Box<dyn DavMetaData>) }
            .boxed()
    }

    fn write_buf(&mut self, _buffer: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        async { Err(FsError::Forbidden) }.boxed()
    }

    fn write_bytes(&mut self, _bytes: Bytes) -> FsFuture<'_, ()> {
        async { Err(FsError::Forbidden) }.boxed()
    }

    fn read_bytes(&mut self, count: usize) -> FsFuture<'_, Bytes> {
        async move {
            if count == 0 || self.position >= self.entry.content_length {
                return Ok(Bytes::new());
            }
            if self.buffer.is_empty() {
                let end = self
                    .position
                    .saturating_add(DAV_READ_AHEAD_BYTES as u64)
                    .min(self.entry.content_length);
                self.buffer = self
                    .file_service
                    .get_entry_range(&self.entry, self.position..end)
                    .await
                    .map_err(map_file_error)?;
            }
            let bytes = self.buffer.split_to(count.min(self.buffer.len()));
            self.position = self.position.saturating_add(bytes.len() as u64);
            Ok(bytes)
        }
        .boxed()
    }

    fn seek(&mut self, position: SeekFrom) -> FsFuture<'_, u64> {
        async move {
            self.position = seek_position(self.position, self.entry.content_length, position)?;
            self.buffer = Bytes::new();
            Ok(self.position)
        }
        .boxed()
    }

    fn flush(&mut self) -> FsFuture<'_, ()> {
        async { Ok(()) }.boxed()
    }
}

fn seek_position(current: u64, length: u64, position: SeekFrom) -> Result<u64, FsError> {
    let (base, offset) = match position {
        SeekFrom::Start(position) => return Ok(position),
        SeekFrom::End(offset) => (length, offset),
        SeekFrom::Current(offset) => (current, offset),
    };
    if offset >= 0 {
        base.checked_add(offset as u64)
            .ok_or(FsError::GeneralFailure)
    } else {
        base.checked_sub(offset.unsigned_abs())
            .ok_or(FsError::GeneralFailure)
    }
}

#[derive(Debug, Clone)]
struct AdminDavDirEntry {
    name: String,
    metadata: AdminDavMetadata,
}

impl DavDirEntry for AdminDavDirEntry {
    fn name(&self) -> Vec<u8> {
        self.name.as_bytes().to_vec()
    }

    fn metadata(&self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let metadata = self.metadata.clone();
        async move { Ok(Box::new(metadata) as Box<dyn DavMetaData>) }.boxed()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AdminDavMetadata {
    length: u64,
    modified: SystemTime,
    directory: bool,
    etag: Option<String>,
}

impl AdminDavMetadata {
    fn directory() -> Self {
        Self {
            length: 0,
            modified: UNIX_EPOCH,
            directory: true,
            etag: None,
        }
    }

    pub(crate) fn file(entry: &EntryEntity) -> Self {
        let timestamp = entry.modified_at.and_utc().timestamp().max(0) as u64;
        Self {
            length: entry.content_length,
            modified: UNIX_EPOCH + Duration::from_secs(timestamp),
            directory: false,
            etag: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                entry.content_hash.as_bytes(),
            )),
        }
    }
}

impl DavMetaData for AdminDavMetadata {
    fn len(&self) -> u64 {
        self.length
    }

    fn modified(&self) -> Result<SystemTime, FsError> {
        Ok(self.modified)
    }

    fn is_dir(&self) -> bool {
        self.directory
    }

    fn etag(&self) -> Option<String> {
        self.etag.clone()
    }
}

fn map_file_error(error: FileIoError) -> FsError {
    match error {
        FileIoError::NotFound => FsError::NotFound,
        FileIoError::DiskSpaceQuotaExceeded => FsError::InsufficientStorage,
        FileIoError::WritePathForbidden => FsError::Forbidden,
        FileIoError::PathCollision => FsError::Exists,
        _ => FsError::GeneralFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppContext;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_remote_read_ahead_and_seek() {
        let context = AppContext::test().await;
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&public_key).await.unwrap();
        let entry_path = EntryPath::new(
            public_key.clone(),
            StoragePath::new("/pub/file.bin").unwrap(),
        );
        let content: Vec<u8> = (0..DAV_READ_AHEAD_BYTES * 2 + 17)
            .map(|i| (i % 251) as u8)
            .collect();
        context
            .file_service
            .write(&entry_path, opendal::Buffer::from(content.clone()))
            .await
            .unwrap();
        let filesystem = AdminDavFileSystem::new(context.file_service.clone());
        let path = DavPath::new(&format!("/{}/pub/file.bin", public_key.z32())).unwrap();
        let mut file = filesystem
            .open(
                &path,
                OpenOptions {
                    read: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(file.read_bytes(0).await.unwrap().is_empty());
        assert_eq!(context.file_service.opendal.range_read_count(), 0);
        let mut received = Vec::new();
        loop {
            let bytes = file.read_bytes(16 * 1024).await.unwrap();
            if bytes.is_empty() {
                break;
            }
            received.extend_from_slice(&bytes);
        }
        assert_eq!(received, content);
        assert_eq!(context.file_service.opendal.range_read_count(), 3);

        file.seek(SeekFrom::Start(7)).await.unwrap();
        assert_eq!(file.read_bytes(19).await.unwrap().as_ref(), &content[7..26]);
        file.seek(SeekFrom::Current(11)).await.unwrap();
        assert_eq!(
            file.read_bytes(19).await.unwrap().as_ref(),
            &content[37..56]
        );
        file.seek(SeekFrom::End(-3)).await.unwrap();
        assert_eq!(
            file.read_bytes(19).await.unwrap().as_ref(),
            &content[content.len() - 3..]
        );
        assert!(file.read_bytes(19).await.unwrap().is_empty());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_remote_read_fails_after_blob_cleanup() {
        let context = AppContext::test().await;
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&public_key).await.unwrap();
        let entry_path = EntryPath::new(
            public_key.clone(),
            StoragePath::new("/pub/file.bin").unwrap(),
        );
        let original = context
            .file_service
            .write(
                &entry_path,
                opendal::Buffer::from(vec![1; DAV_READ_AHEAD_BYTES + 1]),
            )
            .await
            .unwrap();
        let filesystem = AdminDavFileSystem::new(context.file_service.clone());
        let path = DavPath::new(&format!("/{}/pub/file.bin", public_key.z32())).unwrap();
        let mut file = filesystem
            .open(
                &path,
                OpenOptions {
                    read: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            file.read_bytes(DAV_READ_AHEAD_BYTES).await.unwrap().len(),
            DAV_READ_AHEAD_BYTES
        );
        context
            .file_service
            .write(
                &entry_path,
                opendal::Buffer::from(vec![2; DAV_READ_AHEAD_BYTES + 1]),
            )
            .await
            .unwrap();
        sqlx::query("UPDATE unreferenced_blobs SET eligible_at = statement_timestamp() WHERE state != 'uploading'")
            .execute(context.sql_db.pool())
            .await
            .unwrap();
        context.file_service.recover_blob_storage().await.unwrap();
        assert!(!context
            .file_service
            .opendal
            .blob_exists(original.blob_key.as_ref().unwrap())
            .await
            .unwrap());
        assert!(matches!(file.read_bytes(1).await, Err(FsError::NotFound)));
        assert_eq!(
            context
                .file_service
                .get(&entry_path)
                .await
                .unwrap()
                .as_ref(),
            vec![2; DAV_READ_AHEAD_BYTES + 1]
        );
    }
}
