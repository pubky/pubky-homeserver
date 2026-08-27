//! Database-backed WebDAV view over logical homeserver files.
//!
//! Directories are derived from file paths; empty directories are not persisted.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::SeekFrom,
    path::PathBuf,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
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
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;

use crate::{
    persistence::files::{BlobReadLease, FileIoError, FileService, WriteStreamError},
    shared::webdav::{EntryPath, StoragePath},
};

#[derive(Clone)]
pub(crate) struct AdminDavFileSystem {
    file_service: FileService,
    spool_directory: Arc<PathBuf>,
    spool_budget: Arc<DavSpoolBudget>,
}

impl AdminDavFileSystem {
    pub(crate) fn new(
        file_service: FileService,
        spool_directory: PathBuf,
        spool_limit: u64,
    ) -> Self {
        Self {
            file_service,
            spool_directory: Arc::new(spool_directory),
            spool_budget: Arc::new(DavSpoolBudget::new(spool_limit)),
        }
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

    fn file_entry_path(path: &DavPath) -> Result<EntryPath, FsError> {
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

    async fn metadata_for_path(&self, path: &DavPath) -> Result<AdminDavMetadata, FsError> {
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
        match self
            .file_service
            .get_info(&entry_path, &mut self.file_service.db.pool().into())
            .await
        {
            Ok(entry) => Ok(AdminDavMetadata::file(&entry)),
            Err(FileIoError::NotFound) => {
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
            Err(error) => Err(map_file_error(error)),
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
            let entry_path = Self::file_entry_path(path)?;
            let existing = match self
                .file_service
                .get_info(&entry_path, &mut self.file_service.db.pool().into())
                .await
            {
                Ok(entry) => Some(entry),
                Err(FileIoError::NotFound) => None,
                Err(error) => return Err(map_file_error(error)),
            };
            if options.create_new && existing.is_some() {
                return Err(FsError::Exists);
            }
            if existing.is_none() && !options.create && !options.create_new {
                return Err(FsError::NotFound);
            }

            let writable = options.write || options.append;
            let spool_limit = if writable {
                self.file_service
                    .admin_spool_limit(&entry_path, existing.as_ref())
                    .await
                    .map_err(map_file_error)?
            } else {
                None
            };
            let data = if !writable {
                let entry = existing.clone().ok_or(FsError::NotFound)?;
                let lease = self
                    .file_service
                    .acquire_entry_read_lease(&entry)
                    .await
                    .map_err(map_file_error)?;
                AdminDavFileData::Remote {
                    entry: Box::new(entry),
                    position: 0,
                    lease,
                }
            } else {
                std::fs::create_dir_all(self.spool_directory.as_ref())
                    .map_err(|_| FsError::GeneralFailure)?;
                let std_file = tempfile::tempfile_in(self.spool_directory.as_ref())
                    .map_err(|_| FsError::GeneralFailure)?;
                let mut file = tokio::fs::File::from_std(std_file);
                let mut reservation = DavSpoolReservation::new(Arc::clone(&self.spool_budget));
                if let Some(existing) = existing.as_ref().filter(|_| !options.truncate) {
                    if spool_limit.is_some_and(|limit| existing.content_length > limit) {
                        return Err(FsError::InsufficientStorage);
                    }
                    reservation.reserve_to(existing.content_length)?;
                    let mut stream = self
                        .file_service
                        .get_entry_stream(existing)
                        .await
                        .map_err(map_file_error)?;
                    let mut copied = 0u64;
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk.map_err(|_| FsError::GeneralFailure)?;
                        copied = copied.saturating_add(chunk.len() as u64);
                        if spool_limit.is_some_and(|limit| copied > limit) {
                            return Err(FsError::InsufficientStorage);
                        }
                        reservation.reserve_to(copied)?;
                        file.write_all(&chunk)
                            .await
                            .map_err(|_| FsError::GeneralFailure)?;
                    }
                }
                let position = if options.append {
                    SeekFrom::End(0)
                } else {
                    SeekFrom::Start(0)
                };
                file.seek(position)
                    .await
                    .map_err(|_| FsError::GeneralFailure)?;
                AdminDavFileData::Temporary { file, reservation }
            };

            Ok(Box::new(AdminDavFile {
                file_service: self.file_service.clone(),
                entry_path,
                data,
                metadata: existing.as_ref().map(AdminDavMetadata::file),
                writable,
                create_new: options.create_new,
                dirty: writable && (options.truncate || existing.is_none()),
                spool_limit,
                expected_write_length: options.size,
                written_length: 0,
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
                let base = if path_string.contains('/') {
                    EntryPath::from_str(&path_string).map_err(|_| FsError::NotFound)?
                } else {
                    let pubkey = pubky_common::crypto::PublicKey::try_from_z32(&path_string)
                        .map_err(|_| FsError::NotFound)?;
                    EntryPath::new(
                        pubkey,
                        StoragePath::new("/").map_err(|_| FsError::NotFound)?,
                    )
                };
                let prefix = format!("{}/", base.path().as_str().trim_end_matches('/'));
                let children = self
                    .file_service
                    .list_shallow_all(&base)
                    .await
                    .map_err(map_file_error)?;
                let files = children
                    .iter()
                    .filter(|child| !child.path().as_str().ends_with('/'))
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
                let mut names = HashSet::new();
                for child in children {
                    let relative = child
                        .path()
                        .as_str()
                        .strip_prefix(&prefix)
                        .unwrap_or(child.path().as_str())
                        .trim_end_matches('/');
                    let name = relative.split('/').next().unwrap_or(relative).to_string();
                    if !names.insert(name.clone()) {
                        continue;
                    }
                    let metadata = if child.path().as_str().ends_with('/') {
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
            let from = Self::entry_path(from)?;
            let to = Self::entry_path(to)?;
            match self
                .file_service
                .get_info(&from, &mut self.file_service.db.pool().into())
                .await
            {
                Ok(_) => self
                    .file_service
                    .admin_rename(&from, &to)
                    .await
                    .map_err(map_file_error),
                Err(FileIoError::NotFound) => {
                    if !self
                        .file_service
                        .contains_directory(&from)
                        .await
                        .map_err(map_file_error)?
                    {
                        return Err(FsError::NotFound);
                    }
                    self.file_service
                        .admin_rename_directory(&from, &to)
                        .await
                        .map_err(map_file_error)
                }
                Err(error) => Err(map_file_error(error)),
            }
        }
        .boxed()
    }
}

struct AdminDavFile {
    file_service: FileService,
    entry_path: EntryPath,
    data: AdminDavFileData,
    metadata: Option<AdminDavMetadata>,
    writable: bool,
    create_new: bool,
    dirty: bool,
    spool_limit: Option<u64>,
    expected_write_length: Option<u64>,
    written_length: u64,
}

enum AdminDavFileData {
    Remote {
        entry: Box<crate::persistence::sql::entry::EntryEntity>,
        position: u64,
        lease: BlobReadLease,
    },
    Temporary {
        file: tokio::fs::File,
        reservation: DavSpoolReservation,
    },
}

struct DavSpoolBudget {
    limit: u64,
    reserved: AtomicU64,
}

impl DavSpoolBudget {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            reserved: AtomicU64::new(0),
        }
    }

    fn try_reserve(&self, additional: u64) -> bool {
        self.reserved
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
                reserved
                    .checked_add(additional)
                    .filter(|next| *next <= self.limit)
            })
            .is_ok()
    }

    fn release(&self, bytes: u64) {
        self.reserved.fetch_sub(bytes, Ordering::AcqRel);
    }
}

struct DavSpoolReservation {
    budget: Arc<DavSpoolBudget>,
    bytes: u64,
}

impl DavSpoolReservation {
    fn new(budget: Arc<DavSpoolBudget>) -> Self {
        Self { budget, bytes: 0 }
    }

    fn reserve_to(&mut self, bytes: u64) -> Result<(), FsError> {
        let additional = bytes.saturating_sub(self.bytes);
        if additional > 0 && !self.budget.try_reserve(additional) {
            return Err(FsError::InsufficientStorage);
        }
        self.bytes = self.bytes.max(bytes);
        Ok(())
    }
}

impl Drop for DavSpoolReservation {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

impl fmt::Debug for AdminDavFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminDavFile")
            .field("entry_path", &self.entry_path)
            .field(
                "storage",
                &match self.data {
                    AdminDavFileData::Remote { .. } => "remote",
                    AdminDavFileData::Temporary { .. } => "temporary",
                },
            )
            .field("writable", &self.writable)
            .field("dirty", &self.dirty)
            .finish()
    }
}

impl DavFile for AdminDavFile {
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        async move {
            if !self.dirty {
                if let Some(metadata) = self.metadata.clone() {
                    return Ok(Box::new(metadata) as Box<dyn DavMetaData>);
                }
            }
            let length = match &self.data {
                AdminDavFileData::Remote { entry, .. } => entry.content_length,
                AdminDavFileData::Temporary { file, .. } => file
                    .metadata()
                    .await
                    .map_err(|_| FsError::GeneralFailure)?
                    .len(),
            };
            Ok(Box::new(AdminDavMetadata::temporary_file(length)) as Box<dyn DavMetaData>)
        }
        .boxed()
    }

    fn write_buf(&mut self, mut buffer: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        let bytes = buffer.copy_to_bytes(buffer.remaining());
        self.write_bytes(bytes)
    }

    fn write_bytes(&mut self, bytes: Bytes) -> FsFuture<'_, ()> {
        async move {
            if !self.writable {
                return Err(FsError::Forbidden);
            }
            let AdminDavFileData::Temporary { file, reservation } = &mut self.data else {
                return Err(FsError::GeneralFailure);
            };
            let position = file
                .stream_position()
                .await
                .map_err(|_| FsError::GeneralFailure)?;
            if self
                .spool_limit
                .is_some_and(|limit| position.saturating_add(bytes.len() as u64) > limit)
            {
                return Err(FsError::InsufficientStorage);
            }
            let next_written_length = self
                .written_length
                .checked_add(bytes.len() as u64)
                .ok_or(FsError::TooLarge)?;
            if self
                .expected_write_length
                .is_some_and(|expected| next_written_length > expected)
            {
                return Err(FsError::TooLarge);
            }
            reservation.reserve_to(position.saturating_add(bytes.len() as u64))?;
            file.write_all(&bytes)
                .await
                .map_err(|_| FsError::GeneralFailure)?;
            self.written_length = next_written_length;
            self.dirty = true;
            Ok(())
        }
        .boxed()
    }

    fn read_bytes(&mut self, count: usize) -> FsFuture<'_, Bytes> {
        async move {
            match &mut self.data {
                AdminDavFileData::Remote {
                    entry,
                    position,
                    lease,
                } => {
                    let end = position
                        .saturating_add(count as u64)
                        .min(entry.content_length);
                    if end <= *position {
                        return Ok(Bytes::new());
                    }
                    let bytes = self
                        .file_service
                        .get_entry_range(entry, lease, *position..end)
                        .await
                        .map_err(map_file_error)?;
                    *position = position.saturating_add(bytes.len() as u64);
                    Ok(bytes)
                }
                AdminDavFileData::Temporary { file, .. } => {
                    let mut bytes = vec![0; count];
                    let read = file
                        .read(&mut bytes)
                        .await
                        .map_err(|_| FsError::GeneralFailure)?;
                    bytes.truncate(read);
                    Ok(bytes.into())
                }
            }
        }
        .boxed()
    }

    fn seek(&mut self, position: SeekFrom) -> FsFuture<'_, u64> {
        async move {
            match &mut self.data {
                AdminDavFileData::Remote {
                    entry,
                    position: current,
                    ..
                } => {
                    *current = seek_position(*current, entry.content_length, position)?;
                    Ok(*current)
                }
                AdminDavFileData::Temporary { file, .. } => file
                    .seek(position)
                    .await
                    .map_err(|_| FsError::GeneralFailure),
            }
        }
        .boxed()
    }

    fn flush(&mut self) -> FsFuture<'_, ()> {
        async move {
            if !self.dirty {
                return Ok(());
            }
            let AdminDavFileData::Temporary { file, .. } = &mut self.data else {
                return Err(FsError::GeneralFailure);
            };
            if self
                .expected_write_length
                .is_some_and(|expected| self.written_length != expected)
            {
                return Err(FsError::TooLarge);
            }
            file.flush().await.map_err(|_| FsError::GeneralFailure)?;
            let content_length = file
                .metadata()
                .await
                .map_err(|_| FsError::GeneralFailure)?
                .len();

            let mut reader = file
                .try_clone()
                .await
                .map_err(|_| FsError::GeneralFailure)?;
            reader
                .seek(SeekFrom::Start(0))
                .await
                .map_err(|_| FsError::GeneralFailure)?;
            let stream = ReaderStream::new(reader).map(|result| {
                result.map_err(|error| WriteStreamError::Other(anyhow::Error::new(error)))
            });
            let entry = if self.create_new {
                self.file_service
                    .admin_create_stream_with_size_hint(&self.entry_path, stream, content_length)
                    .await
            } else {
                self.file_service
                    .admin_write_stream_with_size_hint(&self.entry_path, stream, content_length)
                    .await
            }
            .map_err(map_file_error)?;
            self.metadata = Some(AdminDavMetadata::file(&entry));
            self.dirty = false;
            Ok(())
        }
        .boxed()
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
struct AdminDavMetadata {
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

    fn file(entry: &crate::persistence::sql::entry::EntryEntity) -> Self {
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

    fn temporary_file(length: u64) -> Self {
        Self {
            length,
            modified: SystemTime::now(),
            directory: false,
            etag: None,
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
    async fn test_create_new_is_checked_when_content_is_committed() {
        let context = AppContext::test().await;
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&public_key).await.unwrap();
        let filesystem = AdminDavFileSystem::new(
            context.file_service.clone(),
            context.data_dir.path().to_path_buf(),
            u64::MAX,
        );
        let path = DavPath::new(&format!("/{}/pub/state.bin", public_key.z32())).unwrap();
        let options = OpenOptions {
            write: true,
            create: true,
            create_new: true,
            truncate: true,
            ..Default::default()
        };
        let mut first = filesystem.open(&path, options.clone()).await.unwrap();
        let mut second = filesystem.open(&path, options).await.unwrap();
        first
            .write_bytes(Bytes::from_static(b"first"))
            .await
            .unwrap();
        second
            .write_bytes(Bytes::from_static(b"second"))
            .await
            .unwrap();

        let (first_result, second_result) = tokio::join!(first.flush(), second.flush());
        assert_ne!(first_result.is_ok(), second_result.is_ok());
        assert!(matches!(
            first_result.as_ref().err().or(second_result.as_ref().err()),
            Some(FsError::Exists)
        ));

        let entry_path = EntryPath::new(public_key, StoragePath::new("/pub/state.bin").unwrap());
        let content = context.file_service.get(&entry_path).await.unwrap();
        assert!(content.as_ref() == b"first" || content.as_ref() == b"second");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_flush_rejects_declared_length_mismatch_before_commit() {
        let context = AppContext::test().await;
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&public_key).await.unwrap();
        let entry_path = EntryPath::new(
            public_key.clone(),
            StoragePath::new("/pub/state.bin").unwrap(),
        );
        context
            .file_service
            .write(&entry_path, opendal::Buffer::from(b"original".to_vec()))
            .await
            .unwrap();
        let filesystem = AdminDavFileSystem::new(
            context.file_service.clone(),
            context.data_dir.path().to_path_buf(),
            u64::MAX,
        );
        let path = DavPath::new(&format!("/{}/pub/state.bin", public_key.z32())).unwrap();
        let mut file = filesystem
            .open(
                &path,
                OpenOptions {
                    write: true,
                    create: true,
                    truncate: true,
                    size: Some(5),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        file.write_bytes(Bytes::from_static(b"four")).await.unwrap();

        assert!(matches!(file.flush().await, Err(FsError::TooLarge)));
        assert_eq!(
            context
                .file_service
                .get(&entry_path)
                .await
                .unwrap()
                .as_ref(),
            b"original"
        );
    }

    #[test]
    fn test_spool_budget_is_shared_and_released() {
        let budget = Arc::new(DavSpoolBudget::new(5));
        let mut first = DavSpoolReservation::new(Arc::clone(&budget));
        let mut second = DavSpoolReservation::new(Arc::clone(&budget));

        first.reserve_to(3).unwrap();
        assert!(matches!(
            second.reserve_to(3),
            Err(FsError::InsufficientStorage)
        ));
        drop(first);
        second.reserve_to(3).unwrap();
    }
}
