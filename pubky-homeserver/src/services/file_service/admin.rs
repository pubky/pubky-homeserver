use crate::{
    persistence::{
        files::{FileIoError, WritePreconditions, WriteStreamError},
        sql::{
            entry::{EntryEntity, EntryRepository},
            user::UserEntity,
            UnifiedExecutor,
        },
    },
    services::user_service::FILE_METADATA_SIZE,
    shared::webdav::EntryPath,
};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};

use super::{writes::WriteMode, FileService};

impl FileService {
    /// Delete a file bypassing write-path restrictions.
    /// Used by both admin file APIs.
    pub async fn admin_delete(&self, path: &EntryPath) -> Result<(), FileIoError> {
        self.delete_inner(path, false).await
    }

    /// Write through the admin interface without user write-path policy.
    pub(crate) async fn admin_write_stream(
        &self,
        path: &EntryPath,
        stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
        size_hint: Option<u64>,
    ) -> Result<EntryEntity, FileIoError> {
        self.write_stream_inner(
            path,
            stream,
            WriteMode::AdminOverwrite,
            size_hint,
            WritePreconditions::default(),
        )
        .await
        .map(|(entry, _)| entry)
    }

    pub(crate) async fn admin_users(&self) -> Result<Vec<String>, FileIoError> {
        Ok(self
            .user_service
            .get_all()
            .await?
            .into_iter()
            .map(|user| user.public_key.z32())
            .collect())
    }

    pub(crate) async fn contains_directory(&self, path: &EntryPath) -> Result<bool, FileIoError> {
        Ok(EntryRepository::contains_directory(path, &mut self.db.pool().into()).await?)
    }

    pub(crate) async fn list_shallow_all(
        &self,
        path: &EntryPath,
    ) -> Result<Vec<EntryPath>, FileIoError> {
        let mut entries = Vec::new();
        let mut cursor = None;
        loop {
            let page = EntryRepository::list_shallow(
                path,
                Some(crate::constants::DEFAULT_MAX_LIST_LIMIT),
                cursor,
                false,
                &mut self.db.pool().into(),
            )
            .await?;
            let Some(last) = page.last().cloned() else {
                break;
            };
            let page_len = page.len();
            entries.extend(page);
            if page_len < crate::constants::DEFAULT_MAX_LIST_LIMIT as usize {
                break;
            }
            cursor = Some(last);
        }
        Ok(entries)
    }

    pub(crate) async fn get_info_many(
        &self,
        paths: &[EntryPath],
    ) -> Result<Vec<EntryEntity>, FileIoError> {
        let Some(first) = paths.first() else {
            return Ok(Vec::new());
        };
        Ok(
            EntryRepository::get_by_paths(first.pubkey(), paths, &mut self.db.pool().into())
                .await?,
        )
    }

    pub(crate) async fn admin_copy(
        &self,
        from: &EntryPath,
        to: &EntryPath,
    ) -> Result<(), FileIoError> {
        let source = self.get_info(from, &mut self.db.pool().into()).await?;
        let source_length = source.content_length;
        let stream = self.get_entry_stream(&source).await?;
        self.write_stream_inner(
            to,
            stream.map(|result| {
                result.map_err(|error| WriteStreamError::Other(anyhow::Error::new(error)))
            }),
            WriteMode::AdminCreate,
            Some(source_length),
            WritePreconditions::default(),
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn admin_rename(
        &self,
        from: &EntryPath,
        to: &EntryPath,
    ) -> Result<(), FileIoError> {
        if from == to {
            return Ok(());
        }

        let mut tx = self.db.pool().begin().await?;
        let result = async {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            let (mut source_user, mut destination_user) =
                self.lock_move_users(from, to, &mut executor).await?;

            let source_entry = match EntryRepository::get_by_path(from, &mut executor).await {
                Ok(entry) => entry,
                Err(sqlx::Error::RowNotFound) => return Err(FileIoError::NotFound),
                Err(error) => return Err(error.into()),
            };
            match EntryRepository::get_by_path(to, &mut executor).await {
                Ok(_) => return Err(FileIoError::PathCollision),
                Err(sqlx::Error::RowNotFound) => {}
                Err(error) => return Err(error.into()),
            }
            let destination_user_id = destination_user
                .as_ref()
                .map_or(source_user.id, |user| user.id);
            let source_blob_key = Self::backend_key(&source_entry);
            EntryRepository::move_to(
                source_entry.id,
                destination_user_id,
                to.path(),
                &source_blob_key,
                &mut executor,
            )
            .await?;

            self.events_service
                .create_event(
                    destination_user_id,
                    crate::persistence::files::events::EventType::Put {
                        content_hash: source_entry.content_hash,
                    },
                    to,
                    &mut executor,
                )
                .await?;
            self.events_service
                .create_event(
                    source_user.id,
                    crate::persistence::files::events::EventType::Delete,
                    from,
                    &mut executor,
                )
                .await?;

            self.transfer_move_usage(
                &mut source_user,
                destination_user.as_mut(),
                source_entry
                    .content_length
                    .saturating_add(FILE_METADATA_SIZE),
                &mut executor,
            )
            .await?;
            Ok(())
        }
        .await;

        match result {
            Ok(()) => tx.commit().await?,
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::error!(%rollback_error, "Failed to roll back admin rename");
                }
                return Err(error);
            }
        }
        self.events_service.notify_event().await;
        Ok(())
    }

    pub(crate) async fn admin_rename_directory(
        &self,
        from: &EntryPath,
        to: &EntryPath,
    ) -> Result<(), FileIoError> {
        if from == to {
            return Ok(());
        }
        let source_prefix = format!("{}/", from.path().as_str().trim_end_matches('/'));
        let destination_prefix = format!("{}/", to.path().as_str().trim_end_matches('/'));
        if from.pubkey() == to.pubkey() && destination_prefix.starts_with(&source_prefix) {
            return Err(FileIoError::PathCollision);
        }

        let mut tx = self.db.pool().begin().await?;
        let result = async {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            let (mut source_user, mut destination_user) =
                self.lock_move_users(from, to, &mut executor).await?;
            let entries = EntryRepository::list_descendants(from, &mut executor).await?;
            if entries.is_empty() {
                return Err(FileIoError::NotFound);
            }
            if EntryRepository::contains_directory(to, &mut executor).await? {
                return Err(FileIoError::PathCollision);
            }
            match EntryRepository::get_by_path(to, &mut executor).await {
                Ok(_) => return Err(FileIoError::PathCollision),
                Err(sqlx::Error::RowNotFound) => {}
                Err(error) => return Err(error.into()),
            }
            let moved_bytes = entries.iter().fold(0u64, |total, entry| {
                total.saturating_add(entry.content_length.saturating_add(FILE_METADATA_SIZE))
            });

            self.transfer_move_usage(
                &mut source_user,
                destination_user.as_mut(),
                moved_bytes,
                &mut executor,
            )
            .await?;

            let destination_user_id = destination_user
                .as_ref()
                .map_or(source_user.id, |user| user.id);
            for entry in entries {
                let suffix = entry
                    .path
                    .path()
                    .as_str()
                    .strip_prefix(&source_prefix)
                    .ok_or(FileIoError::PathCollision)?;
                let destination_path = crate::shared::webdav::StoragePath::new(&format!(
                    "{destination_prefix}{suffix}"
                ))
                .map_err(|_| FileIoError::PathCollision)?;
                let destination_entry_path = EntryPath::new(to.pubkey().clone(), destination_path);
                let blob_key = Self::backend_key(&entry);
                EntryRepository::move_to(
                    entry.id,
                    destination_user_id,
                    destination_entry_path.path(),
                    &blob_key,
                    &mut executor,
                )
                .await?;
                self.events_service
                    .create_event(
                        destination_user_id,
                        crate::persistence::files::events::EventType::Put {
                            content_hash: entry.content_hash,
                        },
                        &destination_entry_path,
                        &mut executor,
                    )
                    .await?;
                self.events_service
                    .create_event(
                        source_user.id,
                        crate::persistence::files::events::EventType::Delete,
                        &entry.path,
                        &mut executor,
                    )
                    .await?;
            }
            Ok(())
        }
        .await;

        match result {
            Ok(()) => tx.commit().await?,
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::error!(%rollback_error, "Failed to roll back admin directory rename");
                }
                return Err(error);
            }
        }
        self.events_service.notify_event().await;
        Ok(())
    }

    async fn transfer_move_usage(
        &self,
        source_user: &mut UserEntity,
        destination_user: Option<&mut UserEntity>,
        moved_bytes: u64,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<(), FileIoError> {
        let Some(destination_user) = destination_user else {
            return Ok(());
        };
        let max_bytes = crate::persistence::files::storage_quota::resolve_storage_max_bytes(
            destination_user,
            self.default_storage_mb,
        );
        let destination_usage = destination_user.used_bytes.saturating_add(moved_bytes);
        if max_bytes.is_some_and(|limit| destination_usage > limit) {
            return Err(FileIoError::DiskSpaceQuotaExceeded);
        }
        destination_user.used_bytes = destination_usage;
        source_user.used_bytes = source_user.used_bytes.saturating_sub(moved_bytes);
        self.user_service
            .update_in_tx(destination_user, executor)
            .await?;
        self.user_service
            .update_in_tx(source_user, executor)
            .await?;
        Ok(())
    }

    async fn lock_move_users(
        &self,
        from: &EntryPath,
        to: &EntryPath,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<(UserEntity, Option<UserEntity>), sqlx::Error> {
        if from.pubkey() == to.pubkey() {
            return self
                .user_service
                .get_for_no_key_update(from.pubkey(), executor)
                .await
                .map(|user| (user, None));
        }
        if from.pubkey().z32() < to.pubkey().z32() {
            let source = self
                .user_service
                .get_for_no_key_update(from.pubkey(), executor)
                .await?;
            let destination = self
                .user_service
                .get_for_no_key_update(to.pubkey(), executor)
                .await?;
            Ok((source, Some(destination)))
        } else {
            let destination = self
                .user_service
                .get_for_no_key_update(to.pubkey(), executor)
                .await?;
            let source = self
                .user_service
                .get_for_no_key_update(from.pubkey(), executor)
                .await?;
            Ok((source, Some(destination)))
        }
    }
}
