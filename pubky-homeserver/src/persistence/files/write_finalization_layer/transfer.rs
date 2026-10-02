use std::{fmt, future::Future};

use crate::persistence::files::events::EventType;
use crate::persistence::sql::{
    entry::{EntryEntity, EntryRepository},
    user::UserEntity,
    UnifiedExecutor,
};
use crate::services::user_service::FILE_METADATA_SIZE;
use crate::shared::webdav::{EntryPath, StoragePath};
use opendal::Result;
use pubky_common::crypto::PublicKey;

use super::{
    layer::{
        check_no_path_collision, path_collision_error, quota_exceeded_error, unexpected, Finalizer,
    },
    resolve_storage_max_bytes, would_exceed_limit,
};

/// A copy or rename asked of the layer.
#[derive(Debug)]
pub(super) struct Transfer {
    pub(super) kind: TransferKind,
    pub(super) from: EntryPath,
    pub(super) to: EntryPath,
}

/// Both a copy and a rename give tracked blobs an entry at a new path; a
/// rename also removes the entries they had. A copy only ever takes a file,
/// while a rename takes whichever the backend says its source is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TransferKind {
    CopyFile,
    RenameFile,
    RenameFolder,
}

impl TransferKind {
    fn removes_source(self) -> bool {
        !matches!(self, Self::CopyFile)
    }
}

impl fmt::Display for TransferKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CopyFile => "copy",
            Self::RenameFile | Self::RenameFolder => "rename",
        })
    }
}

/// An entry and the path its blob is copied or moved to.
struct TransferredEntry {
    source: EntryEntity,
    destination: EntryPath,
    /// The entry of the file the destination overwrites.
    replaced: Option<EntryEntity>,
}

/// The users of a transfer, row-locked for its transaction.
struct LockedUsers {
    source: UserEntity,
    /// `None` when the destination is in the source user's own drive.
    destination: Option<UserEntity>,
}

/// A locked user and what the transfer does to their used bytes.
struct UserUsage {
    user: UserEntity,
    bytes_delta: i64,
}

struct PreparedTransfer {
    kind: TransferKind,
    source: UserUsage,
    /// `None` when the destination is in the source user's own drive.
    destination: Option<UserUsage>,
    entries: Vec<TransferredEntry>,
}

impl PreparedTransfer {
    fn new(kind: TransferKind, users: LockedUsers, entries: Vec<TransferredEntry>) -> Self {
        let transferred: i64 = entries
            .iter()
            .map(|entry| stored_bytes(&entry.source))
            .sum();
        let replaced: i64 = entries
            .iter()
            .filter_map(|entry| entry.replaced.as_ref())
            .map(stored_bytes)
            .sum();
        let gained = transferred - replaced;
        let released = if kind.removes_source() {
            transferred
        } else {
            0
        };
        let usage = |user, bytes_delta| UserUsage { user, bytes_delta };
        let (source, destination) = match users.destination {
            Some(user) => (usage(users.source, -released), Some(usage(user, gained))),
            None => (usage(users.source, gained - released), None),
        };

        Self {
            kind,
            source,
            destination,
            entries,
        }
    }

    /// The usage of the user whose drive the destination is in.
    fn receiving(&self) -> &UserUsage {
        self.destination.as_ref().unwrap_or(&self.source)
    }

    /// A transfer that does not grow a user's usage is allowed even when they
    /// are over quota: a rename within a drive must stay possible.
    fn ensure_within_quota(&self, default_storage_mb: Option<u64>) -> Result<()> {
        let UserUsage { user, bytes_delta } = self.receiving();
        let max_bytes = resolve_storage_max_bytes(user, default_storage_mb);
        if *bytes_delta > 0 && would_exceed_limit(user.used_bytes, *bytes_delta, max_bytes) {
            return Err(quota_exceeded_error());
        }
        Ok(())
    }
}

/// The bytes an entry counts against its user's quota.
fn stored_bytes(entry: &EntryEntity) -> i64 {
    entry.content_length.saturating_add(FILE_METADATA_SIZE) as i64
}

/// Where an entry beneath the folder `from` lands when the folder is renamed
/// to `to`: the same place beneath `to`.
fn destination_beneath(
    to: &EntryPath,
    source: &EntryEntity,
    from: &EntryPath,
) -> Result<EntryPath> {
    let beneath_from = &source.path.path().as_str()[from.path().as_str().len()..];
    let path = StoragePath::new(&format!("{}{beneath_from}", to.path())).map_err(|error| {
        unexpected(
            format!("Invalid destination for {} under {to}", source.path),
            error,
        )
    })?;
    Ok(EntryPath::new(to.pubkey().clone(), path))
}

async fn find_entry(
    path: &EntryPath,
    executor: &mut UnifiedExecutor<'_>,
) -> Result<Option<EntryEntity>> {
    match EntryRepository::get_by_path(path, executor).await {
        Ok(entry) => Ok(Some(entry)),
        Err(sqlx::Error::RowNotFound) => Ok(None),
        Err(error) => Err(unexpected(format!("Failed to load entry {path}"), error)),
    }
}

impl Finalizer {
    /// Run a backend copy or rename and commit its entries, events and quota
    /// accounting together. The backend operation only runs once the transfer
    /// is known to be allowed, and nothing is committed if it fails.
    pub(super) async fn finalize_transfer<T>(
        &self,
        transfer: &Transfer,
        backend_operation: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let Transfer { kind, from, to } = transfer;
        let mut tx = self.sql_db.pool().begin().await.map_err(|error| {
            unexpected(
                format!("Failed to begin {kind} finalization transaction"),
                error,
            )
        })?;

        let result = {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            self.transfer_in_transaction(transfer, backend_operation, &mut executor)
                .await
        };

        match result {
            Ok(output) => {
                tx.commit().await.map_err(|error| {
                    unexpected(format!("Failed to commit {kind} finalization"), error)
                })?;
                self.notify_event();
                Ok(output)
            }
            Err(error) => {
                // WebDAV reports a refusal as a bare status, so the reason
                // would otherwise be lost to the operator.
                tracing::warn!(
                    from = %from,
                    to = %to,
                    error = %error,
                    "Refused or failed to {kind}"
                );
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::error!(
                        from = %from,
                        to = %to,
                        error = %rollback_error,
                        "Failed to roll back {kind} finalization transaction"
                    );
                }
                Err(error)
            }
        }
    }

    async fn transfer_in_transaction<T>(
        &self,
        transfer: &Transfer,
        backend_operation: impl Future<Output = Result<T>>,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<T> {
        let prepared = self.prepare_transfer(transfer, executor).await?;
        let output = backend_operation.await?;
        self.apply_transfer_effects(prepared, executor).await?;
        Ok(output)
    }

    async fn prepare_transfer(
        &self,
        transfer: &Transfer,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<PreparedTransfer> {
        let users = self.lock_transfer_users(transfer, executor).await?;
        let entries = match transfer.kind {
            TransferKind::RenameFolder => self.folder_entries(transfer, executor).await?,
            TransferKind::CopyFile | TransferKind::RenameFile => {
                vec![self.file_entry(transfer, executor).await?]
            }
        };

        let prepared = PreparedTransfer::new(transfer.kind, users, entries);
        prepared.ensure_within_quota(self.default_storage_mb)?;
        Ok(prepared)
    }

    /// Row-lock the users of both paths. Two users are locked in key order,
    /// so transfers crossing between the same pair cannot deadlock.
    async fn lock_transfer_users(
        &self,
        transfer: &Transfer,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<LockedUsers> {
        let (from, to) = (transfer.from.pubkey(), transfer.to.pubkey());
        if from == to {
            let source = self.lock_user(from, executor).await?;
            return Ok(LockedUsers {
                source,
                destination: None,
            });
        }

        let (source, destination) = if from.z32() < to.z32() {
            let source = self.lock_user(from, executor).await?;
            (source, self.lock_user(to, executor).await?)
        } else {
            let destination = self.lock_user(to, executor).await?;
            (self.lock_user(from, executor).await?, destination)
        };
        Ok(LockedUsers {
            source,
            destination: Some(destination),
        })
    }

    async fn lock_user(
        &self,
        pubkey: &PublicKey,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<UserEntity> {
        match self
            .user_service
            .get_for_no_key_update(pubkey, executor)
            .await
        {
            Ok(user) => Ok(user),
            Err(sqlx::Error::RowNotFound) => Err(opendal::Error::new(
                opendal::ErrorKind::NotFound,
                format!("No user {pubkey}"),
            )),
            Err(error) => Err(unexpected(format!("Failed to lock user {pubkey}"), error)),
        }
    }

    /// The entry of the file a copy or rename takes. A file the database does
    /// not know is refused, not passed on to the backend.
    async fn file_entry(
        &self,
        transfer: &Transfer,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<TransferredEntry> {
        let Transfer { kind, from, to } = transfer;
        let Some(source) = find_entry(from, executor).await? else {
            return Err(opendal::Error::new(
                opendal::ErrorKind::NotFound,
                format!("No entry for {from}, refusing to {kind} an untracked file"),
            ));
        };
        if self.collision_policy.enforces_collisions() {
            check_no_path_collision(to, executor).await?;
        }

        Ok(TransferredEntry {
            source,
            destination: to.clone(),
            replaced: find_entry(to, executor).await?,
        })
    }

    /// The entries beneath the folder a rename takes. There may be none: a
    /// file manager makes a folder before naming it, and that rename has
    /// nothing to record.
    async fn folder_entries(
        &self,
        transfer: &Transfer,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<Vec<TransferredEntry>> {
        let Transfer { from, to, .. } = transfer;
        // A folder only moves to a free path, whatever the collision policy:
        // merging it into what is already there is not a rename.
        if find_entry(to, executor).await?.is_some() {
            return Err(path_collision_error(to));
        }
        check_no_path_collision(to, executor).await?;

        let sources = EntryRepository::get_descendants(from, executor)
            .await
            .map_err(|error| unexpected(format!("Failed to load entries beneath {from}"), error))?;
        sources
            .into_iter()
            .map(|source| {
                Ok(TransferredEntry {
                    destination: destination_beneath(to, &source, from)?,
                    source,
                    replaced: None,
                })
            })
            .collect()
    }

    async fn apply_transfer_effects(
        &self,
        prepared: PreparedTransfer,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<()> {
        let destination_user_id = prepared.receiving().user.id;
        let PreparedTransfer {
            kind,
            source,
            destination,
            entries,
        } = prepared;

        for entry in &entries {
            self.record_arrival(destination_user_id, entry, executor)
                .await?;
            if kind.removes_source() {
                self.record_departure(&entry.source, executor).await?;
            }
        }

        self.apply_usage(source, executor).await?;
        if let Some(destination) = destination {
            self.apply_usage(destination, executor).await?;
        }
        Ok(())
    }

    /// Give the destination its entry, a copy of the source's, and report it
    /// to the event feed as a `PUT`.
    async fn record_arrival(
        &self,
        user_id: i32,
        transferred: &TransferredEntry,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<()> {
        let TransferredEntry {
            source,
            destination,
            replaced,
        } = transferred;
        match replaced {
            Some(replaced) => {
                let overwritten = EntryEntity {
                    content_hash: source.content_hash,
                    content_length: source.content_length,
                    content_type: source.content_type.clone(),
                    ..replaced.clone()
                };
                EntryRepository::update(&overwritten, executor).await
            }
            None => EntryRepository::create(
                user_id,
                destination.path(),
                &source.content_hash,
                source.content_length,
                &source.content_type,
                executor,
            )
            .await
            .map(|_| ()),
        }
        .map_err(|error| {
            unexpected(
                format!(
                    "Failed to write entry {destination} after the backend operation; \
                     potential orphaned file"
                ),
                error,
            )
        })?;
        self.events_service
            .create_event(
                user_id,
                EventType::Put {
                    content_hash: source.content_hash,
                },
                destination,
                executor,
            )
            .await
            .map_err(|error| unexpected(format!("Failed to create event {destination}"), error))?;

        Ok(())
    }

    /// Remove the entry of a renamed file and report it to the event feed as
    /// a `DEL`.
    async fn record_departure(
        &self,
        source: &EntryEntity,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<()> {
        EntryRepository::delete(source.id, executor)
            .await
            .map_err(|error| {
                unexpected(format!("Failed to delete entry {}", source.path), error)
            })?;
        self.events_service
            .create_event(source.user_id, EventType::Delete, &source.path, executor)
            .await
            .map_err(|error| {
                unexpected(
                    format!("Failed to create delete event for {}", source.path),
                    error,
                )
            })?;

        Ok(())
    }

    async fn apply_usage(
        &self,
        usage: UserUsage,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<()> {
        let UserUsage {
            mut user,
            bytes_delta,
        } = usage;
        if bytes_delta == 0 {
            return Ok(());
        }
        user.used_bytes = user.used_bytes.saturating_add_signed(bytes_delta);
        self.user_service
            .update_in_tx(&user, executor)
            .await
            .map_err(|error| {
                unexpected(
                    format!("Failed to update quota for {}", user.public_key),
                    error,
                )
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use opendal::Operator;
    use pubky_common::crypto::Keypair;
    use tempfile::TempDir;

    use crate::persistence::files::FileIoError;
    use crate::persistence::sql::SqlDb;

    use super::super::layer::test_support::{
        all_events, create_user, install_slow_event_insert, test_admin_fs_operator,
        test_fs_operator, test_user_service, user_usage, wait_for_slow_event_insert, wait_until,
    };
    use super::*;

    fn entry_path(pubkey: &PublicKey, path: &str) -> EntryPath {
        EntryPath::new(pubkey.clone(), StoragePath::new(path).unwrap())
    }

    async fn entry(db: &SqlDb, path: &EntryPath) -> Option<EntryEntity> {
        find_entry(path, &mut db.pool().into()).await.unwrap()
    }

    async fn read(operator: &Operator, path: &EntryPath) -> Vec<u8> {
        operator.read(path.as_str()).await.unwrap().to_vec()
    }

    /// The type and path of every event, in feed order.
    async fn event_log(db: &SqlDb) -> Vec<(&'static str, String)> {
        all_events(db)
            .await
            .into_iter()
            .map(|event| (event.event_type.as_str(), event.path.to_string()))
            .collect()
    }

    /// Put a file in the backend behind the layer's back, as a rename or copy
    /// through the admin share did before they were finalized.
    fn write_untracked(tmp_dir: &TempDir, path: &EntryPath, content: &[u8]) {
        let file = tmp_dir.path().join("files").join(path.as_str());
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, content).unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn rename_moves_the_entry_and_reports_it_to_the_event_feed() {
        let db = SqlDb::test().await;
        let (operator, _tmp_dir) = test_fs_operator(&db);
        let pubkey = create_user(&db).await;
        let old = entry_path(&pubkey, "/pub/old.txt");
        let new = entry_path(&pubkey, "/pub/new.txt");
        operator.write(old.as_str(), vec![1; 10]).await.unwrap();
        let written = entry(&db, &old).await.unwrap();

        operator.rename(old.as_str(), new.as_str()).await.unwrap();

        assert_eq!(entry(&db, &old).await, None);
        let renamed = entry(&db, &new).await.unwrap();
        assert_eq!(renamed.content_hash, written.content_hash);
        assert_eq!(renamed.content_length, 10);
        assert_eq!(renamed.content_type, written.content_type);
        assert_eq!(read(&operator, &new).await, vec![1; 10]);
        assert!(!operator.exists(old.as_str()).await.unwrap());
        assert_eq!(user_usage(&db, &pubkey).await, 10 + FILE_METADATA_SIZE);
        assert_eq!(
            event_log(&db).await,
            vec![
                ("PUT", old.to_string()),
                ("PUT", new.to_string()),
                ("DEL", old.to_string()),
            ]
        );
    }

    /// dav-server renames a collection in one call, without a trailing slash.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn renaming_a_folder_moves_every_entry_beneath_it() {
        let db = SqlDb::test().await;
        let (operator, _tmp_dir) = test_fs_operator(&db);
        let pubkey = create_user(&db).await;
        let moved = [
            ("/pub/d_r/a.txt", "/pub/moved/a.txt"),
            ("/pub/d_r/sub/b.txt", "/pub/moved/sub/b.txt"),
        ]
        .map(|(old, new)| (entry_path(&pubkey, old), entry_path(&pubkey, new)));
        // `_` matches any character in a SQL `LIKE`, which must not make this
        // folder part of the renamed one.
        let sibling = entry_path(&pubkey, "/pub/dxr/keep.txt");
        for (old, _) in &moved {
            operator.write(old.as_str(), vec![1; 10]).await.unwrap();
        }
        operator.write(sibling.as_str(), vec![2; 10]).await.unwrap();
        let usage_before = user_usage(&db, &pubkey).await;

        operator
            .rename(
                entry_path(&pubkey, "/pub/d_r").as_str(),
                entry_path(&pubkey, "/pub/moved").as_str(),
            )
            .await
            .unwrap();

        for (old, new) in &moved {
            assert_eq!(entry(&db, old).await, None);
            assert_eq!(entry(&db, new).await.unwrap().content_length, 10);
            assert_eq!(read(&operator, new).await, vec![1; 10]);
        }
        assert!(entry(&db, &sibling).await.is_some());
        assert_eq!(read(&operator, &sibling).await, vec![2; 10]);
        assert_eq!(user_usage(&db, &pubkey).await, usage_before);
        assert_eq!(
            event_log(&db).await[3..],
            [
                ("PUT", moved[0].1.to_string()),
                ("DEL", moved[0].0.to_string()),
                ("PUT", moved[1].1.to_string()),
                ("DEL", moved[1].0.to_string()),
            ]
        );
    }

    /// A file manager makes "untitled folder" and then renames it.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn renaming_a_folder_without_entries_moves_it_and_records_nothing() {
        let db = SqlDb::test().await;
        let (operator, _tmp_dir) = test_fs_operator(&db);
        let pubkey = create_user(&db).await;
        let untitled = entry_path(&pubkey, "/pub/untitled folder");
        let named = entry_path(&pubkey, "/pub/photos");
        operator.create_dir(&format!("{untitled}/")).await.unwrap();

        operator
            .rename(untitled.as_str(), named.as_str())
            .await
            .unwrap();

        assert!(operator.exists(&format!("{named}/")).await.unwrap());
        assert!(!operator.exists(&format!("{untitled}/")).await.unwrap());
        assert!(all_events(&db).await.is_empty());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn copy_gives_the_copy_an_entry_and_counts_it_as_usage() {
        let db = SqlDb::test().await;
        let (operator, _tmp_dir) = test_fs_operator(&db);
        let pubkey = create_user(&db).await;
        let original = entry_path(&pubkey, "/pub/original.txt");
        let copy = entry_path(&pubkey, "/pub/copy.txt");
        operator
            .write(original.as_str(), vec![1; 10])
            .await
            .unwrap();

        operator
            .copy(original.as_str(), copy.as_str())
            .await
            .unwrap();

        let original_entry = entry(&db, &original).await.unwrap();
        let copy_entry = entry(&db, &copy).await.unwrap();
        assert_eq!(copy_entry.content_hash, original_entry.content_hash);
        assert_eq!(copy_entry.content_length, 10);
        assert_eq!(read(&operator, &copy).await, vec![1; 10]);
        assert_eq!(
            user_usage(&db, &pubkey).await,
            2 * (10 + FILE_METADATA_SIZE)
        );
        assert_eq!(
            event_log(&db).await,
            vec![("PUT", original.to_string()), ("PUT", copy.to_string())]
        );

        // The copy is a file like any other, so deleting it is accounted for.
        operator.delete(copy.as_str()).await.unwrap();
        assert_eq!(user_usage(&db, &pubkey).await, 10 + FILE_METADATA_SIZE);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn copy_beyond_the_quota_is_refused_before_any_bytes_are_copied() {
        let db = SqlDb::test().await;
        let (operator, _tmp_dir) = test_fs_operator(&db);
        let pubkey = Keypair::random().public_key();
        test_user_service(&db)
            .create_with_quota_mb(&pubkey, 1)
            .await;
        let original = entry_path(&pubkey, "/pub/original.bin");
        let copy = entry_path(&pubkey, "/pub/copy.bin");
        operator
            .write(original.as_str(), vec![1; 600 * 1024])
            .await
            .unwrap();
        let usage_before = user_usage(&db, &pubkey).await;

        let rejection = operator
            .copy(original.as_str(), copy.as_str())
            .await
            .expect_err("the copy should exceed the quota");

        assert!(matches!(
            FileIoError::from(rejection),
            FileIoError::DiskSpaceQuotaExceeded
        ));
        assert!(!operator.exists(copy.as_str()).await.unwrap());
        assert_eq!(entry(&db, &copy).await, None);
        assert_eq!(user_usage(&db, &pubkey).await, usage_before);
        assert_eq!(event_log(&db).await.len(), 1);
    }

    /// A user over their quota can still rename: it does not grow their usage.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn rename_within_a_drive_is_allowed_over_quota() {
        let db = SqlDb::test().await;
        let (operator, _tmp_dir) = test_fs_operator(&db);
        let pubkey = Keypair::random().public_key();
        let user_service = test_user_service(&db);
        let mut user = user_service.create_with_quota_mb(&pubkey, 1).await;
        let old = entry_path(&pubkey, "/pub/old.txt");
        let new = entry_path(&pubkey, "/pub/new.txt");
        operator.write(old.as_str(), vec![1; 10]).await.unwrap();
        user.used_bytes = 2 * 1024 * 1024;
        user_service
            .update_in_tx(&user, &mut db.pool().into())
            .await
            .unwrap();

        operator.rename(old.as_str(), new.as_str()).await.unwrap();

        assert!(entry(&db, &new).await.is_some());
        assert_eq!(user_usage(&db, &pubkey).await, 2 * 1024 * 1024);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn untracked_files_are_neither_copied_nor_renamed() {
        let db = SqlDb::test().await;
        let (operator, tmp_dir) = test_fs_operator(&db);
        let pubkey = create_user(&db).await;
        let untracked = entry_path(&pubkey, "/pub/untracked.txt");
        let destination = entry_path(&pubkey, "/pub/destination.txt");
        write_untracked(&tmp_dir, &untracked, b"unknown to the database");

        let copy_refusal = operator
            .copy(untracked.as_str(), destination.as_str())
            .await
            .expect_err("copying an untracked file should be refused");
        let rename_refusal = operator
            .rename(untracked.as_str(), destination.as_str())
            .await
            .expect_err("renaming an untracked file should be refused");

        assert_eq!(copy_refusal.kind(), opendal::ErrorKind::NotFound);
        assert_eq!(rename_refusal.kind(), opendal::ErrorKind::NotFound);
        assert!(operator.exists(untracked.as_str()).await.unwrap());
        assert!(!operator.exists(destination.as_str()).await.unwrap());
        assert_eq!(entry(&db, &destination).await, None);
        assert!(all_events(&db).await.is_empty());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn rename_over_an_existing_file_replaces_its_entry() {
        let db = SqlDb::test().await;
        let (operator, _tmp_dir) = test_fs_operator(&db);
        let pubkey = create_user(&db).await;
        let source = entry_path(&pubkey, "/pub/source.txt");
        let overwritten = entry_path(&pubkey, "/pub/overwritten.txt");
        operator.write(source.as_str(), vec![1; 10]).await.unwrap();
        operator
            .write(overwritten.as_str(), vec![2; 30])
            .await
            .unwrap();

        operator
            .rename(source.as_str(), overwritten.as_str())
            .await
            .unwrap();

        assert_eq!(entry(&db, &source).await, None);
        assert_eq!(entry(&db, &overwritten).await.unwrap().content_length, 10);
        assert_eq!(read(&operator, &overwritten).await, vec![1; 10]);
        assert_eq!(user_usage(&db, &pubkey).await, 10 + FILE_METADATA_SIZE);
    }

    /// The admin operator spans every drive, so a transfer can cross users.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn rename_into_another_drive_moves_the_usage_with_it() {
        let db = SqlDb::test().await;
        let (operator, _tmp_dir) = test_fs_operator(&db);
        let giver = create_user(&db).await;
        let receiver = create_user(&db).await;
        let given = entry_path(&giver, "/pub/file.txt");
        let received = entry_path(&receiver, "/pub/file.txt");
        operator.write(given.as_str(), vec![1; 10]).await.unwrap();

        operator
            .rename(given.as_str(), received.as_str())
            .await
            .unwrap();

        assert_eq!(entry(&db, &given).await, None);
        assert_eq!(entry(&db, &received).await.unwrap().content_length, 10);
        assert_eq!(user_usage(&db, &giver).await, 0);
        assert_eq!(user_usage(&db, &receiver).await, 10 + FILE_METADATA_SIZE);
        assert_eq!(
            event_log(&db).await[1..],
            [("PUT", received.to_string()), ("DEL", given.to_string())]
        );
    }

    /// Try a file onto a folder, by copy and by rename, then a folder onto a
    /// file and into a folder that has entries. Whatever refuses each of them,
    /// nothing may have changed. Returns the refusals in that order.
    async fn refusals_of_colliding_destinations(
        db: &SqlDb,
        operator: &Operator,
    ) -> [opendal::Error; 4] {
        const PATHS: [&str; 3] = ["/pub/file.txt", "/pub/folder/a.txt", "/pub/occupied/b.txt"];
        let pubkey = create_user(db).await;
        let file = entry_path(&pubkey, "/pub/file.txt");
        let folder = entry_path(&pubkey, "/pub/folder");
        let occupied = entry_path(&pubkey, "/pub/occupied");
        for path in PATHS {
            let path = entry_path(&pubkey, path);
            operator.write(path.as_str(), vec![1; 10]).await.unwrap();
        }
        let events_before = event_log(db).await;

        let refusals = [
            operator.copy(file.as_str(), occupied.as_str()).await.err(),
            operator
                .rename(file.as_str(), occupied.as_str())
                .await
                .err(),
            operator.rename(folder.as_str(), file.as_str()).await.err(),
            operator
                .rename(folder.as_str(), occupied.as_str())
                .await
                .err(),
        ]
        .map(|refusal| refusal.expect("a colliding destination should be refused"));

        assert_eq!(event_log(db).await, events_before);
        for path in PATHS {
            let path = entry_path(&pubkey, path);
            assert_eq!(entry(db, &path).await.unwrap().content_length, 10);
            assert_eq!(read(operator, &path).await, vec![1; 10]);
        }
        refusals
    }

    fn is_path_collision(error: opendal::Error) -> bool {
        matches!(FileIoError::from(error), FileIoError::PathCollision)
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn colliding_destinations_are_refused_and_change_nothing() {
        let db = SqlDb::test().await;
        let (operator, _tmp_dir) = test_fs_operator(&db);

        let refusals = refusals_of_colliding_destinations(&db, &operator).await;

        for refusal in refusals {
            assert!(is_path_collision(refusal));
        }
    }

    /// The admin operator, the one WebDAV copies and renames through, does not
    /// enforce collisions: a file onto a folder is left for the backend to
    /// refuse. A folder is still never merged into what is already there.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn colliding_destinations_change_nothing_under_the_admin_policy() {
        let db = SqlDb::test().await;
        let (operator, _tmp_dir) = test_admin_fs_operator(&db);

        let [copy_onto_folder, rename_onto_folder, folder_onto_file, folder_into_folder] =
            refusals_of_colliding_destinations(&db, &operator).await;

        assert!(!is_path_collision(copy_onto_folder));
        assert!(!is_path_collision(rename_onto_folder));
        assert!(is_path_collision(folder_onto_file));
        assert!(is_path_collision(folder_into_folder));
    }

    /// What the admin policy is for: a file entry left by legacy data makes
    /// every path beneath it a collision, and repairing that means writing
    /// there anyway.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn admin_policy_transfers_past_a_legacy_collision() {
        let db = SqlDb::test().await;
        let (admin_operator, _tmp_dir) = test_admin_fs_operator(&db);
        let pubkey = create_user(&db).await;
        let user = test_user_service(&db).get(&pubkey).await.unwrap();
        let file = entry_path(&pubkey, "/pub/file.txt");
        let legacy = entry_path(&pubkey, "/pub/legacy");
        let copied = entry_path(&pubkey, "/pub/legacy/copied.txt");
        let renamed = entry_path(&pubkey, "/pub/legacy/renamed.txt");
        admin_operator
            .write(file.as_str(), vec![1; 10])
            .await
            .unwrap();
        EntryRepository::create(
            user.id,
            legacy.path(),
            &pubky_common::crypto::Hash::from_bytes([0; 32]),
            0,
            "text/plain",
            &mut db.pool().into(),
        )
        .await
        .unwrap();

        // The app-facing policy refuses before its backend is asked, so it
        // does not matter that this one has a backend of its own.
        let (enforcing_operator, _enforcing_tmp_dir) = test_fs_operator(&db);
        let refusal = enforcing_operator
            .copy(file.as_str(), copied.as_str())
            .await
            .expect_err("the app-facing policy should refuse the collision");
        assert!(is_path_collision(refusal));

        admin_operator
            .copy(file.as_str(), copied.as_str())
            .await
            .unwrap();
        admin_operator
            .rename(file.as_str(), renamed.as_str())
            .await
            .unwrap();

        assert_eq!(entry(&db, &file).await, None);
        for path in [&copied, &renamed] {
            assert_eq!(entry(&db, path).await.unwrap().content_length, 10);
            assert_eq!(read(&admin_operator, path).await, vec![1; 10]);
        }
    }

    /// A caller that disconnects while the rename is being finalized drops
    /// its future. The entry must still follow the blob that already moved.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn rename_finalization_completes_after_the_caller_is_dropped() {
        let db = SqlDb::test().await;
        let (operator, _tmp_dir) = test_fs_operator(&db);
        let pubkey = create_user(&db).await;
        let old = entry_path(&pubkey, "/pub/old.txt");
        let new = entry_path(&pubkey, "/pub/new.txt");
        operator.write(old.as_str(), vec![1; 10]).await.unwrap();
        install_slow_event_insert(&db).await;

        let rename = {
            let (operator, old, new) = (operator.clone(), old.clone(), new.clone());
            tokio::spawn(async move { operator.rename(old.as_str(), new.as_str()).await })
        };
        wait_for_slow_event_insert(&db).await;
        rename.abort();
        assert!(rename.await.unwrap_err().is_cancelled());

        wait_until(
            || async { entry(&db, &new).await.is_some() && entry(&db, &old).await.is_none() },
            "the dropped rename never completed",
        )
        .await;
        assert_eq!(read(&operator, &new).await, vec![1; 10]);
        assert_eq!(all_events(&db).await.len(), 3);
    }
}
