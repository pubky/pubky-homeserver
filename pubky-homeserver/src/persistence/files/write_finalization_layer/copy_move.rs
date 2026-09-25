//! Finalizes server-side copy and rename.
//!
//! These used to pass straight through to the backend, so a copy or rename
//! changed storage while entries, events and quota stayed as they were. A
//! renamed file became unreachable over REST at both its old and new path, and
//! copying had no quota limit at all. Nothing in the REST API calls either
//! operation, which is how it went unnoticed until WebDAV did.
//!
//! Both follow the write path's ordering: lock the affected users, check
//! collisions and quota, commit the backend operation, then write entries,
//! events and usage in the same transaction. Storage cannot join that
//! transaction, so a database failure after the backend commits leaves the same
//! kind of orphan the write path already documents.
use crate::persistence::files::events::EventType;
use crate::persistence::sql::{
    entry::{EntryEntity, EntryRepository},
    user::UserEntity,
    UnifiedExecutor,
};
use crate::services::user_service::FILE_METADATA_SIZE;
use crate::shared::webdav::{EntryPath, StoragePath};
use opendal::raw::{Access, OpCopy, OpRename, RpCopy, RpRename};
use opendal::Result;

use super::{
    layer::{check_no_path_collision, quota_exceeded_error, unexpected, Finalizer},
    resolve_storage_max_bytes, would_exceed_limit,
};

/// Page size when enumerating a directory being renamed.
const LIST_PAGE: u16 = 1000;

/// One file a rename carries to a new path.
struct PlannedMove {
    source: EntryEntity,
    destination: EntryPath,
    /// An entry already at the destination, which the rename replaces.
    displaced: Option<EntryEntity>,
}

impl PlannedMove {
    fn source_bytes(&self) -> u64 {
        self.source
            .content_length
            .saturating_add(FILE_METADATA_SIZE)
    }

    fn displaced_bytes(&self) -> u64 {
        self.displaced.as_ref().map_or(0, |entry| {
            entry.content_length.saturating_add(FILE_METADATA_SIZE)
        })
    }
}

impl Finalizer {
    pub(super) async fn finalize_copy<A: Access>(
        &self,
        backend: &A,
        from: &EntryPath,
        to: &EntryPath,
        args: OpCopy,
    ) -> Result<RpCopy> {
        let mut tx = self
            .sql_db
            .pool()
            .begin()
            .await
            .map_err(|error| unexpected("Failed to begin copy finalization", error))?;

        let result = {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            self.copy_in_transaction(backend, from, to, args, &mut executor)
                .await
        };

        match result {
            Ok(rp) => {
                tx.commit()
                    .await
                    .map_err(|error| unexpected("Failed to commit copy finalization", error))?;
                self.notify_event();
                Ok(rp)
            }
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::error!(
                        from = %from,
                        to = %to,
                        error = %rollback_error,
                        "Failed to roll back copy finalization"
                    );
                }
                Err(error)
            }
        }
    }

    /// A copy is always of a single file: dav-server recurses through a
    /// collection itself, creating each directory and copying file by file.
    async fn copy_in_transaction<A: Access>(
        &self,
        backend: &A,
        from: &EntryPath,
        to: &EntryPath,
        args: OpCopy,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<RpCopy> {
        let mut user = self.lock_user(to, executor).await?;
        if self.collision_policy.enforces_collisions() {
            check_no_path_collision(to, executor).await?;
        }

        let source = tracked_entry(from, executor)
            .await?
            .ok_or_else(|| untracked_source(from))?;
        let displaced = tracked_entry(to, executor).await?;

        // The destination gains the source's bytes, less whatever it replaces.
        let displaced_bytes = displaced.as_ref().map_or(0, |entry| entry.content_length);
        let metadata_bytes = if displaced.is_none() {
            FILE_METADATA_SIZE
        } else {
            0
        };
        let bytes_delta =
            source.content_length as i64 - displaced_bytes as i64 + metadata_bytes as i64;
        self.ensure_within_quota(&user, bytes_delta)?;

        let rp = backend.copy(from.as_str(), to.as_str(), args).await?;

        write_entry_from(&user, to, displaced, &source, executor).await?;
        self.record_event(
            user.id,
            EventType::Put {
                content_hash: source.content_hash,
            },
            to,
            executor,
        )
        .await?;
        user.used_bytes = user.used_bytes.saturating_add_signed(bytes_delta);
        self.save_usage(&user, executor).await?;

        Ok(rp)
    }

    pub(super) async fn finalize_rename<A: Access>(
        &self,
        backend: &A,
        from: &EntryPath,
        to: &EntryPath,
        args: OpRename,
    ) -> Result<RpRename> {
        let mut tx = self
            .sql_db
            .pool()
            .begin()
            .await
            .map_err(|error| unexpected("Failed to begin rename finalization", error))?;

        let result = {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            self.rename_in_transaction(backend, from, to, args, &mut executor)
                .await
        };

        match result {
            Ok(rp) => {
                tx.commit()
                    .await
                    .map_err(|error| unexpected("Failed to commit rename finalization", error))?;
                self.notify_event();
                Ok(rp)
            }
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::error!(
                        from = %from,
                        to = %to,
                        error = %rollback_error,
                        "Failed to roll back rename finalization"
                    );
                }
                Err(error)
            }
        }
    }

    /// Unlike a copy, a rename of a collection arrives as one call for the whole
    /// tree, so every entry beneath it moves in this transaction.
    async fn rename_in_transaction<A: Access>(
        &self,
        backend: &A,
        from: &EntryPath,
        to: &EntryPath,
        args: OpRename,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<RpRename> {
        let (mut from_user, mut to_user) = self.lock_users(from, to, executor).await?;
        if self.collision_policy.enforces_collisions() {
            check_no_path_collision(to, executor).await?;
        }

        let moves = plan_moves(from, to, executor).await?;
        if moves.is_empty() {
            return Err(untracked_source(from));
        }

        let moved: u64 = moves.iter().map(PlannedMove::source_bytes).sum();
        let displaced: u64 = moves.iter().map(PlannedMove::displaced_bytes).sum();

        // Within one drive a rename can only free space (by replacing files), so
        // quota is only in question when it carries files to another user.
        let to_delta = match &to_user {
            Some(user) => {
                let delta = moved as i64 - displaced as i64;
                self.ensure_within_quota(user, delta)?;
                delta
            }
            None => -(displaced as i64),
        };

        let rp = backend.rename(from.as_str(), to.as_str(), args).await?;

        for planned in moves {
            let owner = to_user.as_ref().unwrap_or(&from_user);
            write_entry_from(
                owner,
                &planned.destination,
                planned.displaced,
                &planned.source,
                executor,
            )
            .await?;
            EntryRepository::delete(planned.source.id, executor)
                .await
                .map_err(|error| {
                    unexpected(
                        format!("Failed to remove renamed entry {}", planned.source.path),
                        error,
                    )
                })?;

            // Deletion before creation, so a consumer replaying the feed never
            // sees the same content at two paths at once.
            self.record_event(
                from_user.id,
                EventType::Delete,
                &planned.source.path,
                executor,
            )
            .await?;
            self.record_event(
                owner.id,
                EventType::Put {
                    content_hash: planned.source.content_hash,
                },
                &planned.destination,
                executor,
            )
            .await?;
        }

        match &mut to_user {
            Some(user) => {
                from_user.used_bytes = from_user.used_bytes.saturating_sub(moved);
                user.used_bytes = user.used_bytes.saturating_add_signed(to_delta);
                self.save_usage(&from_user, executor).await?;
                self.save_usage(user, executor).await?;
            }
            None => {
                from_user.used_bytes = from_user.used_bytes.saturating_add_signed(to_delta);
                self.save_usage(&from_user, executor).await?;
            }
        }

        Ok(rp)
    }

    async fn lock_user(
        &self,
        path: &EntryPath,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<UserEntity> {
        self.user_service
            .get_for_no_key_update(path.pubkey(), executor)
            .await
            .map_err(|error| unexpected(format!("Failed to lock user {}", path.pubkey()), error))
    }

    /// Lock the source and destination owners, returning the destination
    /// separately only when it is a different user.
    ///
    /// Two users are locked in a fixed order, so renames running in opposite
    /// directions between the same pair cannot deadlock.
    async fn lock_users(
        &self,
        from: &EntryPath,
        to: &EntryPath,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<(UserEntity, Option<UserEntity>)> {
        if from.pubkey() == to.pubkey() {
            return Ok((self.lock_user(from, executor).await?, None));
        }
        if from.pubkey().z32() < to.pubkey().z32() {
            let from_user = self.lock_user(from, executor).await?;
            let to_user = self.lock_user(to, executor).await?;
            Ok((from_user, Some(to_user)))
        } else {
            let to_user = self.lock_user(to, executor).await?;
            let from_user = self.lock_user(from, executor).await?;
            Ok((from_user, Some(to_user)))
        }
    }

    fn ensure_within_quota(&self, user: &UserEntity, bytes_delta: i64) -> Result<()> {
        let max_bytes = resolve_storage_max_bytes(user, self.default_storage_mb);
        if would_exceed_limit(user.used_bytes, bytes_delta, max_bytes) {
            return Err(quota_exceeded_error());
        }
        Ok(())
    }

    async fn record_event(
        &self,
        user_id: i32,
        event: EventType,
        path: &EntryPath,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<()> {
        self.events_service
            .create_event(user_id, event, path, executor)
            .await
            .map(|_| ())
            .map_err(|error| unexpected(format!("Failed to create event for {path}"), error))
    }

    async fn save_usage(
        &self,
        user: &UserEntity,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<()> {
        self.user_service
            .update_in_tx(user, executor)
            .await
            .map(|_| ())
            .map_err(|error| {
                unexpected(
                    format!("Failed to update quota for user {}", user.id),
                    error,
                )
            })
    }
}

/// Every file a rename of `from` carries, with where each one lands.
///
/// `from` names either a file or a directory, and a directory path arrives
/// without its trailing slash, so the shape of the string cannot be trusted:
/// an exact entry means a file, otherwise everything beneath the path moves.
async fn plan_moves(
    from: &EntryPath,
    to: &EntryPath,
    executor: &mut UnifiedExecutor<'_>,
) -> Result<Vec<PlannedMove>> {
    if let Some(source) = tracked_entry(from, executor).await? {
        let displaced = tracked_entry(to, executor).await?;
        return Ok(vec![PlannedMove {
            source,
            destination: to.clone(),
            displaced,
        }]);
    }

    let from_dir = as_directory(from.path());
    let to_dir = as_directory(to.path());
    let mut moves = Vec::new();
    let mut cursor = None;

    loop {
        let page = EntryRepository::list_deep(from, Some(LIST_PAGE), cursor, false, executor)
            .await
            .map_err(|error| unexpected(format!("Failed to list {from} for rename"), error))?;
        let full_page = page.len() == LIST_PAGE as usize;
        cursor = page.last().cloned();

        for path in page {
            let suffix = path
                .path()
                .as_str()
                .strip_prefix(from_dir.as_str())
                .ok_or_else(|| {
                    unexpected("Listed entry is outside the renamed directory", &path)
                })?;
            let destination = StoragePath::new(&format!("{to_dir}{suffix}"))
                .map(|storage_path| EntryPath::new(to.pubkey().clone(), storage_path))
                .map_err(|error| {
                    unexpected(format!("Invalid rename destination for {path}"), error)
                })?;

            let source = tracked_entry(&path, executor)
                .await?
                .ok_or_else(|| untracked_source(&path))?;
            let displaced = tracked_entry(&destination, executor).await?;
            moves.push(PlannedMove {
                source,
                destination,
                displaced,
            });
        }

        if !full_page {
            return Ok(moves);
        }
    }
}

fn as_directory(path: &StoragePath) -> String {
    let path = path.as_str();
    if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{path}/")
    }
}

async fn tracked_entry(
    path: &EntryPath,
    executor: &mut UnifiedExecutor<'_>,
) -> Result<Option<EntryEntity>> {
    match EntryRepository::get_by_path(path, executor).await {
        Ok(entry) => Ok(Some(entry)),
        Err(sqlx::Error::RowNotFound) => Ok(None),
        Err(error) => Err(unexpected(format!("Failed to load entry {path}"), error)),
    }
}

/// Point `destination` at `source`'s content, reusing an entry already there.
async fn write_entry_from(
    owner: &UserEntity,
    destination: &EntryPath,
    displaced: Option<EntryEntity>,
    source: &EntryEntity,
    executor: &mut UnifiedExecutor<'_>,
) -> Result<()> {
    match displaced {
        Some(mut entry) => {
            entry.content_hash = source.content_hash;
            entry.content_length = source.content_length;
            entry.content_type = source.content_type.clone();
            EntryRepository::update(&entry, executor).await
        }
        None => EntryRepository::create(
            owner.id,
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
            format!("Failed to write entry {destination}; potential orphaned file"),
            error,
        )
    })
}

/// Only files the database knows about can be copied or renamed consistently:
/// there is no size to charge or hash to record for anything else.
fn untracked_source(path: &EntryPath) -> opendal::Error {
    opendal::Error::new(
        opendal::ErrorKind::NotFound,
        format!("{path} is not a tracked file"),
    )
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use opendal::Operator;
    use pubky_common::crypto::{Keypair, PublicKey};
    use tempfile::TempDir;

    use crate::data_directory::storage_config::{StorageConfigToml, StorageToml};
    use crate::persistence::files::events::{EventEntity, EventsService};
    use crate::persistence::files::opendal::opendal_service::build_storage_operators;
    use crate::persistence::sql::{entry::EntryRepository, SqlDb};
    use crate::services::user_service::{UserService, FILE_METADATA_SIZE};
    use crate::shared::webdav::{EntryPath, StoragePath};

    use super::super::layer::test_support::{all_events, user_usage};

    const MB: u64 = 1024 * 1024;

    /// The storage stack exactly as production builds it on the `file_system`
    /// backend — atomic writes included. The fs backend is the one that
    /// matters: it supports native copy and rename, and it is where writes used
    /// to land directly in the destination file.
    struct Drive {
        db: SqlDb,
        operator: Operator,
        dir: TempDir,
        owner: PublicKey,
    }

    impl Drive {
        async fn new(quota_mb: Option<u64>) -> Self {
            let db = SqlDb::test().await;
            let dir = tempfile::tempdir().unwrap();
            let users = UserService::new(db.clone());
            let owner = Keypair::random().public_key();
            match quota_mb {
                Some(mb) => {
                    users.create_with_quota_mb(&owner, mb).await;
                }
                None => {
                    users.create(&owner).await.unwrap();
                }
            }

            let storage = StorageToml {
                backend: StorageConfigToml::FileSystem,
                default_quota_mb: None,
            };
            let (operator, _admin) = build_storage_operators(
                &storage,
                dir.path(),
                db.clone(),
                EventsService::new(db.clone(), 100),
                users,
            )
            .unwrap();

            Self {
                db,
                operator,
                dir,
                owner,
            }
        }

        fn path(&self, path: &str) -> EntryPath {
            EntryPath::new(self.owner.clone(), StoragePath::new(path).unwrap())
        }

        fn key(&self, path: &str) -> String {
            self.path(path).as_str().to_string()
        }

        async fn put(&self, path: &str, bytes: Vec<u8>) {
            self.operator.write(&self.key(path), bytes).await.unwrap();
        }

        /// What is physically on disk, bypassing every layer.
        fn on_disk(&self, path: &str) -> Option<Vec<u8>> {
            std::fs::read(self.disk_path(path)).ok()
        }

        /// Put bytes on disk with no entry, as the old unfinalized copy did.
        fn plant_untracked(&self, path: &str, bytes: &[u8]) {
            let target = self.disk_path(path);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, bytes).unwrap();
        }

        fn disk_path(&self, path: &str) -> PathBuf {
            self.dir
                .path()
                .join("data/files")
                .join(self.owner.z32())
                .join(path.trim_start_matches('/'))
        }

        async fn entry_length(&self, path: &str) -> Option<u64> {
            EntryRepository::get_by_path(&self.path(path), &mut self.db.pool().into())
                .await
                .ok()
                .map(|entry| entry.content_length)
        }

        async fn usage(&self) -> u64 {
            user_usage(&self.db, &self.owner).await
        }

        /// Events for this drive, as `(PUT|DEL, path)`.
        async fn events(&self) -> Vec<(&'static str, String)> {
            all_events(&self.db)
                .await
                .into_iter()
                .filter(|event: &EventEntity| event.user_pubkey == self.owner)
                .map(|event| (event.event_type.as_str(), event.path.path().to_string()))
                .collect()
        }
    }

    fn ev(kind: &'static str, path: &str) -> (&'static str, String) {
        (kind, path.to_string())
    }

    // ── copy ────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn copy_records_the_destination_charges_quota_and_emits_an_event() {
        let drive = Drive::new(None).await;
        drive.put("/pub/a.txt", vec![7; 100]).await;
        let before = drive.usage().await;

        drive
            .operator
            .copy(&drive.key("/pub/a.txt"), &drive.key("/pub/b.txt"))
            .await
            .unwrap();

        assert_eq!(drive.on_disk("/pub/b.txt"), Some(vec![7; 100]));
        assert_eq!(
            drive.entry_length("/pub/b.txt").await,
            Some(100),
            "the copy must be visible to REST, which reads the entries table"
        );
        assert_eq!(drive.usage().await, before + 100 + FILE_METADATA_SIZE);
        assert_eq!(
            drive.events().await,
            vec![ev("PUT", "/pub/a.txt"), ev("PUT", "/pub/b.txt")]
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn copy_past_the_quota_is_refused_and_leaves_nothing_behind() {
        // Before this was finalized, five copies of a 600 KB file put 4 MB on
        // disk against a 1 MB cap while usage never moved.
        let drive = Drive::new(Some(1)).await;
        drive
            .put("/pub/big.bin", vec![1; (600 * 1024) as usize])
            .await;
        let usage = drive.usage().await;

        let error = drive
            .operator
            .copy(&drive.key("/pub/big.bin"), &drive.key("/pub/copy.bin"))
            .await
            .expect_err("a copy that exceeds the quota must fail");

        assert_eq!(error.kind(), opendal::ErrorKind::RateLimited);
        assert_eq!(drive.on_disk("/pub/copy.bin"), None);
        assert_eq!(drive.entry_length("/pub/copy.bin").await, None);
        assert_eq!(drive.usage().await, usage);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn copy_over_an_existing_file_charges_only_the_difference() {
        let drive = Drive::new(None).await;
        drive.put("/pub/small.txt", vec![1; 10]).await;
        drive.put("/pub/large.txt", vec![2; 500]).await;
        let before = drive.usage().await;

        drive
            .operator
            .copy(&drive.key("/pub/large.txt"), &drive.key("/pub/small.txt"))
            .await
            .unwrap();

        assert_eq!(drive.entry_length("/pub/small.txt").await, Some(500));
        // An overwrite keeps its entry, so no second metadata charge.
        assert_eq!(drive.usage().await, before + 490);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn copying_a_file_the_database_does_not_know_is_refused() {
        // The file is really on disk — it is the entry that is missing, which is
        // what the unfinalized copy used to leave behind. Copying it would mint a
        // second untracked file, so it must be refused by the finalizer rather
        // than merely failing to find anything.
        let drive = Drive::new(None).await;
        drive.plant_untracked("/pub/orphan.txt", b"bytes nobody accounted for");

        let error = drive
            .operator
            .copy(&drive.key("/pub/orphan.txt"), &drive.key("/pub/b.txt"))
            .await
            .expect_err("there is no size to charge for a file the database does not know");

        assert_eq!(error.kind(), opendal::ErrorKind::NotFound);
        assert_eq!(drive.on_disk("/pub/b.txt"), None);
    }

    // ── rename ──────────────────────────────────────────────────────────────

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn rename_moves_the_entry_so_rest_finds_the_file_at_its_new_path() {
        // Renaming in a file manager used to leave the file unreachable over REST
        // at both names: a stale entry pointing at nothing, and bytes with no entry.
        let drive = Drive::new(None).await;
        drive.put("/pub/report.txt", b"quarterly".to_vec()).await;
        let usage = drive.usage().await;

        drive
            .operator
            .rename(
                &drive.key("/pub/report.txt"),
                &drive.key("/pub/report-final.txt"),
            )
            .await
            .unwrap();

        assert_eq!(
            drive.on_disk("/pub/report-final.txt"),
            Some(b"quarterly".to_vec())
        );
        assert_eq!(drive.entry_length("/pub/report.txt").await, None);
        assert_eq!(drive.entry_length("/pub/report-final.txt").await, Some(9));
        assert_eq!(
            drive.usage().await,
            usage,
            "a rename within a drive is free"
        );
        assert_eq!(
            drive.events().await,
            vec![
                ev("PUT", "/pub/report.txt"),
                ev("DEL", "/pub/report.txt"),
                ev("PUT", "/pub/report-final.txt"),
            ]
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn renaming_a_directory_moves_every_file_beneath_it() {
        // dav-server renames a collection in one call, and hands over the path
        // without a trailing slash, so the finalizer has to find the tree itself.
        let drive = Drive::new(None).await;
        drive.put("/pub/album/one.jpg", vec![1; 10]).await;
        drive.put("/pub/album/two.jpg", vec![2; 20]).await;
        drive.put("/pub/album/raw/three.cr2", vec![3; 30]).await;
        drive.put("/pub/elsewhere.txt", vec![4; 5]).await;
        let usage = drive.usage().await;

        drive
            .operator
            .rename(&drive.key("/pub/album"), &drive.key("/pub/holiday"))
            .await
            .unwrap();

        for (old, new, len) in [
            ("/pub/album/one.jpg", "/pub/holiday/one.jpg", 10),
            ("/pub/album/two.jpg", "/pub/holiday/two.jpg", 20),
            ("/pub/album/raw/three.cr2", "/pub/holiday/raw/three.cr2", 30),
        ] {
            assert_eq!(drive.entry_length(old).await, None, "{old} should be gone");
            assert_eq!(
                drive.entry_length(new).await,
                Some(len),
                "{new} should exist"
            );
            assert!(drive.on_disk(new).is_some(), "{new} should be on disk");
        }
        assert_eq!(
            drive.entry_length("/pub/elsewhere.txt").await,
            Some(5),
            "a sibling outside the directory must not move"
        );
        assert_eq!(drive.usage().await, usage);

        let moved = drive
            .events()
            .await
            .into_iter()
            .filter(|(_, path)| path.starts_with("/pub/holiday/"))
            .count();
        assert_eq!(moved, 3, "every moved file needs its own PUT for indexers");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn rename_over_an_existing_file_frees_what_it_replaces() {
        let drive = Drive::new(None).await;
        drive.put("/pub/new.txt", vec![1; 100]).await;
        drive.put("/pub/old.txt", vec![2; 300]).await;
        let before = drive.usage().await;

        drive
            .operator
            .rename(&drive.key("/pub/new.txt"), &drive.key("/pub/old.txt"))
            .await
            .unwrap();

        assert_eq!(drive.entry_length("/pub/new.txt").await, None);
        assert_eq!(drive.entry_length("/pub/old.txt").await, Some(100));
        assert_eq!(drive.usage().await, before - 300 - FILE_METADATA_SIZE);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn renaming_a_file_the_database_does_not_know_is_refused() {
        let drive = Drive::new(None).await;
        drive.plant_untracked("/pub/orphan.txt", b"bytes nobody accounted for");

        let error = drive
            .operator
            .rename(&drive.key("/pub/orphan.txt"), &drive.key("/pub/b.txt"))
            .await
            .expect_err("nothing tracked at that path, file or directory");

        assert_eq!(error.kind(), opendal::ErrorKind::NotFound);
        assert!(
            drive.on_disk("/pub/orphan.txt").is_some(),
            "a refused rename must leave the file where it was"
        );
        assert_eq!(drive.on_disk("/pub/b.txt"), None);
    }

    // ── writes that fail after streaming ──────────────────────────────────────

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_refused_overwrite_leaves_the_original_intact() {
        // Without atomic writes the fs backend wrote straight into the target, so
        // an overwrite refused at finalize had already destroyed the original.
        let drive = Drive::new(Some(1)).await;
        drive
            .put("/pub/important.txt", b"the original".to_vec())
            .await;

        drive
            .operator
            .write(
                &drive.key("/pub/important.txt"),
                vec![b'N'; (2 * MB) as usize],
            )
            .await
            .expect_err("an overwrite past the quota must fail");

        assert_eq!(
            drive.on_disk("/pub/important.txt"),
            Some(b"the original".to_vec()),
            "a refused overwrite must not touch the existing content"
        );
        assert_eq!(drive.entry_length("/pub/important.txt").await, Some(12));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_refused_new_file_leaves_nothing_on_disk() {
        let drive = Drive::new(Some(1)).await;

        drive
            .operator
            .write(&drive.key("/pub/too-big.bin"), vec![0; (2 * MB) as usize])
            .await
            .expect_err("a write past the quota must fail");

        assert_eq!(drive.on_disk("/pub/too-big.bin"), None);
        assert!(
            staged_writes(drive.dir.path()).is_empty(),
            "the aborted write must not leave a temp file behind either"
        );
    }

    fn staged_writes(data_dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(data_dir.join("data/tmp"))
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default()
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn writes_interrupted_by_a_crash_are_cleared_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("data/tmp");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("abandoned-upload"), b"half a file").unwrap();

        let db = SqlDb::test().await;
        let storage = StorageToml {
            backend: StorageConfigToml::FileSystem,
            default_quota_mb: None,
        };
        build_storage_operators(
            &storage,
            dir.path(),
            db.clone(),
            EventsService::new(db.clone(), 100),
            UserService::new(db),
        )
        .unwrap();

        assert!(staged_writes(dir.path()).is_empty());
    }
}
