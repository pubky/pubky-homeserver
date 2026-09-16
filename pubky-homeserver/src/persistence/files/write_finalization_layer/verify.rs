//! Detects and repairs entry rows that disagree with their blob.
//!
//! A write publishes its blob and then commits the entry row. If the process
//! dies, or the commit fails, between those two steps the row keeps the
//! previous content hash while the blob holds the new bytes. A conditional
//! write would then be compared against the wrong ETag, and a stale ETag
//! could win. So before a precondition is evaluated, the row is verified
//! against the blob and repaired under the user lock.
//!
//! Verification is cheap when the row carries the blob's fingerprint (the
//! backend's ETag, version, or last-modified time plus length, recorded when
//! the write committed): a `stat` that matches means the row is trusted. A
//! mismatch, or a row without a fingerprint, falls back to reading and
//! hashing the blob, and the fingerprint is then recorded so the blob is
//! hashed once, not on every probe. Unconditional writes and reads do not
//! verify.
//!
//! A blob the backend cannot find is never repaired automatically. A stat
//! `NotFound` is also what an unmounted volume, a misconfigured bucket, or a
//! restore in progress looks like, and deleting rows in response would turn
//! an outage into permanent index loss. The condition is evaluated as if
//! nothing were stored, the row is left alone, and the case is logged.

use opendal::raw::{oio::ReadDyn, AccessDyn, OpRead, OpStat};
use opendal::{ErrorKind, Metadata, Result};
use pubky_common::crypto::Hash;

use crate::persistence::files::{events::EventType, FileMetadata, FileMetadataBuilder};
use crate::persistence::sql::{
    entry::{EntryEntity, EntryRepository},
    user::UserEntity,
    UnifiedExecutor,
};
use crate::shared::webdav::EntryPath;

use super::layer::{unexpected, Finalizer};

/// Identity of a stored blob as the backend reports it, obtainable with a
/// `stat`. `None` when the backend reports nothing that changes with content.
///
/// The modification time is the weakest of the three. Kernels stamp it at a
/// granularity of a few milliseconds, so two same-length publishes within
/// one tick get the same fingerprint, and a row left stale by the second one
/// (its commit failed after the publish) would be trusted. The filesystem
/// backend reports nothing stronger; both conditions together are rare.
pub(super) fn blob_fingerprint(metadata: &Metadata) -> Option<String> {
    if let Some(etag) = metadata.etag() {
        return Some(format!("etag:{etag}"));
    }
    if let Some(version) = metadata.version() {
        return Some(format!("version:{version}"));
    }
    metadata.last_modified().map(|modified| {
        format!(
            "modified:{}:{}",
            modified.into_inner().as_nanosecond(),
            metadata.content_length()
        )
    })
}

/// What a `stat` of the blob says about the row.
enum StatVerdict {
    /// The blob's fingerprint matches the row: the row can be trusted.
    Vouched,
    /// The row has no fingerprint, or a different one: the blob must be
    /// hashed to know. Carries the blob's current fingerprint.
    Unvouched(Option<String>),
    /// The backend has no blob at the entry's path, or cannot see it.
    Missing,
}

/// How the blob at an entry's path relates to the row.
pub(super) enum BlobState {
    /// The blob holds what the row describes.
    Consistent,
    /// The blob holds different content than the row describes.
    Diverged(FileMetadata),
    /// The backend has no blob at the entry's path, or cannot see it.
    Missing,
}

pub(super) struct VerifiedBlob {
    pub(super) state: BlobState,
    /// The blob's current fingerprint, to record on the row.
    pub(super) fingerprint: Option<String>,
}

/// The outcome of reconciling an entry row with its blob.
pub(super) struct Reconciled {
    /// The entry row as it now stands. Always kept, even when the blob is
    /// missing.
    pub(super) entry: EntryEntity,
    /// The content a precondition must be evaluated against: the verified
    /// row's hash, or `None` when the backend has no blob for it.
    pub(super) content_hash: Option<Hash>,
    /// The event the repair owes the feed, if it changed the content the row
    /// describes. Inserted by the caller, as late in its transaction as
    /// possible: see [`Finalizer::record_event`].
    pub(super) event: Option<EventType>,
}

fn log_missing_blob(entry_path: &EntryPath) {
    tracing::error!(
        path = %entry_path,
        "Entry row has no blob behind it, or the backend cannot see it; \
         leaving the row for an administrator"
    );
}

impl Finalizer {
    /// The fingerprint of the blob at `entry_path`, by `stat`.
    pub(super) async fn stat_blob_fingerprint(
        &self,
        entry_path: &EntryPath,
    ) -> Result<Option<String>> {
        let stat = self
            .probe
            .stat_dyn(entry_path.as_str(), OpStat::new())
            .await?;
        Ok(blob_fingerprint(&stat.into_metadata()))
    }

    /// What a `stat` of the blob says about the row, without reading the blob.
    async fn stat_blob(&self, entry: &EntryEntity) -> Result<StatVerdict> {
        let metadata = match self
            .probe
            .stat_dyn(entry.path.as_str(), OpStat::new())
            .await
        {
            Ok(stat) => stat.into_metadata(),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(StatVerdict::Missing),
            Err(error) => return Err(error),
        };
        let fingerprint = blob_fingerprint(&metadata);
        if fingerprint.is_some() && fingerprint == entry.blob_fingerprint {
            Ok(StatVerdict::Vouched)
        } else {
            Ok(StatVerdict::Unvouched(fingerprint))
        }
    }

    /// Compare the blob at the entry's path with the row. Reads the blob only
    /// when its fingerprint does not vouch for the row.
    pub(super) async fn verify_blob(&self, entry: &EntryEntity) -> Result<VerifiedBlob> {
        let fingerprint = match self.stat_blob(entry).await? {
            StatVerdict::Vouched => {
                return Ok(VerifiedBlob {
                    state: BlobState::Consistent,
                    fingerprint: entry.blob_fingerprint.clone(),
                });
            }
            StatVerdict::Missing => {
                return Ok(VerifiedBlob {
                    state: BlobState::Missing,
                    fingerprint: None,
                });
            }
            StatVerdict::Unvouched(fingerprint) => fingerprint,
        };

        let path = entry.path.as_str();
        let (_, mut reader) = self.probe.read_dyn(path, OpRead::new()).await?;
        let mut builder = FileMetadataBuilder::default();
        builder.guess_mime_type_from_path(entry.path.path().as_str());
        loop {
            let buffer = reader.read_dyn().await?;
            if buffer.is_empty() {
                break;
            }
            for chunk in buffer {
                builder.update(&chunk);
            }
        }
        let blob = builder.finalize();

        let state = if blob.hash == entry.content_hash && blob.length as u64 == entry.content_length
        {
            BlobState::Consistent
        } else {
            BlobState::Diverged(blob)
        };
        Ok(VerifiedBlob { state, fingerprint })
    }

    /// The content hash a precondition must be compared with, without holding
    /// the user lock. The row's hash when its fingerprint vouches for it;
    /// otherwise the row is reconciled in a transaction of its own first, so
    /// that a lying row is repaired even when the request is then rejected.
    /// `None` if the backend has no blob for it.
    ///
    /// Only a `stat` happens outside the lock. The blob is hashed by the
    /// repair, under the lock, so concurrent probes of one path hash it once
    /// between them and the first repair records the fingerprint for the rest.
    pub(super) async fn verified_content_hash(&self, entry: EntryEntity) -> Result<Option<Hash>> {
        match self.stat_blob(&entry).await? {
            StatVerdict::Vouched => Ok(Some(entry.content_hash)),
            StatVerdict::Missing => {
                log_missing_blob(&entry.path);
                Ok(None)
            }
            StatVerdict::Unvouched(_) => self.repair_entry(&entry.path).await,
        }
    }

    /// Reconcile the entry at `entry_path` with its blob under the user lock,
    /// in a transaction of its own. Returns the content hash a precondition
    /// must be compared with afterwards.
    async fn repair_entry(&self, entry_path: &EntryPath) -> Result<Option<Hash>> {
        let mut tx = self
            .sql_db
            .pool()
            .begin()
            .await
            .map_err(|error| unexpected("Failed to begin entry repair transaction", error))?;

        let result = {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            self.repair_in_transaction(entry_path, &mut executor).await
        };
        let repaired = match result {
            Ok(repaired) => repaired,
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::error!(
                        path = %entry_path,
                        error = %rollback_error,
                        "Failed to roll back entry repair transaction"
                    );
                }
                return Err(error);
            }
        };
        tx.commit()
            .await
            .map_err(|error| unexpected("Failed to commit entry repair", error))?;
        self.notify_event();
        Ok(repaired)
    }

    async fn repair_in_transaction(
        &self,
        entry_path: &EntryPath,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<Option<Hash>> {
        let mut user = self
            .user_service
            .get_for_no_key_update(entry_path.pubkey(), executor)
            .await
            .map_err(|error| {
                unexpected(
                    format!("Failed to lock user {}", entry_path.pubkey()),
                    error,
                )
            })?;
        let entry = match EntryRepository::get_by_path(entry_path, executor).await {
            Ok(entry) => entry,
            Err(sqlx::Error::RowNotFound) => return Ok(None),
            Err(error) => {
                return Err(unexpected(
                    format!("Failed to load entry {entry_path} for repair"),
                    error,
                ));
            }
        };
        let reconciled = self.reconcile_entry(&mut user, entry, executor).await?;
        if let Some(event) = reconciled.event {
            self.record_event(user.id, event, entry_path, executor)
                .await?;
        }
        Ok(reconciled.content_hash)
    }

    /// Bring an entry row into line with its blob. Must run under the user
    /// lock.
    ///
    /// A repair is accounted like the write that should have been committed:
    /// the row and the user's quota here, and an event handed back for the
    /// caller to insert. A missing blob changes nothing; see the module doc.
    pub(super) async fn reconcile_entry(
        &self,
        user: &mut UserEntity,
        mut entry: EntryEntity,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<Reconciled> {
        let verified = self.verify_blob(&entry).await?;
        let entry_path = entry.path.clone();
        match verified.state {
            BlobState::Consistent => {
                if verified.fingerprint != entry.blob_fingerprint {
                    entry.blob_fingerprint = verified.fingerprint;
                    EntryRepository::set_blob_fingerprint(
                        entry.id,
                        entry.blob_fingerprint.as_deref(),
                        executor,
                    )
                    .await
                    .map_err(|error| {
                        unexpected(
                            format!("Failed to record blob fingerprint for {entry_path}"),
                            error,
                        )
                    })?;
                }
                Ok(Reconciled {
                    content_hash: Some(entry.content_hash),
                    entry,
                    event: None,
                })
            }
            BlobState::Diverged(blob) => {
                tracing::warn!(
                    path = %entry_path,
                    "Entry row did not describe its blob; repaired from the blob"
                );
                let bytes_delta = blob.length as i64 - entry.content_length as i64;
                entry.content_hash = blob.hash;
                entry.content_length = blob.length as u64;
                entry.content_type = blob.content_type;
                entry.blob_fingerprint = verified.fingerprint;
                EntryRepository::update(&entry, executor)
                    .await
                    .map_err(|error| {
                        unexpected(format!("Failed to repair entry {entry_path}"), error)
                    })?;
                user.used_bytes = user.used_bytes.saturating_add_signed(bytes_delta);
                self.update_quota(user, &entry_path, executor).await?;
                Ok(Reconciled {
                    content_hash: Some(blob.hash),
                    entry,
                    event: Some(EventType::Put {
                        content_hash: blob.hash,
                    }),
                })
            }
            BlobState::Missing => {
                log_missing_blob(&entry_path);
                Ok(Reconciled {
                    entry,
                    content_hash: None,
                    event: None,
                })
            }
        }
    }

    async fn update_quota(
        &self,
        user: &UserEntity,
        entry_path: &EntryPath,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<()> {
        self.user_service
            .update_in_tx(user, executor)
            .await
            .map(|_| ())
            .map_err(|error| {
                unexpected(
                    format!("Failed to update quota for {}", entry_path.pubkey()),
                    error,
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use opendal::Metadata;

    use crate::persistence::files::{content_hash_etag, events::EventType, FileIoError};
    use crate::persistence::sql::{entry::EntryRepository, SqlDb};
    use crate::services::user_service::FILE_METADATA_SIZE;
    use crate::shared::webdav::{EntryPath, StoragePath};

    use super::super::layer::test_support::{
        all_events, create_user, test_fs_operator, user_usage,
    };
    use super::*;

    struct Fixture {
        db: SqlDb,
        operator: opendal::Operator,
        _dir: tempfile::TempDir,
        blob_file: PathBuf,
        path: EntryPath,
        pubkey: pubky_common::crypto::PublicKey,
    }

    /// A user with `/test.txt` holding ten `1` bytes on the filesystem backend.
    async fn fixture() -> Fixture {
        let db = SqlDb::test().await;
        let (operator, dir) = test_fs_operator(&db);
        let pubkey = create_user(&db).await;
        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test.txt").unwrap());
        operator.write(path.as_str(), vec![1; 10]).await.unwrap();
        let blob_file = dir.path().join("files").join(path.as_str());
        assert_eq!(std::fs::read(&blob_file).unwrap(), vec![1; 10]);
        Fixture {
            db,
            operator,
            _dir: dir,
            blob_file,
            path,
            pubkey,
        }
    }

    impl Fixture {
        async fn entry(&self) -> EntryEntity {
            EntryRepository::get_by_path(&self.path, &mut self.db.pool().into())
                .await
                .unwrap()
        }

        async fn etag(&self) -> String {
            content_hash_etag(&self.entry().await.content_hash)
        }

        /// Replace the blob behind the back of the database, as a publish
        /// whose commit never happened would.
        fn corrupt_blob(&self, content: &[u8]) {
            std::fs::write(&self.blob_file, content).unwrap();
        }

        async fn stat_fingerprint(&self) -> Option<String> {
            blob_fingerprint(&self.operator.stat(self.path.as_str()).await.unwrap())
        }

        async fn write_if_match(&self, etag: &str, content: Vec<u8>) -> Result<()> {
            let mut writer = self
                .operator
                .writer_with(self.path.as_str())
                .if_match(etag)
                .await?;
            writer.write(content).await?;
            writer.close().await.map(|_| ())
        }

        async fn delete_if_match(&self, etag: &str) -> Result<()> {
            self.operator
                .delete_with(self.path.as_str())
                .version(etag)
                .await
        }

        async fn event_types(&self) -> Vec<EventType> {
            all_events(&self.db)
                .await
                .into_iter()
                .map(|event| event.event_type)
                .collect()
        }
    }

    fn assert_precondition_failed(error: opendal::Error) {
        assert!(matches!(
            FileIoError::from(error),
            FileIoError::PreconditionFailed
        ));
    }

    fn put(content: &[u8]) -> EventType {
        EventType::Put {
            content_hash: pubky_common::crypto::hash(content),
        }
    }

    #[test]
    fn fingerprint_prefers_etag_then_version_then_modification_time() {
        assert_eq!(blob_fingerprint(&Metadata::default()), None);

        let mut metadata = Metadata::default();
        metadata.set_content_length(7);
        metadata.set_last_modified(opendal::raw::Timestamp::new(1, 1).unwrap());
        assert_eq!(
            blob_fingerprint(&metadata).as_deref(),
            Some("modified:1000000001:7")
        );

        metadata.set_version("gen-3");
        assert_eq!(
            blob_fingerprint(&metadata).as_deref(),
            Some("version:gen-3")
        );

        metadata.set_etag("\"abc\"");
        assert_eq!(blob_fingerprint(&metadata).as_deref(), Some("etag:\"abc\""));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_write_records_the_fingerprint_of_the_blob_it_published() {
        let fixture = fixture().await;

        let recorded = fixture.entry().await.blob_fingerprint;
        assert!(recorded.is_some());
        assert_eq!(recorded, fixture.stat_fingerprint().await);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn conditional_write_repairs_a_row_that_disagrees_with_its_blob() {
        let fixture = fixture().await;
        let stale_etag = fixture.etag().await;
        fixture.corrupt_blob(&[2; 20]);

        // The stale tag matches the row but not the blob: rejected, and the
        // row is brought into line so the client's next GET sees the truth.
        let error = fixture
            .write_if_match(&stale_etag, vec![3; 30])
            .await
            .expect_err("stale tag must not win against the real content");
        assert_precondition_failed(error);

        let entry = fixture.entry().await;
        assert_eq!(entry.content_hash, pubky_common::crypto::hash(&[2; 20]));
        assert_eq!(entry.content_length, 20);
        assert_eq!(entry.blob_fingerprint, fixture.stat_fingerprint().await);
        assert_eq!(std::fs::read(&fixture.blob_file).unwrap(), vec![2; 20]);
        assert_eq!(
            user_usage(&fixture.db, &fixture.pubkey).await,
            20 + FILE_METADATA_SIZE
        );
        assert_eq!(
            fixture.event_types().await,
            vec![put(&[1; 10]), put(&[2; 20])]
        );

        // The repaired tag is the one a compare-and-set must present.
        fixture
            .write_if_match(&fixture.etag().await, vec![3; 30])
            .await
            .unwrap();
        assert_eq!(std::fs::read(&fixture.blob_file).unwrap(), vec![3; 30]);
        assert_eq!(
            user_usage(&fixture.db, &fixture.pubkey).await,
            30 + FILE_METADATA_SIZE
        );
    }

    /// The preflight at writer creation runs without the user lock. The check
    /// at close must verify again, so a blob replaced in between is caught.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn divergence_after_preflight_is_repaired_under_the_lock() {
        let fixture = fixture().await;
        let etag_v1 = fixture.etag().await;

        let mut writer = fixture
            .operator
            .writer_with(fixture.path.as_str())
            .if_match(&etag_v1)
            .await
            .unwrap();
        writer.write(vec![3; 30]).await.unwrap();
        fixture.corrupt_blob(&[2; 20]);

        let error = writer
            .close()
            .await
            .expect_err("close must re-verify the blob");
        assert_precondition_failed(error);

        let entry = fixture.entry().await;
        assert_eq!(entry.content_hash, pubky_common::crypto::hash(&[2; 20]));
        assert_eq!(std::fs::read(&fixture.blob_file).unwrap(), vec![2; 20]);
        assert_eq!(
            fixture.event_types().await,
            vec![put(&[1; 10]), put(&[2; 20])]
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn conditional_delete_repairs_the_row_before_evaluating_the_condition() {
        let fixture = fixture().await;
        let stale_etag = fixture.etag().await;
        fixture.corrupt_blob(&[2; 20]);

        let error = fixture
            .delete_if_match(&stale_etag)
            .await
            .expect_err("stale tag must not delete the real content");
        assert_precondition_failed(error);
        assert_eq!(std::fs::read(&fixture.blob_file).unwrap(), vec![2; 20]);
        assert_eq!(
            fixture.entry().await.content_hash,
            pubky_common::crypto::hash(&[2; 20])
        );

        fixture
            .delete_if_match(&fixture.etag().await)
            .await
            .unwrap();
        assert!(!fixture.blob_file.exists());
        assert_eq!(user_usage(&fixture.db, &fixture.pubkey).await, 0);
        assert_eq!(
            fixture.event_types().await,
            vec![put(&[1; 10]), put(&[2; 20]), EventType::Delete]
        );
    }

    /// A blob the backend cannot find is what an outage looks like too, so
    /// the row is never deleted automatically. The condition is evaluated as
    /// if nothing were stored; a create-only write then restores the blob.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_row_without_a_blob_is_kept_and_evaluated_as_absent() {
        let fixture = fixture().await;
        let stale_etag = fixture.etag().await;
        std::fs::remove_file(&fixture.blob_file).unwrap();

        let error = fixture
            .write_if_match(&stale_etag, vec![3; 30])
            .await
            .expect_err("If-Match must fail when nothing is stored");
        assert_precondition_failed(error);
        let entry = fixture.entry().await;
        assert_eq!(entry.content_hash, pubky_common::crypto::hash(&[1; 10]));
        assert_eq!(
            user_usage(&fixture.db, &fixture.pubkey).await,
            10 + FILE_METADATA_SIZE
        );
        assert_eq!(fixture.event_types().await, vec![put(&[1; 10])]);

        let error = fixture
            .delete_if_match(&stale_etag)
            .await
            .expect_err("conditional delete must not remove the row either");
        assert_precondition_failed(error);
        fixture.entry().await;

        // Create-only succeeds, as for an absent path, and the row is updated
        // in place rather than duplicated.
        let mut writer = fixture
            .operator
            .writer_with(fixture.path.as_str())
            .if_none_match("*")
            .await
            .unwrap();
        writer.write(vec![3; 30]).await.unwrap();
        writer.close().await.unwrap();
        assert_eq!(std::fs::read(&fixture.blob_file).unwrap(), vec![3; 30]);
        assert_eq!(fixture.entry().await.id, entry.id);
        assert_eq!(
            user_usage(&fixture.db, &fixture.pubkey).await,
            30 + FILE_METADATA_SIZE
        );
        assert_eq!(
            fixture.event_types().await,
            vec![put(&[1; 10]), put(&[3; 30])]
        );
    }

    /// A rejected probe must still record the fingerprint, otherwise a client
    /// could make the server hash the whole blob on every wrong `If-Match`.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_rejected_probe_still_records_the_fingerprint() {
        let fixture = fixture().await;
        let entry = fixture.entry().await;
        EntryRepository::set_blob_fingerprint(entry.id, None, &mut fixture.db.pool().into())
            .await
            .unwrap();

        let error = fixture
            .write_if_match("\"wrong\"", vec![2; 20])
            .await
            .expect_err("wrong tag must be rejected");
        assert_precondition_failed(error);

        let entry = fixture.entry().await;
        assert!(entry.blob_fingerprint.is_some());
        assert_eq!(entry.blob_fingerprint, fixture.stat_fingerprint().await);
        assert_eq!(entry.content_hash, pubky_common::crypto::hash(&[1; 10]));
        assert_eq!(fixture.event_types().await, vec![put(&[1; 10])]);
    }

    /// Rows written before fingerprints existed are verified by hashing the
    /// blob, and pick up a fingerprint on the way.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_row_without_a_fingerprint_is_verified_by_hashing() {
        let fixture = fixture().await;
        let entry = fixture.entry().await;
        EntryRepository::set_blob_fingerprint(entry.id, None, &mut fixture.db.pool().into())
            .await
            .unwrap();
        assert_eq!(fixture.entry().await.blob_fingerprint, None);

        fixture
            .write_if_match(&fixture.etag().await, vec![2; 20])
            .await
            .expect("a correct row must pass without a fingerprint");
        assert_eq!(std::fs::read(&fixture.blob_file).unwrap(), vec![2; 20]);
        assert!(fixture.entry().await.blob_fingerprint.is_some());

        // Without a fingerprint a lying row is still caught, by content.
        let entry = fixture.entry().await;
        EntryRepository::set_blob_fingerprint(entry.id, None, &mut fixture.db.pool().into())
            .await
            .unwrap();
        let stale_etag = fixture.etag().await;
        fixture.corrupt_blob(&[4; 40]);
        let error = fixture
            .write_if_match(&stale_etag, vec![5; 50])
            .await
            .expect_err("stale tag must not win against the real content");
        assert_precondition_failed(error);
        assert_eq!(
            fixture.entry().await.content_hash,
            pubky_common::crypto::hash(&[4; 40])
        );
    }

    /// Reads and unconditional writes take the row at its word; only a
    /// precondition pays for verification.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn unconditional_write_does_not_verify() {
        let fixture = fixture().await;
        fixture.corrupt_blob(&[2; 20]);

        fixture
            .operator
            .write(fixture.path.as_str(), vec![3; 30])
            .await
            .unwrap();

        assert_eq!(
            fixture.event_types().await,
            vec![put(&[1; 10]), put(&[3; 30])]
        );
        assert_eq!(
            user_usage(&fixture.db, &fixture.pubkey).await,
            30 + FILE_METADATA_SIZE
        );
    }
}

/// Proves a blob is hashed at most once per conditional write: by the repair,
/// under the user lock, never by the preflight itself. The fingerprint it
/// records then spares the check at close and every later probe.
#[cfg(test)]
mod read_count_tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use opendal::raw::{
        Access, Layer, LayeredAccess, OpList, OpRead, OpWrite, RpDelete, RpList, RpRead, RpWrite,
    };
    use opendal::Result;

    use crate::persistence::files::{
        content_hash_etag, events::EventsService,
        opendal::opendal_test_operators::get_atomic_fs_operator,
    };
    use crate::persistence::sql::{entry::EntryRepository, SqlDb};
    use crate::services::user_service::UserService;
    use crate::shared::webdav::{EntryPath, StoragePath};

    use super::super::layer::test_support::create_user;
    use super::super::WriteFinalizationLayer;

    /// Counts backend reads. Sits beneath the finalization layer, where the
    /// backend would, so the finalizer's probe reads are counted too.
    #[derive(Debug, Clone)]
    struct CountReadsLayer {
        reads: Arc<AtomicUsize>,
    }

    impl<A: Access> Layer<A> for CountReadsLayer {
        type LayeredAccess = CountReadsAccessor<A>;

        fn layer(&self, inner: A) -> Self::LayeredAccess {
            CountReadsAccessor {
                inner,
                reads: self.reads.clone(),
            }
        }
    }

    #[derive(Debug)]
    struct CountReadsAccessor<A> {
        inner: A,
        reads: Arc<AtomicUsize>,
    }

    impl<A: Access> LayeredAccess for CountReadsAccessor<A> {
        type Inner = A;
        type Reader = A::Reader;
        type Writer = A::Writer;
        type Lister = A::Lister;
        type Deleter = A::Deleter;
        type Copier = A::Copier;

        fn inner(&self) -> &Self::Inner {
            &self.inner
        }

        async fn read(&self, path: &str, args: OpRead) -> Result<(RpRead, Self::Reader)> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read(path, args).await
        }

        async fn write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::Writer)> {
            self.inner.write(path, args).await
        }

        async fn list(&self, path: &str, args: OpList) -> Result<(RpList, Self::Lister)> {
            self.inner.list(path, args).await
        }

        async fn delete(&self) -> Result<(RpDelete, Self::Deleter)> {
            self.inner.delete().await
        }
    }

    async fn current_etag(db: &SqlDb, path: &EntryPath) -> String {
        let entry = EntryRepository::get_by_path(path, &mut db.pool().into())
            .await
            .unwrap();
        content_hash_etag(&entry.content_hash)
    }

    async fn write_if_match(
        operator: &opendal::Operator,
        path: &EntryPath,
        etag: &str,
        content: Vec<u8>,
    ) {
        let mut writer = operator
            .writer_with(path.as_str())
            .if_match(etag)
            .await
            .unwrap();
        writer.write(content).await.unwrap();
        writer.close().await.unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_row_without_a_fingerprint_is_hashed_once_per_conditional_write() {
        let db = SqlDb::test().await;
        let (backend, _dir) = get_atomic_fs_operator();
        let reads = Arc::new(AtomicUsize::new(0));
        let operator = backend
            .layer(CountReadsLayer {
                reads: reads.clone(),
            })
            .layer(WriteFinalizationLayer::new(
                UserService::new(db.clone()),
                db.clone(),
                EventsService::new(db.clone(), 100),
                None,
                true,
            ));
        let pubkey = create_user(&db).await;
        let path = EntryPath::new(pubkey, StoragePath::new("/test.txt").unwrap());

        operator.write(path.as_str(), vec![1; 10]).await.unwrap();
        let entry = EntryRepository::get_by_path(&path, &mut db.pool().into())
            .await
            .unwrap();
        EntryRepository::set_blob_fingerprint(entry.id, None, &mut db.pool().into())
            .await
            .unwrap();
        reads.store(0, Ordering::SeqCst);

        write_if_match(
            &operator,
            &path,
            &current_etag(&db, &path).await,
            vec![2; 20],
        )
        .await;
        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "an unfingerprinted row must be hashed exactly once"
        );

        // The fingerprint is recorded now: a `stat` vouches for the row.
        write_if_match(
            &operator,
            &path,
            &current_etag(&db, &path).await,
            vec![3; 30],
        )
        .await;
        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "a fingerprinted row must not be read at all"
        );
    }
}
