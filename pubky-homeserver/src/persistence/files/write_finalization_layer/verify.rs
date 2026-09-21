//! Detects and repairs entry rows that disagree with their blob.
//!
//! A write publishes its blob and then commits the entry row. If the process
//! dies, or the commit fails, between those two steps the row keeps the
//! previous content hash while the blob holds the new bytes. A conditional
//! write would then be compared against the wrong ETag, and a stale ETag
//! could win. So before a precondition is evaluated, the blob is read and
//! hashed under the user lock, inside the finalization transaction, and the
//! row is repaired if it disagrees. Unconditional writes and reads do not
//! verify.
//!
//! A blob the backend cannot find is never repaired automatically. A
//! `NotFound` is also what an unmounted volume, a misconfigured bucket, or a
//! restore in progress looks like, and deleting rows in response would turn
//! an outage into permanent index loss. The condition is evaluated as if
//! nothing were stored, the row is left alone, and the case is logged.

use opendal::raw::{oio::ReadDyn, AccessDyn, OpRead};
use opendal::{ErrorKind, Result};
use pubky_common::crypto::Hash;

use crate::persistence::files::{events::EventType, FileMetadata, FileMetadataBuilder};
use crate::persistence::sql::{
    entry::{EntryEntity, EntryRepository},
    user::UserEntity,
    UnifiedExecutor,
};
use crate::shared::webdav::EntryPath;

use super::layer::{unexpected, Finalizer};

/// How the blob at an entry's path relates to the row.
enum BlobState {
    /// The blob holds what the row describes.
    Consistent,
    /// The blob holds different content than the row describes.
    Diverged(FileMetadata),
    /// The backend has no blob at the entry's path, or cannot see it.
    Missing,
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
    /// Read and hash the blob at the entry's path and compare it with the row.
    async fn verify_blob(&self, entry: &EntryEntity) -> Result<BlobState> {
        let (_, mut reader) = match self
            .probe
            .read_dyn(entry.path.as_str(), OpRead::new())
            .await
        {
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(BlobState::Missing),
            Err(error) => return Err(error),
        };
        let mut builder = FileMetadataBuilder::default();
        builder.guess_mime_type_from_path(entry.path.path().as_str());
        loop {
            let buffer = match reader.read_dyn().await {
                Ok(buffer) => buffer,
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    return Ok(BlobState::Missing);
                }
                Err(error) => return Err(error),
            };
            if buffer.is_empty() {
                break;
            }
            for chunk in buffer {
                builder.update(&chunk);
            }
        }
        let blob = builder.finalize();

        Ok(
            if blob.hash == entry.content_hash && blob.length as u64 == entry.content_length {
                BlobState::Consistent
            } else {
                BlobState::Diverged(blob)
            },
        )
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
        let entry_path = entry.path.clone();
        match self.verify_blob(&entry).await? {
            BlobState::Consistent => Ok(Reconciled {
                content_hash: Some(entry.content_hash),
                entry,
                event: None,
            }),
            BlobState::Diverged(blob) => {
                tracing::warn!(
                    path = %entry_path,
                    "Entry row did not describe its blob; repaired from the blob"
                );
                let bytes_delta = blob.length as i64 - entry.content_length as i64;
                entry.content_hash = blob.hash;
                entry.content_length = blob.length as u64;
                entry.content_type = blob.content_type;
                EntryRepository::update(&entry, executor)
                    .await
                    .map_err(|error| {
                        unexpected(format!("Failed to repair entry {entry_path}"), error)
                    })?;
                user.used_bytes = user.used_bytes.saturating_add_signed(bytes_delta);
                self.user_service
                    .update_in_tx(user, executor)
                    .await
                    .map_err(|error| {
                        unexpected(
                            format!("Failed to update quota for {}", entry_path.pubkey()),
                            error,
                        )
                    })?;
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
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

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

        async fn write_if_match(&self, etag: &str, content: Vec<u8>) -> Result<()> {
            let mut writer = self
                .operator
                .writer_with(self.path.as_str())
                .if_match(etag)
                .await?;
            writer.write(content).await?;
            writer.close().await.map(|_| ())
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

    /// The check happens at close, under the user lock, so a blob replaced
    /// after the writer was opened is still caught.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn divergence_after_open_is_repaired_at_close() {
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
            .expect_err("close must verify the blob");
        assert_precondition_failed(error);

        let entry = fixture.entry().await;
        assert_eq!(entry.content_hash, pubky_common::crypto::hash(&[2; 20]));
        assert_eq!(std::fs::read(&fixture.blob_file).unwrap(), vec![2; 20]);
        assert_eq!(
            fixture.event_types().await,
            vec![put(&[1; 10]), put(&[2; 20])]
        );
    }

    /// A rejected write against a row that was right all along changes
    /// nothing: no row update, no quota change, no event.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_rejected_write_leaves_a_correct_row_untouched() {
        let fixture = fixture().await;
        let before = fixture.entry().await;

        let error = fixture
            .write_if_match("\"wrong\"", vec![2; 20])
            .await
            .expect_err("wrong tag must be rejected");
        assert_precondition_failed(error);

        assert_eq!(fixture.entry().await, before);
        assert_eq!(std::fs::read(&fixture.blob_file).unwrap(), vec![1; 10]);
        assert_eq!(
            user_usage(&fixture.db, &fixture.pubkey).await,
            10 + FILE_METADATA_SIZE
        );
        assert_eq!(fixture.event_types().await, vec![put(&[1; 10])]);
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

/// Proves the blob is read exactly once per conditional write, by the check
/// under the lock, and not at all by an unconditional one.
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
    /// backend would, so the finalizer's verification reads are counted too.
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
    async fn a_conditional_write_reads_the_blob_exactly_once() {
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
        assert_eq!(
            reads.load(Ordering::SeqCst),
            0,
            "an unconditional write must not read the blob"
        );

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
            "a conditional write must read the blob exactly once"
        );

        write_if_match(
            &operator,
            &path,
            &current_etag(&db, &path).await,
            vec![3; 30],
        )
        .await;
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }
}
