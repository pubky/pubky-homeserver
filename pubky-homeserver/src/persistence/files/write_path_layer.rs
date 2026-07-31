use std::sync::Arc;

use crate::persistence::files::layer_domain_error::LayerDomainError;
use crate::services::user_service::UserService;
use crate::shared::webdav::EntryPath;
use opendal::raw::*;
use opendal::Result;

/// OpenDAL layer that enforces per-user `allowed_write_paths` restrictions.
///
/// Stacked as the outermost layer so rejected mutations never reach write
/// finalization or the storage backend.
///
/// - Reads, stats, and lists pass through unmodified.
/// - Writes, deletes, copies, renames, and create_dir check the user's
///   `allowed_write_paths` and return `PermissionDenied` if the path is not in the allow list.
#[derive(Clone)]
pub struct WritePathLayer {
    user_service: UserService,
}

impl WritePathLayer {
    pub fn new(user_service: UserService) -> Self {
        Self { user_service }
    }
}

impl<A: Access> Layer<A> for WritePathLayer {
    type LayeredAccess = WritePathAccessor<A>;

    fn layer(&self, inner: A) -> Self::LayeredAccess {
        WritePathAccessor {
            inner: Arc::new(inner),
            user_service: self.user_service.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WritePathAccessor<A: Access> {
    inner: Arc<A>,
    user_service: UserService,
}

/// Check whether the user associated with `path` is allowed to write there.
///
/// Uses the cached quota lookup for efficiency.
async fn check_write_path_allowed(user_service: &UserService, path: &str) -> Result<()> {
    let entry_path = EntryPath::parse_opendal(path)?;
    let pubkey = entry_path.pubkey();

    let quota = user_service.resolve_quota(pubkey).await.map_err(|e| {
        opendal::Error::new(
            opendal::ErrorKind::Unexpected,
            format!("Failed to get quota for user {pubkey}: {e}"),
        )
    })?;

    // If user not found, let inner layers handle it (they'll reject unknown users).
    let Some(quota) = quota else {
        return Ok(());
    };

    if !quota.is_write_path_allowed(entry_path.path().as_str()) {
        return Err(opendal::Error::new(
            opendal::ErrorKind::PermissionDenied,
            format!(
                "Write to path '{}' is not allowed for user {}",
                entry_path.path(),
                pubkey
            ),
        )
        .set_source(LayerDomainError::WritePathForbidden));
    }
    Ok(())
}

impl<A: Access> LayeredAccess for WritePathAccessor<A> {
    type Inner = A;
    type Reader = A::Reader;
    type Writer = A::Writer;
    type Lister = A::Lister;
    type Deleter = WritePathDeleter<A::Deleter>;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    async fn create_dir(&self, path: &str, args: OpCreateDir) -> Result<RpCreateDir> {
        check_write_path_allowed(&self.user_service, path).await?;
        self.inner.create_dir(path, args).await
    }

    async fn read(&self, path: &str, args: OpRead) -> Result<(RpRead, Self::Reader)> {
        self.inner.read(path, args).await
    }

    async fn write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::Writer)> {
        check_write_path_allowed(&self.user_service, path).await?;
        self.inner.write(path, args).await
    }

    async fn copy(&self, from: &str, to: &str, args: OpCopy) -> Result<RpCopy> {
        check_write_path_allowed(&self.user_service, to).await?;
        self.inner.copy(from, to, args).await
    }

    async fn rename(&self, from: &str, to: &str, args: OpRename) -> Result<RpRename> {
        // Rename removes the source file, so both paths require write permission.
        check_write_path_allowed(&self.user_service, from).await?;
        check_write_path_allowed(&self.user_service, to).await?;
        self.inner.rename(from, to, args).await
    }

    async fn stat(&self, path: &str, args: OpStat) -> Result<RpStat> {
        self.inner.stat(path, args).await
    }

    async fn delete(&self) -> Result<(RpDelete, Self::Deleter)> {
        let (rp, deleter) = self.inner.delete().await?;
        Ok((
            rp,
            WritePathDeleter {
                inner: deleter,
                user_service: self.user_service.clone(),
                path_queue: Vec::new(),
            },
        ))
    }

    async fn list(&self, path: &str, args: OpList) -> Result<(RpList, Self::Lister)> {
        self.inner.list(path, args).await
    }

    async fn presign(&self, path: &str, args: OpPresign) -> Result<RpPresign> {
        // Default to checking — only skip for known read-only operations.
        if !matches!(args.operation(), PresignOperation::Read(_)) {
            check_write_path_allowed(&self.user_service, path).await?;
        }
        self.inner.presign(path, args).await
    }
}

/// Deleter wrapper that checks write-path restrictions in `flush()`.
///
/// Since `delete()` is sync, we buffer paths locally and only forward them
/// to the inner deleter in `flush()` after the async permission check passes.
///
/// If any path in the batch fails the permission check, the entire batch is
/// rejected (fail-closed). The queue is **not** drained on error, so a
/// subsequent `flush()` will re-check and re-attempt all buffered paths.
pub struct WritePathDeleter<R> {
    inner: R,
    user_service: UserService,
    path_queue: Vec<(String, OpDelete)>,
}

impl<R: oio::Delete> oio::Delete for WritePathDeleter<R> {
    fn delete(&mut self, path: &str, args: OpDelete) -> Result<()> {
        // Buffer locally — don't forward to inner yet.
        self.path_queue.push((path.to_string(), args));
        Ok(())
    }

    async fn flush(&mut self) -> Result<usize> {
        // Check all queued paths first.
        for (path, _) in &self.path_queue {
            check_write_path_allowed(&self.user_service, path).await?;
        }
        // All checks passed — forward to inner deleter and flush.
        for (path, args) in self.path_queue.drain(..) {
            self.inner.delete(&path, args)?;
        }
        self.inner.flush().await
    }
}

#[cfg(test)]
mod tests {
    use crate::persistence::files::opendal::opendal_test_operators::{
        get_fs_operator, get_memory_operator,
    };
    use crate::persistence::files::{
        events::EventsService, write_finalization_layer::WriteFinalizationLayer,
    };
    use crate::persistence::sql::user::UserRepository;
    use crate::persistence::sql::SqlDb;
    use crate::services::user_service::UserService;
    use crate::shared::user_quota::UserQuota;
    use crate::shared::webdav::StoragePath;

    use super::*;

    fn wdp(s: &str) -> StoragePath {
        s.parse().unwrap()
    }

    /// Create a user and set allowed_write_paths on them.
    async fn create_user_with_write_paths(
        db: &SqlDb,
        allowed_write_paths: Option<Vec<StoragePath>>,
    ) -> pubky_common::crypto::PublicKey {
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        let user = UserRepository::create(&pubkey, &mut db.pool().into())
            .await
            .unwrap();
        let config = UserQuota {
            allowed_write_paths,
            ..Default::default()
        };
        UserRepository::set_quota(user.id, &config, &mut db.pool().into())
            .await
            .unwrap();
        pubkey
    }

    /// Build an operator with both WritePathLayer (outermost) and WriteFinalizationLayer,
    /// matching the production stack order.
    fn build_test_operator(db: &SqlDb) -> opendal::Operator {
        build_test_operator_with(db, get_memory_operator())
    }

    /// Build a test operator backed by the filesystem (supports copy/rename).
    fn build_fs_test_operator(db: &SqlDb) -> (opendal::Operator, tempfile::TempDir) {
        let (op, tmp_dir) = get_fs_operator();
        (build_test_operator_with(db, op), tmp_dir)
    }

    fn build_test_operator_with(db: &SqlDb, base: opendal::Operator) -> opendal::Operator {
        let user_service = UserService::new(db.clone());
        let write_finalization_layer =
            WriteFinalizationLayer::new(user_service.clone(), EventsService::new(100), None, true);
        let write_path_layer = WritePathLayer::new(user_service);
        base.layer(write_finalization_layer).layer(write_path_layer)
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_write_to_allowed_path_succeeds() {
        let db = SqlDb::test().await;
        let operator = build_test_operator(&db);

        let pubkey = create_user_with_write_paths(&db, Some(vec![wdp("/pub/tokens/")])).await;

        operator
            .write(
                &format!("{}/pub/tokens/foo.json", pubkey.z32()),
                vec![0; 10],
            )
            .await
            .expect("Write to allowed path should succeed");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_write_to_disallowed_path_rejected() {
        let db = SqlDb::test().await;
        let operator = build_test_operator(&db);

        let pubkey = create_user_with_write_paths(&db, Some(vec![wdp("/pub/tokens/")])).await;

        let err = operator
            .write(&format!("{}/pub/other/foo.json", pubkey.z32()), vec![0; 10])
            .await
            .expect_err("Write to disallowed path should fail");
        assert_eq!(err.kind(), opendal::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_empty_write_paths_blocks_all_writes() {
        let db = SqlDb::test().await;
        let operator = build_test_operator(&db);

        let pubkey = create_user_with_write_paths(&db, Some(vec![])).await;

        let err = operator
            .write(
                &format!("{}/pub/anything/foo.json", pubkey.z32()),
                vec![0; 10],
            )
            .await
            .expect_err("Empty allowed_write_paths should block all writes");
        assert_eq!(err.kind(), opendal::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_none_write_paths_allows_everything() {
        let db = SqlDb::test().await;
        let operator = build_test_operator(&db);

        let pubkey = create_user_with_write_paths(&db, None).await;

        operator
            .write(
                &format!("{}/pub/anything/foo.json", pubkey.z32()),
                vec![0; 10],
            )
            .await
            .expect("None allowed_write_paths should allow all writes");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_delete_from_disallowed_path_rejected() {
        let db = SqlDb::test().await;
        let operator = build_test_operator(&db);

        // Create with no restrictions, write a file, then restrict.
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        let user = UserRepository::create(&pubkey, &mut db.pool().into())
            .await
            .unwrap();
        let raw = pubkey.z32();

        operator
            .write(&format!("{raw}/pub/other/file.txt"), vec![0; 10])
            .await
            .expect("Write should succeed with no restrictions");

        // Now restrict to /pub/tokens/ only.
        let config = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/tokens/")]),
            ..Default::default()
        };
        UserRepository::set_quota(user.id, &config, &mut db.pool().into())
            .await
            .unwrap();
        // Invalidate cache by creating a fresh operator.
        let operator = build_test_operator(&db);

        let err = operator
            .delete(&format!("{raw}/pub/other/file.txt"))
            .await
            .expect_err("Delete from disallowed path should fail");
        assert_eq!(err.kind(), opendal::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_rename_within_allowed_path_succeeds() {
        let db = SqlDb::test().await;
        let (operator, _tmp) = build_fs_test_operator(&db);

        let pubkey = create_user_with_write_paths(&db, Some(vec![wdp("/pub/tokens/")])).await;
        let raw = pubkey.z32();

        operator
            .write(&format!("{raw}/pub/tokens/a.txt"), vec![1; 10])
            .await
            .unwrap();

        operator
            .rename(
                &format!("{raw}/pub/tokens/a.txt"),
                &format!("{raw}/pub/tokens/b.txt"),
            )
            .await
            .expect("Rename within allowed path should succeed");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_rename_to_disallowed_destination_rejected() {
        let db = SqlDb::test().await;
        let operator = build_test_operator(&db);

        let pubkey = create_user_with_write_paths(&db, Some(vec![wdp("/pub/tokens/")])).await;
        let raw = pubkey.z32();

        operator
            .write(&format!("{raw}/pub/tokens/c.txt"), vec![2; 10])
            .await
            .unwrap();

        let err = operator
            .rename(
                &format!("{raw}/pub/tokens/c.txt"),
                &format!("{raw}/pub/other/c.txt"),
            )
            .await
            .expect_err("Rename to disallowed destination should fail");
        assert_eq!(err.kind(), opendal::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_rename_from_disallowed_source_rejected() {
        let db = SqlDb::test().await;

        // Create unrestricted, write a file, then restrict.
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        let user = UserRepository::create(&pubkey, &mut db.pool().into())
            .await
            .unwrap();
        let raw = pubkey.z32();

        let operator = build_test_operator(&db);
        operator
            .write(&format!("{raw}/pub/other/d.txt"), vec![3; 10])
            .await
            .unwrap();

        let config = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/tokens/")]),
            ..Default::default()
        };
        UserRepository::set_quota(user.id, &config, &mut db.pool().into())
            .await
            .unwrap();
        let operator = build_test_operator(&db);

        let err = operator
            .rename(
                &format!("{raw}/pub/other/d.txt"),
                &format!("{raw}/pub/tokens/d.txt"),
            )
            .await
            .expect_err("Rename from disallowed source should fail");
        assert_eq!(err.kind(), opendal::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_copy_to_disallowed_path_rejected() {
        let db = SqlDb::test().await;
        let operator = build_test_operator(&db);

        let pubkey = create_user_with_write_paths(&db, Some(vec![wdp("/pub/tokens/")])).await;
        let raw = pubkey.z32();

        // Write a file to an allowed path.
        operator
            .write(&format!("{raw}/pub/tokens/src.txt"), vec![1; 10])
            .await
            .unwrap();

        // Copy to a disallowed destination should fail.
        let err = operator
            .copy(
                &format!("{raw}/pub/tokens/src.txt"),
                &format!("{raw}/pub/other/dst.txt"),
            )
            .await
            .expect_err("Copy to disallowed destination should fail");
        assert_eq!(err.kind(), opendal::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_copy_within_allowed_path_succeeds() {
        let db = SqlDb::test().await;
        let (operator, _tmp) = build_fs_test_operator(&db);

        let pubkey = create_user_with_write_paths(&db, Some(vec![wdp("/pub/tokens/")])).await;
        let raw = pubkey.z32();

        operator
            .write(&format!("{raw}/pub/tokens/src.txt"), vec![1; 10])
            .await
            .unwrap();

        operator
            .copy(
                &format!("{raw}/pub/tokens/src.txt"),
                &format!("{raw}/pub/tokens/dst.txt"),
            )
            .await
            .expect("Copy within allowed path should succeed");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_dir_in_allowed_path_succeeds() {
        let db = SqlDb::test().await;
        let operator = build_test_operator(&db);

        let pubkey = create_user_with_write_paths(&db, Some(vec![wdp("/pub/tokens/")])).await;

        operator
            .create_dir(&format!("{}/pub/tokens/subdir/", pubkey.z32()))
            .await
            .expect("create_dir in allowed path should succeed");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_dir_in_disallowed_path_rejected() {
        let db = SqlDb::test().await;
        let operator = build_test_operator(&db);

        let pubkey = create_user_with_write_paths(&db, Some(vec![wdp("/pub/tokens/")])).await;

        let err = operator
            .create_dir(&format!("{}/pub/other/subdir/", pubkey.z32()))
            .await
            .expect_err("create_dir in disallowed path should fail");
        assert_eq!(err.kind(), opendal::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_read_not_affected_by_write_path_restriction() {
        let db = SqlDb::test().await;
        let operator = build_test_operator(&db);

        // Create user restricted to /pub/tokens/ only.
        let pubkey = create_user_with_write_paths(&db, Some(vec![wdp("/pub/tokens/")])).await;
        let raw = pubkey.z32();

        // Write to the allowed path.
        operator
            .write(&format!("{raw}/pub/tokens/data.txt"), vec![42; 10])
            .await
            .unwrap();

        // Read from the allowed path works.
        let data = operator
            .read(&format!("{raw}/pub/tokens/data.txt"))
            .await
            .expect("Read should not be blocked by write path restrictions");
        assert_eq!(data.to_vec(), vec![42; 10]);

        // Stat on a non-matching path is not blocked (reads pass through).
        // The path doesn't exist so we get NotFound, not PermissionDenied.
        let err = operator
            .stat(&format!("{raw}/pub/other/"))
            .await
            .expect_err("File doesn't exist");
        assert_eq!(
            err.kind(),
            opendal::ErrorKind::NotFound,
            "Stat should return NotFound, not PermissionDenied"
        );
    }
}
