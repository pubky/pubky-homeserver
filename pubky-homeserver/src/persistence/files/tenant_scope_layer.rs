//! Confines an operator to a single user's subtree.
//!
//! The WebDAV endpoint points one `DavHandler` at the whole storage root and
//! relies on an HTTP-level guard to keep a session inside its own drive. That
//! guard is tested and holds, but it is one function: a future change to path
//! normalisation would turn a bug there into a cross-tenant data breach.
//!
//! This layer is the second line. Applied per request with the caller's key, it
//! refuses any object key outside `{user_z32}/` at the storage boundary, so the
//! HTTP guard becomes a source of good error messages rather than the only
//! control. `opendal` has no `SubdirLayer` and `OpendalFs` takes no root, so
//! this is written out by hand.
//!
//! Every operation is checked, reads included — unlike
//! [`WritePathLayer`](super::write_path_layer::WritePathLayer), which guards
//! mutations only. Cross-tenant reads are exactly what this exists to stop.
use std::sync::Arc;

use opendal::raw::*;
use opendal::Result;
use pubky_common::crypto::PublicKey;

/// Restricts an operator to the keys belonging to one user.
#[derive(Clone, Debug)]
pub struct TenantScopeLayer {
    /// The owner's key with a trailing slash, e.g. `8pinxx…ewo/`.
    prefix: Arc<str>,
}

impl TenantScopeLayer {
    pub fn new(owner: &PublicKey) -> Self {
        Self {
            prefix: format!("{}/", owner.z32()).into(),
        }
    }
}

impl<A: Access> Layer<A> for TenantScopeLayer {
    type LayeredAccess = TenantScopeAccessor<A>;

    fn layer(&self, inner: A) -> Self::LayeredAccess {
        TenantScopeAccessor {
            inner: Arc::new(inner),
            prefix: Arc::clone(&self.prefix),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TenantScopeAccessor<A: Access> {
    inner: Arc<A>,
    prefix: Arc<str>,
}

/// Whether `path` names an object inside the scoped drive.
///
/// The drive's own root is in scope so a client can stat and list the thing it
/// mounted, with or without a trailing slash. Everything else must sit beneath
/// it. Keys are compared with any leading slash removed, because a DAV path
/// arrives absolute while an OpenDAL key is not.
fn is_in_scope(prefix: &str, path: &str) -> bool {
    let path = path.trim_start_matches('/');
    path.starts_with(prefix) || path == prefix.trim_end_matches('/')
}

fn check(prefix: &str, path: &str) -> Result<()> {
    if is_in_scope(prefix, path) {
        return Ok(());
    }
    Err(opendal::Error::new(
        opendal::ErrorKind::PermissionDenied,
        "path is outside the caller's drive",
    ))
}

impl<A: Access> LayeredAccess for TenantScopeAccessor<A> {
    type Inner = A;
    type Reader = A::Reader;
    type Writer = A::Writer;
    type Lister = A::Lister;
    type Deleter = TenantScopeDeleter<A::Deleter>;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    async fn create_dir(&self, path: &str, args: OpCreateDir) -> Result<RpCreateDir> {
        check(&self.prefix, path)?;
        self.inner.create_dir(path, args).await
    }

    async fn read(&self, path: &str, args: OpRead) -> Result<(RpRead, Self::Reader)> {
        check(&self.prefix, path)?;
        self.inner.read(path, args).await
    }

    async fn write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::Writer)> {
        check(&self.prefix, path)?;
        self.inner.write(path, args).await
    }

    async fn copy(&self, from: &str, to: &str, args: OpCopy) -> Result<RpCopy> {
        check(&self.prefix, from)?;
        check(&self.prefix, to)?;
        self.inner.copy(from, to, args).await
    }

    async fn rename(&self, from: &str, to: &str, args: OpRename) -> Result<RpRename> {
        check(&self.prefix, from)?;
        check(&self.prefix, to)?;
        self.inner.rename(from, to, args).await
    }

    async fn stat(&self, path: &str, args: OpStat) -> Result<RpStat> {
        check(&self.prefix, path)?;
        self.inner.stat(path, args).await
    }

    async fn delete(&self) -> Result<(RpDelete, Self::Deleter)> {
        let (rp, deleter) = self.inner.delete().await?;
        Ok((
            rp,
            TenantScopeDeleter {
                inner: deleter,
                prefix: Arc::clone(&self.prefix),
            },
        ))
    }

    async fn list(&self, path: &str, args: OpList) -> Result<(RpList, Self::Lister)> {
        check(&self.prefix, path)?;
        self.inner.list(path, args).await
    }

    async fn presign(&self, path: &str, args: OpPresign) -> Result<RpPresign> {
        check(&self.prefix, path)?;
        self.inner.presign(path, args).await
    }
}

/// Deleter wrapper that rejects out-of-scope keys as they are queued.
///
/// The check is a string comparison rather than a database lookup, so unlike
/// [`WritePathDeleter`](super::write_path_layer::WritePathDeleter) it can run in
/// `delete()` itself and fail immediately instead of buffering until `flush()`.
pub struct TenantScopeDeleter<D> {
    inner: D,
    prefix: Arc<str>,
}

impl<D: oio::Delete> oio::Delete for TenantScopeDeleter<D> {
    fn delete(&mut self, path: &str, args: OpDelete) -> Result<()> {
        check(&self.prefix, path)?;
        self.inner.delete(path, args)
    }

    async fn flush(&mut self) -> Result<usize> {
        self.inner.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_common::crypto::Keypair;

    #[test]
    fn keys_inside_the_drive_are_in_scope() {
        let owner = Keypair::random().public_key().z32();
        let prefix = format!("{owner}/");

        for path in [
            format!("{owner}/"),
            format!("{owner}/pub/file.txt"),
            format!("{owner}/priv/deep/nested/file.txt"),
            // The drive root arrives both ways depending on the caller.
            owner.clone(),
            format!("/{owner}/pub/file.txt"),
        ] {
            assert!(is_in_scope(&prefix, &path), "{path} should be in scope");
        }
    }

    #[test]
    fn another_drive_is_out_of_scope() {
        let owner = Keypair::random().public_key().z32();
        let other = Keypair::random().public_key().z32();
        let prefix = format!("{owner}/");

        for path in [
            format!("{other}/pub/file.txt"),
            format!("{other}/"),
            other.clone(),
            // The storage root itself would list every drive on the server.
            String::new(),
            "/".to_string(),
        ] {
            assert!(!is_in_scope(&prefix, &path), "{path} should be denied");
        }
    }

    #[test]
    fn a_key_that_merely_starts_with_the_owners_is_out_of_scope() {
        // Without the separator this would match by prefix alone, which is how
        // "confined to a subtree" checks usually go wrong.
        let owner = Keypair::random().public_key().z32();
        let prefix = format!("{owner}/");

        for path in [
            format!("{owner}-evil/pub/file.txt"),
            format!("{owner}x/pub/file.txt"),
        ] {
            assert!(!is_in_scope(&prefix, &path), "{path} should be denied");
        }
    }

    #[test]
    fn traversal_inside_a_key_does_not_escape() {
        // OpenDAL keys are opaque strings, so `..` is a literal segment here
        // rather than a traversal — but it must still not read as in-scope when
        // it climbs out of the drive.
        let owner = Keypair::random().public_key().z32();
        let other = Keypair::random().public_key().z32();
        let prefix = format!("{owner}/");

        assert!(!is_in_scope(&prefix, &format!("../{other}/pub/x")));
        assert!(is_in_scope(&prefix, &format!("{owner}/pub/../priv/x")));
    }

    #[test]
    fn check_reports_permission_denied() {
        let owner = Keypair::random().public_key().z32();
        let other = Keypair::random().public_key().z32();

        let error = check(&format!("{owner}/"), &format!("{other}/pub/x"))
            .expect_err("another drive must be refused");
        assert_eq!(error.kind(), opendal::ErrorKind::PermissionDenied);
    }
}
