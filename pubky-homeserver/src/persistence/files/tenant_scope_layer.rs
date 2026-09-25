//! Confines an operator to a single user's public folder.
//!
//! The WebDAV endpoint points a `DavHandler` at the whole storage root and
//! relies on an HTTP-level check to keep a request inside `/pub/`. That check
//! is tested and holds, but it is one function: a future change to path
//! normalisation would turn a bug there into a private-data leak.
//!
//! This layer is the second line. Applied per request with the drive's key, it
//! refuses any object key outside `{user_z32}/pub/` at the storage boundary, so
//! the HTTP check becomes a source of good error messages rather than the only
//! control. `opendal` has no `SubdirLayer` and `OpendalFs` takes no root, so
//! this is written out by hand.
//!
//! Every operation is checked, reads included — unlike
//! [`WritePathLayer`](super::write_path_layer::WritePathLayer), which guards
//! mutations only. Reads outside the public folder are exactly what this exists
//! to stop.
use std::sync::Arc;

use opendal::raw::*;
use opendal::Result;
use pubky_common::crypto::PublicKey;

use crate::constants::PUBLIC_ROOT;

/// Restricts an operator to the keys in one user's public folder.
#[derive(Clone, Debug)]
pub struct TenantScopeLayer {
    /// The owner's public folder with a trailing slash, e.g. `8pinxx…ewo/pub/`.
    prefix: Arc<str>,
}

impl TenantScopeLayer {
    /// Scope to `owner`'s public folder.
    pub fn public(owner: &PublicKey) -> Self {
        Self {
            prefix: format!("{}{PUBLIC_ROOT}", owner.z32()).into(),
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

/// Whether `path` names an object inside the scoped folder.
///
/// The folder itself is in scope so a client can stat and list the thing it
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
        "path is outside the public folder",
    ))
}

impl<A: Access> LayeredAccess for TenantScopeAccessor<A> {
    type Inner = A;
    type Reader = A::Reader;
    type Writer = A::Writer;
    type Lister = A::Lister;
    type Deleter = TenantScopeDeleter<A::Deleter>;
    type Copier = A::Copier;

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

    async fn copy(
        &self,
        from: &str,
        to: &str,
        args: OpCopy,
        opts: OpCopier,
    ) -> Result<(RpCopy, Self::Copier)> {
        check(&self.prefix, from)?;
        check(&self.prefix, to)?;
        self.inner.copy(from, to, args, opts).await
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
/// The check is a string comparison rather than a database lookup, so it fails
/// as the key is queued rather than when the batch is closed.
pub struct TenantScopeDeleter<D> {
    inner: D,
    prefix: Arc<str>,
}

impl<D: oio::Delete> oio::Delete for TenantScopeDeleter<D> {
    async fn delete(&mut self, path: &str, args: OpDelete) -> Result<()> {
        check(&self.prefix, path)?;
        self.inner.delete(path, args).await
    }

    async fn close(&mut self) -> Result<()> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_common::crypto::Keypair;

    fn prefix_for(owner: &str) -> String {
        format!("{owner}/pub/")
    }

    #[test]
    fn keys_inside_the_public_folder_are_in_scope() {
        let owner = Keypair::random().public_key().z32();
        let prefix = prefix_for(&owner);

        for path in [
            format!("{owner}/pub/"),
            format!("{owner}/pub/file.txt"),
            format!("{owner}/pub/deep/nested/file.txt"),
            // The folder root arrives both ways depending on the caller.
            format!("{owner}/pub"),
            format!("/{owner}/pub/file.txt"),
        ] {
            assert!(is_in_scope(&prefix, &path), "{path} should be in scope");
        }
    }

    #[test]
    fn the_rest_of_the_drive_is_out_of_scope() {
        let owner = Keypair::random().public_key().z32();
        let prefix = prefix_for(&owner);

        for path in [
            // The drive root would list `priv/` next to `pub/`.
            format!("{owner}/"),
            owner.clone(),
            format!("{owner}/priv/"),
            format!("{owner}/priv/secret.txt"),
            format!("{owner}/.DS_Store"),
        ] {
            assert!(!is_in_scope(&prefix, &path), "{path} should be denied");
        }
    }

    #[test]
    fn other_drives_and_the_storage_root_are_out_of_scope() {
        let owner = Keypair::random().public_key().z32();
        let other = Keypair::random().public_key().z32();
        let prefix = prefix_for(&owner);

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
    fn a_key_that_merely_starts_with_the_prefix_is_out_of_scope() {
        // Without the separator these would match by prefix alone, which is
        // how "confined to a subtree" checks usually go wrong.
        let owner = Keypair::random().public_key().z32();
        let prefix = prefix_for(&owner);

        for path in [
            format!("{owner}/public/file.txt"),
            format!("{owner}/pubx"),
            format!("{owner}-evil/pub/file.txt"),
        ] {
            assert!(!is_in_scope(&prefix, &path), "{path} should be denied");
        }
    }

    #[test]
    fn traversal_inside_a_key_does_not_escape() {
        // OpenDAL keys are opaque strings, so `..` is a literal segment here
        // rather than a traversal. The HTTP layer collapses it before a key is
        // built; this check only has to refuse a key that starts outside.
        let owner = Keypair::random().public_key().z32();
        let other = Keypair::random().public_key().z32();
        let prefix = prefix_for(&owner);

        assert!(!is_in_scope(&prefix, &format!("../{other}/pub/x")));
        assert!(!is_in_scope(&prefix, &format!("{owner}/../{other}/pub/x")));
    }

    #[test]
    fn check_reports_permission_denied() {
        let owner = Keypair::random().public_key().z32();

        let error = check(&prefix_for(&owner), &format!("{owner}/priv/secret.txt"))
            .expect_err("a private path must be refused");
        assert_eq!(error.kind(), opendal::ErrorKind::PermissionDenied);
    }
}
