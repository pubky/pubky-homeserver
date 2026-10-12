/// Domain-specific errors produced by our custom OpenDAL layers.
///
/// OpenDAL layers must return [`opendal::Error`], so we embed this enum as the
/// [`.set_source()`][opendal::Error::set_source] — then downcast it in
/// [`OpendalService`](super::opendal::opendal_service::OpendalService) to recover
/// the typed variant.
#[derive(Debug, thiserror::Error)]
pub enum LayerDomainError {
    #[error("write_path_forbidden")]
    WritePathForbidden,
    #[error("disk_space_quota_exceeded")]
    DiskSpaceQuotaExceeded,
    #[error("path_collision")]
    PathCollision,
    #[error("lock_lost")]
    LockLost,
    /// A change under the lock is still being published; retry after the
    /// given number of seconds.
    #[error("lock_busy")]
    LockBusy { retry_after_secs: u64 },
    /// The backend refused a publish or delete: the object was not the one
    /// the change was made against.
    #[error("publish_conflict")]
    PublishConflict,
    /// A change failed before anything was sent to the real path. What went
    /// wrong is in the error's kind; this only says nothing can land.
    #[error("not_published")]
    NotPublished,
}

impl LayerDomainError {
    /// The domain error `error` carries, if one of our layers raised it.
    pub(crate) fn of(error: &opendal::Error) -> Option<&Self> {
        use std::error::Error as _;
        error
            .source()
            .and_then(|source| source.downcast_ref::<Self>())
    }
}
