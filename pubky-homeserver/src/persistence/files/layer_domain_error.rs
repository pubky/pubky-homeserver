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
    #[error("precondition_failed")]
    PreconditionFailed,
}
