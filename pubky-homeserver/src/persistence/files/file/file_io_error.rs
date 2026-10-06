use crate::persistence::files::layer_domain_error::LayerDomainError;

/// Error type for file operations.
#[derive(Debug, thiserror::Error)]
pub enum FileIoError {
    #[error("File not found")]
    NotFound,
    #[error("DB error: {0}")]
    SqlDb(#[from] sqlx::Error),
    #[error("OpenDAL error: {0}")]
    OpenDAL(opendal::Error),
    #[error("Storage backend rate limited: {0}")]
    BackendRateLimited(#[source] opendal::Error),
    #[error("Temp file error: {0}")]
    TempFile(#[from] std::io::Error),
    #[error(transparent)]
    StreamBroken(#[from] WriteStreamError),
    #[error("Disk space quota exceeded")]
    DiskSpaceQuotaExceeded,
    #[error("Write to path is forbidden")]
    WritePathForbidden,
    #[error("File/folder path collision")]
    PathCollision,
    #[error("Lock lost before the file was changed")]
    LockLost,
}

impl From<opendal::Error> for FileIoError {
    fn from(e: opendal::Error) -> Self {
        use std::error::Error as _;
        // Recover domain-specific errors embedded by our custom OpenDAL layers.
        if let Some(domain) = e
            .source()
            .and_then(|s| s.downcast_ref::<LayerDomainError>())
        {
            return match domain {
                LayerDomainError::WritePathForbidden => FileIoError::WritePathForbidden,
                LayerDomainError::DiskSpaceQuotaExceeded => FileIoError::DiskSpaceQuotaExceeded,
                LayerDomainError::PathCollision => FileIoError::PathCollision,
                LayerDomainError::LockLost => FileIoError::LockLost,
            };
        }
        match e.kind() {
            opendal::ErrorKind::NotFound => FileIoError::NotFound,
            // A quota rejection has this kind too, but was recovered above.
            opendal::ErrorKind::RateLimited => FileIoError::BackendRateLimited(e),
            _ => FileIoError::OpenDAL(e),
        }
    }
}

/// A unified error type for writing streams.
#[derive(Debug, thiserror::Error)]
pub enum WriteStreamError {
    #[error("Axum error: {0}")]
    Axum(#[from] axum::Error),
    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate_limited() -> opendal::Error {
        opendal::Error::new(
            opendal::ErrorKind::RateLimited,
            "object mutation rate limit exceeded",
        )
    }

    /// The finalization layer reports a quota rejection with the same kind as
    /// a throttled backend. Only the embedded domain error tells them apart.
    #[test]
    fn rate_limited_kind_is_a_backend_throttle_unless_it_carries_a_quota_rejection() {
        assert!(matches!(
            FileIoError::from(rate_limited()),
            FileIoError::BackendRateLimited(_)
        ));
        assert!(matches!(
            FileIoError::from(rate_limited().set_source(LayerDomainError::DiskSpaceQuotaExceeded)),
            FileIoError::DiskSpaceQuotaExceeded
        ));
    }
}
