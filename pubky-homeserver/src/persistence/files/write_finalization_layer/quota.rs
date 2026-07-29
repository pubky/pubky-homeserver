use crate::persistence::sql::user::UserEntity;

/// Check whether adding `bytes_delta` to `current_bytes` would exceed `max_bytes`.
/// `None` means unlimited storage.
pub(crate) fn would_exceed_limit(
    current_bytes: u64,
    bytes_delta: i64,
    max_bytes: Option<u64>,
) -> bool {
    let Some(max) = max_bytes else {
        return false;
    };
    let new_total = current_bytes as i128 + bytes_delta as i128;
    new_total > 0 && new_total > max as i128
}

/// Resolve the effective storage limit from the per-user override and system default.
pub(crate) fn resolve_storage_max_bytes(
    user: &UserEntity,
    default_storage_mb: Option<u64>,
) -> Option<u64> {
    user.quota()
        .storage_quota_mb
        .resolve_with_default(default_storage_mb)
        .map(|mb| mb.saturating_mul(1024 * 1024))
}

#[cfg(test)]
mod tests {
    use super::would_exceed_limit;

    #[test]
    fn quota_limit_math_handles_boundaries_and_negative_deltas() {
        assert!(!would_exceed_limit(500, 500, Some(1000)));
        assert!(would_exceed_limit(500, 501, Some(1000)));
        assert!(!would_exceed_limit(1000, -500, Some(1000)));
        assert!(!would_exceed_limit(u64::MAX, i64::MAX, None));
        assert!(would_exceed_limit(0, 1, Some(0)));
        assert!(!would_exceed_limit(0, 0, Some(0)));
    }
}
