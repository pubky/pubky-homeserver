use crate::persistence::sql::{entry::EntryEntity, user::UserEntity};
use crate::services::user_service::FILE_METADATA_SIZE;

/// The change in a user's stored bytes from writing `new_length` bytes where
/// `existing_entry` is. A new entry also pays [`FILE_METADATA_SIZE`].
pub(crate) fn write_bytes_delta(existing_entry: Option<&EntryEntity>, new_length: u64) -> i64 {
    // `new_length` may be a client's Content-Length. Past `i64::MAX` it
    // saturates rather than wrapping negative, which would pass the quota.
    let new_length = i64::try_from(new_length).unwrap_or(i64::MAX);
    match existing_entry {
        Some(entry) => {
            new_length.saturating_sub(i64::try_from(entry.content_length).unwrap_or(i64::MAX))
        }
        None => new_length.saturating_add(FILE_METADATA_SIZE as i64),
    }
}

/// Whether adding `bytes_delta` to the user's usage would exceed their storage
/// quota, with `default_storage_mb` for users without a quota of their own.
pub(crate) fn would_exceed_quota(
    user: &UserEntity,
    bytes_delta: i64,
    default_storage_mb: Option<u64>,
) -> bool {
    let max_bytes = resolve_storage_max_bytes(user, default_storage_mb);
    would_exceed_limit(user.used_bytes, bytes_delta, max_bytes)
}

/// Check whether adding `bytes_delta` to `current_bytes` would exceed `max_bytes`.
/// `None` means unlimited storage.
fn would_exceed_limit(current_bytes: u64, bytes_delta: i64, max_bytes: Option<u64>) -> bool {
    let Some(max) = max_bytes else {
        return false;
    };
    let new_total = current_bytes as i128 + bytes_delta as i128;
    new_total > 0 && new_total > max as i128
}

/// Resolve the effective storage limit from the per-user override and system default.
fn resolve_storage_max_bytes(user: &UserEntity, default_storage_mb: Option<u64>) -> Option<u64> {
    user.quota()
        .storage_quota_mb
        .resolve_with_default(default_storage_mb)
        .map(|mb| mb.saturating_mul(1024 * 1024))
}

#[cfg(test)]
mod tests {
    use super::{would_exceed_limit, write_bytes_delta, FILE_METADATA_SIZE};

    #[test]
    fn write_bytes_delta_charges_metadata_for_new_entries_and_saturates() {
        assert_eq!(write_bytes_delta(None, 10), 10 + FILE_METADATA_SIZE as i64);
        assert_eq!(write_bytes_delta(None, u64::MAX), i64::MAX);
        assert_eq!(write_bytes_delta(None, i64::MAX as u64), i64::MAX);
    }

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
