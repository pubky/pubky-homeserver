//! Authorization shared by every handler that changes a storage path: `PUT`,
//! `DELETE`, `LOCK` and `UNLOCK`. One place decides what a write demands, so a
//! lock can never be granted on a path a write would refuse.

use crate::{
    client_server::{
        auth::{has_write_permission, AuthSession},
        AppState,
    },
    persistence::sql::user::UserEntity,
    shared::{webdav::EntryPath, HttpError, HttpResult},
};

/// What a write to `entry_path` demands: a file path, a session with write
/// capability on it, and a known owner. `must_be_enabled` additionally refuses
/// a disabled owner; `DELETE` and `UNLOCK` let one clean up.
pub(super) async fn authorize_write(
    state: &AppState,
    session: &AuthSession,
    entry_path: &EntryPath,
    must_be_enabled: bool,
) -> HttpResult<UserEntity> {
    if !entry_path.path().is_file() {
        return Err(HttpError::bad_request("Target path must be a file"));
    }
    has_write_permission(session, entry_path.pubkey(), entry_path.path())?;
    state
        .context
        .user_service
        .get_or_http_error(entry_path.pubkey(), must_be_enabled)
        .await
}
