//! A user's account as exposed by the admin `GET /users` routes and the client
//! `GET /account` route, so both servers serialise the same shape.

use serde::Serialize;
use sqlx::types::chrono::NaiveDateTime;

use crate::persistence::sql::user::UserEntity;
use crate::shared::quota::UserQuota;
use crate::ConfigToml;

/// The effective quota (overrides merged with system defaults) and the raw
/// per-user overrides, so callers can see what applies and what was
/// explicitly customised in a single request.
#[derive(Debug, Serialize)]
pub(crate) struct UserQuotaResponse {
    /// The effective quota: overrides merged with system defaults.
    /// All fields are always present (no fields omitted).
    pub effective: UserQuota,
    /// Only the per-user overrides. Fields using the system default are omitted.
    pub overrides: UserQuota,
}

impl UserQuotaResponse {
    /// Resolve `user`'s quota overrides against the system defaults in `config`.
    pub(crate) fn new(user: &UserEntity, config: &ConfigToml) -> Self {
        let overrides = user.quota();
        let effective = overrides
            .resolve_with_defaults(config.storage.default_quota_mb, &config.default_quotas);
        Self {
            effective,
            overrides,
        }
    }
}

/// One user, as returned by admin `GET /users`, `GET /users/{pubkey}` and the
/// client `GET /account`.
#[derive(Debug, Serialize)]
pub(crate) struct UserItem {
    /// z-base-32 user public key, named as in the client `GrantSessionInfo`.
    pubky: String,
    created_at: NaiveDateTime,
    disabled: bool,
    used_bytes: u64,
    /// Same shape as `GET /users/{pubkey}/quota`.
    quota: UserQuotaResponse,
}

impl UserItem {
    pub(crate) fn new(user: &UserEntity, config: &ConfigToml) -> Self {
        Self {
            pubky: user.public_key.z32(),
            created_at: user.created_at,
            disabled: user.disabled,
            used_bytes: user.used_bytes,
            quota: UserQuotaResponse::new(user, config),
        }
    }
}
