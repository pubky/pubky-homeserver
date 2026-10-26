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

#[cfg(test)]
mod tests {
    use pubky_common::account::{AccountInfo, QuotaLimit};
    use pubky_common::crypto::Keypair;

    use super::*;

    /// The SDK reads `GET /account` into `pubky_common::account::AccountInfo`,
    /// so what `UserItem` writes must parse into it, field for field.
    #[test]
    fn user_item_matches_the_shared_account_info() {
        let user = UserEntity {
            id: 1,
            public_key: Keypair::random().public_key(),
            created_at: sqlx::types::chrono::NaiveDateTime::default(),
            disabled: true,
            used_bytes: 42,
            quota_storage_mb: Some(500),
            quota_rate_read: Some("100mb/m".to_string()),
            quota_rate_write: Some("unlimited".to_string()),
            quota_rate_read_burst: Some(50),
            quota_rate_write_burst: None,
            allowed_write_paths: Some("[\"/pub/tokens/\"]".to_string()),
        };
        let config = ConfigToml::default_test_config();

        let json = serde_json::to_value(UserItem::new(&user, &config)).unwrap();
        let info: AccountInfo = serde_json::from_value(json).unwrap();

        assert_eq!(info.pubky, user.public_key);
        assert_eq!(
            info.created_at,
            user.created_at.to_string().replace(' ', "T")
        );
        assert!(info.disabled);
        assert_eq!(info.used_bytes, 42);
        let effective = &info.quota.effective;
        assert_eq!(effective.storage_quota_mb, Some(QuotaLimit::Value(500)));
        assert_eq!(
            effective.rate_read,
            Some(QuotaLimit::Value("100mb/m".to_string()))
        );
        assert_eq!(effective.rate_write, Some(QuotaLimit::Unlimited));
        assert_eq!(effective.rate_read_burst, Some(50));
        assert_eq!(effective.rate_write_burst, None);
        assert_eq!(
            effective
                .allowed_write_paths
                .as_deref()
                .map(|p| p[0].as_str()),
            Some("/pub/tokens/")
        );
        assert_eq!(
            info.quota.overrides.storage_quota_mb,
            Some(QuotaLimit::Value(500))
        );
        assert_eq!(info.quota.overrides.rate_write, Some(QuotaLimit::Unlimited));
    }
}
