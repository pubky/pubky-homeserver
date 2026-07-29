use std::{fmt::Display, str::FromStr};

use base32::{decode, encode, Alphabet};
use pubky_common::crypto::random_bytes;
use pubky_common::crypto::PublicKey;
use sea_query::{Expr, Iden, Order, PostgresQueryBuilder, Query, SimpleExpr};
use sea_query_binder::SqlxBinder;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sqlx::{postgres::PgRow, FromRow, Row};

use crate::shared::user_quota::UserQuota;
use crate::{
    constants::{DEFAULT_LIST_LIMIT, DEFAULT_MAX_LIST_LIMIT},
    persistence::sql::UnifiedExecutor,
};

pub const SIGNUP_CODE_TABLE: &str = "signup_codes";

/// Repository that handles all the queries regarding the SignupCodeEntity.
pub struct SignupCodeRepository;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignupCodeListState {
    All,
    Used,
    Unused,
}

#[derive(Debug, Clone)]
pub struct SignupCodeListQuery {
    pub state: SignupCodeListState,
    pub limit: Option<u16>,
    pub cursor: Option<SignupCode>,
}

impl SignupCodeListQuery {
    fn effective_limit(&self) -> u16 {
        self.limit
            .unwrap_or(DEFAULT_LIST_LIMIT)
            .min(DEFAULT_MAX_LIST_LIMIT)
    }
}

#[derive(Debug, Clone)]
pub struct SignupCodeListPage {
    pub items: Vec<SignupCodeEntity>,
    pub next_cursor: Option<SignupCode>,
}

impl SignupCodeRepository {
    /// Create a new signup code with the given limits for users who redeem it.
    /// The executor can either be db.pool() or a transaction.
    ///
    /// Rate limit strings are validated by roundtripping through `BandwidthQuota`
    /// parsing to ensure only well-formed values reach the database.
    pub async fn create<'a>(
        id: &SignupCode,
        limits: &UserQuota,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<SignupCodeEntity, sqlx::Error> {
        limits.validate().map_err(sqlx::Error::InvalidArgument)?;

        let statement = Query::insert()
            .into_table(SIGNUP_CODE_TABLE)
            .columns([
                SignupCodeIden::Id,
                SignupCodeIden::QuotaStorageMb,
                SignupCodeIden::QuotaRateRead,
                SignupCodeIden::QuotaRateWrite,
                SignupCodeIden::QuotaRateReadBurst,
                SignupCodeIden::QuotaRateWriteBurst,
                SignupCodeIden::AllowedWritePaths,
            ])
            .values(vec![
                SimpleExpr::Value(id.to_string().into()),
                SimpleExpr::Value(limits.storage_quota_mb_i32().into()),
                SimpleExpr::Value(limits.rate_read_str().into()),
                SimpleExpr::Value(limits.rate_write_str().into()),
                SimpleExpr::Value(limits.rate_read_burst_i32().into()),
                SimpleExpr::Value(limits.rate_write_burst_i32().into()),
                SimpleExpr::Value(
                    limits
                        .allowed_write_paths_db()
                        .map_err(|e| sqlx::Error::InvalidArgument(e.to_string()))?
                        .into(),
                ),
            ])
            .unwrap()
            .returning_all()
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let code: SignupCodeEntity = sqlx::query_as_with(&query, values).fetch_one(con).await?;
        Ok(code)
    }

    /// Get a signup code by its ID.
    /// The executor can either be db.pool() or a transaction.
    pub async fn get<'a>(
        id: &SignupCode,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<SignupCodeEntity, sqlx::Error> {
        let statement = Query::select()
            .from(SIGNUP_CODE_TABLE)
            .columns([
                SignupCodeIden::Id,
                SignupCodeIden::CreatedAt,
                SignupCodeIden::UsedAt,
                SignupCodeIden::UsedBy,
                SignupCodeIden::QuotaStorageMb,
                SignupCodeIden::QuotaRateRead,
                SignupCodeIden::QuotaRateWrite,
                SignupCodeIden::QuotaRateReadBurst,
                SignupCodeIden::QuotaRateWriteBurst,
                SignupCodeIden::AllowedWritePaths,
            ])
            .and_where(Expr::col(SignupCodeIden::Id).eq(id.to_string()))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let code: SignupCodeEntity = sqlx::query_as_with(&query, values).fetch_one(con).await?;
        Ok(code)
    }

    /// List signup codes in token order.
    /// The executor can either be db.pool() or a transaction.
    pub async fn list<'a>(
        list_query: SignupCodeListQuery,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<SignupCodeListPage, sqlx::Error> {
        let mut statement = Query::select()
            .from(SIGNUP_CODE_TABLE)
            .columns([
                SignupCodeIden::Id,
                SignupCodeIden::CreatedAt,
                SignupCodeIden::UsedAt,
                SignupCodeIden::UsedBy,
                SignupCodeIden::QuotaStorageMb,
                SignupCodeIden::QuotaRateRead,
                SignupCodeIden::QuotaRateWrite,
                SignupCodeIden::QuotaRateReadBurst,
                SignupCodeIden::QuotaRateWriteBurst,
                SignupCodeIden::AllowedWritePaths,
            ])
            .order_by(SignupCodeIden::Id, Order::Asc)
            .to_owned();

        statement = match list_query.state {
            SignupCodeListState::All => statement,
            SignupCodeListState::Used => statement
                .and_where(Expr::col(SignupCodeIden::UsedBy).is_not_null())
                .to_owned(),
            SignupCodeListState::Unused => statement
                .and_where(Expr::col(SignupCodeIden::UsedBy).is_null())
                .to_owned(),
        };

        if let Some(cursor) = &list_query.cursor {
            statement = statement
                .and_where(Expr::col(SignupCodeIden::Id).gt(cursor.to_string()))
                .to_owned();
        }

        let limit = list_query.effective_limit();
        statement = statement.limit((limit as u64) + 1).to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let mut codes: Vec<SignupCodeEntity> =
            sqlx::query_as_with(&query, values).fetch_all(con).await?;
        let next_cursor = if codes.len() > limit as usize {
            codes.truncate(limit as usize);
            codes.last().map(|code| code.id.clone())
        } else {
            None
        };

        Ok(SignupCodeListPage {
            items: codes,
            next_cursor,
        })
    }

    /// Get overview statistics for signup codes.
    /// The executor can either be db.pool() or a transaction.
    pub async fn get_overview<'a>(
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<SignupCodeOverview, sqlx::Error> {
        // Query to get total number of signup codes
        let total_statement = Query::select()
            .expr(Expr::col(SignupCodeIden::Id).count())
            .from(SIGNUP_CODE_TABLE)
            .to_owned();

        let (total_query, total_values) = total_statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let total_count: i64 = sqlx::query_scalar_with(&total_query, total_values)
            .fetch_one(con)
            .await?;

        // Query to get number of unused signup codes (where used_by is NULL)
        let unused_statement = Query::select()
            .expr(Expr::col(SignupCodeIden::Id).count())
            .from(SIGNUP_CODE_TABLE)
            .and_where(Expr::col(SignupCodeIden::UsedBy).is_null())
            .to_owned();

        let (unused_query, unused_values) = unused_statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let unused_count: i64 = sqlx::query_scalar_with(&unused_query, unused_values)
            .fetch_one(con)
            .await?;

        Ok(SignupCodeOverview {
            num_signup_codes: total_count as u64,
            num_unused_signup_codes: unused_count as u64,
        })
    }

    pub async fn mark_as_used<'a>(
        id: &SignupCode,
        used_by: &PublicKey,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<SignupCodeEntity, sqlx::Error> {
        let statement = Query::update()
            .table(SIGNUP_CODE_TABLE)
            .values(vec![
                (
                    SignupCodeIden::UsedBy,
                    SimpleExpr::Value(used_by.z32().into()),
                ),
                (SignupCodeIden::UsedAt, Expr::current_timestamp().into()),
            ])
            .and_where(Expr::col(SignupCodeIden::Id).eq(id.to_string()))
            .and_where(Expr::col(SignupCodeIden::UsedBy).is_null())
            .returning_all()
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let updated_code: SignupCodeEntity =
            sqlx::query_as_with(&query, values).fetch_one(con).await?;
        Ok(updated_code)
    }
}

/// Iden for the signup code table.
/// Basically a list of columns in the signup code table
#[derive(Iden)]
pub enum SignupCodeIden {
    Id,
    CreatedAt,
    UsedAt,
    UsedBy,
    QuotaStorageMb,
    QuotaRateRead,
    QuotaRateWrite,
    QuotaRateReadBurst,
    QuotaRateWriteBurst,
    AllowedWritePaths,
}

/// Signup code id in the format of "JZY0-D6MY-ZFNG".
/// Base32 encoded with the Crockford alphabet, separated by hyphens.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignupCode(pub String);

impl SignupCode {
    /// Create a new signup code id.
    /// Returns an error if the id is invalid.
    pub fn new(id: String) -> anyhow::Result<Self> {
        if !Self::is_valid(&id) {
            return Err(anyhow::anyhow!("Invalid signup code id"));
        }
        Ok(Self(id))
    }

    /// Check if a signup code id is in a valid format.
    pub fn is_valid(value: &str) -> bool {
        if value.len() != 14 {
            return false;
        }

        let without_hyphens = value.replace("-", "");
        decode(Alphabet::Crockford, &without_hyphens).is_some()
    }

    /// Create a random signup code id.
    pub fn random() -> Self {
        let bytes = random_bytes::<7>();
        let encoded = encode(Alphabet::Crockford, &bytes).to_uppercase();
        let mut with_hyphens = String::new();
        for (i, ch) in encoded.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                with_hyphens.push('-');
            }
            with_hyphens.push(ch);
        }

        SignupCode(with_hyphens)
    }
}

impl Display for SignupCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for SignupCode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl Serialize for SignupCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SignupCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Overview statistics for signup codes
#[derive(Debug, Clone)]
pub struct SignupCodeOverview {
    pub num_signup_codes: u64,
    pub num_unused_signup_codes: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignupCodeEntity {
    pub id: SignupCode,
    pub created_at: sqlx::types::chrono::NaiveDateTime,
    pub used_at: Option<sqlx::types::chrono::NaiveDateTime>,
    pub used_by: Option<PublicKey>,
    /// Per-user storage quota in MB. `None` = Default (resolved from system config at enforcement time).
    pub quota_storage_mb: Option<i32>,
    /// Per-user read rate limit. `None` = Default (resolved from system config at enforcement time).
    pub quota_rate_read: Option<String>,
    /// Per-user write rate limit. `None` = Default (resolved from system config at enforcement time).
    pub quota_rate_write: Option<String>,
    /// Per-user read rate burst override. `None` = default (burst = rate).
    pub quota_rate_read_burst: Option<i32>,
    /// Per-user write rate burst override. `None` = default (burst = rate).
    pub quota_rate_write_burst: Option<i32>,
    /// Allowed write paths as JSON array string. `None` = unrestricted.
    pub allowed_write_paths: Option<String>,
}

impl SignupCodeEntity {
    /// Extract quota from the DB columns.
    pub fn quota(&self) -> UserQuota {
        UserQuota::from_nullable_columns(
            self.quota_storage_mb,
            self.quota_rate_read.clone(),
            self.quota_rate_write.clone(),
            self.quota_rate_read_burst,
            self.quota_rate_write_burst,
            self.allowed_write_paths.clone(),
        )
    }
}

impl FromRow<'_, PgRow> for SignupCodeEntity {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        let token: String = row.try_get(SignupCodeIden::Id.to_string().as_str())?;
        let id = SignupCode::new(token).map_err(|e| {
            sqlx::Error::Decode(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e,
            )))
        })?;
        let created_at: sqlx::types::chrono::NaiveDateTime =
            row.try_get(SignupCodeIden::CreatedAt.to_string().as_str())?;
        let used_at: Option<sqlx::types::chrono::NaiveDateTime> =
            row.try_get(SignupCodeIden::UsedAt.to_string().as_str())?;
        let used_by_raw: Option<String> =
            row.try_get(SignupCodeIden::UsedBy.to_string().as_str())?;
        let used_by = used_by_raw
            .map(|s| {
                PublicKey::try_from_z32(s.as_str()).map_err(|e| sqlx::Error::Decode(Box::new(e)))
            })
            .transpose()?;

        let quota_storage_mb: Option<i32> =
            row.try_get(SignupCodeIden::QuotaStorageMb.to_string().as_str())?;
        let quota_rate_read: Option<String> =
            row.try_get(SignupCodeIden::QuotaRateRead.to_string().as_str())?;
        let quota_rate_write: Option<String> =
            row.try_get(SignupCodeIden::QuotaRateWrite.to_string().as_str())?;
        let quota_rate_read_burst: Option<i32> =
            row.try_get(SignupCodeIden::QuotaRateReadBurst.to_string().as_str())?;
        let quota_rate_write_burst: Option<i32> =
            row.try_get(SignupCodeIden::QuotaRateWriteBurst.to_string().as_str())?;
        let allowed_write_paths: Option<String> =
            row.try_get(SignupCodeIden::AllowedWritePaths.to_string().as_str())?;

        Ok(SignupCodeEntity {
            id,
            created_at,
            used_at,
            used_by,
            quota_storage_mb,
            quota_rate_read,
            quota_rate_write,
            quota_rate_read_burst,
            quota_rate_write_burst,
            allowed_write_paths,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::persistence::sql::SqlDb;
    use pubky_common::crypto::Keypair;

    use super::*;

    async fn current_db_timestamp(db: &SqlDb) -> sqlx::types::chrono::NaiveDateTime {
        sqlx::query_scalar("SELECT CURRENT_TIMESTAMP::timestamp")
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_get_signup_code() {
        let db = SqlDb::test().await;
        let signup_code_id = SignupCode::random();

        // Test create code with default (all-Default) limits
        let code = SignupCodeRepository::create(
            &signup_code_id,
            &UserQuota::default(),
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert_eq!(code.id, signup_code_id);
        assert_eq!(code.used_at, None);
        assert_eq!(code.used_by, None);
        // All-default quota: all fields should be Default
        assert_eq!(code.quota(), UserQuota::default());

        // Test get code
        let code = SignupCodeRepository::get(&signup_code_id, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(code.id, signup_code_id);
        assert_eq!(code.used_at, None);
        assert_eq!(code.used_by, None);
        assert_eq!(code.quota(), UserQuota::default());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_with_quota() {
        use crate::data_directory::quota_config::BandwidthQuota;
        use crate::shared::user_quota::QuotaOverride;
        use std::str::FromStr;

        let db = SqlDb::test().await;
        let signup_code_id = SignupCode::random();

        let config = UserQuota {
            storage_quota_mb: QuotaOverride::Value(500),
            rate_read: QuotaOverride::Value(BandwidthQuota::from_str("100mb/m").unwrap()),
            rate_write: QuotaOverride::Default,
            ..Default::default()
        };

        let code = SignupCodeRepository::create(&signup_code_id, &config, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(code.quota(), config.clone());

        // Verify get also returns the config
        let code = SignupCodeRepository::get(&signup_code_id, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(code.quota(), config);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_mark_as_used() {
        let db = SqlDb::test().await;
        let signup_code_id = SignupCode::random();
        let _ = SignupCodeRepository::create(
            &signup_code_id,
            &UserQuota::default(),
            &mut db.pool().into(),
        )
        .await
        .unwrap();

        let user_pubkey = Keypair::random().public_key();

        let before = current_db_timestamp(&db).await;
        let marked_code = SignupCodeRepository::mark_as_used(
            &signup_code_id,
            &user_pubkey,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        let after = current_db_timestamp(&db).await;
        let used_at = marked_code.used_at.expect("used_at should be set");
        assert!(
            used_at >= before && used_at <= after,
            "used_at {used_at} should be between DB timestamps {before} and {after}"
        );

        let updated_code = SignupCodeRepository::get(&signup_code_id, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(updated_code.id, signup_code_id);
        assert_eq!(updated_code.used_by, Some(user_pubkey));
        assert_eq!(updated_code.used_at, Some(used_at));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_overview() {
        let db = SqlDb::test().await;

        // Initially, there should be no signup codes
        let overview = SignupCodeRepository::get_overview(&mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(overview.num_signup_codes, 0);
        assert_eq!(overview.num_unused_signup_codes, 0);

        // Create some signup codes
        let code1 = SignupCode::random();
        let code2 = SignupCode::random();
        let code3 = SignupCode::random();

        let _ = SignupCodeRepository::create(&code1, &UserQuota::default(), &mut db.pool().into())
            .await
            .unwrap();
        let _ = SignupCodeRepository::create(&code2, &UserQuota::default(), &mut db.pool().into())
            .await
            .unwrap();
        let _ = SignupCodeRepository::create(&code3, &UserQuota::default(), &mut db.pool().into())
            .await
            .unwrap();

        // After creating 3 codes, all should be unused
        let overview = SignupCodeRepository::get_overview(&mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(overview.num_signup_codes, 3);
        assert_eq!(overview.num_unused_signup_codes, 3);

        // Mark one code as used
        let user_pubkey = Keypair::random().public_key();
        SignupCodeRepository::mark_as_used(&code1, &user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

        // Now there should be 3 total codes, 2 unused
        let overview = SignupCodeRepository::get_overview(&mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(overview.num_signup_codes, 3);
        assert_eq!(overview.num_unused_signup_codes, 2);

        // Mark another code as used
        let user_pubkey2 = Keypair::random().public_key();
        SignupCodeRepository::mark_as_used(&code2, &user_pubkey2, &mut db.pool().into())
            .await
            .unwrap();

        // Now there should be 3 total codes, 1 unused
        let overview = SignupCodeRepository::get_overview(&mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(overview.num_signup_codes, 3);
        assert_eq!(overview.num_unused_signup_codes, 1);
    }

    /// Verify that signup token custom limits are propagated to the user
    /// entity when the token is redeemed.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_signup_token_limits_applied_to_user() {
        use crate::data_directory::quota_config::BandwidthQuota;
        use crate::persistence::sql::user::UserRepository;
        use crate::shared::user_quota::QuotaOverride;
        use std::str::FromStr;

        let db = SqlDb::test().await;

        fn bw(s: &str) -> BandwidthQuota {
            BandwidthQuota::from_str(s).unwrap()
        }

        // 1) Create a signup code with custom limits
        let user_quota = UserQuota {
            storage_quota_mb: QuotaOverride::Value(1024),
            rate_read: QuotaOverride::Value(bw("200mb/m")),
            rate_write: QuotaOverride::Default,
            ..Default::default()
        };
        let code_id = SignupCode::random();
        let code = SignupCodeRepository::create(&code_id, &user_quota, &mut db.pool().into())
            .await
            .unwrap();

        // 2) Simulate the signup flow: create user, mark code used, apply limits
        let keypair = Keypair::random();
        let pubkey = keypair.public_key();
        let mut tx = db.pool().begin().await.unwrap();
        let user = UserRepository::create(&pubkey, &mut (&mut tx).into())
            .await
            .unwrap();
        SignupCodeRepository::mark_as_used(&code_id, &pubkey, &mut (&mut tx).into())
            .await
            .unwrap();
        let token_limits = code.quota();
        UserRepository::set_quota(user.id, &token_limits, &mut (&mut tx).into())
            .await
            .unwrap();
        tx.commit().await.unwrap();

        // 3) Re-read from DB and verify limits were persisted
        let user = UserRepository::get(&pubkey, &mut db.pool().into())
            .await
            .unwrap();
        let user_quota = user.quota();
        assert_eq!(user_quota.storage_quota_mb, QuotaOverride::Value(1024));
        assert_eq!(user_quota.rate_read, QuotaOverride::Value(bw("200mb/m")));
        assert_eq!(user_quota.rate_write, QuotaOverride::Default);
    }

    /// Verify that signup code `allowed_write_paths` are propagated to the user.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_signup_token_write_paths_applied_to_user() {
        use crate::persistence::sql::user::UserRepository;
        use crate::shared::webdav::StoragePath;

        let db = SqlDb::test().await;

        fn wdp(s: &str) -> StoragePath {
            s.parse().unwrap()
        }

        // 1) Create a signup code with allowed_write_paths restriction
        let code_quota = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/tokens/"), wdp("/pub/paykit/")]),
            ..Default::default()
        };
        let code_id = SignupCode::random();
        let code = SignupCodeRepository::create(&code_id, &code_quota, &mut db.pool().into())
            .await
            .unwrap();

        // Verify the code itself persisted the paths
        let fetched_code = SignupCodeRepository::get(&code_id, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(
            fetched_code.quota().allowed_write_paths,
            code_quota.allowed_write_paths
        );

        // 2) Simulate signup flow: create user, mark code, apply limits
        let keypair = Keypair::random();
        let pubkey = keypair.public_key();
        let mut tx = db.pool().begin().await.unwrap();
        let user = UserRepository::create(&pubkey, &mut (&mut tx).into())
            .await
            .unwrap();
        SignupCodeRepository::mark_as_used(&code_id, &pubkey, &mut (&mut tx).into())
            .await
            .unwrap();
        let token_quota = code.quota();
        UserRepository::set_quota(user.id, &token_quota, &mut (&mut tx).into())
            .await
            .unwrap();
        tx.commit().await.unwrap();

        // 3) Verify the user inherited the write path restrictions
        let user = UserRepository::get(&pubkey, &mut db.pool().into())
            .await
            .unwrap();
        let user_quota = user.quota();
        assert_eq!(
            user_quota.allowed_write_paths,
            Some(vec![wdp("/pub/tokens/"), wdp("/pub/paykit/")]),
            "allowed_write_paths should propagate from signup code to user"
        );
        assert!(user_quota.is_write_path_allowed("/pub/tokens/foo.json"));
        assert!(user_quota.is_write_path_allowed("/pub/paykit/bar"));
        assert!(!user_quota.is_write_path_allowed("/pub/other/file"));
    }
}
