use crate::constants::{DEFAULT_LIST_LIMIT, DEFAULT_MAX_LIST_LIMIT};
use crate::persistence::sql::entry::EntryEntity;
use crate::{
    persistence::sql::{
        entities::user::{UserIden, USER_TABLE},
        UnifiedExecutor,
    },
    shared::webdav::{EntryPath, StoragePath},
};
use sea_query::{Alias, Expr, Iden, Order, PostgresQueryBuilder, Query, SimpleExpr};
use sea_query_binder::SqlxBinder;
use sqlx::{postgres::PgRow, Row};

pub const ENTRY_TABLE: &str = "entries";

/// Repository that handles all the queries regarding the EntryEntity.
pub struct EntryRepository;

impl EntryRepository {
    /// Create a new entry.
    /// The executor can either be db.pool() or a transaction.
    pub async fn create<'a>(
        user_id: i32,
        path: &StoragePath,
        content_hash: &pubky_common::crypto::Hash,
        content_length: u64,
        content_type: &str,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<i64, sqlx::Error> {
        let statement = Query::insert()
            .into_table(ENTRY_TABLE)
            .columns([
                EntryIden::User,
                EntryIden::Path,
                EntryIden::ContentHash,
                EntryIden::ContentLength,
                EntryIden::ContentType,
            ])
            .values(vec![
                SimpleExpr::Value(user_id.into()),
                SimpleExpr::Value(path.as_str().into()),
                SimpleExpr::Value(content_hash.as_bytes().to_vec().into()),
                SimpleExpr::Value(content_length.into()),
                SimpleExpr::Value(content_type.to_string().into()),
            ])
            .expect("Failed to build insert statement")
            .returning_col(EntryIden::Id)
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);

        let con = executor.get_con().await?;
        let ret_row: PgRow = sqlx::query_with(&query, values).fetch_one(con).await?;
        let entry_id: i64 = ret_row.try_get(EntryIden::Id.to_string().as_str())?;
        Ok(entry_id)
    }

    /// Get an entry by its path.
    /// The executor can either be db.pool() or a transaction.
    pub async fn get_by_path<'a>(
        path: &EntryPath,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<EntryEntity, sqlx::Error> {
        let statement = Query::select()
            .from(ENTRY_TABLE)
            .columns([
                (ENTRY_TABLE, EntryIden::Id),
                (ENTRY_TABLE, EntryIden::User),
                (ENTRY_TABLE, EntryIden::Path),
                (ENTRY_TABLE, EntryIden::ContentHash),
                (ENTRY_TABLE, EntryIden::ContentLength),
                (ENTRY_TABLE, EntryIden::ContentType),
                (ENTRY_TABLE, EntryIden::ModifiedAt),
                (ENTRY_TABLE, EntryIden::CreatedAt),
            ])
            .column((USER_TABLE, UserIden::PublicKey))
            .left_join(
                USER_TABLE,
                Expr::col((ENTRY_TABLE, EntryIden::User)).eq(Expr::col((USER_TABLE, UserIden::Id))),
            )
            .and_where(Expr::col((ENTRY_TABLE, EntryIden::Path)).eq(path.path().as_str()))
            .and_where(Expr::col((USER_TABLE, UserIden::PublicKey)).eq(path.pubkey().z32()))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let entry: EntryEntity = sqlx::query_as_with(&query, values).fetch_one(con).await?;
        Ok(entry)
    }

    pub async fn update<'a>(
        entry: &EntryEntity,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let statement = Query::update()
            .table(ENTRY_TABLE)
            .values(vec![
                (
                    EntryIden::ContentHash,
                    SimpleExpr::Value(entry.content_hash.as_bytes().to_vec().into()),
                ),
                (
                    EntryIden::ContentLength,
                    SimpleExpr::Value(entry.content_length.into()),
                ),
                (
                    EntryIden::ContentType,
                    SimpleExpr::Value(entry.content_type.clone().into()),
                ),
                (EntryIden::ModifiedAt, Expr::current_timestamp().into()),
            ])
            .and_where(Expr::col((ENTRY_TABLE, EntryIden::Id)).eq(entry.id))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_with(&query, values).execute(con).await?;
        Ok(())
    }

    /// Delete an entry by its id.
    /// The executor can either be db.pool() or a transaction.
    pub async fn delete<'a>(
        id: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let statement = Query::delete()
            .from_table(ENTRY_TABLE)
            .and_where(Expr::col((ENTRY_TABLE, EntryIden::Id)).eq(id))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_with(&query, values).execute(con).await?;
        Ok(())
    }

    /// Delete an entry by its path.
    /// The executor can either be db.pool() or a transaction.
    #[cfg(test)]
    pub async fn delete_by_path<'a>(
        path: &EntryPath,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        // First get the id of the entry to delete
        let subquery = Query::select()
            .column((ENTRY_TABLE, EntryIden::Id))
            .from(ENTRY_TABLE)
            .left_join(
                USER_TABLE,
                Expr::col((ENTRY_TABLE, EntryIden::User)).eq(Expr::col((USER_TABLE, UserIden::Id))),
            )
            .and_where(Expr::col((ENTRY_TABLE, EntryIden::Path)).eq(path.path().as_str()))
            .and_where(Expr::col((USER_TABLE, UserIden::PublicKey)).eq(path.pubkey().z32()))
            .to_owned();

        // Then delete the entry by the id
        let statement = Query::delete()
            .from_table(ENTRY_TABLE)
            .and_where(Expr::col((ENTRY_TABLE, EntryIden::Id)).in_subquery(subquery))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_with(&query, values).execute(con).await?;
        Ok(())
    }

    /// Check if a directory exists.
    /// Path is the path to the folder.
    pub async fn contains_directory<'a>(
        path: &EntryPath,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<bool, sqlx::Error> {
        let mut full_path = path.path().to_string();
        if !full_path.ends_with("/") {
            // Make sure the path is a folder
            full_path.push('/');
        }

        let statement = Query::select()
            .from(ENTRY_TABLE)
            .expr(Expr::col((ENTRY_TABLE, EntryIden::Id)).count())
            .left_join(
                USER_TABLE,
                Expr::col((ENTRY_TABLE, EntryIden::User)).eq(Expr::col((USER_TABLE, UserIden::Id))),
            )
            .and_where(Expr::col((ENTRY_TABLE, EntryIden::Path)).like(format!("{}%", full_path))) // Everything that starts with the path
            .and_where(Expr::col((USER_TABLE, UserIden::PublicKey)).eq(path.pubkey().z32()))
            .limit(1)
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let count: i64 = sqlx::query_scalar_with(&query, values)
            .fetch_one(con)
            .await?;

        Ok(count > 0)
    }

    /// Check if writing `path` would make an exact file path collide with an
    /// implicit folder path for the same user.
    pub async fn has_file_folder_collision<'a>(
        path: &EntryPath,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<bool, sqlx::Error> {
        let path_str = path.path().as_str();
        let descendant_prefix = if path_str.ends_with('/') {
            path_str.to_string()
        } else {
            format!("{path_str}/")
        };
        let mut ancestor_paths = Self::ancestor_file_paths(path_str);
        // If the path ends with a trailing slash (a directory-style path),
        // also reject.
        if let Some(without_trailing_slash) = path_str.strip_suffix('/') {
            if !without_trailing_slash.is_empty() {
                ancestor_paths.push(without_trailing_slash.to_string());
            }
        }

        // Reject both collision directions for the same user:
        // - existing descendants under `path/`
        // - existing exact-file ancestors of `path`
        let con = executor.get_con().await?;
        sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM entries
                JOIN users
                  ON users.id = entries."user"
                WHERE users.public_key = $1
                  AND (
                    (
                      entries.path <> $3
                      AND substr(entries.path, 1, length($2)) = $2
                    )
                    OR entries.path = ANY($4::text[])
                  )
            )
            "#,
        )
        .bind(path.pubkey().z32())
        .bind(descendant_prefix)
        .bind(path_str)
        .bind(ancestor_paths)
        .fetch_one(con)
        .await
    }

    fn ancestor_file_paths(path: &str) -> Vec<String> {
        let mut path = path.trim_end_matches('/');
        if path.is_empty() {
            return Vec::new();
        }

        let mut paths = Vec::new();
        while let Some((parent, _)) = path.rsplit_once('/') {
            if parent.is_empty() {
                break;
            }
            paths.push(parent.to_string());
            path = parent;
        }
        paths
    }

    /// List shallow files + folders.
    /// Path is the path to the folder.
    /// Limit is the maximum number of entries to return.
    /// Cursor is path of the entry to start from. Set it to None to start from the beginning.
    pub async fn list_shallow<'a>(
        path: &EntryPath,
        limit: Option<u16>,
        cursor: Option<EntryPath>,
        reverse: bool,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Vec<EntryPath>, sqlx::Error> {
        let mut dir_path = path.path().to_string();
        if !dir_path.ends_with("/") {
            // Make sure the path is a folder
            dir_path.push('/');
        }
        // Use this regex to get the distinct paths
        // ^(?'fixed_directory'\/test\/)(?'path_segment'[^\/]*)(?'opt_slash_indicating_dir'\/?)(?'rest_of_path'.*)$
        // DISTINCT ON makes sure that the same path is only returned once.
        let inner_statement = Query::select()
            .from(ENTRY_TABLE)
            .expr(Expr::cust_with_values(
                "DISTINCT ON (regpath) regexp_replace(entries.path, '^'||$1||'([^/]*)(\\/?)(.*)?$', $1||'\\1'||'\\2') as regpath",
                vec![sea_query::Value::from(dir_path.clone())],
            ))
            .left_join(
                USER_TABLE,
                Expr::col((ENTRY_TABLE, EntryIden::User)).eq(Expr::col((USER_TABLE, UserIden::Id))),
            )
            .and_where(Expr::col((ENTRY_TABLE, EntryIden::Path)).like(format!("{}%", dir_path))) // Everything that starts with the path
            .and_where(Expr::col((USER_TABLE, UserIden::PublicKey)).eq(path.pubkey().z32()))
            .to_owned();

        // Use a select in select to filter the previous regex regpath
        // to make the cursor and limit work.
        let mut outer_statement = Query::select()
            .expr(Expr::col("regpath"))
            .from_subquery(inner_statement, Alias::new("t"))
            .to_owned();

        if reverse {
            outer_statement = outer_statement
                .order_by_expr(Expr::cust("regpath COLLATE \"C\""), Order::Desc)
                .to_owned();
        } else {
            outer_statement = outer_statement
                .order_by_expr(Expr::cust("regpath COLLATE \"C\""), Order::Asc)
                .to_owned();
        }

        if let Some(cursor_entry_path) = cursor {
            if reverse {
                outer_statement = outer_statement
                    .and_where(Expr::cust_with_values(
                        "regpath COLLATE \"C\" < $1",
                        vec![sea_query::Value::from(cursor_entry_path.path().as_str())],
                    ))
                    .to_owned();
            } else {
                outer_statement = outer_statement
                    .and_where(Expr::cust_with_values(
                        "regpath COLLATE \"C\" > $1",
                        vec![sea_query::Value::from(cursor_entry_path.path().as_str())],
                    ))
                    .to_owned();
            }
        }

        let limit = limit.unwrap_or(DEFAULT_LIST_LIMIT);
        let limit = limit.min(DEFAULT_MAX_LIST_LIMIT);
        outer_statement = outer_statement.limit(limit.into()).to_owned();

        let (query, values) = outer_statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let rows: Vec<PgRow> = sqlx::query_with(&query, values).fetch_all(con).await?;

        let entries = rows
            .iter()
            .map(|row| {
                let user_pubkey = path.pubkey().clone();
                let regpath: String = row.try_get("regpath")?;
                let storage_path =
                    StoragePath::new(&regpath).map_err(|e| sqlx::Error::Decode(e.into()))?;
                let entry_path = EntryPath::new(user_pubkey, storage_path);
                Ok(entry_path)
            })
            .collect::<Result<Vec<EntryPath>, sqlx::Error>>()?;

        Ok(entries)
    }

    /// List deep files + folders.
    /// Path is the path to the folder.
    /// Limit is the maximum number of entries to return.
    /// Cursor is the id of the entry to start from (non-inclusive). Set it to None to start from the beginning.
    pub async fn list_deep<'a>(
        path: &EntryPath,
        limit: Option<u16>,
        cursor: Option<EntryPath>,
        reverse: bool,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Vec<EntryPath>, sqlx::Error> {
        let mut full_path = path.path().to_string();
        if !full_path.ends_with("/") {
            // Make sure the path is a folder
            full_path.push('/');
        }

        // let cursor_id = EntryRepository::get_cursor_id_deep(cursor, executor).await?;
        let mut statement = Query::select()
            .from(ENTRY_TABLE)
            .columns([(ENTRY_TABLE, EntryIden::Path)])
            .left_join(
                USER_TABLE,
                Expr::col((ENTRY_TABLE, EntryIden::User)).eq(Expr::col((USER_TABLE, UserIden::Id))),
            )
            .and_where(Expr::col((ENTRY_TABLE, EntryIden::Path)).like(format!("{}%", full_path))) // Everything that starts with the path
            .and_where(Expr::col((USER_TABLE, UserIden::PublicKey)).eq(path.pubkey().z32()))
            .to_owned();

        if reverse {
            statement = statement
                .order_by_expr(Expr::cust("entries.path COLLATE \"C\""), Order::Desc)
                .to_owned();
        } else {
            statement = statement
                .order_by_expr(Expr::cust("entries.path COLLATE \"C\""), Order::Asc)
                .to_owned();
        }

        if let Some(cursor) = cursor {
            if reverse {
                statement = statement
                    .and_where(Expr::cust_with_values(
                        "entries.path COLLATE \"C\" < $1",
                        vec![sea_query::Value::from(cursor.path().as_str())],
                    ))
                    .to_owned();
            } else {
                statement = statement
                    .and_where(Expr::cust_with_values(
                        "entries.path COLLATE \"C\" > $1",
                        vec![sea_query::Value::from(cursor.path().as_str())],
                    ))
                    .to_owned();
            }
        }

        let limit = limit.unwrap_or(DEFAULT_LIST_LIMIT);
        let limit = limit.min(DEFAULT_MAX_LIST_LIMIT);
        statement = statement.limit(limit.into()).to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let rows: Vec<PgRow> = sqlx::query_with(&query, values).fetch_all(con).await?;

        let entries = rows
            .iter()
            .map(|row| {
                let user_pubkey = path.pubkey().clone();
                let path: String = row.try_get(EntryIden::Path.to_string().as_str())?;
                let storage_path =
                    StoragePath::new(&path).map_err(|e| sqlx::Error::Decode(e.into()))?;
                let entry_path = EntryPath::new(user_pubkey, storage_path);
                Ok(entry_path)
            })
            .collect::<Result<Vec<EntryPath>, sqlx::Error>>()?;

        Ok(entries)
    }
}

#[derive(Iden)]
pub enum EntryIden {
    Id,
    Path,
    User,
    ContentHash,
    ContentLength,
    ContentType,
    ModifiedAt,
    CreatedAt,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::{entities::user::UserRepository, SqlDb};
    use pubky_common::crypto::Keypair;
    use std::collections::HashSet;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_get_and_delete_entry_by_path() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();

        // Test create user
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

        // Test create entry
        let entry_id = EntryRepository::create(
            user.id,
            &StoragePath::new("/test").unwrap(),
            &pubky_common::crypto::Hash::from_bytes([0; 32]),
            100,
            "text/plain",
            &mut db.pool().into(),
        )
        .await
        .unwrap();

        // Test get entry by path
        let entry_path = EntryPath::new(user_pubkey.clone(), StoragePath::new("/test").unwrap());
        let entry = EntryRepository::get_by_path(&entry_path, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(entry.id, entry_id);
        assert_eq!(entry.user_id, user.id);
        assert_eq!(entry.path, entry_path);
        assert_eq!(entry.content_hash, [0; 32]);
        assert_eq!(entry.content_length, 100);
        assert_eq!(entry.content_type, "text/plain");

        // test delete
        EntryRepository::delete_by_path(&entry.path, &mut db.pool().into())
            .await
            .unwrap();
        EntryRepository::get_by_path(&entry.path, &mut db.pool().into())
            .await
            .expect_err("Entry should be deleted");
    }

    async fn create_entry_for_path(db: &SqlDb, user_id: i32, path: &str) {
        EntryRepository::create(
            user_id,
            &StoragePath::new(path).unwrap(),
            &pubky_common::crypto::Hash::from_bytes([0; 32]),
            100,
            "text/plain",
            &mut db.pool().into(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_file_folder_collision_when_descendant_exists() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();
        create_entry_for_path(&db, user.id, "/test/sub1/1.txt").await;

        let target = EntryPath::new(user_pubkey, StoragePath::new("/test/sub1").unwrap());
        let has_collision =
            EntryRepository::has_file_folder_collision(&target, &mut db.pool().into())
                .await
                .unwrap();

        assert!(has_collision);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_file_folder_collision_when_ancestor_file_exists() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();
        create_entry_for_path(&db, user.id, "/test/sub1").await;

        let target = EntryPath::new(user_pubkey, StoragePath::new("/test/sub1/1.txt").unwrap());
        let has_collision =
            EntryRepository::has_file_folder_collision(&target, &mut db.pool().into())
                .await
                .unwrap();

        assert!(has_collision);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_file_folder_collision_when_writing_directory_over_existing_file() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();
        create_entry_for_path(&db, user.id, "/test/sub1").await;

        // Directory-style target (trailing slash) over an existing exact file.
        let target = EntryPath::new(user_pubkey, StoragePath::new("/test/sub1/").unwrap());
        let has_collision =
            EntryRepository::has_file_folder_collision(&target, &mut db.pool().into())
                .await
                .unwrap();

        assert!(has_collision);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_file_folder_collision_allows_exact_overwrite() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();
        create_entry_for_path(&db, user.id, "/test/sub1").await;

        let target = EntryPath::new(user_pubkey, StoragePath::new("/test/sub1").unwrap());
        let has_collision =
            EntryRepository::has_file_folder_collision(&target, &mut db.pool().into())
                .await
                .unwrap();

        assert!(!has_collision);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_file_folder_collision_does_not_match_siblings() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();
        create_entry_for_path(&db, user.id, "/test/sub11/file.txt").await;

        let target = EntryPath::new(user_pubkey, StoragePath::new("/test/sub1").unwrap());
        let has_collision =
            EntryRepository::has_file_folder_collision(&target, &mut db.pool().into())
                .await
                .unwrap();

        assert!(!has_collision);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_file_folder_collision_is_scoped_to_user() {
        let db = SqlDb::test().await;
        let user_a_pubkey = Keypair::random().public_key();
        let user_a = UserRepository::create(&user_a_pubkey, &mut db.pool().into())
            .await
            .unwrap();
        let user_b_pubkey = Keypair::random().public_key();
        UserRepository::create(&user_b_pubkey, &mut db.pool().into())
            .await
            .unwrap();
        create_entry_for_path(&db, user_a.id, "/test/sub1").await;

        let target = EntryPath::new(user_b_pubkey, StoragePath::new("/test/sub1/1.txt").unwrap());
        let has_collision =
            EntryRepository::has_file_folder_collision(&target, &mut db.pool().into())
                .await
                .unwrap();

        assert!(!has_collision);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_shallow() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();

        // Test create user
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();
        // Test create entries
        let paths = vec![
            "/test/1.txt",
            "/test/2.txt",
            "/test/3.txt",
            "/test/sub1",
            "/test/sub1/1/1.txt",
            "/test/sub1/2.txt",
            "/test/sub2/1.txt",
            "/test/sub2/2.txt",
        ];
        for path in paths {
            EntryRepository::create(
                user.id,
                &StoragePath::new(path).unwrap(),
                &pubky_common::crypto::Hash::from_bytes([0; 32]),
                100,
                "text/plain",
                &mut db.pool().into(),
            )
            .await
            .unwrap();
        }

        // Test list shallow basic
        let entry_path = EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/").unwrap());
        let entries =
            EntryRepository::list_shallow(&entry_path, None, None, false, &mut db.pool().into())
                .await
                .unwrap();
        assert_eq!(entries.len(), 6);
        assert_eq!(
            entries[0],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/1.txt").unwrap()
            )
        );
        assert_eq!(
            entries[1],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/2.txt").unwrap()
            )
        );
        assert_eq!(
            entries[2],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/3.txt").unwrap()
            )
        );
        assert_eq!(
            entries[3],
            EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/sub1").unwrap())
        );
        assert_eq!(
            entries[4],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub1/").unwrap()
            )
        );
        assert_eq!(
            entries[5],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub2/").unwrap()
            )
        );

        // Test list shallow with limit
        let entries =
            EntryRepository::list_shallow(&entry_path, Some(2), None, false, &mut db.pool().into())
                .await
                .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/1.txt").unwrap()
            )
        );
        assert_eq!(
            entries[1],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/2.txt").unwrap()
            )
        );

        // Test list shallow with cursor
        let entries = EntryRepository::list_shallow(
            &entry_path,
            None,
            Some(EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/3.txt").unwrap(),
            )),
            false,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0],
            EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/sub1").unwrap())
        );
        assert_eq!(
            entries[1],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub1/").unwrap()
            )
        );
        assert_eq!(
            entries[2],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub2/").unwrap()
            )
        );

        // Test list shallow with limit and cursor
        let entries = EntryRepository::list_shallow(
            &entry_path,
            Some(2),
            Some(EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/3.txt").unwrap(),
            )),
            false,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/sub1").unwrap())
        );
        assert_eq!(
            entries[1],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub1/").unwrap()
            )
        );

        // Test list shallow with limit. Pull all entries.
        let mut set: HashSet<EntryPath> = HashSet::new();
        let mut last_cursor: Option<EntryPath> = None;
        let mut count = 0;
        loop {
            count += 1;
            let new_entries = EntryRepository::list_shallow(
                &entry_path,
                Some(2),
                last_cursor,
                false,
                &mut db.pool().into(),
            )
            .await
            .unwrap();
            if let Some(last_entry) = new_entries.last() {
                last_cursor = Some(last_entry.clone());
            } else {
                break;
            }
            for entry in new_entries {
                set.insert(entry);
            }
            if count > 10 {
                panic!("Too many loops to pull all entries");
            }
        }
        assert_eq!(set.len(), 6);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_shallow_reverse() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();

        // Test create user
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();
        // Test create entries
        let paths = vec![
            "/test/1.txt",
            "/test/2.txt",
            "/test/3.txt",
            "/test/sub1",
            "/test/sub1/1/1.txt",
            "/test/sub1/2.txt",
            "/test/sub2/1.txt",
            "/test/sub2/2.txt",
        ];
        for path in paths {
            EntryRepository::create(
                user.id,
                &StoragePath::new(path).unwrap(),
                &pubky_common::crypto::Hash::from_bytes([0; 32]),
                100,
                "text/plain",
                &mut db.pool().into(),
            )
            .await
            .unwrap();
        }

        // Regular order aka reverse false
        let entry_path = EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/").unwrap());
        let entries =
            EntryRepository::list_shallow(&entry_path, None, None, false, &mut db.pool().into())
                .await
                .unwrap();
        assert_eq!(entries.len(), 6);
        assert_eq!(
            entries[0],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/1.txt").unwrap()
            )
        );
        assert_eq!(
            entries[1],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/2.txt").unwrap()
            )
        );
        assert_eq!(
            entries[2],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/3.txt").unwrap()
            )
        );
        assert_eq!(
            entries[3],
            EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/sub1").unwrap())
        );
        assert_eq!(
            entries[4],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub1/").unwrap()
            )
        );
        assert_eq!(
            entries[5],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub2/").unwrap()
            )
        );

        // Reverse order aka reverse true
        let entry_path = EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/").unwrap());
        let entries =
            EntryRepository::list_shallow(&entry_path, None, None, true, &mut db.pool().into())
                .await
                .unwrap();
        assert_eq!(entries.len(), 6);
        assert_eq!(
            entries[5],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/1.txt").unwrap()
            )
        );
        assert_eq!(
            entries[4],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/2.txt").unwrap()
            )
        );
        assert_eq!(
            entries[3],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/3.txt").unwrap()
            )
        );
        assert_eq!(
            entries[2],
            EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/sub1").unwrap())
        );
        assert_eq!(
            entries[1],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub1/").unwrap()
            )
        );
        assert_eq!(
            entries[0],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub2/").unwrap()
            )
        );

        // Reverse order aka reverse true with cursor
        let cursor = EntryPath::new(
            user_pubkey.clone(),
            StoragePath::new("/test/3.txt").unwrap(),
        );
        let entry_path = EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/").unwrap());
        let entries = EntryRepository::list_shallow(
            &entry_path,
            None,
            Some(cursor),
            true,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[1],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/1.txt").unwrap()
            )
        );
        assert_eq!(
            entries[0],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/2.txt").unwrap()
            )
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_deep() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();

        // Test create user
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();
        // Test create entries
        let paths = vec![
            "/test/1.txt",
            "/test/2.txt",
            "/test/3.txt",
            "/test/sub1/1/1.txt",
            "/test/sub1/2.txt",
            "/test/sub2/1.txt",
            "/test/sub2/2.txt",
        ];
        for path in paths {
            EntryRepository::create(
                user.id,
                &StoragePath::new(path).unwrap(),
                &pubky_common::crypto::Hash::from_bytes([0; 32]),
                100,
                "text/plain",
                &mut db.pool().into(),
            )
            .await
            .unwrap();
        }

        // Test basic
        let entry_path = EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/").unwrap());
        let entries =
            EntryRepository::list_deep(&entry_path, None, None, false, &mut db.pool().into())
                .await
                .unwrap();
        assert_eq!(entries.len(), 7);

        // Test with limit
        let entries =
            EntryRepository::list_shallow(&entry_path, Some(2), None, false, &mut db.pool().into())
                .await
                .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/1.txt").unwrap()
            )
        );
        assert_eq!(
            entries[1],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/2.txt").unwrap()
            )
        );

        // Test with cursor
        let entries = EntryRepository::list_deep(
            &entry_path,
            None,
            Some(EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/3.txt").unwrap(),
            )),
            false,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(
            entries[0],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub1/1/1.txt").unwrap()
            )
        );
        assert_eq!(
            entries[1],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub1/2.txt").unwrap()
            )
        );
        assert_eq!(
            entries[2],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub2/1.txt").unwrap()
            )
        );
        assert_eq!(
            entries[3],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub2/2.txt").unwrap()
            )
        );

        // Test with limit and cursor
        let entries = EntryRepository::list_deep(
            &entry_path,
            Some(2),
            Some(EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/3.txt").unwrap(),
            )),
            false,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub1/1/1.txt").unwrap()
            )
        );
        assert_eq!(
            entries[1],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub1/2.txt").unwrap()
            )
        );

        // Test with limit. Pull all entries.
        let mut set: HashSet<EntryPath> = HashSet::new();
        let mut last_cursor: Option<EntryPath> = None;
        loop {
            let new_entries = EntryRepository::list_deep(
                &entry_path,
                Some(2),
                last_cursor.clone(),
                false,
                &mut db.pool().into(),
            )
            .await
            .unwrap();
            if let Some(last_entry) = new_entries.last() {
                last_cursor = Some(last_entry.clone());
            } else {
                break;
            }
            for entry in new_entries {
                set.insert(entry);
            }
        }
        assert_eq!(set.len(), 7);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_deep_reverse() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();

        // Test create user
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();
        // Test create entries
        let paths = vec![
            "/test/1.txt",
            "/test/2.txt",
            "/test/3.txt",
            "/test/sub1/1/1.txt",
            "/test/sub1/2.txt",
            "/test/sub2/1.txt",
            "/test/sub2/2.txt",
        ];
        for path in paths {
            EntryRepository::create(
                user.id,
                &StoragePath::new(path).unwrap(),
                &pubky_common::crypto::Hash::from_bytes([0; 32]),
                100,
                "text/plain",
                &mut db.pool().into(),
            )
            .await
            .unwrap();
        }

        // Reverse order aka reverse true
        let entry_path = EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/").unwrap());
        let entries =
            EntryRepository::list_deep(&entry_path, None, None, true, &mut db.pool().into())
                .await
                .unwrap();
        assert_eq!(entries.len(), 7);
        assert_eq!(
            entries[0],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub2/2.txt").unwrap()
            )
        );
        assert_eq!(
            entries[1],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub2/1.txt").unwrap()
            )
        );
        assert_eq!(
            entries[2],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub1/2.txt").unwrap()
            )
        );
        assert_eq!(
            entries[3],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/sub1/1/1.txt").unwrap()
            )
        );
        assert_eq!(
            entries[4],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/3.txt").unwrap()
            )
        );
        assert_eq!(
            entries[5],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/2.txt").unwrap()
            )
        );
        assert_eq!(
            entries[6],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/1.txt").unwrap()
            )
        );

        // Reverse order aka reverse true with cursor
        let entry_path = EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/").unwrap());
        let cursor = EntryPath::new(
            user_pubkey.clone(),
            StoragePath::new("/test/3.txt").unwrap(),
        );
        let entries = EntryRepository::list_deep(
            &entry_path,
            None,
            Some(cursor),
            true,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/2.txt").unwrap()
            )
        );
        assert_eq!(
            entries[1],
            EntryPath::new(
                user_pubkey.clone(),
                StoragePath::new("/test/1.txt").unwrap()
            )
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_contains_directory() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();

        // Test create user
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

        // Test directory that doesn't exist
        let exists = EntryRepository::contains_directory(
            &EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/").unwrap()),
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert!(!exists);

        // Test if directory exists
        EntryRepository::create(
            user.id,
            &StoragePath::new("/test/file.txt").unwrap(),
            &pubky_common::crypto::Hash::from_bytes([0; 32]),
            100,
            "text/plain",
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        let exists = EntryRepository::contains_directory(
            &EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/").unwrap()),
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert!(exists);

        // Test if directory doesn't exist but file does
        EntryRepository::create(
            user.id,
            &StoragePath::new("/test/sub1").unwrap(),
            &pubky_common::crypto::Hash::from_bytes([0; 32]),
            100,
            "text/plain",
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        let exists = EntryRepository::contains_directory(
            &EntryPath::new(user_pubkey.clone(), StoragePath::new("/test/sub1").unwrap()),
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert!(!exists);
    }
}
