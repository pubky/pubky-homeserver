use pubky_common::events::{EventCursor, EventType};
use pubky_common::timestamp::Timestamp;
use sea_query::{Condition, Expr, Iden, Order, PostgresQueryBuilder, Query, SimpleExpr};
use sea_query_binder::SqlxBinder;
use sqlx::{
    postgres::PgRow,
    types::chrono::{DateTime, Utc},
    Row,
};

use crate::{
    constants::{DEFAULT_LIST_LIMIT, DEFAULT_MAX_LIST_LIMIT, PUBLIC_ROOT},
    persistence::{
        files::events::EventEntity,
        sql::{
            user::{UserIden, USER_TABLE},
            UnifiedExecutor,
        },
    },
    shared::{timestamp_to_sqlx_datetime, webdav::EntryPath},
};

use super::PathFilter;

pub const EVENT_TABLE: &str = "events";

/// Selects which events a cursor query returns, by storage-root visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventVisibility {
    /// Only public (`/pub/...`) events.
    Public,
    /// All events, includes `/priv/...` events.
    All,
}

/// Repository that handles all the queries regarding the EventEntity.
pub struct EventRepository;

impl EventRepository {
    /// Advisory lock ID used to serialize event inserts.
    /// Ensures auto-increment IDs are always committed in order.
    const EVENT_INSERT_LOCK_ID: i64 = 0x6576656e_74730000; // "events"

    /// Get the maximum event ID in the database.
    /// Returns 0 if no events exist.
    pub async fn get_max_id<'a>(executor: &mut UnifiedExecutor<'a>) -> Result<u64, sqlx::Error> {
        let (query, values) = Query::select()
            .expr(Expr::col((EVENT_TABLE, EventIden::Id)).max())
            .from(EVENT_TABLE)
            .build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let row: PgRow = sqlx::query_with(&query, values).fetch_one(con).await?;
        let max_id: Option<i64> = row.try_get(0)?;
        let max_id = max_id.unwrap_or(0);
        Ok(u64::try_from(max_id).unwrap_or(0))
    }

    /// Create a new event.
    /// The executor can either be db.pool() or a transaction.
    pub async fn create<'a>(
        user_id: i32,
        event_type: EventType,
        path: &EntryPath,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<EventEntity, sqlx::Error> {
        Self::create_with_timestamp(user_id, event_type, path, &Utc::now(), executor).await
    }

    /// Create a new event with a specific timestamp.
    /// The executor can either be db.pool() or a transaction.
    pub async fn create_with_timestamp<'a>(
        user_id: i32,
        event_type: EventType,
        path: &EntryPath,
        created_at: &DateTime<Utc>,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<EventEntity, sqlx::Error> {
        let mut columns = vec![
            EventIden::Type,
            EventIden::User,
            EventIden::Path,
            EventIden::CreatedAt,
        ];
        let mut values = vec![
            SimpleExpr::Value(event_type.to_string().into()),
            SimpleExpr::Value(user_id.into()),
            SimpleExpr::Value(path.path().as_str().into()),
            SimpleExpr::Value(created_at.naive_utc().into()),
        ];

        if let Some(hash) = event_type.content_hash() {
            columns.push(EventIden::ContentHash);
            values.push(SimpleExpr::Value(hash.as_bytes().to_vec().into()));
        }

        let statement = Query::insert()
            .into_table(EVENT_TABLE)
            .columns(columns)
            .values(values)
            .expect("Failed to build insert statement")
            .returning_col(EventIden::Id)
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);

        let con = executor.get_con().await?;

        // Serialize event creation so that auto-increment IDs are committed in
        // order. Without this, concurrent transactions can commit out of sequence
        // order, creating a window where a later ID is visible before an earlier
        // one, causing the poll-based event broadcaster to skip events.
        // The lock is transaction-scoped and auto-releases on commit/rollback.
        // In autocommit mode (bare pool connection) the lock is harmless: the
        // implicit transaction covers the entire statement, so there is no
        // interleaving window to begin with.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(Self::EVENT_INSERT_LOCK_ID)
            .execute(&mut *con)
            .await?;
        let ret_row: PgRow = sqlx::query_with(&query, values).fetch_one(con).await?;
        let event_id: i64 = ret_row.try_get(EventIden::Id.to_string().as_str())?;
        Ok(EventEntity {
            id: event_id as u64,
            user_id,
            user_pubkey: path.pubkey().clone(),
            event_type,
            path: path.clone(),
            created_at: created_at.naive_utc(),
        })
    }

    /// Parse the cursor to a Cursor.
    /// The cursor can be either a new cursor format or a legacy cursor format.
    /// The new cursor format is the ID of the last event - a u64.
    /// The legacy cursor format is a timestamp.
    /// If you don't want to use the cursor, set it to "0".
    pub async fn parse_cursor<'a>(
        cursor: &str,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<EventCursor, sqlx::Error> {
        if let Ok(cursor) = cursor.parse::<EventCursor>() {
            // Is new cursor format
            return Ok(cursor);
        }
        // Check for the legacy cursor format
        let timestamp: Timestamp = match cursor.to_string().try_into() {
            Ok(timestamp) => timestamp,
            Err(e) => return Err(sqlx::Error::Decode(e.into())),
        };

        // Check the timestamp with the database to convert it to the event id
        let datetime = timestamp_to_sqlx_datetime(&timestamp);
        let statement = Query::select()
            .column((EVENT_TABLE, EventIden::Id))
            .from(EVENT_TABLE)
            .and_where(Expr::col((EVENT_TABLE, EventIden::CreatedAt)).eq(datetime))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let ret_row: PgRow = sqlx::query_with(&query, values).fetch_one(con).await?;
        let event_id: i64 = ret_row.try_get(EventIden::Id.to_string().as_str())?;
        Ok(EventCursor::new(event_id as u64))
    }

    /// Get a list of events with per-user cursors.
    /// The limit is the maximum total number of events to return across all users.
    /// The executor can either be db.pool() or a transaction.
    pub async fn get_by_user_cursors<'a>(
        user_cursors: Vec<(i32, Option<EventCursor>)>,
        reverse: bool,
        allowed_paths: &[PathFilter],
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Vec<EventEntity>, sqlx::Error> {
        if user_cursors.is_empty() {
            return Ok(Vec::new());
        }

        // Build a UNION query for each user with their individual cursor
        // This ensures we get events after each user's last seen position
        let order = if reverse {
            sea_query::Order::Desc
        } else {
            sea_query::Order::Asc
        };

        let mut union_queries = Vec::new();

        for (user_id, cursor) in user_cursors {
            let mut statement = Query::select()
                .columns([
                    (EVENT_TABLE, EventIden::Id),
                    (EVENT_TABLE, EventIden::User),
                    (EVENT_TABLE, EventIden::Type),
                    (EVENT_TABLE, EventIden::Path),
                    (EVENT_TABLE, EventIden::CreatedAt),
                    (EVENT_TABLE, EventIden::ContentHash),
                ])
                .column((USER_TABLE, UserIden::PublicKey))
                .from(EVENT_TABLE)
                .left_join(
                    USER_TABLE,
                    Expr::col((EVENT_TABLE, EventIden::User))
                        .eq(Expr::col((USER_TABLE, UserIden::Id))),
                )
                .and_where(Expr::col((EVENT_TABLE, EventIden::User)).eq(user_id))
                .to_owned();

            // Restrict results to events whose path matches at least one
            // authorized path. The list is non-empty in practice (the route
            // defaults to `/pub/`), an empty list applies no path restriction.
            // Paths are stored without the user pubkey prefix
            // (e.g. "/pub/files/doc.txt").
            if !allowed_paths.is_empty() {
                let mut path_condition = Condition::any();
                for filter in allowed_paths {
                    path_condition = path_condition.add(filter.to_condition());
                }
                statement = statement.cond_where(path_condition).to_owned();
            }

            if let Some(cursor) = cursor {
                if reverse {
                    statement = statement
                        .and_where(Expr::col((EVENT_TABLE, EventIden::Id)).lt(cursor.id()))
                        .to_owned();
                } else {
                    statement = statement
                        .and_where(Expr::col((EVENT_TABLE, EventIden::Id)).gt(cursor.id()))
                        .to_owned();
                }
            }

            union_queries.push(statement);
        }

        // Combine all user queries with UNION ALL and wrap in subquery
        let mut combined_query = union_queries[0].clone();
        for query in union_queries.iter().skip(1) {
            combined_query = combined_query
                .union(sea_query::UnionType::All, query.clone())
                .to_owned();
        }

        // Wrap the UNION in a subquery and apply ordering and limit
        // This is necessary because we can't order UNION results directly
        let subquery_alias = sea_query::Alias::new("union_result");
        combined_query = Query::select()
            .from_subquery(combined_query, subquery_alias.clone())
            .column((subquery_alias.clone(), EventIden::Id))
            .column((subquery_alias.clone(), EventIden::User))
            .column((subquery_alias.clone(), EventIden::Type))
            .column((subquery_alias.clone(), EventIden::Path))
            .column((subquery_alias.clone(), EventIden::CreatedAt))
            .column((subquery_alias.clone(), EventIden::ContentHash))
            .column((subquery_alias.clone(), UserIden::PublicKey))
            .order_by((subquery_alias, EventIden::Id), order)
            .limit(DEFAULT_LIST_LIMIT as u64)
            .to_owned();

        let (query, values) = combined_query.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let events: Vec<EventEntity> = sqlx::query_as_with(&query, values).fetch_all(con).await?;
        Ok(events)
    }

    /// Get a list of events by the cursor.
    /// The limit is the maximum number of events to return.
    /// `visibility` selects which storage roots are returned (see [`EventVisibility`]).
    /// The executor can either be db.pool() or a transaction.
    pub async fn get_by_cursor<'a>(
        cursor: Option<EventCursor>,
        limit: Option<u16>,
        visibility: EventVisibility,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Vec<EventEntity>, sqlx::Error> {
        let cursor = cursor.unwrap_or(EventCursor::new(0));
        let limit = limit.unwrap_or(DEFAULT_LIST_LIMIT);
        let limit = limit.min(DEFAULT_MAX_LIST_LIMIT);

        let mut statement = Query::select()
            .columns([
                (EVENT_TABLE, EventIden::Id),
                (EVENT_TABLE, EventIden::User),
                (EVENT_TABLE, EventIden::Type),
                (EVENT_TABLE, EventIden::Path),
                (EVENT_TABLE, EventIden::CreatedAt),
                (EVENT_TABLE, EventIden::ContentHash),
            ])
            .column((USER_TABLE, UserIden::PublicKey))
            .from(EVENT_TABLE)
            .left_join(
                USER_TABLE,
                Expr::col((EVENT_TABLE, EventIden::User)).eq(Expr::col((USER_TABLE, UserIden::Id))),
            )
            .and_where(Expr::col((EVENT_TABLE, EventIden::Id)).gt(cursor.id()))
            .order_by((EVENT_TABLE, EventIden::Id), Order::Asc)
            .limit(limit as u64)
            .to_owned();

        // `All` adds no predicate; `Public` restricts to the public root.
        if let EventVisibility::Public = visibility {
            statement = statement
                .and_where(
                    Expr::col((EVENT_TABLE, EventIden::Path)).like(format!("{PUBLIC_ROOT}%")),
                )
                .to_owned();
        }

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let events: Vec<EventEntity> = sqlx::query_as_with(&query, values).fetch_all(con).await?;
        Ok(events)
    }

    /// Get **all** events (public and private) by a single global cursor, with optional reverse,
    /// path, and user-id filters. `path_filters` is a union — an event is returned if it matches
    /// **any** of them (empty = no path restriction); each uses [`PathFilter`] file-vs-directory
    /// matching. Backs the admin events stream.
    pub async fn get_all_filtered_by_cursor<'a>(
        cursor: Option<EventCursor>,
        limit: Option<u16>,
        reverse: bool,
        path_filters: &[PathFilter],
        user_ids: Option<&[i32]>,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Vec<EventEntity>, sqlx::Error> {
        // An explicit empty user filter matches nothing; short-circuit before querying.
        if matches!(user_ids, Some(ids) if ids.is_empty()) {
            return Ok(Vec::new());
        }

        let limit = limit
            .unwrap_or(DEFAULT_LIST_LIMIT)
            .min(DEFAULT_MAX_LIST_LIMIT);
        let order = if reverse { Order::Desc } else { Order::Asc };

        let mut statement = Query::select()
            .columns([
                (EVENT_TABLE, EventIden::Id),
                (EVENT_TABLE, EventIden::User),
                (EVENT_TABLE, EventIden::Type),
                (EVENT_TABLE, EventIden::Path),
                (EVENT_TABLE, EventIden::CreatedAt),
                (EVENT_TABLE, EventIden::ContentHash),
            ])
            .column((USER_TABLE, UserIden::PublicKey))
            .from(EVENT_TABLE)
            .left_join(
                USER_TABLE,
                Expr::col((EVENT_TABLE, EventIden::User)).eq(Expr::col((USER_TABLE, UserIden::Id))),
            )
            .order_by((EVENT_TABLE, EventIden::Id), order)
            .limit(limit as u64)
            .to_owned();

        if let Some(cursor) = cursor {
            let id_col = Expr::col((EVENT_TABLE, EventIden::Id));
            statement = statement
                .and_where(if reverse {
                    id_col.lt(cursor.id())
                } else {
                    id_col.gt(cursor.id())
                })
                .to_owned();
        }

        // Union of path filters: an event matches if it satisfies ANY of them.
        if !path_filters.is_empty() {
            let mut path_condition = Condition::any();
            for filter in path_filters {
                path_condition = path_condition.add(filter.to_condition());
            }
            statement = statement.cond_where(path_condition).to_owned();
        }

        if let Some(ids) = user_ids {
            statement = statement
                .and_where(Expr::col((EVENT_TABLE, EventIden::User)).is_in(ids.iter().copied()))
                .to_owned();
        }

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let events: Vec<EventEntity> = sqlx::query_as_with(&query, values).fetch_all(con).await?;
        Ok(events)
    }
}

#[derive(Iden)]
pub enum EventIden {
    Id,
    Type,
    User,
    Path,
    CreatedAt,
    ContentHash,
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::{Hash, Keypair};

    use crate::{
        persistence::sql::{user::UserRepository, SqlDb},
        shared::webdav::StoragePath,
    };

    use super::*;
    use std::ops::Add;

    fn pf(s: &str) -> PathFilter {
        StoragePath::new(s).unwrap().into()
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_list_event() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();

        // Create user
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

        // Create events
        for _ in 0..10 {
            let path = EntryPath::new(user_pubkey.clone(), StoragePath::new("/test").unwrap());
            let _ = EventRepository::create(
                user.id,
                EventType::Put {
                    content_hash: Hash::from_bytes([0; 32]),
                },
                &path,
                &mut db.pool().into(),
            )
            .await
            .unwrap();
        }

        // Test get events by cursor
        let events = EventRepository::get_by_cursor(
            Some(EventCursor::new(5)),
            Some(4),
            EventVisibility::All,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].id, 6);
        assert_eq!(events[0].user_id, user.id);
        assert_eq!(
            events[0].path,
            EntryPath::new(user_pubkey, StoragePath::new("/test").unwrap())
        );
        assert!(matches!(events[0].event_type, EventType::Put { .. }));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_by_cursor_public_visibility_excludes_private() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

        // Interleave public, private, and look-alike roots that must NOT match
        // the `/pub/` prefix (`/public/...` and `/pub` without a trailing slash).
        let paths = [
            "/pub/a",       // 1: public
            "/priv/x",      // 2: private  -> excluded
            "/pub/b",       // 3: public
            "/public/evil", // 4: not the public root -> excluded
            "/priv/y",      // 5: private  -> excluded
            "/pub/c",       // 6: public
            "/pub",         // 7: bare root, not under `/pub/` -> excluded
        ];
        for p in paths {
            let path = EntryPath::new(user_pubkey.clone(), StoragePath::new(p).unwrap());
            EventRepository::create(
                user.id,
                EventType::Put {
                    content_hash: Hash::from_bytes([0; 32]),
                },
                &path,
                &mut db.pool().into(),
            )
            .await
            .unwrap();
        }

        // Public-only view: only the three `/pub/<scope>/...` events.
        let public = EventRepository::get_by_cursor(
            None,
            None,
            EventVisibility::Public,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        let public_paths: Vec<&str> = public.iter().map(|e| e.path.path().as_str()).collect();
        assert_eq!(public_paths, vec!["/pub/a", "/pub/b", "/pub/c"]);

        // The internal all-events view is unchanged (regression guard for the
        // broadcaster / quota / admin callers).
        let all =
            EventRepository::get_by_cursor(None, None, EventVisibility::All, &mut db.pool().into())
                .await
                .unwrap();
        assert_eq!(all.len(), 7);

        // Pagination stays correct across filtered-out private events: a limit of
        // 2 returns a full page (ids 1 and 3) and the next cursor resumes after it.
        let page = EventRepository::get_by_cursor(
            None,
            Some(2),
            EventVisibility::Public,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert_eq!(page.iter().map(|e| e.id).collect::<Vec<_>>(), vec![1, 3]);
        let next = page.last().unwrap().cursor();
        let page = EventRepository::get_by_cursor(
            Some(next),
            Some(2),
            EventVisibility::Public,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert_eq!(page.iter().map(|e| e.id).collect::<Vec<_>>(), vec![6]);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_transform_legacy_cursor() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();

        // Create user
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

        let mut timestamp_events = Vec::new();
        // Create events with specific timestamps
        for i in 0..10 {
            let timestamp = Timestamp::now().add(1_000_000 * i); // Add 1s for each event
            let created_at = timestamp_to_sqlx_datetime(&timestamp);
            let path = EntryPath::new(user_pubkey.clone(), StoragePath::new("/test").unwrap());
            let event = EventRepository::create_with_timestamp(
                user.id,
                EventType::Put {
                    content_hash: Hash::from_bytes([0; 32]),
                },
                &path,
                &created_at,
                &mut db.pool().into(),
            )
            .await
            .unwrap();
            timestamp_events.push((timestamp, event.id));
        }

        // Test legacy cursor parsing
        for (timestamp, should_be_event_id) in timestamp_events {
            let cursor =
                EventRepository::parse_cursor(&timestamp.to_string(), &mut db.pool().into())
                    .await
                    .unwrap();
            assert_eq!(should_be_event_id, cursor.id());
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_parse_cursor_backwards_compatibility() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();

        // Create user
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

        // Create test events with specific timestamps
        let mut events = Vec::new();
        for i in 0..5 {
            let timestamp = Timestamp::now().add(1_000_000 * i); // Add 1s for each event
            let created_at = timestamp_to_sqlx_datetime(&timestamp);
            let path = EntryPath::new(user_pubkey.clone(), StoragePath::new("/test").unwrap());
            let event = EventRepository::create_with_timestamp(
                user.id,
                EventType::Put {
                    content_hash: Hash::from_bytes([0; 32]),
                },
                &path,
                &created_at,
                &mut db.pool().into(),
            )
            .await
            .unwrap();
            events.push((event, timestamp));
        }

        let test_event = &events[2].0; // Use the third event for testing
        let test_timestamp = &events[2].1;

        // Test 1: New format - just the id as string
        let new_format_cursor = test_event.id.to_string();
        let parsed_new = EventRepository::parse_cursor(&new_format_cursor, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(parsed_new, test_event.cursor());

        // Test 2: Legacy format - timestamp only
        let legacy_timestamp_format = test_timestamp.to_string();
        let parsed_timestamp =
            EventRepository::parse_cursor(&legacy_timestamp_format, &mut db.pool().into())
                .await
                .unwrap();
        assert_eq!(parsed_timestamp, test_event.cursor());

        // Test 3: Use parsed cursors in get_by_cursor to verify they work correctly
        for (cursor_str, test_name) in [
            (new_format_cursor, "new format"),
            (legacy_timestamp_format, "legacy timestamp"),
        ] {
            let cursor_id = EventRepository::parse_cursor(&cursor_str, &mut db.pool().into())
                .await
                .unwrap();

            let events_after = EventRepository::get_by_cursor(
                Some(cursor_id),
                None,
                EventVisibility::All,
                &mut db.pool().into(),
            )
            .await
            .unwrap();

            // Should get events after the cursor (events[3] and events[4])
            assert_eq!(
                events_after.len(),
                2,
                "Failed for cursor format: {}",
                test_name
            );
            assert_eq!(
                events_after[0].id, events[3].0.id,
                "Failed for cursor format: {}",
                test_name
            );
            assert_eq!(
                events_after[1].id, events[4].0.id,
                "Failed for cursor format: {}",
                test_name
            );
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_by_user_cursors_multi_path_union_and_boundaries() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

        // ids 1..=6
        let paths = [
            "/pub/a",           // 1 public
            "/priv/app/x",      // 2 under /priv/app/
            "/priv/app",        // 3 the file /priv/app itself
            "/priv/app-evil/y", // 4 sibling-prefix (must NOT match /priv/app/)
            "/priv/other/z",    // 5 other private scope
            "/pub/b",           // 6 public
        ];
        for p in paths {
            let path = EntryPath::new(user_pubkey.clone(), StoragePath::new(p).unwrap());
            EventRepository::create(
                user.id,
                EventType::Put {
                    content_hash: Hash::from_bytes([0; 32]),
                },
                &path,
                &mut db.pool().into(),
            )
            .await
            .unwrap();
        }

        // Union of `/pub/` (dir) and `/priv/app/` (dir): pub/a, priv/app/x,
        // pub/b. The dir filter must NOT match the parent file `/priv/app` nor
        // the sibling `/priv/app-evil/y`, and `/priv/other/z` is out of scope.
        let filters = vec![pf("/pub/"), pf("/priv/app/")];
        let events = EventRepository::get_by_user_cursors(
            vec![(user.id, None)],
            false,
            &filters,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        let got: Vec<&str> = events.iter().map(|e| e.path.path().as_str()).collect();
        assert_eq!(got, vec!["/pub/a", "/priv/app/x", "/pub/b"]);

        // A file filter matches only the exact file, not its would-be children.
        let filters = vec![pf("/priv/app")];
        let events = EventRepository::get_by_user_cursors(
            vec![(user.id, None)],
            false,
            &filters,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        let got: Vec<&str> = events.iter().map(|e| e.path.path().as_str()).collect();
        assert_eq!(got, vec!["/priv/app"]);

        // Reverse ordering over the `/pub/` filter.
        let filters = vec![pf("/pub/")];
        let events = EventRepository::get_by_user_cursors(
            vec![(user.id, None)],
            true,
            &filters,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        let got: Vec<&str> = events.iter().map(|e| e.path.path().as_str()).collect();
        assert_eq!(got, vec!["/pub/b", "/pub/a"]);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_by_user_cursors_escapes_like_metacharacters() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

        for p in ["/priv/a_b/x", "/priv/axb/y", "/priv/a%/m", "/priv/apct/n"] {
            let path = EntryPath::new(user_pubkey.clone(), StoragePath::new(p).unwrap());
            EventRepository::create(
                user.id,
                EventType::Put {
                    content_hash: Hash::from_bytes([0; 32]),
                },
                &path,
                &mut db.pool().into(),
            )
            .await
            .unwrap();
        }

        // `_` must be matched literally: `/priv/a_b/` matches `a_b` but not `axb`.
        let filters = vec![pf("/priv/a_b/")];
        let events = EventRepository::get_by_user_cursors(
            vec![(user.id, None)],
            false,
            &filters,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        let got: Vec<&str> = events.iter().map(|e| e.path.path().as_str()).collect();
        assert_eq!(got, vec!["/priv/a_b/x"]);

        // `%` must be matched literally: `/priv/a%/` matches `a%` but not `apct`.
        let filters = vec![pf("/priv/a%/")];
        let events = EventRepository::get_by_user_cursors(
            vec![(user.id, None)],
            false,
            &filters,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        let got: Vec<&str> = events.iter().map(|e| e.path.path().as_str()).collect();
        assert_eq!(got, vec!["/priv/a%/m"]);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_by_user_cursors_multi_user_public_filter_excludes_private() {
        let db = SqlDb::test().await;
        let ka = Keypair::random().public_key();
        let kb = Keypair::random().public_key();
        let ua = UserRepository::create(&ka, &mut db.pool().into())
            .await
            .unwrap();
        let ub = UserRepository::create(&kb, &mut db.pool().into())
            .await
            .unwrap();

        for (k, uid) in [(&ka, ua.id), (&kb, ub.id)] {
            for p in ["/pub/x", "/priv/secret"] {
                let path = EntryPath::new(k.clone(), StoragePath::new(p).unwrap());
                EventRepository::create(
                    uid,
                    EventType::Put {
                        content_hash: Hash::from_bytes([0; 32]),
                    },
                    &path,
                    &mut db.pool().into(),
                )
                .await
                .unwrap();
            }
        }

        // Public filter across two users returns both users' `/pub/x` and
        // never their `/priv/secret`.
        let filters = vec![pf("/pub/")];
        let events = EventRepository::get_by_user_cursors(
            vec![(ua.id, None), (ub.id, None)],
            false,
            &filters,
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        let got: Vec<&str> = events.iter().map(|e| e.path.path().as_str()).collect();
        assert_eq!(got, vec!["/pub/x", "/pub/x"]);
        assert!(events
            .iter()
            .all(|e| !e.path.path().as_str().starts_with("/priv/")));
    }
}
