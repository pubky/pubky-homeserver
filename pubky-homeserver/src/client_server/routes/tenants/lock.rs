//! Minimal WebDAV locking (RFC 4918) for storage files.
//!
//! Only exclusive write locks with depth 0 on file paths are granted. A lock is
//! a bearer token: `LOCK` returns it, `PUT` and `DELETE` must present it in the
//! `If` header while the lock lives, and `UNLOCK` presents it in `Lock-Token`.
//! Locks expire after the granted `Timeout`, so a client that disappears blocks
//! a path for at most [`MAX_LOCK_TIMEOUT_SECS`]. The lifetime is the client's
//! to manage: a slow upload needs a lock that covers it, refreshed as needed.
//!
//! A write checks the lock before it starts, see [`with_write_lock`]. An
//! unlocked write holds nothing: a lock taken while it is still streaming does
//! not stop it from landing. A write that presents a token runs under that
//! lock: when it comes to change the file it reserves the lock for as long as
//! the change can still reach the storage backend, and until then the lock
//! cannot run out, be released or be used for another change, so no later
//! holder can be overwritten by it. Should the lock be gone by then, the
//! write is refused. Lifetimes are measured on the database clock, so every
//! instance agrees on which locks are live.
//!
//! `LOCK` and `UNLOCK` exist on the path-addressed `/storage` route only. The
//! deprecated owner-relative routes cannot take a lock, but their writes make
//! the same check and are refused while a path is locked.
//!
//! Not provided: shared locks, `Depth: infinity`, lock-null resources (locking
//! an unmapped path records the lock but creates nothing), and entity tags or
//! the `Not` operator in `If`.

use std::future::Future;

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, Method, Response, StatusCode, Uri},
    response::IntoResponse,
};

use super::authorize::authorize_write;
use crate::{
    client_server::{auth::AuthSession, AppState},
    persistence::files::write_finalization_layer::write_lock,
    persistence::sql::{
        entry_lock::{EntryLockEntity, EntryLockRepository, ReleaseOutcome},
        SqlDb, UnifiedExecutor,
    },
    shared::{webdav::EntryPath, HttpError, HttpResult},
};

/// Lock lifetime granted when the request carries no usable `Timeout`.
const DEFAULT_LOCK_TIMEOUT_SECS: i64 = 30;
/// Longest lock lifetime granted, whatever the client asks for.
const MAX_LOCK_TIMEOUT_SECS: i64 = 600;
/// Largest `lockinfo` body read. A real one is a few hundred bytes.
const MAX_LOCKINFO_BYTES: usize = 16 * 1024;
const LOCK_TOKEN_SCHEME: &str = "opaquelocktoken:";
const ALLOWED_METHODS: &str = "GET, HEAD, PUT, DELETE, LOCK, UNLOCK";

/// Method-router fallback for the storage route: serves `LOCK` and `UNLOCK`,
/// which axum's method filters do not know, and answers 405 to anything else.
/// The body is taken unread: nothing is buffered for an unknown method or an
/// unauthorized request.
pub async fn dispatch(
    State(state): State<AppState>,
    session: Option<AuthSession>,
    entry_path: EntryPath,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response<Body>> {
    match method.as_str() {
        "LOCK" => lock(&state, session, &entry_path, uri.path(), &headers, body).await,
        "UNLOCK" => unlock(&state, session, &entry_path, &headers).await,
        _ => Ok((
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, ALLOWED_METHODS)],
        )
            .into_response()),
    }
}

/// Run `write` on `entry_path` if the path's lock allows it.
///
/// - No token and no live lock: the write runs, holding nothing.
/// - No token and a live lock: 423 Locked.
/// - The `If` header names the live lock: the write runs under that lock. The
///   token is handed to the write itself, which reserves the lock when it
///   comes to change the file, and is refused if the lock is gone by then.
/// - Tokens that name no live lock on this path: 412 Precondition Failed. A
///   client whose lock expired learns that instead of silently writing unlocked.
pub async fn with_write_lock<T>(
    sql_db: &SqlDb,
    entry_path: &EntryPath,
    headers: &HeaderMap,
    write: impl Future<Output = HttpResult<T>>,
) -> HttpResult<T> {
    let lock_token = check_lock(sql_db, entry_path, headers).await?;
    write_lock::run_under(lock_token, write).await
}

/// The check of [`with_write_lock`], returning the token of the live lock the
/// write runs under. A separate function so its pool connection is returned
/// before the write runs: an upload can take a long time, and holding a
/// connection for its duration would starve the write itself of one.
async fn check_lock(
    sql_db: &SqlDb,
    entry_path: &EntryPath,
    headers: &HeaderMap,
) -> HttpResult<Option<String>> {
    let mut executor: UnifiedExecutor = sql_db.pool().into();
    let live = EntryLockRepository::get_active(entry_path, &mut executor).await?;
    let held = if_header_tokens(headers);
    match live {
        None if held.is_empty() => Ok(None),
        None => Err(HttpError::lock_token_mismatch()),
        Some(_) if held.is_empty() => Err(HttpError::locked()),
        Some(live) if held.contains(&live.token) => Ok(Some(live.token)),
        Some(_) => Err(HttpError::lock_token_mismatch()),
    }
}

async fn lock(
    state: &AppState,
    session: Option<AuthSession>,
    entry_path: &EntryPath,
    lock_root: &str,
    headers: &HeaderMap,
    body: Body,
) -> HttpResult<Response<Body>> {
    // The fallback route cannot demand a session up front without turning an
    // unknown method's 405 into a 401, so it is required here.
    let session = session.ok_or_else(HttpError::unauthorized)?;
    authorize_write(state, &session, entry_path, true).await?;

    // A request naming a token is a refresh of the lock it holds.
    let presented = if_header_tokens(headers);
    let is_new = presented.is_empty();
    if is_new {
        // Before the lock is taken, so a slow body does not eat into the
        // lifetime that is granted and reported.
        check_lockinfo(body).await?;
    }

    let sql_db = &state.context.sql_db;
    let lifetime = requested_timeout(headers);
    let lock = if is_new {
        create_lock(sql_db, entry_path, lifetime).await?
    } else {
        EntryLockRepository::refresh(entry_path, &presented, lifetime, &mut sql_db.pool().into())
            .await?
            .ok_or_else(HttpError::lock_token_mismatch)?
    };
    lock_response(&lock, lock_root, lifetime, is_new)
}

/// Refuse a `lockinfo` body that asks for a kind of lock that is not granted.
/// An empty body asks for the default.
async fn check_lockinfo(lockinfo: Body) -> HttpResult<()> {
    let lockinfo = axum::body::to_bytes(lockinfo, MAX_LOCKINFO_BYTES)
        .await
        .map_err(|_| {
            HttpError::new_with_message(StatusCode::PAYLOAD_TOO_LARGE, "lockinfo body too large")
        })?;
    if !lockinfo.is_empty() && !is_exclusive_write_lockinfo(&lockinfo) {
        return Err(HttpError::bad_request(
            "Only exclusive write locks are supported",
        ));
    }
    Ok(())
}

/// Grant a new lock, sweeping expired ones first.
async fn create_lock(
    sql_db: &SqlDb,
    entry_path: &EntryPath,
    lifetime_secs: i64,
) -> HttpResult<EntryLockEntity> {
    let token = uuid::Uuid::new_v4().to_string();
    let mut executor: UnifiedExecutor = sql_db.pool().into();
    EntryLockRepository::delete_expired(&mut executor).await?;
    EntryLockRepository::acquire(entry_path, &token, lifetime_secs, &mut executor)
        .await?
        .ok_or_else(HttpError::locked)
}

async fn unlock(
    state: &AppState,
    session: Option<AuthSession>,
    entry_path: &EntryPath,
    headers: &HeaderMap,
) -> HttpResult<Response<Body>> {
    let session = session.ok_or_else(HttpError::unauthorized)?;
    authorize_write(state, &session, entry_path, false).await?;

    let token = lock_token_header(headers)
        .ok_or_else(|| HttpError::bad_request("Missing or malformed Lock-Token header"))?;
    let released =
        EntryLockRepository::release(entry_path, &token, &mut state.context.sql_db.pool().into())
            .await?;
    match released {
        ReleaseOutcome::Released => Ok(StatusCode::NO_CONTENT.into_response()),
        // A change under the lock may still reach the backend; releasing now
        // would let it land on the next holder. The lock is still the
        // caller's, and this call succeeds once the change is over.
        ReleaseOutcome::Reserved { remaining_secs } => {
            Err(HttpError::lock_busy(remaining_secs as u64))
        }
        ReleaseOutcome::NotHeld => Err(HttpError::conflict("No lock with this token on this path")),
    }
}

/// The `lockdiscovery` body of a lock just granted or refreshed for `remaining`
/// seconds. `Lock-Token` is set on creation only, as the RFC asks.
fn lock_response(
    lock: &EntryLockEntity,
    lock_root: &str,
    remaining: i64,
    created: bool,
) -> HttpResult<Response<Body>> {
    let token_url = format!("{LOCK_TOKEN_SCHEME}{}", lock.token);
    let body = format!(
        concat!(
            r#"<?xml version="1.0" encoding="utf-8"?>"#,
            r#"<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>"#,
            "<D:locktype><D:write/></D:locktype>",
            "<D:lockscope><D:exclusive/></D:lockscope>",
            "<D:depth>0</D:depth>",
            "<D:timeout>Second-{remaining}</D:timeout>",
            "<D:locktoken><D:href>{token_url}</D:href></D:locktoken>",
            "<D:lockroot><D:href>{lock_root}</D:href></D:lockroot>",
            "</D:activelock></D:lockdiscovery></D:prop>",
        ),
        remaining = remaining,
        token_url = token_url,
        lock_root = xml_escape(lock_root),
    );
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .header("Timeout", format!("Second-{remaining}"));
    if created {
        response = response.header("Lock-Token", format!("<{token_url}>"));
    }
    Ok(response.body(Body::from(body))?)
}

/// Lifetime to grant: `Second-N` capped at the maximum, `Infinite` as the
/// maximum, anything else as the default.
fn requested_timeout(headers: &HeaderMap) -> i64 {
    let Some(value) = headers.get("timeout").and_then(|v| v.to_str().ok()) else {
        return DEFAULT_LOCK_TIMEOUT_SECS;
    };
    value
        .split(',')
        .map(str::trim)
        .find_map(|part| {
            if part.eq_ignore_ascii_case("infinite") {
                return Some(MAX_LOCK_TIMEOUT_SECS);
            }
            part.strip_prefix("Second-")?.parse::<i64>().ok()
        })
        .map(|seconds| seconds.clamp(1, MAX_LOCK_TIMEOUT_SECS))
        .unwrap_or(DEFAULT_LOCK_TIMEOUT_SECS)
}

/// Every lock token in the `If` header. Resource tags and `Not` are ignored:
/// a token counts wherever it appears.
fn if_header_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("if")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(coded_urls)
        .filter_map(|url| url.strip_prefix(LOCK_TOKEN_SCHEME))
        .map(str::to_owned)
        .collect()
}

/// The token in `Lock-Token`, with or without its angle brackets.
fn lock_token_header(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("lock-token")?.to_str().ok()?;
    let url = coded_urls(value).into_iter().next().unwrap_or(value.trim());
    url.strip_prefix(LOCK_TOKEN_SCHEME).map(str::to_owned)
}

/// The `<...>` groups of a header value, in order.
fn coded_urls(value: &str) -> Vec<&str> {
    let mut urls = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find('<') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('>') else { break };
        urls.push(after[..end].trim());
        rest = &after[end + 1..];
    }
    urls
}

/// Whether a `lockinfo` body asks for what is granted. Elements are matched by
/// local name, so any namespace prefix works. Nothing else in the body is read.
fn is_exclusive_write_lockinfo(body: &[u8]) -> bool {
    let Ok(xml) = std::str::from_utf8(body) else {
        return false;
    };
    has_element(xml, "exclusive") && has_element(xml, "write") && !has_element(xml, "shared")
}

fn has_element(xml: &str, local_name: &str) -> bool {
    xml.split('<').skip(1).any(|tag| {
        let name = tag
            .split(|c: char| c == '/' || c == '>' || c.is_whitespace())
            .next()
            .unwrap_or("");
        name.rsplit(':').next() == Some(local_name)
    })
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use axum::{
        body::Bytes,
        http::{header, HeaderValue, Method},
    };
    use axum_test::{TestRequest, TestResponse, TestServer};
    use pubky_common::{auth::AuthToken, capabilities::Capability, crypto::Keypair};

    use super::*;
    use crate::{
        app_context::AppContext, client_server::ClientServer, shared::webdav::StoragePath,
    };

    const LOCKINFO: &str = r#"<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#;

    fn method(name: &str) -> Method {
        Method::from_bytes(name.as_bytes()).unwrap()
    }

    fn headers_with(name: &'static str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn if_header_tokens_ignores_tags_and_not() {
        let headers = headers_with(
            "if",
            "<http://x/a> (Not <opaquelocktoken:one> [\"etag\"]) (<opaquelocktoken:two>) (<urn:other>)",
        );
        assert_eq!(if_header_tokens(&headers), vec!["one", "two"]);
        assert!(if_header_tokens(&HeaderMap::new()).is_empty());
        assert!(if_header_tokens(&headers_with("if", "(<opaquelocktoken:broken")).is_empty());
    }

    #[test]
    fn lock_token_header_accepts_bracketed_and_bare() {
        let bracketed = headers_with("lock-token", "<opaquelocktoken:abc>");
        assert_eq!(lock_token_header(&bracketed).as_deref(), Some("abc"));
        let bare = headers_with("lock-token", " opaquelocktoken:abc ");
        assert_eq!(lock_token_header(&bare).as_deref(), Some("abc"));
        let other = headers_with("lock-token", "<urn:uuid:abc>");
        assert_eq!(lock_token_header(&other), None);
        assert_eq!(lock_token_header(&HeaderMap::new()), None);
    }

    #[test]
    fn requested_timeout_is_capped_and_defaulted() {
        assert_eq!(
            requested_timeout(&HeaderMap::new()),
            DEFAULT_LOCK_TIMEOUT_SECS
        );
        assert_eq!(requested_timeout(&headers_with("timeout", "Second-10")), 10);
        assert_eq!(
            requested_timeout(&headers_with("timeout", "Second-99999")),
            MAX_LOCK_TIMEOUT_SECS
        );
        assert_eq!(
            requested_timeout(&headers_with("timeout", "Infinite, Second-10")),
            MAX_LOCK_TIMEOUT_SECS
        );
        assert_eq!(requested_timeout(&headers_with("timeout", "Second-0")), 1);
        assert_eq!(
            requested_timeout(&headers_with("timeout", "nonsense")),
            DEFAULT_LOCK_TIMEOUT_SECS
        );
    }

    #[test]
    fn lockinfo_is_matched_by_local_name() {
        assert!(is_exclusive_write_lockinfo(LOCKINFO.as_bytes()));
        assert!(is_exclusive_write_lockinfo(
            br#"<lockinfo xmlns="DAV:"><lockscope><exclusive /></lockscope><locktype><write/></locktype><owner>shared with nobody</owner></lockinfo>"#
        ));
        assert!(!is_exclusive_write_lockinfo(
            br#"<d:lockinfo xmlns:d="DAV:"><d:lockscope><d:shared/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>"#
        ));
        assert!(!is_exclusive_write_lockinfo(b"<D:lockinfo/>"));
        assert!(!is_exclusive_write_lockinfo(&[0xff, 0xfe]));
    }

    #[test]
    fn lock_root_is_escaped() {
        assert_eq!(xml_escape("/a&b<c>\"d"), "/a&amp;b&lt;c&gt;&quot;d");
    }

    async fn signed_up_server() -> (TestServer, Keypair, String) {
        let (_, server, keypair, cookie) = signed_up_server_with_context().await;
        (server, keypair, cookie)
    }

    async fn signed_up_server_with_context() -> (Arc<AppContext>, TestServer, Keypair, String) {
        let context = AppContext::test().await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router);
        let keypair = Keypair::random();
        let cookie = signup(&server, &keypair).await;
        (context, server, keypair, cookie)
    }

    async fn signup(server: &TestServer, keypair: &Keypair) -> String {
        let auth_token = AuthToken::sign(keypair, vec![Capability::root()]);
        let body: Bytes = auth_token.serialize().into();
        let response = server
            .post("/signup")
            .add_header("host", keypair.public_key().z32())
            .bytes(body)
            .expect_success()
            .await;
        response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|h| h.to_str().ok())
            .expect("signup should return a session cookie")
            .to_string()
    }

    fn storage_url(keypair: &Keypair, path: &str) -> String {
        format!("/storage/{}{path}", keypair.public_key().z32())
    }

    fn lock_token(response: &TestResponse) -> String {
        let header = response
            .headers()
            .get("lock-token")
            .expect("LOCK must return Lock-Token")
            .to_str()
            .unwrap()
            .to_string();
        assert!(header.starts_with("<opaquelocktoken:") && header.ends_with('>'));
        header
    }

    /// `If` header value that presents `token` (a bracketed lock token URL).
    fn holding(token: &str) -> String {
        format!("({token})")
    }

    async fn test_path() -> (Arc<AppContext>, EntryPath) {
        let context = AppContext::test().await;
        let path = EntryPath::new(
            Keypair::random().public_key(),
            StoragePath::new("/pub/state.bin").unwrap(),
        );
        (context, path)
    }

    async fn expires_at(db: &SqlDb, path: &EntryPath) -> Option<i64> {
        EntryLockRepository::get_active(path, &mut db.pool().into())
            .await
            .unwrap()
            .map(|lock| lock.expires_at)
    }

    /// An unlocked write holds nothing, a write under the client's own lock
    /// leaves that lock as it was, and everything else is refused before the
    /// write starts.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn write_runs_only_when_the_lock_allows_it() {
        // One connection: a write that needs the database while the lock
        // check still holds its connection would time out. Uploads are long,
        // so the check must give its connection back before the write runs.
        let db = SqlDb::test_with_pool_options(1, Duration::from_secs(2)).await;
        let path = EntryPath::new(
            Keypair::random().public_key(),
            StoragePath::new("/pub/state.bin").unwrap(),
        );
        let status_of = |result: HttpResult<()>| result.err().map(|e| e.into_response().status());
        let write = |headers: HeaderMap, body: HttpResult<()>| {
            let (db, path) = (db.clone(), path.clone());
            async move {
                with_write_lock(&db, &path, &headers, async {
                    db.pool()
                        .acquire()
                        .await
                        .expect("the lock check must not hold a connection over the write");
                    body
                })
                .await
            }
        };

        // Free path: the write runs, and a failure changes nothing.
        write(HeaderMap::new(), Ok(())).await.unwrap();
        let failed = write(HeaderMap::new(), Err(HttpError::not_found())).await;
        assert_eq!(status_of(failed), Some(StatusCode::NOT_FOUND));
        assert_eq!(expires_at(&db, &path).await, None);
        let stale = write(headers_with("if", "(<opaquelocktoken:stale>)"), Ok(())).await;
        assert_eq!(status_of(stale), Some(StatusCode::PRECONDITION_FAILED));

        // Locked path.
        let granted = EntryLockRepository::acquire(&path, "t", 5, &mut db.pool().into())
            .await
            .unwrap()
            .unwrap();
        let unlocked = write(HeaderMap::new(), Ok(())).await;
        assert_eq!(status_of(unlocked), Some(StatusCode::LOCKED));
        let wrong = write(headers_with("if", "(<opaquelocktoken:other>)"), Ok(())).await;
        assert_eq!(status_of(wrong), Some(StatusCode::PRECONDITION_FAILED));
        write(headers_with("if", "(<opaquelocktoken:t>)"), Ok(()))
            .await
            .unwrap();
        // Still held, as granted: the lifetime is the holder's to manage.
        assert_eq!(expires_at(&db, &path).await, Some(granted.expires_at));
        let unlocked = write(HeaderMap::new(), Ok(())).await;
        assert_eq!(status_of(unlocked), Some(StatusCode::LOCKED));
    }

    /// A token is only good on the path it was granted for: presenting it on
    /// another path of the same user, or the same path of another user, is a
    /// mismatch, and the lock it names is neither extended nor released.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn token_is_refused_on_any_other_path() {
        let (context, path) = test_path().await;
        let granted =
            EntryLockRepository::acquire(&path, "t", 5, &mut context.sql_db.pool().into())
                .await
                .unwrap()
                .unwrap();

        let sibling = EntryPath::new(
            path.pubkey().clone(),
            StoragePath::new("/pub/other.bin").unwrap(),
        );
        let same_path_other_user =
            EntryPath::new(Keypair::random().public_key(), path.path().clone());
        for other in [&sibling, &same_path_other_user] {
            let headers = headers_with("if", "(<opaquelocktoken:t>)");
            let result = with_write_lock(&context.sql_db, other, &headers, async { Ok(()) }).await;
            assert_eq!(
                result.err().map(|e| e.into_response().status()),
                Some(StatusCode::PRECONDITION_FAILED),
                "token for {path} must be refused on {other}"
            );
            assert_eq!(expires_at(&context.sql_db, other).await, None);
        }
        assert_eq!(
            expires_at(&context.sql_db, &path).await,
            Some(granted.expires_at)
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn lock_gates_put_and_delete_until_unlock() {
        let (server, keypair, cookie) = signed_up_server().await;
        let url = storage_url(&keypair, "/pub/state.bin");

        let response = server
            .method(method("LOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .text(LOCKINFO)
            .await;
        response.assert_status(StatusCode::OK);
        response.assert_header(header::CONTENT_TYPE, "application/xml; charset=utf-8");
        response.assert_header("timeout", format!("Second-{DEFAULT_LOCK_TIMEOUT_SECS}"));
        let token = lock_token(&response);
        let body = response.text();
        assert!(body.contains("<D:lockdiscovery>"));
        assert!(body.contains(&format!(
            "<D:href>{}</D:href>",
            token.trim_matches(['<', '>'])
        )));
        assert!(body.contains(&format!("<D:lockroot><D:href>{url}</D:href></D:lockroot>")));

        // Unlocked and wrongly-tokened writes are refused.
        server
            .put(&url)
            .add_header(header::COOKIE, cookie.clone())
            .bytes(vec![1].into())
            .await
            .assert_status(StatusCode::LOCKED);
        server
            .method(method("LOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .await
            .assert_status(StatusCode::LOCKED);

        server
            .put(&url)
            .add_header(header::COOKIE, cookie.clone())
            .add_header("if", holding(&token))
            .bytes(vec![1].into())
            .await
            .assert_status(StatusCode::CREATED);
        server
            .delete(&url)
            .add_header(header::COOKIE, cookie.clone())
            .await
            .assert_status(StatusCode::LOCKED);

        server
            .method(method("UNLOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .add_header("lock-token", token.clone())
            .await
            .assert_status(StatusCode::NO_CONTENT);

        // Released: plain writes work again, the old token is stale.
        server
            .put(&url)
            .add_header(header::COOKIE, cookie.clone())
            .add_header("if", holding(&token))
            .bytes(vec![2].into())
            .await
            .assert_status(StatusCode::PRECONDITION_FAILED);
        server
            .delete(&url)
            .add_header(header::COOKIE, cookie.clone())
            .await
            .assert_status(StatusCode::NO_CONTENT);
    }

    /// Lock lifetimes run on the real clock. Once the granted lifetime has
    /// passed the path is writable and lockable again, and the old token is
    /// stale.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn expired_lock_frees_the_path() {
        let (server, keypair, cookie) = signed_up_server().await;
        let url = storage_url(&keypair, "/pub/state.bin");
        let response = server
            .method(method("LOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .add_header("timeout", "Second-1")
            .await;
        response.assert_status(StatusCode::OK);
        response.assert_header("timeout", "Second-1");
        let token = lock_token(&response);
        server
            .put(&url)
            .add_header(header::COOKIE, cookie.clone())
            .bytes(vec![1].into())
            .await
            .assert_status(StatusCode::LOCKED);

        // Lifetimes are whole seconds: the lock is dead once the next second
        // has begun.
        tokio::time::sleep(Duration::from_millis(1500)).await;

        server
            .put(&url)
            .add_header(header::COOKIE, cookie.clone())
            .bytes(vec![2].into())
            .await
            .assert_status(StatusCode::CREATED);
        server
            .put(&url)
            .add_header(header::COOKIE, cookie.clone())
            .add_header("if", holding(&token))
            .bytes(vec![3].into())
            .await
            .assert_status(StatusCode::PRECONDITION_FAILED);
        let response = server
            .method(method("LOCK"), &url)
            .add_header(header::COOKIE, cookie)
            .await;
        response.assert_status(StatusCode::OK);
        assert_ne!(lock_token(&response), token);
    }

    /// The lock is checked when a request starts, but the file changes later,
    /// on a finalization task, which reserves the lock for the change. A
    /// reservation used up before the change can be published must refuse
    /// the `PUT` and the `DELETE`, leaving the file as it was, and end, so the
    /// holder can retry at once. This drives the whole chain from the route to
    /// the finalization: the token has to survive every layer in between, or
    /// the write lands unreserved.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn write_and_delete_are_refused_once_their_window_is_used_up_in_flight() {
        let (context, server, keypair, cookie) = signed_up_server_with_context().await;
        let url = storage_url(&keypair, "/pub/state.bin");
        let path = EntryPath::new(
            keypair.public_key(),
            StoragePath::new("/pub/state.bin").unwrap(),
        );
        server
            .put(&url)
            .add_header(header::COOKIE, cookie.clone())
            .bytes(b"kept".to_vec().into())
            .await
            .assert_status(StatusCode::CREATED);

        for verb in ["PUT", "DELETE"] {
            let response = server
                .method(method("LOCK"), &url)
                .add_header(header::COOKIE, cookie.clone())
                .add_header("timeout", "Second-60")
                .await;
            response.assert_status(StatusCode::OK);
            let token = lock_token(&response);

            let request = match verb {
                "PUT" => server.put(&url).bytes(b"lost".to_vec().into()),
                _ => server.delete(&url),
            }
            .add_header(header::COOKIE, cookie.clone())
            .add_header("if", holding(&token));
            let response = with_window_used_up_in_flight(&context, &path, request).await;
            response.assert_status(StatusCode::LOCKED);
            response.assert_header("retry-after", "1");

            let stored = server
                .get(&url)
                .add_header(header::COOKIE, cookie.clone())
                .await;
            stored.assert_status(StatusCode::OK);
            assert_eq!(
                stored.text(),
                "kept",
                "a refused {verb} must not change the file"
            );

            // Nothing was sent: the reservation is over and the lock is the
            // holder's to release.
            server
                .method(method("UNLOCK"), &url)
                .add_header(header::COOKIE, cookie.clone())
                .add_header("lock-token", token)
                .await
                .assert_status(StatusCode::NO_CONTENT);
        }

        server
            .delete(&url)
            .add_header(header::COOKIE, cookie)
            .await
            .assert_status(StatusCode::NO_CONTENT);
    }

    /// Run `request`, which presents the live lock on `path`, and use up the
    /// reservation its finalization took before that finalization changes the
    /// file. The finalization is held back on the user row until the
    /// reservation is seen, then left with too little of its window.
    async fn with_window_used_up_in_flight(
        context: &AppContext,
        path: &EntryPath,
        request: TestRequest,
    ) -> TestResponse {
        let db = &context.sql_db;
        let mut holder = db.pool().begin().await.unwrap();
        context
            .user_service
            .get_for_no_key_update(path.pubkey(), &mut UnifiedExecutor::from_tx(&mut holder))
            .await
            .unwrap();

        let use_up_the_window = async {
            wait_for_reservation(db, path).await;
            EntryLockRepository::set_publish_window(path, 1, &mut db.pool().into())
                .await
                .unwrap();
            holder.commit().await.unwrap();
        };
        let (response, ()) = tokio::join!(async { request.await }, use_up_the_window);
        response
    }

    /// Poll until the live lock on `path` is reserved for a change.
    async fn wait_for_reservation(db: &SqlDb, path: &EntryPath) {
        for _ in 0..500 {
            let reserved = EntryLockRepository::get_active(path, &mut db.pool().into())
                .await
                .unwrap()
                .is_some_and(|lock| lock.publishing_until > 0);
            if reserved {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the request never reserved its lock");
    }

    /// `UNLOCK` while a change under the lock is still in flight is refused
    /// with a retry hint, and goes through once the change has landed.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn unlock_waits_for_a_change_in_flight() {
        let (context, server, keypair, cookie) = signed_up_server_with_context().await;
        let url = storage_url(&keypair, "/pub/state.bin");
        let path = EntryPath::new(
            keypair.public_key(),
            StoragePath::new("/pub/state.bin").unwrap(),
        );
        let response = server
            .method(method("LOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .await;
        response.assert_status(StatusCode::OK);
        let token = lock_token(&response);

        let db = &context.sql_db;
        let mut holder = db.pool().begin().await.unwrap();
        context
            .user_service
            .get_for_no_key_update(path.pubkey(), &mut UnifiedExecutor::from_tx(&mut holder))
            .await
            .unwrap();
        let write = server
            .put(&url)
            .add_header(header::COOKIE, cookie.clone())
            .add_header("if", holding(&token))
            .bytes(b"landing".to_vec().into());
        let unlock_meanwhile = async {
            wait_for_reservation(db, &path).await;
            let refused = server
                .method(method("UNLOCK"), &url)
                .add_header(header::COOKIE, cookie.clone())
                .add_header("lock-token", token.clone())
                .await;
            refused.assert_status(StatusCode::LOCKED);
            let retry_after: i64 = refused
                .headers()
                .get("retry-after")
                .expect("a refused UNLOCK says when to retry")
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            assert!((1..=write_lock::PUBLISH_WINDOW_SECS).contains(&retry_after));
            holder.commit().await.unwrap();
        };
        let (response, ()) = tokio::join!(async { write.await }, unlock_meanwhile);
        response.assert_status(StatusCode::CREATED);

        server
            .method(method("UNLOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .add_header("lock-token", token)
            .await
            .assert_status(StatusCode::NO_CONTENT);
        server
            .put(&url)
            .add_header(header::COOKIE, cookie)
            .bytes(b"free".to_vec().into())
            .await
            .assert_status(StatusCode::CREATED);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn refresh_unlock_and_precondition_paths() {
        let (server, keypair, cookie) = signed_up_server().await;
        let url = storage_url(&keypair, "/pub/state.bin");
        let response = server
            .method(method("LOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .add_header("timeout", "Second-99999")
            .await;
        response.assert_status(StatusCode::OK);
        response.assert_header("timeout", format!("Second-{MAX_LOCK_TIMEOUT_SECS}"));
        let token = lock_token(&response);

        // Refresh keeps the lock and reports the new lifetime without Lock-Token.
        let response = server
            .method(method("LOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .add_header("if", holding(&token))
            .add_header("timeout", "Second-10")
            .await;
        response.assert_status(StatusCode::OK);
        response.assert_header("timeout", "Second-10");
        assert!(response.headers().get("lock-token").is_none());

        let stale = "(<opaquelocktoken:00000000-0000-0000-0000-000000000000>)";
        server
            .method(method("LOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .add_header("if", stale)
            .await
            .assert_status(StatusCode::PRECONDITION_FAILED);
        server
            .put(&url)
            .add_header(header::COOKIE, cookie.clone())
            .add_header("if", stale)
            .bytes(vec![1].into())
            .await
            .assert_status(StatusCode::PRECONDITION_FAILED);

        server
            .method(method("UNLOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .await
            .assert_status(StatusCode::BAD_REQUEST);
        server
            .method(method("UNLOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .add_header(
                "lock-token",
                "<opaquelocktoken:00000000-0000-0000-0000-000000000000>",
            )
            .await
            .assert_status(StatusCode::CONFLICT);
        server
            .method(method("UNLOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .add_header("lock-token", token)
            .await
            .assert_status(StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn lock_rejects_bad_requests() {
        let (server, keypair, cookie) = signed_up_server().await;
        let url = storage_url(&keypair, "/pub/state.bin");

        server
            .method(method("LOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .text(LOCKINFO.replace("exclusive", "shared"))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
        server
            .method(method("LOCK"), &storage_url(&keypair, "/pub/dir/"))
            .add_header(header::COOKIE, cookie.clone())
            .await
            .assert_status(StatusCode::BAD_REQUEST);
        server
            .method(method("LOCK"), &url)
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
        server
            .method(method("LOCK"), &storage_url(&keypair, "/other/state.bin"))
            .add_header(header::COOKIE, cookie.clone())
            .await
            .assert_status(StatusCode::FORBIDDEN);

        // Another user's cookie is not a session for this tenant.
        let intruder = Keypair::random();
        let intruder_cookie = signup(&server, &intruder).await;
        server
            .method(method("LOCK"), &url)
            .add_header(header::COOKIE, intruder_cookie)
            .await
            .assert_status(StatusCode::UNAUTHORIZED);

        let response = server
            .method(method("PATCH"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .await;
        response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
        response.assert_header(header::ALLOW, ALLOWED_METHODS);
    }

    /// `UNLOCK` is as guarded as `LOCK`: knowing a token is not enough.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn unlock_requires_write_access() {
        let (server, keypair, cookie) = signed_up_server().await;
        let url = storage_url(&keypair, "/pub/state.bin");
        let response = server
            .method(method("LOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .await;
        let token = lock_token(&response);

        server
            .method(method("UNLOCK"), &url)
            .add_header("lock-token", token.clone())
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
        let intruder_cookie = signup(&server, &Keypair::random()).await;
        server
            .method(method("UNLOCK"), &url)
            .add_header(header::COOKIE, intruder_cookie)
            .add_header("lock-token", token.clone())
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
        server
            .method(method("UNLOCK"), &storage_url(&keypair, "/other/state.bin"))
            .add_header(header::COOKIE, cookie.clone())
            .add_header("lock-token", token.clone())
            .await
            .assert_status(StatusCode::FORBIDDEN);

        // The lock survived all of it.
        server
            .method(method("LOCK"), &url)
            .add_header(header::COOKIE, cookie)
            .await
            .assert_status(StatusCode::LOCKED);
    }

    /// The body is read only for an authorized `LOCK`, and only a small one.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn lockinfo_body_is_bounded_and_read_after_authorization() {
        let (server, keypair, cookie) = signed_up_server().await;
        let url = storage_url(&keypair, "/pub/state.bin");
        let oversized = vec![b' '; MAX_LOCKINFO_BYTES + 1];

        server
            .method(method("LOCK"), &url)
            .add_header(header::COOKIE, cookie.clone())
            .bytes(oversized.clone().into())
            .await
            .assert_status(StatusCode::PAYLOAD_TOO_LARGE);
        server
            .method(method("LOCK"), &url)
            .bytes(oversized.clone().into())
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
        server
            .method(method("PATCH"), &url)
            .bytes(oversized.into())
            .await
            .assert_status(StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn legacy_route_respects_locks_but_cannot_take_them() {
        let (server, keypair, cookie) = signed_up_server().await;
        let host = keypair.public_key().z32();

        server
            .method(method("LOCK"), "/pub/state.bin")
            .add_header("pubky-host", host.clone())
            .add_header(header::COOKIE, cookie.clone())
            .await
            .assert_status(StatusCode::METHOD_NOT_ALLOWED);

        let response = server
            .method(method("LOCK"), &storage_url(&keypair, "/pub/state.bin"))
            .add_header(header::COOKIE, cookie.clone())
            .await;
        response.assert_status(StatusCode::OK);
        let token = lock_token(&response);
        server
            .put("/pub/state.bin")
            .add_header("pubky-host", host.clone())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(vec![1].into())
            .await
            .assert_status(StatusCode::LOCKED);

        // The holder may still write through the deprecated route.
        server
            .put("/pub/state.bin")
            .add_header("pubky-host", host)
            .add_header(header::COOKIE, cookie)
            .add_header("if", holding(&token))
            .bytes(vec![1].into())
            .await
            .assert_status(StatusCode::CREATED);
    }
}
