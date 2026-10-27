//! Static websites served from users' public storage.
//!
//! `Host: <user-key>` serves `/pub/website/_/` and `Host: <label>.<user-key>`
//! serves `/pub/website/<label>/`. See `docs/WEBSITES.md`.
//!
//! [`resolve`] classifies a request before tracing and rate limiting, so both
//! see the site file's storage path. [`serve`] answers it after the existing
//! middleware has run.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, request::Parts, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use percent_encoding::percent_decode_str;
use pubky_common::crypto::PublicKey;

use crate::{
    client_server::{middleware::request_tenant::RequestTenant, AppState},
    persistence::{files::FileIoError, sql::entry::EntryEntity},
    shared::{
        webdav::{EntryPath, StoragePath},
        HttpError, HttpResult,
    },
};

use super::tenants::read::{is_not_modified, not_modified_response};

/// First path segments that stay on the client API under a website `Host`.
const API_SEGMENTS: &[&str] = &[
    "account",
    "auth",
    "events",
    "events-stream",
    "info",
    "priv",
    "pub",
    "session",
    "signup",
    "signup_tokens",
    "storage",
];

/// A GET or HEAD request for a page of a user's website.
#[derive(Debug, Clone)]
pub(crate) struct Website {
    owner: PublicKey,
    /// The site's storage folder without a trailing slash, e.g. `/pub/website/_`.
    root: String,
    /// The normalized request path.
    path: StoragePath,
    /// The file the request names inside `root`. A folder path names its
    /// `index.html`.
    target: StoragePath,
}

impl Website {
    /// Returns `Ok(None)` when the request is not for a website.
    fn from_request(request: &Request, homeserver: &PublicKey) -> Result<Option<Self>, String> {
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            return Ok(None);
        }
        let raw_path = request.uri().path();
        let first_segment = raw_path.split('/').nth(1).unwrap_or_default();
        if API_SEGMENTS.contains(&first_segment) {
            return Ok(None);
        }
        let Some((owner, label)) = request
            .headers()
            .get(header::HOST)
            .and_then(|host| host.to_str().ok())
            .or_else(|| request.uri().host())
            .and_then(|host| parse_host(host, homeserver))
        else {
            return Ok(None);
        };

        let decoded = percent_decode_str(raw_path)
            .decode_utf8()
            .map_err(|_| "Website path is not valid UTF-8".to_string())?;
        // Normalizing before joining keeps `..` inside the site folder.
        let path = StoragePath::normalize(&decoded)
            .map_err(|error| format!("Invalid website path: {error}"))?;
        let root = format!("/pub/website/{label}");
        // Name a folder's `index.html` here, so rate limits for that file also
        // cover requests for the folder.
        let index = if path.is_directory() {
            "index.html"
        } else {
            ""
        };
        let target = StoragePath::new(&format!("{root}{path}{index}"))
            .map_err(|error| format!("Invalid website path: {error}"))?;

        Ok(Some(Self {
            owner,
            root,
            path,
            target,
        }))
    }

    async fn respond(&self, state: &AppState, request: &Parts) -> HttpResult<Response> {
        let target = self.target.as_str();
        // Check the owner while looking up the page.
        let (_, page) = tokio::try_join!(
            state
                .context
                .user_service
                .get_or_http_error(&self.owner, true),
            self.entry(state, target),
        )?;
        if let Some(page) = page {
            return file(state, request, StatusCode::OK, page).await;
        }
        if self.path.is_file()
            && self
                .entry(state, &format!("{target}/index.html"))
                .await?
                .is_some()
        {
            // Relative links in the index resolve against the folder.
            let mut location = format!("{}/", self.path.url_encode());
            if let Some(query) = request.uri.query() {
                location.push('?');
                location.push_str(query);
            }
            return Ok((
                StatusCode::MOVED_PERMANENTLY,
                [(header::LOCATION, location)],
            )
                .into_response());
        }

        match self
            .entry(state, &format!("{}/404.html", self.root))
            .await?
        {
            Some(page) => file(state, request, StatusCode::NOT_FOUND, page).await,
            None => Err(HttpError::not_found()),
        }
    }

    async fn entry(
        &self,
        state: &AppState,
        path: &str,
    ) -> HttpResult<Option<(EntryPath, EntryEntity)>> {
        // A path over the storage length limit cannot exist.
        let Ok(path) = StoragePath::new(path) else {
            return Ok(None);
        };
        let entry_path = EntryPath::new(self.owner.clone(), path);
        match state
            .context
            .file_service
            .get_info(&entry_path, &mut state.context.sql_db.pool().into())
            .await
        {
            Ok(entry) => Ok(Some((entry_path, entry))),
            Err(FileIoError::NotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

/// Serves `page` with `status`.
async fn file(
    state: &AppState,
    request: &Parts,
    status: StatusCode,
    (entry_path, entry): (EntryPath, EntryEntity),
) -> HttpResult<Response> {
    if status == StatusCode::OK && is_not_modified(&request.headers, &entry) {
        return not_modified_response(&entry);
    }

    let file_service = &state.context.file_service;
    let (length, body) = if request.method == Method::HEAD {
        (file_service.blob_length(&entry_path).await?, Body::empty())
    } else {
        let (length, stream) = file_service.get_sized_stream(&entry_path).await?;
        (length, Body::from_stream(stream))
    };
    let mut response = (status, entry.to_response_headers(length), body).into_response();
    if status != StatusCode::OK {
        // A missing page has no version for a browser to revalidate.
        response.headers_mut().remove(header::ETAG);
        response.headers_mut().remove(header::LAST_MODIFIED);
    }
    Ok(response)
}

/// The site owner and label named by `host`, or `None` when it names no website.
fn parse_host(host: &str, homeserver: &PublicKey) -> Option<(PublicKey, String)> {
    let host = host.to_ascii_lowercase();
    let host = host
        .split_once(':')
        .map_or(host.as_str(), |(hostname, _port)| hostname);
    let host = host.strip_suffix('.').unwrap_or(host);
    let (label, key) = match host.rsplit_once('.') {
        Some((label, key)) if is_label(label) => (label, key),
        Some(_) => return None,
        None => ("_", host),
    };
    // pkarr also reads a key out of longer strings, so insist on the bare key.
    let owner = PublicKey::try_from_z32(key)
        .ok()
        .filter(|owner| owner.z32() == key)?;
    if owner == *homeserver {
        return None;
    }
    Some((owner, label.to_string()))
}

/// A DNS hostname label. Excludes `_pubky`, which the SDK uses as a Host.
fn is_label(label: &str) -> bool {
    !label.contains('.') && hostname_validator::is_valid(label)
}

/// Marks website requests and maps their tenant to the site file.
///
/// Runs after [`RequestTenant::resolve`] and replaces its legacy tenant, so
/// the owner comes from `Host` alone, never from `pubky-host`. Does nothing
/// when `[drive] websites` is off.
pub(crate) async fn resolve(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let context = &state.context;
    if !context.config_toml.drive.websites {
        return next.run(request).await;
    }
    match Website::from_request(&request, &context.keypair.public_key()) {
        Ok(Some(site)) => {
            let tenant = RequestTenant::mapped(site.owner.clone(), site.target.clone());
            request.extensions_mut().insert(tenant);
            request.extensions_mut().insert(site);
        }
        Ok(None) => {}
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    }
    next.run(request).await
}

/// Answers requests marked by [`resolve`] and passes the rest on.
///
/// The handler never reads the session, so cookies neither change a page nor
/// get set.
pub(crate) async fn serve(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(site) = request.extensions_mut().remove::<Website>() else {
        return next.run(request).await;
    };
    let (parts, _) = request.into_parts();
    let mut response = site
        .respond(&state, &parts)
        .await
        .unwrap_or_else(IntoResponse::into_response);
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{header, Method, Request, StatusCode},
    };
    use axum_test::{TestRequest, TestServer};
    use pubky_common::{auth::AuthToken, capabilities::Capability, crypto::Keypair};

    use super::*;
    use crate::{
        app_context::AppContext,
        client_server::ClientServer,
        data_directory::ConfigToml,
        shared::quota::{GlobPattern, HttpMethod, LimitKeyType, PathLimit},
    };

    struct Site {
        context: Arc<AppContext>,
        server: TestServer,
        owner: PublicKey,
        cookie: String,
    }

    impl Site {
        async fn start(configure: impl FnOnce(&mut ConfigToml)) -> Self {
            let context = AppContext::test_with_config(configure).await;
            let server =
                TestServer::new(ClientServer::create_router(Arc::clone(&context)).unwrap());
            let keypair = Keypair::random();
            let token = AuthToken::sign(&keypair, vec![Capability::root()]);
            let response = server
                .post("/signup")
                .add_header("host", keypair.public_key().z32())
                .bytes(token.serialize().into())
                .expect_success()
                .await;
            let cookie = response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .to_string();
            Self {
                context,
                server,
                owner: keypair.public_key(),
                cookie,
            }
        }

        async fn put(&self, path: &str, body: impl Into<Vec<u8>>) {
            self.server
                .put(&format!("/storage/{}{path}", self.owner.z32()))
                .add_header(header::COOKIE, self.cookie.clone())
                .bytes(body.into().into())
                .expect_success()
                .await;
        }

        fn request(&self, method: Method, host: &str, path: &str) -> TestRequest {
            self.server
                .method(method, path)
                .add_header("host", host.to_string())
        }

        fn get(&self, host: &str, path: &str) -> TestRequest {
            self.request(Method::GET, host, path)
        }
    }

    #[test]
    fn parse_host_accepts_only_website_hosts() {
        let homeserver = Keypair::random().public_key();
        let owner = Keypair::random().public_key();
        let key = owner.z32();
        let label = |host: &str| {
            parse_host(host, &homeserver).map(|(site_owner, label)| {
                assert_eq!(site_owner, owner);
                label
            })
        };

        assert_eq!(label(&key).as_deref(), Some("_"));
        assert_eq!(label(&format!("blog.{key}")).as_deref(), Some("blog"));
        assert_eq!(
            label(&format!("My-Blog.{}.:6287", key.to_uppercase())).as_deref(),
            Some("my-blog")
        );
        for host in [
            format!("_pubky.{key}"),
            format!("_.{key}"),
            format!("a.b.{key}"),
            format!("-a.{key}"),
            format!("pubky{key}"),
            format!("x@{key}"),
            homeserver.z32(),
            "example.com".to_string(),
        ] {
            assert_eq!(parse_host(&host, &homeserver), None, "{host}");
        }
    }

    #[test]
    fn from_request_keeps_api_paths_and_site_folders() {
        let homeserver = Keypair::random().public_key();
        let key = Keypair::random().public_key().z32();
        let classify = |method: Method, path: &str| {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .header(header::HOST, format!("blog.{key}"))
                .body(Body::empty())
                .unwrap();
            Website::from_request(&request, &homeserver)
                .map(|site| site.map(|site| site.target.as_str().to_string()))
        };

        assert_eq!(
            classify(Method::GET, "/a/%2e%2e/b%20c.html"),
            Ok(Some("/pub/website/blog/b c.html".into()))
        );
        // Collapsed slashes keep redirects on this host.
        assert_eq!(
            classify(Method::HEAD, "//evil.com"),
            Ok(Some("/pub/website/blog/evil.com".into()))
        );
        assert_eq!(
            classify(Method::GET, "/signup-page/"),
            Ok(Some("/pub/website/blog/signup-page/index.html".into()))
        );
        for path in [
            "/session",
            "/pub/file.txt",
            "/events/",
            "/storage/x/pub/y",
            "/info",
        ] {
            assert_eq!(classify(Method::GET, path), Ok(None), "{path}");
        }
        assert_eq!(classify(Method::PUT, "/index.html"), Ok(None));
        for path in ["/a/%2e%2e%2F..%2Fpriv", "/%5Cevil.com", "/%FF"] {
            assert!(classify(Method::GET, path).is_err(), "{path}");
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn serves_indexes_redirects_and_not_found_pages() {
        let site = Site::start(|_| {}).await;
        let key = site.owner.z32();
        site.put("/pub/website/_/index.html", "home").await;
        site.put("/pub/website/_/docs/index.html", "docs").await;
        site.put("/pub/website/_/404.html", "missing").await;
        site.put("/pub/website/blog/index.html", "blog").await;

        let response = site.get(&key, "/").await;
        response.assert_status_ok();
        response.assert_text("home");
        response.assert_header(header::CACHE_CONTROL, "no-cache");
        response.assert_header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
        assert!(response
            .headers()
            .get(header::VARY)
            .is_none_or(|vary| !vary.to_str().unwrap().contains("pubky-host")));

        site.get(&key, "/docs/").await.assert_text("docs");
        let response = site.get(&key, "/docs?lang=en").await;
        response.assert_status(StatusCode::MOVED_PERMANENTLY);
        response.assert_header(header::LOCATION, "/docs/?lang=en");

        let response = site.get(&key, "/nope.html").await;
        response.assert_status_not_found();
        response.assert_text("missing");
        assert!(!response.headers().contains_key(header::ETAG));
        // A folder never lists its files.
        site.put("/pub/website/_/assets/logo.svg", "<svg/>").await;
        site.get(&key, "/assets/").await.assert_text("missing");

        // A label site never falls back to another site.
        let blog = format!("blog.{key}");
        site.get(&blog, "/").await.assert_text("blog");
        let response = site.get(&blog, "/docs/").await;
        response.assert_status_not_found();
        assert_ne!(response.text(), "missing");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn head_and_conditional_requests_match_get() {
        let site = Site::start(|_| {}).await;
        let key = site.owner.z32();
        site.put("/pub/website/_/index.html", "home").await;

        let get = site.get(&key, "/").await;
        let head = site.request(Method::HEAD, &key, "/").await;
        head.assert_status_ok();
        head.assert_header(header::CONTENT_LENGTH, "4");
        assert!(head.as_bytes().is_empty());
        let etag = get.headers()[header::ETAG].clone();
        assert_eq!(head.headers()[header::ETAG], etag);

        for method in [Method::GET, Method::HEAD] {
            let response = site
                .request(method, &key, "/")
                .add_header(header::IF_NONE_MATCH, etag.clone())
                .await;
            response.assert_status(StatusCode::NOT_MODIFIED);
            response.assert_header(header::CACHE_CONTROL, "no-cache");
        }

        site.request(Method::HEAD, &key, "/missing")
            .await
            .assert_status_not_found();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn serves_web_file_types() {
        let site = Site::start(|_| {}).await;
        let key = site.owner.z32();
        let files: [(&str, &[u8], &str); 6] = [
            ("page.html", b"<!doctype html><p>hi</p>", "text/html"),
            ("style.css", b"body { color: red; }", "text/css"),
            ("app.js", b"console.log(1);", "text/javascript"),
            ("app.mjs", b"export const a = 1;", "application/javascript"),
            ("app.wasm", b"\0asm\x01\0\0\0", "application/wasm"),
            (
                "logo.svg",
                b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
                "image/svg+xml",
            ),
        ];
        for (name, body, _) in files {
            site.put(&format!("/pub/website/_/{name}"), body).await;
        }
        for (name, _, content_type) in files {
            site.get(&key, &format!("/{name}"))
                .await
                .assert_header(header::CONTENT_TYPE, content_type);
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn api_paths_and_other_hosts_behave_as_before() {
        // `/account` has a default IP rate limit, which needs the client address
        // a real connection carries; `TestServer` requests have none.
        let site = Site::start(|config| config.drive.rate_limits.clear()).await;
        let key = site.owner.z32();
        site.put("/pub/website/_/index.html", "home").await;
        site.put("/pub/data.txt", "data").await;

        // Legacy reads stay on the API, including through the SDK's `_pubky` host.
        for host in [key.clone(), format!("_pubky.{key}")] {
            let response = site.get(&host, "/pub/data.txt").await;
            response.assert_text("data");
            response.assert_header(header::VARY, "pubky-host");
        }
        let homeserver = site.context.keypair.public_key().z32();
        site.get(&homeserver, "/")
            .await
            .assert_text("Pubky Homeserver");
        // `/account` is an API route on a site host too, not a site folder.
        site.get(&key, "/account")
            .await
            .assert_status(StatusCode::UNAUTHORIZED);

        // The owner comes from `Host` alone, and cookies are neither used nor set.
        let other = Keypair::random().public_key().z32();
        let response = site
            .get(&key, "/")
            .add_header("pubky-host", other)
            .add_header(header::COOKIE, site.cookie.clone())
            .await;
        response.assert_text("home");
        assert!(!response.headers().contains_key(header::SET_COOKIE));

        site.get(&Keypair::random().public_key().z32(), "/")
            .await
            .assert_status_not_found();
        site.context
            .user_service
            .admin_disable(&site.owner)
            .await
            .unwrap();
        site.get(&key, "/")
            .await
            .assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn disabled_websites_keep_the_previous_behavior() {
        let site = Site::start(|config| config.drive.websites = false).await;
        let key = site.owner.z32();
        site.put("/pub/website/_/index.html", "home").await;

        site.get(&key, "/").await.assert_text("Pubky Homeserver");
        let info: serde_json::Value = site.server.get("/info").await.json();
        assert!(!info["features"]
            .as_array()
            .unwrap()
            .contains(&"websites".into()));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn rate_limits_match_the_site_path_and_metrics_skip_websites() {
        let site = Site::start(|config| {
            config.drive.rate_limits = vec![PathLimit {
                path: GlobPattern::new("/pub/website/_/index.html"),
                method: HttpMethod(Method::GET),
                quota: "1r/m".parse().unwrap(),
                key: LimitKeyType::User,
                burst: None,
                whitelist: Vec::new(),
            }];
        })
        .await;
        let key = site.owner.z32();
        site.put("/pub/website/_/index.html", "home").await;
        let storage_samples = || {
            site.context
                .metrics
                .render()
                .unwrap()
                .lines()
                .filter(|line| line.starts_with("storage_request_count_total{"))
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        let before = storage_samples();

        // `/` serves `index.html`, so both paths share the file's limit.
        site.get(&key, "/").await.assert_status_ok();
        site.get(&key, "/index.html")
            .await
            .assert_status(StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(storage_samples(), before);
    }
}
