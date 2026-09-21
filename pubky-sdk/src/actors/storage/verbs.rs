use reqwest::{Method, RequestBuilder, Response, StatusCode};

use super::core::{PublicStorage, SessionStorage};
use super::resource::{IntoPubkyResource, IntoResourcePath};
use super::stats::ResourceStats;
use crate::{PubkyHttpClient, Result, cross_log};

/// Interpret the result of a `HEAD` request into a shared outcome used by both
/// session and public storage clients.
async fn interpret_head(client: &PubkyHttpClient, resp: Response) -> Result<Option<Response>> {
    match resp.status() {
        StatusCode::NOT_FOUND | StatusCode::GONE => {
            cross_log!(debug, "HEAD request returned {}", resp.status());
            Ok(None)
        }
        _ => {
            cross_log!(debug, "HEAD request returned {}", resp.status());
            Ok(Some(client.check_http_status(resp).await?))
        }
    }
}

/// Send a prepared request and ensure the HTTP status indicates success.
async fn send_checked(client: &PubkyHttpClient, rb: RequestBuilder) -> Result<Response> {
    let resp = rb.send().await?;
    cross_log!(debug, "Request completed with status {}", resp.status());
    client.check_http_status(resp).await
}

/// Send a prepared `HEAD` request and interpret the outcome.
async fn send_head(client: &PubkyHttpClient, rb: RequestBuilder) -> Result<Option<Response>> {
    let resp = rb.send().await?;
    cross_log!(
        debug,
        "HEAD request completed with status {}",
        resp.status()
    );
    interpret_head(client, resp).await
}

//
// SessionStorage (authenticated, as-me)
//

impl SessionStorage {
    /// HTTP `GET` (as me) for an **absolute path**.
    ///
    /// Returns a successful response without consuming its body. Reading the body
    /// through the response can still fail.
    ///
    /// # Examples
    /// ```no_run
    /// # async fn ex(session: pubky::PubkySession) -> pubky::Result<()> {
    /// let text = session
    ///     .storage()
    ///     .get("/pub/my-cool-app/hello.txt").await?
    ///     .text().await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// A missing resource (404 or 410) is a [`crate::errors::RequestError::Server`]
    /// error, not an empty response. See [`SessionStorage`] for shared path,
    /// credential, transport, and HTTP failures.
    pub async fn get<P: IntoResourcePath>(&self, path: P) -> Result<Response> {
        let rb = self.request(Method::GET, path).await?;
        send_checked(&self.client, rb).await
    }

    /// Lightweight existence check (HEAD) for an **absolute path**.
    ///
    /// Returns `Ok(true)` on a successful response and `Ok(false)` on HTTP
    /// **404 Not Found** or **410 Gone**.
    ///
    /// # Errors
    /// Other non-success statuses, including 401/403 and 5xx, remain errors.
    /// See [`SessionStorage`] for shared path, credential, and transport failures;
    /// these are not converted to `false`.
    pub async fn exists<P: IntoResourcePath>(&self, path: P) -> Result<bool> {
        let rb = self.request(Method::HEAD, path).await?;
        Ok(send_head(&self.client, rb).await?.is_some())
    }

    /// Retrieve metadata via `HEAD` for an **absolute path** (no body).
    ///
    /// Returns `Ok(Some(stats))` on a successful response and `Ok(None)` on HTTP
    /// **404 Not Found** or **410 Gone**. Missing metadata headers or values that
    /// cannot be parsed leave the corresponding [`ResourceStats`] fields `None`.
    ///
    /// # Errors
    /// Other non-success statuses, including 401/403 and 5xx, remain errors.
    /// See [`SessionStorage`] for shared path, credential, and transport failures;
    /// these are not converted to `None`.
    pub async fn stats<P: IntoResourcePath>(&self, path: P) -> Result<Option<ResourceStats>> {
        let rb = self.request(Method::HEAD, path).await?;
        Ok(send_head(&self.client, rb)
            .await?
            .map(|resp| ResourceStats::from_headers(resp.headers())))
    }

    /// HTTP `PUT` (write) for an **absolute path**.
    ///
    /// Creates or replaces a file and returns the successful response. Requires
    /// a valid session with write permission. Directory targets are unsupported.
    ///
    /// # Errors
    /// See [`SessionStorage`] for shared request failures. Server errors include
    /// directory targets (400), file/directory path conflicts (409), and exceeded
    /// storage quotas (507). Uploading the request body can also fail.
    pub async fn put<P, B>(&self, path: P, body: B) -> Result<Response>
    where
        P: IntoResourcePath,
        B: Into<reqwest::Body>,
    {
        let rb = self.request(Method::PUT, path).await?.body(body);
        send_checked(&self.client, rb).await
    }

    /// Delete a file at an **absolute path** and return the successful response.
    ///
    /// Requires write permission. Directory targets are unsupported.
    ///
    /// # Errors
    /// A missing file returns a server error (404); deleting it again does not
    /// succeed silently. Directory targets return 400. See [`SessionStorage`]
    /// for shared path, credential, transport, and HTTP failures.
    pub async fn delete<P: IntoResourcePath>(&self, path: P) -> Result<Response> {
        let rb = self.request(Method::DELETE, path).await?;
        send_checked(&self.client, rb).await
    }
}

//
// PublicStorage (unauthenticated, any user)
//

impl PublicStorage {
    /// HTTP `GET` for an **addressed resource** (`pubky://<pk>/<path>`, `pubky<pk>/<path>`, or `(PublicKey, path)` tuple).
    ///
    /// # Examples
    /// ```no_run
    /// # async fn ex(user: pubky::PublicKey) -> pubky::Result<()> {
    /// let storage = pubky::PublicStorage::new()?;
    /// let addr = format!("pubky://{}/pub/my-cool-app/file.txt", user.z32());
    /// let resp = storage.get(addr).await?;
    /// let bytes = resp.bytes().await?;
    ///
    /// // Or use a tuple:
    /// let resp2 = storage.get((&user, "/pub/my-cool-app/file.txt")).await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// - [`crate::errors::Error::Request`] on HTTP transport failures or when the server
    ///   responds with a non-success status (the server message is captured).
    /// - [`crate::errors::Error::Parse`] if `addr` cannot be converted into a valid
    ///   addressed resource/URL.
    pub async fn get<A: IntoPubkyResource>(&self, addr: A) -> Result<Response> {
        let rb = self.request(Method::GET, addr).await?;
        send_checked(&self.client, rb).await
    }

    /// HEAD existence check for an addressed resource.
    ///
    /// # Errors
    /// - Propagates transport failures while issuing the `HEAD` request.
    /// - Returns [`crate::errors::Error::Parse`] if `addr` cannot be converted into a valid addressed resource.
    pub async fn exists<A: IntoPubkyResource>(&self, addr: A) -> Result<bool> {
        let rb = self.request(Method::HEAD, addr).await?;
        Ok(send_head(&self.client, rb).await?.is_some())
    }

    /// Metadata via `HEAD` for an addressed resource (no body).
    ///
    /// # Errors
    /// - Propagates transport failures while issuing the `HEAD` request.
    /// - Returns [`crate::errors::Error::Parse`] if `addr` cannot be converted into a valid addressed resource.
    pub async fn stats<A: IntoPubkyResource>(&self, addr: A) -> Result<Option<ResourceStats>> {
        let rb = self.request(Method::HEAD, addr).await?;
        Ok(send_head(&self.client, rb)
            .await?
            .map(|resp| ResourceStats::from_headers(resp.headers())))
    }
}
