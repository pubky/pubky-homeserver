use reqwest::{
    Method, RequestBuilder, Response, StatusCode,
    header::{HeaderValue, IF_MATCH, IF_NONE_MATCH},
};

use super::core::{PublicStorage, SessionStorage};
use super::resource::{IntoPubkyResource, IntoResourcePath};
use super::stats::ResourceStats;
use crate::{Result, cross_log, errors::RequestError, util::check_http_status};

/// Interpret the result of a `HEAD` request into a shared outcome used by both
/// session and public storage clients.
async fn interpret_head(resp: Response) -> Result<Option<Response>> {
    match resp.status() {
        StatusCode::NOT_FOUND | StatusCode::GONE => {
            cross_log!(debug, "HEAD request returned {}", resp.status());
            Ok(None)
        }
        _ => {
            cross_log!(debug, "HEAD request returned {}", resp.status());
            Ok(Some(check_http_status(resp).await?))
        }
    }
}

/// Send a prepared request and ensure the HTTP status indicates success.
async fn send_checked(rb: RequestBuilder) -> Result<Response> {
    let resp = rb.send().await?;
    cross_log!(debug, "Request completed with status {}", resp.status());
    check_http_status(resp).await
}

/// Send a prepared `HEAD` request and interpret the outcome.
async fn send_head(rb: RequestBuilder) -> Result<Option<Response>> {
    let resp = rb.send().await?;
    cross_log!(
        debug,
        "HEAD request completed with status {}",
        resp.status()
    );
    interpret_head(resp).await
}

//
// SessionStorage (authenticated, as-me)
//

impl SessionStorage {
    /// HTTP `GET` (as me) for an **absolute path**.
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
    /// - [`crate::errors::Error::Request`] on HTTP transport failures or when the server
    ///   responds with a non-success status (the server message is captured).
    /// - [`crate::errors::Error::Parse`] if `path` cannot be converted into a valid
    ///   resource/URL.
    pub async fn get<P: IntoResourcePath>(&self, path: P) -> Result<Response> {
        let rb = self.request(Method::GET, path).await?;
        send_checked(rb).await
    }

    /// Lightweight existence check (HEAD) for an **absolute path**.
    ///
    /// # Errors
    /// - Propagates transport failures while issuing the `HEAD` request.
    /// - Returns [`crate::errors::Error::Parse`] if `path` cannot be converted into a valid resource.
    pub async fn exists<P: IntoResourcePath>(&self, path: P) -> Result<bool> {
        let rb = self.request(Method::HEAD, path).await?;
        Ok(send_head(rb).await?.is_some())
    }

    /// Retrieve metadata via `HEAD` for an **absolute path** (no body).
    ///
    /// # Errors
    /// - Propagates transport failures while issuing the `HEAD` request.
    /// - Returns [`crate::errors::Error::Parse`] if `path` cannot be converted into a valid resource.
    pub async fn stats<P: IntoResourcePath>(&self, path: P) -> Result<Option<ResourceStats>> {
        let rb = self.request(Method::HEAD, path).await?;
        Ok(send_head(rb)
            .await?
            .map(|resp| ResourceStats::from_headers(resp.headers())))
    }

    /// HTTP `PUT` (write) for an **absolute path**.
    ///
    /// Requires a valid session; this handle is authenticated already.
    ///
    /// # Errors
    /// - [`crate::errors::Error::Request`] on HTTP transport failures or when the server
    ///   responds with a non-success status (the server message is captured).
    /// - [`crate::errors::Error::Parse`] if `path` cannot be converted into a valid
    ///   resource/URL.
    pub async fn put<P, B>(&self, path: P, body: B) -> Result<Response>
    where
        P: IntoResourcePath,
        B: Into<reqwest::Body>,
    {
        let rb = self.request(Method::PUT, path).await?.body(body);
        send_checked(rb).await
    }

    /// Write a resource only if its current `ETag` matches `etag`.
    ///
    /// Pass the ASCII value of a strong tag returned by [`ResourceStats::etag`]. A
    /// missing resource or stale `ETag` produces a server error with status
    /// [`StatusCode::PRECONDITION_FAILED`].
    ///
    /// Use the `ETag` from the same response as the resource body being modified.
    /// Reading the `ETag` in a later request could observe a newer representation.
    ///
    /// # Errors
    /// - Returns [`crate::errors::RequestError::Validation`] when `etag` is weak
    ///   or cannot be represented as a strong HTTP entity tag.
    /// - Returns [`crate::errors::RequestError::UnsupportedFeature`] when the
    ///   homeserver does not advertise conditional writes.
    /// - Propagates request construction, transport, and server failures.
    pub async fn put_if_match<P, B>(&self, path: P, body: B, etag: &str) -> Result<Response>
    where
        P: IntoResourcePath,
        B: Into<reqwest::Body>,
    {
        let path = path.into_abs_path()?;
        let etag = strong_etag_header_value(etag)?;
        let rb = self
            .conditional_request(Method::PUT, path)
            .await?
            .header(IF_MATCH, etag)
            .body(body);
        send_checked(rb).await
    }

    /// Create a resource only if no current representation exists.
    ///
    /// An existing resource produces a server error with status
    /// [`StatusCode::PRECONDITION_FAILED`].
    ///
    /// # Errors
    /// - Returns [`crate::errors::RequestError::UnsupportedFeature`] when the
    ///   homeserver does not advertise conditional writes.
    /// - Propagates request construction, transport, and server failures.
    pub async fn put_if_absent<P, B>(&self, path: P, body: B) -> Result<Response>
    where
        P: IntoResourcePath,
        B: Into<reqwest::Body>,
    {
        let path = path.into_abs_path()?;
        let rb = self
            .conditional_request(Method::PUT, path)
            .await?
            .header(IF_NONE_MATCH, HeaderValue::from_static("*"))
            .body(body);
        send_checked(rb).await
    }

    /// HTTP `DELETE` for an **absolute path**.
    ///
    /// # Errors
    /// - [`crate::errors::Error::Request`] on HTTP transport failures or when the server
    ///   responds with a non-success status (the server message is captured).
    /// - [`crate::errors::Error::Parse`] if `path` cannot be converted into a valid
    ///   resource/URL.
    pub async fn delete<P: IntoResourcePath>(&self, path: P) -> Result<Response> {
        let rb = self.request(Method::DELETE, path).await?;
        send_checked(rb).await
    }
}

fn strong_etag_header_value(etag: &str) -> Result<HeaderValue> {
    if (etag.starts_with("W/\"") && etag.ends_with('"'))
        || !etag
            .bytes()
            .all(|byte| byte == b'!' || (b'#'..=b'~').contains(&byte))
    {
        return Err(RequestError::Validation {
            message: "ETag must be an ASCII strong validator".into(),
        }
        .into());
    }

    Ok(HeaderValue::from_str(&format!("\"{etag}\"")).expect("validated ETag is a valid header"))
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
        send_checked(rb).await
    }

    /// HEAD existence check for an addressed resource.
    ///
    /// # Errors
    /// - Propagates transport failures while issuing the `HEAD` request.
    /// - Returns [`crate::errors::Error::Parse`] if `addr` cannot be converted into a valid addressed resource.
    pub async fn exists<A: IntoPubkyResource>(&self, addr: A) -> Result<bool> {
        let rb = self.request(Method::HEAD, addr).await?;
        Ok(send_head(rb).await?.is_some())
    }

    /// Metadata via `HEAD` for an addressed resource (no body).
    ///
    /// # Errors
    /// - Propagates transport failures while issuing the `HEAD` request.
    /// - Returns [`crate::errors::Error::Parse`] if `addr` cannot be converted into a valid addressed resource.
    pub async fn stats<A: IntoPubkyResource>(&self, addr: A) -> Result<Option<ResourceStats>> {
        let rb = self.request(Method::HEAD, addr).await?;
        Ok(send_head(rb)
            .await?
            .map(|resp| ResourceStats::from_headers(resp.headers())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strong_etag_header_value_quotes_opaque_validator() {
        assert_eq!(
            strong_etag_header_value("").unwrap(),
            HeaderValue::from_static("\"\"")
        );
        assert_eq!(
            strong_etag_header_value("abc123").unwrap(),
            HeaderValue::from_static("\"abc123\"")
        );
        assert_eq!(
            strong_etag_header_value("W/abc123").unwrap(),
            HeaderValue::from_static("\"W/abc123\"")
        );
    }

    #[test]
    fn test_strong_etag_header_value_rejects_invalid_validator() {
        strong_etag_header_value("W/\"abc123\"").unwrap_err();
        strong_etag_header_value("\"abc123\"").unwrap_err();
        strong_etag_header_value("has space").unwrap_err();
        strong_etag_header_value("line\nbreak").unwrap_err();
    }
}
