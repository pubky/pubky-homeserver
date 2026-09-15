use percent_encoding::percent_decode_str;
use reqwest::Method;
use url::Url;

use super::core::{PublicStorage, SessionStorage, dir_trailing_slash_error};
use crate::actors::storage::resource::{
    IntoPubkyResource, IntoResourcePath, PubkyResource, ResourcePath,
};
use crate::{Result, cross_log, errors::RequestError};

impl SessionStorage {
    /// Directory listing **as me** (authenticated).
    ///
    /// Requirements:
    /// - Path **must** point to a directory and **must end with `/`**.
    ///
    /// Returns addressed [`PubkyResource`] entries.
    ///
    /// # Example
    /// ```no_run
    /// # async fn example(session: pubky::PubkySession) -> pubky::Result<()> {
    /// let entries = session
    ///     .storage()
    ///     .list("/pub/my-cool-app/")?
    ///     .limit(100)
    ///     .shallow(true)
    ///     .send()
    ///     .await?;
    /// for entry in entries {
    ///     println!("{}", entry.to_pubky_url());
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// - Returns [`crate::errors::RequestError::Validation`] if `path` cannot be converted into an absolute resource path ending with `/`.
    pub fn list<P: IntoResourcePath>(&self, path: P) -> Result<ListBuilder<'_>> {
        let path: ResourcePath = path.into_abs_path()?;
        if !path.as_str().ends_with('/') {
            return Err(dir_trailing_slash_error().into());
        }
        Ok(ListBuilder::session(self, path))
    }
}

impl PublicStorage {
    /// Directory listing **public** (unauthenticated).
    ///
    /// Requirements:
    /// - Address **must** point to a directory and **must end with `/`**.
    ///
    /// Returns addressed [`PubkyResource`] entries.
    ///
    /// # Errors
    /// - Returns [`crate::errors::RequestError::Validation`] if `addr` cannot be converted into an addressed directory ending with `/`.
    /// - Propagates transport preparation failures when building the request URL.
    pub fn list<A: IntoPubkyResource>(&self, addr: A) -> Result<ListBuilder<'_>> {
        let resource: PubkyResource = addr.into_pubky_resource()?;
        if !resource.path.as_str().ends_with('/') {
            return Err(dir_trailing_slash_error().into());
        }
        let url = resource.to_transport_url()?;
        Ok(ListBuilder::public(self, url))
    }
}

/// Internal scope for a listing request.
#[derive(Debug)]
enum ListScope<'a> {
    Session(&'a SessionStorage, ResourcePath),
    Public(&'a PublicStorage, Url),
}

/// Unified builder for homeserver `LIST` queries (works for session & public).
///
/// Configure optional flags like `reverse`, `shallow`, `limit`, and `cursor`,
/// then call [`send`](Self::send) to perform the request.
///
/// Returned entries are [`PubkyResource`] values.
///
/// Built via:
/// - [`SessionStorage::list`] for authenticated “as me” listings.
/// - [`PublicStorage::list`] for unauthenticated public listings.
#[derive(Debug)]
#[must_use]
pub struct ListBuilder<'a> {
    scope: ListScope<'a>,
    reverse: bool,
    shallow: bool,
    limit: Option<u16>,
    cursor: Option<String>,
}

impl<'a> ListBuilder<'a> {
    #[inline]
    const fn new(scope: ListScope<'a>) -> Self {
        Self {
            scope,
            reverse: false,
            shallow: false,
            limit: None,
            cursor: None,
        }
    }

    #[inline]
    const fn session(storage: &'a SessionStorage, path: ResourcePath) -> Self {
        Self::new(ListScope::Session(storage, path))
    }

    #[inline]
    const fn public(storage: &'a PublicStorage, url: Url) -> Self {
        Self::new(ListScope::Public(storage, url))
    }

    /// List newest-first instead of oldest-first.
    pub const fn reverse(mut self, reverse: bool) -> Self {
        self.reverse = reverse;
        self
    }

    /// Do not recurse into subdirectories.
    pub const fn shallow(mut self, shallow: bool) -> Self {
        self.shallow = shallow;
        self
    }

    /// Maximum number of entries to return (homeserver may cap).
    pub const fn limit(mut self, limit: u16) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Resume listing from a previous cursor.
    ///
    /// Pass the last entry's [`to_pubky_url()`](crate::PubkyResource::to_pubky_url)
    /// from a previous listing response. Use it to paginate through large
    /// directories.
    pub fn cursor(mut self, cursor: &str) -> Self {
        self.cursor = Some(cursor.to_string());
        self
    }

    /// Execute the LIST request and return addressed entries.
    ///
    /// # Errors
    /// - Propagates transport failures while issuing the HTTP request.
    /// - Returns [`crate::errors::RequestError::Validation`] if the session credential belongs to a different homeserver, the cursor URI contains invalid UTF-8, or any resource line returned by the server is invalid.
    pub async fn send(self) -> Result<Vec<PubkyResource>> {
        let (client, rb) = match self.scope {
            ListScope::Public(storage, url) => (
                &storage.client,
                storage.client.cross_request(Method::GET, url).await?,
            ),
            ListScope::Session(storage, path) => {
                (&storage.client, storage.request(Method::GET, path).await?)
            }
        };
        let (http_client, request) = rb.build_split();
        let mut request = request?;
        {
            let mut query = request.url_mut().query_pairs_mut();
            if self.reverse {
                query.append_key_only("reverse");
            }
            if self.shallow {
                query.append_key_only("shallow");
            }
            if let Some(limit) = self.limit {
                query.append_pair("limit", &limit.to_string());
            }
            if let Some(cursor) = self.cursor {
                // The homeserver cursor is a decoded owner/path, not a URI.
                if cursor.starts_with("pubky://") {
                    let cursor = percent_decode_str(&cursor).decode_utf8().map_err(|_err| {
                        RequestError::Validation {
                            message: "cursor URI is not valid UTF-8".into(),
                        }
                    })?;
                    query.append_pair("cursor", &cursor);
                } else {
                    query.append_pair("cursor", &cursor);
                }
            }
        }

        let resp = http_client.execute(request).await?;
        cross_log!(
            debug,
            "Request completed with status {} (LIST {})",
            resp.status(),
            resp.url()
        );
        let resp = client.check_http_status(resp).await?;

        let bytes = resp.bytes().await?;
        let mut out = Vec::new();
        for line in String::from_utf8_lossy(&bytes).lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            out.push(Self::parse_resource_line(trimmed)?);
        }
        Ok(out)
    }

    fn parse_resource_line(line: &str) -> Result<PubkyResource> {
        if line.starts_with("http://") || line.starts_with("https://") {
            let url = Url::parse(line)?;
            PubkyResource::from_transport_url(&url)
        } else {
            line.parse()
        }
    }
}
