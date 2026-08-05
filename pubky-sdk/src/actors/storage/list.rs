use reqwest::Method;
use url::Url;

use super::core::{PublicStorage, SessionStorage, dir_trailing_slash_error};
use crate::actors::storage::resource::{
    IntoPubkyResource, IntoResourcePath, PubkyResource, ResourcePath,
};
use crate::util::check_http_status;
use crate::{Result, cross_log};

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
    /// - Propagates transport preparation failures when building the request URL.
    pub fn list<P: IntoResourcePath>(&self, path: P) -> Result<ListBuilder<'_>> {
        let path: ResourcePath = path.into_abs_path()?;
        if !path.as_str().ends_with('/') {
            return Err(dir_trailing_slash_error().into());
        }
        let resource = PubkyResource::new(self.user.clone(), path.as_str())?;
        let url = resource.to_transport_url()?;
        Ok(ListBuilder::session(self, url))
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
    Session(&'a SessionStorage),
    Public(&'a PublicStorage),
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
    url: Url,
    reverse: bool,
    shallow: bool,
    limit: Option<u16>,
    cursor: Option<String>,
}

impl<'a> ListBuilder<'a> {
    #[inline]
    const fn new(scope: ListScope<'a>, url: Url) -> Self {
        Self {
            scope,
            url,
            reverse: false,
            shallow: false,
            limit: None,
            cursor: None,
        }
    }

    #[inline]
    const fn session(storage: &'a SessionStorage, url: Url) -> Self {
        Self::new(ListScope::Session(storage), url)
    }

    #[inline]
    const fn public(storage: &'a PublicStorage, url: Url) -> Self {
        Self::new(ListScope::Public(storage), url)
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
    /// - Returns [`crate::errors::RequestError::Validation`] if any resource line returned by the server is invalid.
    pub async fn send(self) -> Result<Vec<PubkyResource>> {
        // 1) Build query params
        let mut url = self.url;
        {
            let mut q = url.query_pairs_mut();
            if self.reverse {
                q.append_key_only("reverse");
            }
            if self.shallow {
                q.append_key_only("shallow");
            }
            if let Some(limit) = self.limit {
                q.append_pair("limit", &limit.to_string());
            }
            if let Some(cursor) = self.cursor {
                q.append_pair("cursor", &cursor);
            }
        }

        // 2) Build request per scope
        let rb = match self.scope {
            ListScope::Public(storage) => {
                storage
                    .client
                    .cross_request(Method::GET, url.clone())
                    .await?
            }
            ListScope::Session(storage) => {
                let rb = storage
                    .client
                    .cross_request(Method::GET, url.clone())
                    .await?;
                storage.attach_credential(rb).await?
            }
        };

        // 3) Send and parse
        let resp = rb.send().await?;
        cross_log!(
            debug,
            "Request completed with status {} (LIST {})",
            resp.status(),
            resp.url()
        );
        let resp = check_http_status(resp).await?;

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
