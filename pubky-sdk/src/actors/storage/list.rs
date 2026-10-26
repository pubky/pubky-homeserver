use reqwest::Method;
use url::Url;

use super::core::{PublicStorage, SessionStorage, dir_trailing_slash_error};
use crate::actors::storage::resource::{
    IntoPubkyResource, IntoResourcePath, PubkyResource, ResourcePath,
};
use crate::errors::RequestError;
use crate::util::read_response_body;
use crate::{Result, cross_log};

/// Maximum size of a directory listing response. The homeserver returns at
/// most 1000 entries per page, so this leaves ample room for long paths.
const MAX_LIST_BYTES: usize = 4 * 1024 * 1024;

/// Read a listing response within [`MAX_LIST_BYTES`].
async fn read_list_body(response: reqwest::Response) -> Result<Vec<u8>> {
    read_response_body(response, MAX_LIST_BYTES)
        .await
        .map_err(|error| {
            error.into_error(|| RequestError::Validation {
                message: format!("List response exceeds the {MAX_LIST_BYTES}-byte limit"),
            })
        })
}

impl SessionStorage {
    /// Directory listing **as me** (authenticated).
    ///
    /// Path **must end with `/`**. Call [`ListBuilder::send`] on the returned
    /// builder to fetch addressed [`PubkyResource`] entries.
    ///
    /// An empty page yields an empty vector; a missing directory is a server error (404).
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
    /// Building validates the path (including its trailing `/`) and prepares the URL.
    /// Sending can fail on invalid cursors (400), invalid response entries, or body
    /// reads. See [`SessionStorage`] for shared errors.
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
    /// - Returns [`crate::errors::RequestError::Validation`] if any resource line returned by the server is invalid
    ///   or the listing exceeds the 4 MiB response limit.
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

        // 2) Send with the scope's credentials.
        let (client, resp) = match self.scope {
            ListScope::Public(storage) => (
                &storage.client,
                storage
                    .client
                    .cross_request(Method::GET, url.clone())
                    .await?
                    .send()
                    .await?,
            ),
            ListScope::Session(storage) => {
                let rb = storage
                    .client
                    .cross_request(Method::GET, url.clone())
                    .await?;
                (&storage.client, storage.send(rb).await?)
            }
        };

        // 3) Parse the response.
        cross_log!(
            debug,
            "Request completed with status {} (LIST {})",
            resp.status(),
            resp.url()
        );
        let resp = client.check_http_status(resp).await?;

        let bytes = read_list_body(resp).await?;
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::Error;
    use crate::util::tests::serve_response;

    #[tokio::test]
    async fn list_bodies_are_bounded() {
        let body = b"pubky://8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo/pub/app/a.txt\n";
        let (response, _connection) =
            serve_response(200, &format!("Content-Length: {}\r\n", body.len()), body).await;
        assert_eq!(read_list_body(response).await.unwrap(), body);

        let declared = MAX_LIST_BYTES + 1;
        let (response, _connection) =
            serve_response(200, &format!("Content-Length: {declared}\r\n"), b"").await;
        let error = read_list_body(response).await.unwrap_err();
        let Error::Request(RequestError::Validation { message }) = error else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(
            message,
            format!("List response exceeds the {MAX_LIST_BYTES}-byte limit")
        );
    }
}
