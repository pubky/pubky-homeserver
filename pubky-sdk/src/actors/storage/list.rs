use reqwest::Method;
use url::Url;

use super::core::{PublicStorage, SessionStorage};
use super::resource::{IntoPubkyResource, IntoResourcePath, PubkyResource};
use crate::actors::session::credential::SessionCredential;
use crate::errors::RequestError;
use crate::util::read_response_body;
use crate::{PubkyHttpClient, Result, cross_log};

/// Maximum size, inclusive, of a directory listing response. A client-side
/// bound: the homeserver returns at most 1000 entries per page, so this leaves
/// ample room for long paths.
const MAX_LIST_BYTES: usize = 4 * 1024 * 1024;

/// Read a listing response within [`MAX_LIST_BYTES`].
async fn read_list_body(response: reqwest::Response) -> Result<Vec<u8>> {
    read_response_body(response, MAX_LIST_BYTES, "List response").await
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
        let resource = PubkyResource::new(self.user.clone(), path)?;
        ListBuilder::new(&resource, &self.client, Some(self.credential.as_ref()))
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
        let resource = addr.into_pubky_resource()?;
        ListBuilder::new(&resource, &self.client, None)
    }
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
    client: &'a PubkyHttpClient,
    credential: Option<&'a dyn SessionCredential>,
    url: Url,
    reverse: bool,
    shallow: bool,
    limit: Option<u16>,
    cursor: Option<String>,
}

impl<'a> ListBuilder<'a> {
    fn new(
        resource: &PubkyResource,
        client: &'a PubkyHttpClient,
        credential: Option<&'a dyn SessionCredential>,
    ) -> Result<Self> {
        if !resource.path.as_str().ends_with('/') {
            return Err(RequestError::Validation {
                message: "directory listings must end with `/`".into(),
            }
            .into());
        }
        Ok(Self {
            client,
            credential,
            url: resource.to_transport_url()?,
            reverse: false,
            shallow: false,
            limit: None,
            cursor: None,
        })
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
    /// - Returns [`crate::errors::RequestError::Oversized`] if the listing exceeds the 4 MiB response limit.
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
        let request = self.client.cross_request(Method::GET, url).await?;
        let response = match self.credential {
            Some(credential) => credential.send(request, self.client).await?,
            None => request.send().await?,
        };

        // 3) Parse the response.
        cross_log!(
            debug,
            "Request completed with status {} (LIST {})",
            response.status(),
            response.url()
        );
        let response = self.client.check_http_status(response).await?;
        let bytes = read_list_body(response).await?;
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

    /// Listing lines are `pubky://<owner><path>`; legacy HTTP URLs are also accepted.
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
        let Error::Request(RequestError::Oversized { limit, label }) = error else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!((limit, label.as_str()), (MAX_LIST_BYTES, "List response"));
    }
}
