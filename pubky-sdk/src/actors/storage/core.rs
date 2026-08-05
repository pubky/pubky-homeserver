use crate::PublicKey;
use crate::actors::session::credential::SessionCredential;
use reqwest::{Method, RequestBuilder};
use std::sync::Arc;

use super::resource::{IntoPubkyResource, IntoResourcePath, PubkyResource, ResourcePath};
use crate::{
    PubkyHttpClient, PubkySession, cross_log,
    errors::{RequestError, Result},
};

/// Read and write **your own data** with simple path-based operations (authenticated).
///
/// Obtained via [`PubkySession::storage()`]. The user is implied by the session —
/// you only supply **absolute paths** (e.g. `"/pub/my.app/file.txt"`).
/// The SDK resolves the homeserver and attaches credentials automatically.
///
/// # Path conventions
///
/// - Paths under `/pub/` are **publicly readable** by anyone via [`PublicStorage`].
/// - Paths under `/priv/` are **private** to the signed-in user.
///
/// # Example
///
/// ```no_run
/// # async fn example(session: pubky::PubkySession) -> pubky::Result<()> {
/// let storage = session.storage();
///
/// // Write
/// storage.put("/pub/my.app/hello.txt", "world").await?;
///
/// // Read
/// let body = storage.get("/pub/my.app/hello.txt").await?.text().await?;
///
/// // Check existence
/// let exists = storage.exists("/pub/my.app/hello.txt").await?;
///
/// // Metadata (content-length, content-type, etag, last-modified)
/// if let Some(stats) = storage.stats("/pub/my.app/hello.txt").await? {
///     println!("size: {:?}", stats.content_length);
/// }
///
/// // List a directory (path must end with `/`)
/// let entries = storage.list("/pub/my.app/")?.limit(50).send().await?;
///
/// // Delete
/// storage.delete("/pub/my.app/hello.txt").await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct SessionStorage {
    pub(crate) client: PubkyHttpClient,
    pub(crate) user: PublicKey,
    /// Cloned credential — sharing the same `Arc<dyn SessionCredential>` as
    /// the parent session is cheap and gives the storage layer access to the
    /// latest authentication material (with auto-refresh for grant credentials).
    pub(crate) credential: Arc<dyn SessionCredential>,
}

impl SessionStorage {
    /// Construct from an existing session.
    ///
    /// Equivalent to `session.storage()`.
    #[must_use]
    pub fn new(session: &PubkySession) -> Self {
        Self {
            client: session.client.clone(),
            user: session.info().public_key().clone(),
            credential: Arc::clone(session.credential()),
        }
    }

    /// Convenience: unauthenticated public reader using the same client.
    #[must_use]
    pub fn public(&self) -> PublicStorage {
        PublicStorage {
            client: self.client.clone(),
        }
    }

    /// Build a request for this storage.
    ///
    /// - Paths are **absolute** (session-scoped).
    /// - The session credential attaches the right authentication header
    ///   (cookie or bearer token) and refreshes the grant credential proactively if needed.
    pub(crate) async fn request<P: IntoResourcePath>(
        &self,
        method: Method,
        path: P,
    ) -> Result<RequestBuilder> {
        let path: ResourcePath = path.into_abs_path()?;
        let resource = PubkyResource::new(self.user.clone(), path.as_str())?;
        let url = resource.to_transport_url()?;
        cross_log!(debug, "Session storage {} request {}", method, url);
        let rb = self.client.cross_request(method, url).await?;
        self.attach_credential(rb).await
    }

    /// Attach the session credential to a request builder.
    pub(crate) async fn attach_credential(&self, rb: RequestBuilder) -> Result<RequestBuilder> {
        self.credential.attach(rb, &self.client).await
    }
}

/// Read **anyone's public data** without signing in (unauthenticated).
///
/// No keys or session needed. Accepts **addressed resources** that pair a user's
/// public key with an absolute path. Supported address formats:
/// - `"pubky://<z32-pubkey>/pub/..."` (canonical)
/// - `"pubky<z32-pubkey>/pub/..."` (compact)
/// - `(PublicKey, "/pub/...")` tuple
///
/// Writes are not available — use [`SessionStorage`] for that.
///
/// # Example
///
/// ```no_run
/// use pubky::{Pubky, PublicKey};
///
/// # async fn example() -> pubky::Result<()> {
/// let pubky = Pubky::new()?;
/// let user: PublicKey = "o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo"
///     .parse().unwrap();
///
/// let public = pubky.public_storage();
///
/// // Read a file
/// let body = public
///     .get(format!("pubky://{}/pub/pubky.app/profile.json", user.z32()))
///     .await?
///     .text().await?;
///
/// // Or use a tuple
/// let exists = public.exists((&user, "/pub/pubky.app/profile.json")).await?;
///
/// // List a directory
/// let entries = public
///     .list(format!("pubky://{}/pub/pubky.app/", user.z32()))?
///     .shallow(true)
///     .send().await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct PublicStorage {
    pub(crate) client: PubkyHttpClient,
}

impl PublicStorage {
    /// Create a public (unauthenticated) storage handle using a new client.
    ///
    /// Tip: If you already have a `Pubky` facade, prefer `pubky.public_storage()`
    /// to reuse its underlying client and configuration.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error`] if the underlying [`PubkyHttpClient`] cannot be constructed.
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: PubkyHttpClient::new()?,
        })
    }

    /// Build a request for this public storage (no cookies).
    pub(crate) async fn request<A: IntoPubkyResource>(
        &self,
        method: Method,
        addr: A,
    ) -> Result<RequestBuilder> {
        let resource: PubkyResource = addr.into_pubky_resource()?;
        let url = resource.to_transport_url()?;
        cross_log!(debug, "Public storage {} request {}", method, url);
        let rb = self.client.cross_request(method, url).await?;
        Ok(rb)
    }
}

/// Helper: validation error for directory listings without trailing slash.
#[inline]
pub fn dir_trailing_slash_error() -> RequestError {
    RequestError::Validation {
        message: "directory listings must end with `/`".into(),
    }
}
