use std::sync::Arc;

use pubky_common::crypto::PublicKey;

use super::SessionInfo;

use super::credential::SessionCredential;
use crate::errors::Error;
use crate::{PubkyHttpClient, Result, SessionStorage, cross_log};

/// Your authenticated handle after signing in.
///
/// A `PubkySession` represents one user/identity authenticated to a homeserver.
/// It carries credentials automatically and provides access to
/// [`SessionStorage`] for reading and writing data as the signed-in user.
///
/// # What it does
///
/// - Attaches the correct authentication header (`Cookie` or `Authorization: Bearer`)
///   to every request targeting this user's homeserver.
/// - Provides [`storage()`](Self::storage) for path-based CRUD operations as this user.
/// - Supports session lifecycle: [`revalidate()`](Self::revalidate) and
///   [`signout()`](Self::signout).
/// - Offers credential-specific views via [`as_grant()`](Self::as_grant) and
///   [`as_cookie()`](Self::as_cookie) for grant management or secret export.
///
/// # Concurrency
///
/// `PubkySession` is **cheap to clone** and **thread-safe**. Pass clones freely to
/// async tasks or threads.
///
/// # Persistence
///
/// Sessions can survive process restarts. See
/// [`GrantSessionView::export_local_secret`](crate::GrantSessionView::export_local_secret)
/// and [`Pubky::restore_session`](crate::Pubky::restore_session).
///
/// # Example
///
/// ```no_run
/// # async fn run(session: pubky::PubkySession) -> pubky::Result<()> {
/// // Write data
/// session.storage().put("/pub/my.app/greeting.txt", "hello").await?;
///
/// // Read it back
/// let text = session.storage().get("/pub/my.app/greeting.txt").await?.text().await?;
/// assert_eq!(text, "hello");
///
/// // List a directory
/// let entries = session.storage().list("/pub/my.app/")?.send().await?;
///
/// // Sign out when done
/// session.signout().await.map_err(|(e, _session)| e)?;
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct PubkySession {
    pub(crate) client: PubkyHttpClient,
    pub(crate) credential: Arc<dyn SessionCredential>,
}

impl PubkySession {
    /// Build a session from a fully-formed credential. Used by the grant-mode
    /// constructors in `crate::actors::auth::grant::grant_exchange` and the
    /// cookie constructors in `crate::actors::auth::cookie`.
    pub(crate) fn from_credential(
        client: PubkyHttpClient,
        credential: Arc<dyn SessionCredential>,
    ) -> Self {
        Self { client, credential }
    }

    /// Returns the current session info.
    ///
    /// `SessionInfo` is small and `Clone`-cheap; this method returns by value
    /// so the API is uniform across credential types.
    #[must_use]
    pub fn info(&self) -> SessionInfo {
        self.credential.info()
    }

    /// Returns a reference to the internal `PubkyHttpClient`.
    ///
    /// Raw transport handle. No per-session credential injection. Use `storage()`
    /// for authenticated, session-scoped requests.
    #[must_use]
    pub const fn client(&self) -> &PubkyHttpClient {
        &self.client
    }

    /// Internal accessor for the credential.
    pub(crate) fn credential(&self) -> &Arc<dyn SessionCredential> {
        &self.credential
    }

    /// Generic downcast of the active credential to a concrete adapter type.
    ///
    /// Auth-side view accessors use this to reach a concrete credential
    /// without the session layer naming it directly.
    pub(crate) fn try_downcast_credential<T: SessionCredential + 'static>(&self) -> Option<&T> {
        self.credential.as_any().downcast_ref::<T>()
    }

    /// User public key for this session (cheap clone of the cached snapshot).
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.info().public_key().clone()
    }

    /// Round-trip the current session with the homeserver to verify it's still valid.
    ///
    /// Returns:
    /// - `Ok(Some(session))` if the server recognizes and returns the session (still valid).
    /// - `Ok(None)` if the session no longer exists (expired/invalidated).
    /// - `Err(_)` for transport or server errors unrelated to validity.
    ///
    /// This does *not* mutate the session; it's a sanity/validity check.
    ///
    /// # Errors
    /// - Propagates transport failures from the session endpoint.
    /// - Returns [`crate::errors::Error::Authentication`] if the homeserver rejects the request.
    pub async fn revalidate(&self) -> Result<Option<SessionInfo>> {
        let user = self.info().public_key().clone();
        cross_log!(info, "Revalidating session for {}", user);
        self.credential.revalidate(&self.client, &user).await
    }

    /// Sign out and invalidate this session server-side.
    ///
    /// - **On success:** the session is consumed (dropped).
    /// - **On failure:** you get `(Error, Self)` back so you can retry or inspect.
    ///
    /// # Errors
    /// - Returns the original [`crate::errors::Error`] alongside `self` when the transport
    ///   request fails or the homeserver responds with a non-success status.
    pub async fn signout(self) -> std::result::Result<(), (Error, Self)> {
        cross_log!(info, "Signing out session for {}", self.info().public_key());
        if let Err(e) = self.credential.signout(&self.client).await {
            cross_log!(error, "Signout failed: {}", e);
            return Err((e, self));
        }
        cross_log!(info, "Session signed out");
        Ok(())
    }

    // `as_grant()` / `as_cookie()` view accessors are defined in
    // `actors/auth/grant/view.rs` and `actors/auth/cookie/view.rs` via inherent
    // `impl PubkySession { … }` blocks. This keeps session/core.rs ignorant
    // of concrete credential adapters while preserving the discoverable
    // method syntax on `PubkySession`.

    /// Create a **session-mode** Storage bound to this user session.
    ///
    /// - Relative paths (e.g. `"pub/my-cool-app/file"`) are resolved to **this** user.
    /// - Requests that target this user's homeserver automatically carry the
    ///   session cookie or bearer token, depending on the credential.
    ///
    /// See [`SessionStorage`] for usage examples.
    #[must_use]
    pub fn storage(&self) -> SessionStorage {
        SessionStorage::new(self)
    }
}

impl std::fmt::Debug for PubkySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("PubkySession");
        ds.field("client", &self.client);
        ds.field("credential", &self.credential);
        ds.field("info", &self.info());
        ds.finish()
    }
}
