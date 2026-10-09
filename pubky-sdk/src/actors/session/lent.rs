//! Borrowed-bearer credential — a session whose grant lives somewhere else.
//!
//! The grant JWS, the `PoP` key and the refresh logic stay with a *lender*
//! (in browsers: a same-site session agent frame that owns the grant through
//! `browserSessionStore`). This side only ever sees the lender's current
//! opaque bearer, so several first-party origins can share one grant without
//! copying restore material or racing each other's exchanges.
//!
//! The lender is reached through [`BearerSource`]; the transport
//! (`postMessage` in browsers) is supplied by the embedding runtime, the same
//! way `GrantSessionCoordinator` injects browser locks into grant sessions.

use std::any::Any;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use pubky_common::{
    auth::grant_session_responses::GrantSessionInfo, capabilities::Capability, crypto::PublicKey,
};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::SessionInfo;
use super::credential::{SessionCredential, credential_session_missing};
use crate::actors::auth::grant::credential::{REFRESH_SLACK_SECS, now_unix};
use crate::{
    PubkyHttpClient, cross_log,
    errors::{AuthError, RequestError, Result},
};

const GRANT_SESSION_PATH: &str = "/auth/grant/session";

/// A bearer lent by the grant holder, with the metadata a borrower needs.
///
/// Carries no grant JWS, grant id or key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LentBearer {
    /// Opaque homeserver bearer.
    pub token: String,
    /// Bearer expiry, Unix seconds.
    pub expires_at: u64,
    /// User the bearer authenticates.
    pub pubky: PublicKey,
    /// Capabilities the bearer carries.
    pub capabilities: Vec<Capability>,
    /// Homeserver that issued the bearer.
    pub homeserver: PublicKey,
}

impl LentBearer {
    /// Session metadata for this bearer.
    #[must_use]
    pub fn session_info(&self) -> SessionInfo {
        SessionInfo::new(self.pubky.clone(), self.capabilities.clone())
    }

    fn needs_refresh(&self, now: u64) -> bool {
        self.expires_at.saturating_sub(REFRESH_SLACK_SECS) <= now
    }
}

impl fmt::Debug for LentBearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LentBearer")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("pubky", &self.pubky)
            .field("capabilities", &self.capabilities)
            .field("homeserver", &self.homeserver)
            .finish()
    }
}

/// Reaches the holder of a grant for its current bearer.
///
/// Implementations live in the runtime that owns the transport. The browser
/// binding talks to a session agent frame over `postMessage`; tests can wrap
/// a local grant session directly.
///
/// The `?Send` split mirrors [`SessionCredential`]: native futures are `Send`
/// for tokio, WASM futures are not because they hold JS values.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait BearerSource: fmt::Debug + Send + Sync {
    /// Return a bearer that is valid now.
    ///
    /// `rejected` is a bearer the homeserver just refused. The holder must
    /// exchange its grant when that is still its current bearer and otherwise
    /// return the newer one it already has, so one grant never produces two
    /// competing exchanges. When the homeserver no longer accepts the grant
    /// (revoked or expired), the holder should sign out before failing, so
    /// [`BearerSource::status`] reports `None`.
    async fn bearer(&self, rejected: Option<&str>) -> Result<LentBearer>;

    /// Whether the holder still has a session: `Some(info)` while signed in,
    /// `None` after sign-out. Errors mean the holder is unreachable.
    async fn status(&self) -> Result<Option<SessionInfo>>;

    /// Sign the shared session out at the holder, revoking the grant.
    async fn signout(&self) -> Result<()>;
}

/// Session credential that borrows bearers from a [`BearerSource`].
///
/// Clones share the cached bearer. The credential never refreshes on its own:
/// it asks the source when the cached bearer is near expiry and once more
/// when the homeserver rejects it.
#[derive(Clone, Debug)]
pub(crate) struct LentBearerCredential {
    source: Arc<dyn BearerSource>,
    homeserver: PublicKey,
    info: SessionInfo,
    cached: Arc<Mutex<Option<LentBearer>>>,
}

impl LentBearerCredential {
    pub(crate) fn new(
        source: Arc<dyn BearerSource>,
        homeserver: PublicKey,
        info: SessionInfo,
    ) -> Self {
        Self {
            source,
            homeserver,
            info,
            cached: Arc::new(Mutex::new(None)),
        }
    }

    /// Ask the source for a bearer and make sure it is for this session.
    ///
    /// The holder may have switched to another user's session since the
    /// handshake. Such a bearer would authenticate requests for this
    /// session's paths as somebody else, so it is refused and not cached.
    async fn borrow(&self, rejected: Option<&str>) -> Result<LentBearer> {
        let lent = self.source.bearer(rejected).await?;
        if lent.pubky != *self.info.public_key() || lent.homeserver != self.homeserver {
            return Err(AuthError::Validation(
                "The session agent lent a bearer for another user or homeserver; reconnect to use the new session."
                    .into(),
            )
            .into());
        }
        Ok(lent)
    }

    /// Bearer to send now, asking the source when none is cached or the
    /// cached one has less than the refresh slack left.
    async fn bearer(&self) -> Result<String> {
        let mut cached = self.cached.lock().await;
        let stale = cached
            .as_ref()
            .is_none_or(|bearer| bearer.needs_refresh(now_unix()));
        if stale {
            cross_log!(info, "Borrowing a fresh bearer");
            *cached = Some(self.borrow(None).await?);
        }
        Ok(cached
            .as_ref()
            .expect("bearer was just cached")
            .token
            .clone())
    }

    /// Replace a bearer the homeserver rejected, unless a clone already did.
    async fn recover(&self, rejected: &str) -> Result<String> {
        let mut cached = self.cached.lock().await;
        if let Some(current) = cached.as_ref()
            && current.token != rejected
        {
            return Ok(current.token.clone());
        }
        cross_log!(info, "Borrowed bearer rejected; asking the holder again");
        let fresh = self.borrow(Some(rejected)).await?;
        let token = fresh.token.clone();
        *cached = Some(fresh);
        Ok(token)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SessionCredential for LentBearerCredential {
    fn info(&self) -> SessionInfo {
        self.info.clone()
    }

    async fn signout(&self, _client: &PubkyHttpClient) -> Result<()> {
        self.source.signout().await?;
        self.cached.lock().await.take();
        Ok(())
    }

    async fn attach(
        &self,
        rb: RequestBuilder,
        _client: &PubkyHttpClient,
    ) -> Result<RequestBuilder> {
        Ok(rb.bearer_auth(self.bearer().await?))
    }

    async fn send(&self, rb: RequestBuilder, _client: &PubkyHttpClient) -> Result<Response> {
        let retry = rb.try_clone();
        let bearer = self.bearer().await?;
        let response = rb.bearer_auth(&bearer).send().await?;
        // The holder may have rotated the bearer since we cached it. Only
        // replayable requests rejected before authentication are retried.
        if response.status() == StatusCode::UNAUTHORIZED
            && let Some(retry) = retry
        {
            let fresh = self.recover(&bearer).await?;
            return Ok(retry.bearer_auth(fresh).send().await?);
        }
        Ok(response)
    }

    async fn can_attach_to(&self, homeserver: &PublicKey) -> bool {
        &self.homeserver == homeserver
    }

    async fn revalidate(
        &self,
        client: &PubkyHttpClient,
        user: &PublicKey,
    ) -> Result<Option<SessionInfo>> {
        // The holder knows about sign-out without a round trip; a grant
        // revoked elsewhere still needs the homeserver's answer.
        if self.source.status().await?.is_none() {
            return Ok(None);
        }
        let request = client
            .cross_request_via_homeserver(Method::GET, &self.homeserver, user, GRANT_SESSION_PATH)
            .await?;
        let response = match self.send(request, client).await {
            Err(crate::Error::Request(RequestError::Server {
                status: StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND,
                ..
            })) => return Ok(None),
            // A holder that finds its grant revoked or expired signs out
            // before failing the bearer request, so check its status again.
            Err(error) => {
                return match self.source.status().await {
                    Ok(None) => Ok(None),
                    _ => Err(error),
                };
            }
            Ok(response) => response,
        };
        if credential_session_missing(&response) {
            return Ok(None);
        }
        let response = client.check_http_status(response).await?;
        let session: GrantSessionInfo =
            response
                .json()
                .await
                .map_err(|e| RequestError::DecodeJson {
                    message: format!("decoding /auth/grant/session response: {e}"),
                })?;
        Ok(Some(SessionInfo::new(session.pubky, session.capabilities)))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use pubky_common::crypto::Keypair;

    use super::*;
    use crate::PubkySession;

    /// Scripted holder: hands out numbered bearers without any network.
    #[derive(Debug)]
    struct FakeSource {
        homeserver: std::sync::Mutex<PublicKey>,
        user: std::sync::Mutex<PublicKey>,
        bearer_lifetime: u64,
        issued: AtomicUsize,
        signed_out: AtomicBool,
        rejections: std::sync::Mutex<Vec<Option<String>>>,
    }

    impl FakeSource {
        fn new(bearer_lifetime: u64) -> Arc<Self> {
            Arc::new(Self {
                homeserver: std::sync::Mutex::new(Keypair::random().public_key()),
                user: std::sync::Mutex::new(Keypair::random().public_key()),
                bearer_lifetime,
                issued: AtomicUsize::new(0),
                signed_out: AtomicBool::new(false),
                rejections: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn user(&self) -> PublicKey {
            self.user.lock().unwrap().clone()
        }

        fn homeserver(&self) -> PublicKey {
            self.homeserver.lock().unwrap().clone()
        }

        fn info(&self) -> SessionInfo {
            SessionInfo::new(self.user(), vec![Capability::root()])
        }

        fn asks(&self) -> usize {
            self.rejections.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl BearerSource for FakeSource {
        async fn bearer(&self, rejected: Option<&str>) -> Result<LentBearer> {
            self.rejections
                .lock()
                .unwrap()
                .push(rejected.map(str::to_owned));
            let number = self.issued.fetch_add(1, Ordering::SeqCst);
            Ok(LentBearer {
                token: format!("bearer-{number}"),
                expires_at: now_unix() + self.bearer_lifetime,
                pubky: self.user(),
                capabilities: vec![Capability::root()],
                homeserver: self.homeserver(),
            })
        }

        async fn status(&self) -> Result<Option<SessionInfo>> {
            Ok((!self.signed_out.load(Ordering::SeqCst)).then(|| self.info()))
        }

        async fn signout(&self) -> Result<()> {
            self.signed_out.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// A credential built from the holder's handshake as it is right now.
    fn credential(source: &Arc<FakeSource>) -> LentBearerCredential {
        LentBearerCredential::new(source.clone(), source.homeserver(), source.info())
    }

    fn client() -> PubkyHttpClient {
        PubkyHttpClient::builder().build().unwrap()
    }

    #[tokio::test]
    async fn bearer_is_cached_shared_by_clones_and_replaced_only_when_rejected() {
        let source = FakeSource::new(3_600);
        let credential = credential(&source);
        let clone = credential.clone();
        assert_eq!(credential.bearer().await.unwrap(), "bearer-0");
        assert_eq!(clone.bearer().await.unwrap(), "bearer-0");
        assert_eq!(
            source.asks(),
            1,
            "a valid bearer is borrowed once for all clones"
        );

        // Another clone already replaced the bearer: reuse it, do not ask.
        assert_eq!(credential.recover("older").await.unwrap(), "bearer-0");
        assert_eq!(source.asks(), 1);

        // The homeserver refused our current bearer: ask, naming it.
        assert_eq!(credential.recover("bearer-0").await.unwrap(), "bearer-1");
        assert_eq!(
            source.rejections.lock().unwrap().last().unwrap().as_deref(),
            Some("bearer-0")
        );
        assert_eq!(clone.bearer().await.unwrap(), "bearer-1");

        // Near expiry the bearer is borrowed again without naming a rejection.
        let near_expiry = FakeSource::new(REFRESH_SLACK_SECS - 1);
        let credential = super::tests::credential(&near_expiry);
        assert_eq!(credential.bearer().await.unwrap(), "bearer-0");
        assert_eq!(credential.bearer().await.unwrap(), "bearer-1");
        assert_eq!(*near_expiry.rejections.lock().unwrap(), vec![None, None]);
    }

    #[tokio::test]
    async fn a_bearer_for_another_user_or_homeserver_is_refused() {
        let source = FakeSource::new(3_600);
        let credential = credential(&source);
        assert_eq!(credential.bearer().await.unwrap(), "bearer-0");

        // The holder now serves somebody else: neither a fresh borrow nor a
        // recovery may adopt that bearer, and the cache keeps the old one.
        let other = Keypair::random().public_key();
        *source.user.lock().unwrap() = other.clone();
        let error = credential
            .recover("bearer-0")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("another user"), "{error}");
        assert_eq!(
            credential.cached.lock().await.as_ref().unwrap().token,
            "bearer-0"
        );
        let stale = FakeSource::new(0);
        let credential = super::tests::credential(&stale);
        *stale.user.lock().unwrap() = other;
        assert!(credential.bearer().await.is_err());
        assert!(credential.cached.lock().await.is_none());

        // Same user on another homeserver is refused too.
        let moved = FakeSource::new(3_600);
        let credential = super::tests::credential(&moved);
        *moved.homeserver.lock().unwrap() = Keypair::random().public_key();
        assert!(credential.bearer().await.is_err());
    }

    #[tokio::test]
    async fn revalidate_maps_holder_status() {
        let source = FakeSource::new(3_600);
        let credential = credential(&source);
        credential.signout(&client()).await.unwrap();
        assert!(source.signed_out.load(Ordering::SeqCst));
        assert_eq!(
            credential
                .revalidate(&client(), &source.user())
                .await
                .unwrap(),
            None,
            "a signed-out holder means no session, without a round trip"
        );

        #[derive(Debug)]
        struct Unreachable;
        #[async_trait]
        impl BearerSource for Unreachable {
            async fn bearer(&self, _: Option<&str>) -> Result<LentBearer> {
                Err(RequestError::Validation {
                    message: "agent gone".into(),
                }
                .into())
            }
            async fn status(&self) -> Result<Option<SessionInfo>> {
                Err(RequestError::Validation {
                    message: "agent gone".into(),
                }
                .into())
            }
            async fn signout(&self) -> Result<()> {
                Ok(())
            }
        }
        let credential =
            LentBearerCredential::new(Arc::new(Unreachable), source.homeserver(), source.info());
        assert!(
            credential
                .revalidate(&client(), &source.user())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn info_and_homeserver_come_from_the_handshake() {
        let source = FakeSource::new(3_600);
        let credential = credential(&source);
        assert_eq!(credential.info(), source.info());
        assert!(credential.can_attach_to(&source.homeserver()).await);
        assert!(
            !credential
                .can_attach_to(&Keypair::random().public_key())
                .await
        );
        let session = PubkySession::from_bearer_source(
            client(),
            source.clone(),
            source.homeserver(),
            source.info(),
        );
        assert!(session.as_grant().is_none());
        assert_eq!(session.public_key(), source.user());
    }

    #[tokio::test]
    async fn debug_output_redacts_the_bearer() {
        let source = FakeSource::new(3_600);
        let credential = credential(&source);
        credential.bearer().await.unwrap();
        let debug = format!("{credential:?}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains("bearer-0"), "{debug}");
    }

    mod with_testnet {
        use pubky_common::auth::jws::ClientId;
        use pubky_testnet::EphemeralTestnet;

        use super::*;
        use crate::Pubky;

        /// In-process holder: the grant session a session agent would own.
        #[derive(Debug)]
        struct LocalSource {
            session: PubkySession,
            signed_out: AtomicBool,
            asked: AtomicUsize,
        }

        #[async_trait]
        impl BearerSource for LocalSource {
            async fn bearer(&self, rejected: Option<&str>) -> Result<LentBearer> {
                self.asked.fetch_add(1, Ordering::SeqCst);
                match self.session.as_grant().unwrap().lend_bearer(rejected).await {
                    Ok(lent) => Ok(lent),
                    Err(error) => {
                        // Like the browser agent: a grant the homeserver no
                        // longer accepts signs the holder out, and the
                        // borrower gets the agent's message without the
                        // HTTP status.
                        if crate::grant_rejected(&error) {
                            self.signed_out.store(true, Ordering::SeqCst);
                        }
                        Err(AuthError::Validation(format!("session agent: {error}")).into())
                    }
                }
            }

            async fn status(&self) -> Result<Option<SessionInfo>> {
                Ok((!self.signed_out.load(Ordering::SeqCst)).then(|| self.session.info()))
            }

            async fn signout(&self) -> Result<()> {
                self.session
                    .clone()
                    .signout()
                    .await
                    .map_err(|(error, _)| error)?;
                self.signed_out.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        async fn lender(testnet: &EphemeralTestnet) -> (Pubky, Arc<LocalSource>) {
            // `testnet.sdk()` is built from the testnet's own copy of this crate.
            let mut builder = PubkyHttpClient::builder();
            builder.pkarr(|b| {
                *b = testnet.pkarr_client_builder();
                b
            });
            let sdk = Pubky::with_client(builder.build().unwrap());
            let homeserver = testnet.homeserver_app().public_key();
            let signer = sdk.signer(Keypair::random());
            signer.signup(&homeserver, None).await.unwrap();
            let session = signer
                .signin(ClientId::new("agent.test").unwrap())
                .await
                .unwrap();
            let source = Arc::new(LocalSource {
                session,
                signed_out: AtomicBool::new(false),
                asked: AtomicUsize::new(0),
            });
            (sdk, source)
        }

        fn borrow(sdk: &Pubky, source: &Arc<LocalSource>, homeserver: &PublicKey) -> PubkySession {
            PubkySession::from_bearer_source(
                sdk.client().clone(),
                source.clone(),
                homeserver.clone(),
                source.session.info(),
            )
        }

        #[tokio::test]
        #[pubky_testnet::test]
        async fn borrowed_sessions_share_one_grant_and_recover_from_rotation() {
            let testnet = EphemeralTestnet::builder().build().await.unwrap();
            let homeserver = testnet.homeserver_app().public_key();
            let (sdk, source) = lender(&testnet).await;

            // Two "origins" borrow from the same holder.
            let app_a = borrow(&sdk, &source, &homeserver);
            let app_b = borrow(&sdk, &source, &homeserver);
            assert_eq!(app_a.public_key(), source.session.public_key());

            app_a
                .storage()
                .put("/pub/agent.test/a", "from a")
                .await
                .unwrap();
            let text = app_b
                .storage()
                .get("/pub/agent.test/a")
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert_eq!(text, "from a");
            assert_eq!(
                source.asked.load(Ordering::SeqCst),
                2,
                "one ask per borrower"
            );

            // The holder rotates its bearer; the cached ones are now invalid.
            let rotated = source
                .session
                .as_grant()
                .unwrap()
                .force_refresh()
                .await
                .unwrap();

            // A replayable write recovers with exactly one extra ask.
            app_a
                .storage()
                .put("/pub/agent.test/b", "after rotation")
                .await
                .unwrap();
            assert_eq!(source.asked.load(Ordering::SeqCst), 3);
            let lent = source.bearer(None).await.unwrap();
            assert_eq!(lent.token, rotated, "the holder lends its newest bearer");

            // A streamed body cannot be replayed, so the rejection is returned.
            let stream = futures_util::stream::once(async { Ok::<_, std::io::Error>("x") });
            let request = sdk
                .client()
                .cross_request_via_homeserver(
                    Method::PUT,
                    &homeserver,
                    &app_b.public_key(),
                    &format!("/storage/{}/pub/agent.test/c", app_b.public_key().z32()),
                )
                .await
                .unwrap()
                .body(reqwest::Body::wrap_stream(stream));
            let response = app_b
                .credential()
                .send(request, sdk.client())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

            // The holder exchanges only for a rejected bearer that is still
            // current; an already-replaced one and no rejection keep the newest.
            let grant = source.session.as_grant().unwrap();
            let fresh = grant.lend_bearer(Some(&rotated)).await.unwrap();
            assert_ne!(fresh.token, rotated);
            assert_eq!(
                grant.lend_bearer(Some(&rotated)).await.unwrap().token,
                fresh.token
            );
            assert_eq!(grant.lend_bearer(None).await.unwrap().token, fresh.token);

            // Signing out through one app revokes the grant for every app.
            app_b.signout().await.map_err(|(e, _)| e).unwrap();
            assert_eq!(app_a.revalidate().await.unwrap(), None);
            assert!(
                source
                    .session
                    .as_grant()
                    .unwrap()
                    .force_refresh()
                    .await
                    .is_err(),
                "the grant is gone, not just the bearer"
            );
        }

        #[tokio::test]
        #[pubky_testnet::test]
        async fn a_grant_revoked_elsewhere_signs_borrowers_out() {
            let testnet = EphemeralTestnet::builder().build().await.unwrap();
            let homeserver = testnet.homeserver_app().public_key();
            let (sdk, source) = lender(&testnet).await;
            let app = borrow(&sdk, &source, &homeserver);
            app.storage()
                .put("/pub/agent.test/before", "ok")
                .await
                .unwrap();

            // Revoke the grant behind the holder's back, as Ring would.
            source
                .session
                .clone()
                .signout()
                .await
                .map_err(|(e, _)| e)
                .unwrap();
            assert!(
                source.status().await.unwrap().is_some(),
                "the holder has not noticed yet"
            );

            // Revalidating hits the dead grant: the holder signs out instead
            // of staying signed in, and the borrower reports no session
            // rather than an error.
            assert_eq!(app.revalidate().await.unwrap(), None);
            assert!(source.status().await.unwrap().is_none());
            assert!(
                app.storage()
                    .put("/pub/agent.test/after", "nope")
                    .await
                    .is_err()
            );
        }
    }
}
