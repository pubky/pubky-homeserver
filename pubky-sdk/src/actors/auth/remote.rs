//! Remote bearer credential — a session whose grant lives somewhere else.
//!
//! The grant JWS, the `PoP` key and the refresh logic stay with a *holder*
//! (in browsers: a same-site auth agent frame that owns the grant through
//! `browserSessionStore`). This side only ever sees the holder's current
//! opaque bearer, so several first-party origins can share one grant without
//! copying restore material or racing each other's exchanges.
//!
//! The holder is reached through [`RemoteBearerProvider`]; the transport
//! (`postMessage` in browsers) is supplied by the embedding runtime, the same
//! way `GrantSessionCoordinator` injects browser locks into grant sessions.

use std::any::Any;
use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use pubky_common::{
    auth::grant_session_responses::{GrantSessionInfo, GrantSessionResponse},
    crypto::PublicKey,
};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use tokio::sync::Mutex;

use crate::actors::auth::grant::credential::{REFRESH_SLACK_SECS, bearer_needs_refresh, now_unix};
use crate::actors::session::core::PubkySession;
use crate::actors::session::credential::{SessionCredential, credential_session_missing};
use crate::{
    PubkyHttpClient,
    actors::session::SessionInfo,
    cross_log,
    errors::{RequestError, Result},
};

const GRANT_SESSION_PATH: &str = "/auth/grant/session";

/// Reaches the holder of a grant for its current bearer.
///
/// Implementations live in the runtime that owns the transport. The browser
/// binding talks to an auth agent frame over `postMessage`; tests can wrap a
/// local [`GrantCredential`](crate::GrantCredential) directly.
///
/// The `?Send` split mirrors [`SessionCredential`]: native futures are `Send`
/// for tokio, WASM futures are not because they hold JS values.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait RemoteBearerProvider: Debug + Send + Sync {
    /// Return a bearer that is valid now, together with its session metadata.
    ///
    /// `rejected` is a bearer the homeserver just refused. The holder must
    /// exchange its grant when that is still its current bearer and otherwise
    /// return the newer one it already has, so one grant never produces two
    /// competing exchanges.
    async fn bearer(&self, rejected: Option<&str>) -> Result<GrantSessionResponse>;

    /// Sign the shared session out at the holder, revoking the grant.
    async fn signout(&self) -> Result<()>;
}

/// Grant-backed session credential whose grant is held by a remote provider.
///
/// Clones share the cached bearer. The credential never refreshes on its own:
/// it asks the provider when the cached bearer is near expiry and once more
/// when the homeserver rejects it.
#[derive(Clone, Debug)]
pub struct RemoteBearerCredential {
    provider: Arc<dyn RemoteBearerProvider>,
    current: Arc<Mutex<GrantSessionResponse>>,
    info: SessionInfo,
}

impl RemoteBearerCredential {
    /// Wrap a provider together with the bearer it handed out on connect.
    #[must_use]
    pub fn new(provider: Arc<dyn RemoteBearerProvider>, current: GrantSessionResponse) -> Self {
        let info = to_session_info(&current.session);
        Self {
            provider,
            current: Arc::new(Mutex::new(current)),
            info,
        }
    }

    /// Session metadata as last reported by the holder.
    pub async fn session_info(&self) -> GrantSessionInfo {
        self.current.lock().await.session.clone()
    }

    /// Bearer to send now, asking the holder when the cached one is near expiry.
    ///
    /// Uses the same slack as a shared grant session so the holder agrees that
    /// a refresh is due when asked, instead of handing the same bearer back.
    async fn bearer(&self) -> Result<String> {
        let mut current = self.current.lock().await;
        let stale = current.token.is_empty()
            || bearer_needs_refresh(
                current.session.token_expires_at,
                current.session.grant_expires_at,
                now_unix(),
                REFRESH_SLACK_SECS / 2,
            );
        if stale {
            cross_log!(info, "Asking remote holder for a fresh bearer");
            *current = self.provider.bearer(None).await?;
        }
        Ok(current.token.clone())
    }

    /// Replace a bearer the homeserver rejected, unless a clone already did.
    async fn recover(&self, rejected: &str) -> Result<String> {
        let mut current = self.current.lock().await;
        if current.token != rejected {
            return Ok(current.token.clone());
        }
        cross_log!(info, "Remote bearer rejected; asking holder to refresh");
        *current = self.provider.bearer(Some(rejected)).await?;
        Ok(current.token.clone())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SessionCredential for RemoteBearerCredential {
    fn info(&self) -> SessionInfo {
        self.info.clone()
    }

    async fn signout(&self, _client: &PubkyHttpClient) -> Result<()> {
        self.provider.signout().await?;
        // A reused handle then asks the holder again instead of replaying.
        self.current.lock().await.token.clear();
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
        &self.current.lock().await.session.homeserver == homeserver
    }

    async fn revalidate(
        &self,
        client: &PubkyHttpClient,
        _user: &PublicKey,
    ) -> Result<Option<SessionInfo>> {
        let (homeserver, user) = {
            let current = self.current.lock().await;
            (
                current.session.homeserver.clone(),
                current.session.pubky.clone(),
            )
        };
        let request = client
            .cross_request_via_homeserver(Method::GET, &homeserver, &user, GRANT_SESSION_PATH)
            .await?;
        let response = match self.send(request, client).await {
            Err(crate::Error::Request(RequestError::Server {
                status: StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND,
                ..
            })) => return Ok(None),
            result => result?,
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
        let info = to_session_info(&session);
        self.current.lock().await.session = session;
        Ok(Some(info))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PubkySession {
    /// Build a session from a bearer held by a remote grant holder.
    ///
    /// The session authenticates with bearers the provider hands out and
    /// never sees the grant or `PoP` key. See [`RemoteBearerProvider`].
    #[must_use]
    pub fn from_remote_bearer(client: PubkyHttpClient, credential: RemoteBearerCredential) -> Self {
        Self::from_credential(client, Arc::new(credential))
    }

    /// Returns the remote bearer credential if this session is backed by one.
    #[must_use]
    pub fn as_remote_bearer(&self) -> Option<&RemoteBearerCredential> {
        self.try_downcast_credential::<RemoteBearerCredential>()
    }
}

fn to_session_info(session: &GrantSessionInfo) -> SessionInfo {
    SessionInfo::new(session.pubky.clone(), session.capabilities.clone())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use pubky_common::{
        auth::jws::{ClientId, GrantId},
        capabilities::Capability,
        crypto::Keypair,
    };

    use super::*;

    /// Scripted holder: hands out numbered bearers without any network.
    #[derive(Debug)]
    struct FakeHolder {
        homeserver: PublicKey,
        user: PublicKey,
        bearer_lifetime: u64,
        issued: AtomicUsize,
        signouts: AtomicUsize,
        rejections: std::sync::Mutex<Vec<Option<String>>>,
    }

    impl FakeHolder {
        fn new(bearer_lifetime: u64) -> Arc<Self> {
            Arc::new(Self {
                homeserver: Keypair::random().public_key(),
                user: Keypair::random().public_key(),
                bearer_lifetime,
                issued: AtomicUsize::new(0),
                signouts: AtomicUsize::new(0),
                rejections: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn issue(&self) -> GrantSessionResponse {
            let number = self.issued.fetch_add(1, Ordering::SeqCst);
            let now = now_unix();
            GrantSessionResponse {
                token: format!("bearer-{number}"),
                session: GrantSessionInfo {
                    homeserver: self.homeserver.clone(),
                    pubky: self.user.clone(),
                    client_id: ClientId::new("agent.test").unwrap(),
                    capabilities: vec![Capability::root()],
                    grant_id: GrantId::generate(),
                    token_expires_at: now + self.bearer_lifetime,
                    grant_expires_at: now + 10_000,
                    created_at: now,
                },
            }
        }

        fn asks(&self) -> usize {
            self.rejections.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl RemoteBearerProvider for FakeHolder {
        async fn bearer(&self, rejected: Option<&str>) -> Result<GrantSessionResponse> {
            self.rejections
                .lock()
                .unwrap()
                .push(rejected.map(str::to_owned));
            Ok(self.issue())
        }

        async fn signout(&self) -> Result<()> {
            self.signouts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn credential(holder: &Arc<FakeHolder>) -> RemoteBearerCredential {
        RemoteBearerCredential::new(holder.clone(), holder.issue())
    }

    fn client() -> PubkyHttpClient {
        PubkyHttpClient::builder().build().unwrap()
    }

    #[tokio::test]
    async fn cached_bearer_is_reused_until_near_expiry() {
        let holder = FakeHolder::new(3_600);
        let credential = credential(&holder);
        assert_eq!(credential.bearer().await.unwrap(), "bearer-0");
        assert_eq!(credential.bearer().await.unwrap(), "bearer-0");
        assert_eq!(holder.asks(), 0, "a valid bearer is never re-requested");

        let near_expiry = FakeHolder::new(REFRESH_SLACK_SECS / 2 - 1);
        let credential = credential_for(&near_expiry);
        assert_eq!(credential.bearer().await.unwrap(), "bearer-1");
        assert_eq!(near_expiry.asks(), 1);
        assert_eq!(*near_expiry.rejections.lock().unwrap(), vec![None]);
    }

    fn credential_for(holder: &Arc<FakeHolder>) -> RemoteBearerCredential {
        credential(holder)
    }

    #[tokio::test]
    async fn recover_asks_only_when_the_rejected_bearer_is_still_current() {
        let holder = FakeHolder::new(3_600);
        let credential = credential(&holder);

        // Another clone already replaced the bearer: reuse it, do not ask.
        assert_eq!(credential.recover("older").await.unwrap(), "bearer-0");
        assert_eq!(holder.asks(), 0);

        // The homeserver refused our current bearer: ask, naming it.
        assert_eq!(credential.recover("bearer-0").await.unwrap(), "bearer-1");
        assert_eq!(
            *holder.rejections.lock().unwrap(),
            vec![Some("bearer-0".to_string())]
        );
        assert_eq!(credential.bearer().await.unwrap(), "bearer-1");
    }

    #[tokio::test]
    async fn clones_share_the_cached_bearer() {
        let holder = FakeHolder::new(3_600);
        let credential = credential(&holder);
        let clone = credential.clone();
        credential.recover("bearer-0").await.unwrap();
        assert_eq!(clone.bearer().await.unwrap(), "bearer-1");
    }

    #[tokio::test]
    async fn signout_forwards_to_the_holder_and_forgets_the_bearer() {
        let holder = FakeHolder::new(3_600);
        let credential = credential(&holder);
        credential.signout(&client()).await.unwrap();
        assert_eq!(holder.signouts.load(Ordering::SeqCst), 1);
        // The next use asks the holder again rather than replaying a dead bearer.
        credential.bearer().await.unwrap();
        assert_eq!(holder.asks(), 1);
    }

    #[tokio::test]
    async fn info_and_homeserver_come_from_the_holder() {
        let holder = FakeHolder::new(3_600);
        let credential = credential(&holder);
        assert_eq!(credential.info().public_key(), &holder.user);
        assert_eq!(credential.info().capabilities(), &[Capability::root()]);
        assert!(credential.can_attach_to(&holder.homeserver).await);
        assert!(
            !credential
                .can_attach_to(&Keypair::random().public_key())
                .await
        );
    }

    mod with_testnet {
        use pubky_testnet::EphemeralTestnet;

        use super::*;
        use crate::Pubky;

        /// In-process holder: the grant session an auth agent would own.
        #[derive(Debug)]
        struct LocalHolder {
            session: PubkySession,
            asked: AtomicUsize,
        }

        #[async_trait]
        impl RemoteBearerProvider for LocalHolder {
            async fn bearer(&self, rejected: Option<&str>) -> Result<GrantSessionResponse> {
                self.asked.fetch_add(1, Ordering::SeqCst);
                self.session
                    .as_grant()
                    .unwrap()
                    .bearer_for_remote(rejected)
                    .await
            }

            async fn signout(&self) -> Result<()> {
                self.session
                    .clone()
                    .signout()
                    .await
                    .map_err(|(error, _)| error)
            }
        }

        async fn holder(testnet: &EphemeralTestnet) -> (Pubky, Arc<LocalHolder>) {
            // `testnet.sdk()` is built from the testnet's own copy of this crate.
            let mut builder = PubkyHttpClient::builder();
            builder.pkarr(|b| {
                *b = testnet.pkarr_client_builder();
                b
            });
            let sdk = Pubky::with_client(builder.build().unwrap());
            let user = Keypair::random();
            let homeserver = testnet.homeserver_app().public_key();
            let signer = sdk.signer(user);
            signer.signup(&homeserver, None).await.unwrap();
            let session = signer
                .signin(ClientId::new("agent.test").unwrap())
                .await
                .unwrap();
            let holder = Arc::new(LocalHolder {
                session,
                asked: AtomicUsize::new(0),
            });
            (sdk, holder)
        }

        async fn connect(sdk: &Pubky, holder: &Arc<LocalHolder>) -> PubkySession {
            let current = holder.bearer(None).await.unwrap();
            let credential = RemoteBearerCredential::new(holder.clone(), current);
            PubkySession::from_remote_bearer(sdk.client().clone(), credential)
        }

        #[tokio::test]
        #[pubky_testnet::test]
        async fn remote_bearer_shares_one_grant_and_recovers_from_rotation() {
            let testnet = EphemeralTestnet::builder().build().await.unwrap();
            let (sdk, holder) = holder(&testnet).await;
            let holder_grant = holder.session.as_grant().unwrap().grant_id().await;

            // Two "origins" connect to the same holder.
            let app_a = connect(&sdk, &holder).await;
            let app_b = connect(&sdk, &holder).await;
            assert_eq!(app_a.public_key(), holder.session.public_key());
            assert!(app_a.as_remote_bearer().is_some());
            assert!(app_a.as_grant().is_none());

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

            // Both apps run on the holder's grant; nobody minted a second one.
            let info = app_b.revalidate().await.unwrap().unwrap();
            assert_eq!(info.public_key(), &holder.session.public_key());
            assert_eq!(
                app_b
                    .as_remote_bearer()
                    .unwrap()
                    .session_info()
                    .await
                    .grant_id,
                holder_grant
            );
            let asked_before = holder.asked.load(Ordering::SeqCst);
            assert_eq!(asked_before, 2, "one ask per connect, none per request");

            // The holder rotates its bearer; the cached one is now invalid.
            let stale = app_a.as_remote_bearer().unwrap().bearer().await.unwrap();
            let rotated = holder
                .session
                .as_grant()
                .unwrap()
                .force_refresh()
                .await
                .unwrap();
            assert_ne!(stale, rotated);

            // A replayable write recovers with exactly one extra ask.
            app_a
                .storage()
                .put("/pub/agent.test/b", "after rotation")
                .await
                .unwrap();
            assert_eq!(holder.asked.load(Ordering::SeqCst), asked_before + 1);
            assert_eq!(
                app_a.as_remote_bearer().unwrap().bearer().await.unwrap(),
                rotated
            );

            // A holder asked with an already-replaced bearer hands out the newer
            // one instead of exchanging again.
            let before = holder
                .session
                .as_grant()
                .unwrap()
                .session_info()
                .await
                .created_at;
            let again = holder.bearer(Some(&stale)).await.unwrap();
            assert_eq!(again.token, rotated);
            assert_eq!(again.session.created_at, before);

            // Signing out through one app revokes the grant for every app.
            app_b.signout().await.map_err(|(e, _)| e).unwrap();
            assert!(app_a.revalidate().await.unwrap().is_none());
            assert!(
                holder
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
        async fn rejected_current_bearer_forces_holder_exchange() {
            let testnet = EphemeralTestnet::builder().build().await.unwrap();
            let (_sdk, holder) = holder(&testnet).await;
            let current = holder.bearer(None).await.unwrap();
            // Asking with the holder's own current bearer is the "server said 401"
            // signal and must mint a new one.
            let fresh = holder.bearer(Some(&current.token)).await.unwrap();
            assert_ne!(fresh.token, current.token);
            // Asking without a rejection keeps the valid bearer.
            let same = holder.bearer(None).await.unwrap();
            assert_eq!(same.token, fresh.token);
        }
    }
}
