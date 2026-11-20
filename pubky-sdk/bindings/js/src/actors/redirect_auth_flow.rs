//! Browser redirect sign-in with persisted requests and single-use callbacks.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky::{
    ClientId, DelegatedRedirectAuthFlowState, PubkyRedirectAuthFlow, RedirectCallback,
    errors::{AuthError, RedirectDenial},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tsify::Tsify;
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroize;

use super::{
    browser_grant_key_store::BrowserGrantKeyStore,
    browser_session::BrowserSessionCoordinator,
    session::Session,
    session_store::{
        SessionMetadata, StoredSessionInfo, StoredSessionRecord,
        browser::{
            js_redirect_acquire, js_redirect_commit, js_redirect_get, js_redirect_release,
            js_redirect_transition, js_redirect_wait, store_error,
        },
        finish_child_signout,
    },
};
use crate::{
    js_error::{JsResult, PubkyError, PubkyErrorName},
    wrappers::capabilities::parse_capabilities,
};

const FLOW_VERSION: &str = "pubky-redirect-flow-v1";

/// Options for `pubky.startRedirectAuthFlow()`.
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RedirectAuthFlowOptions {
    /// Accounts HTTPS authorization URL, without credentials or a fragment.
    pub(crate) accounts_url: String,
    /// Registered HTTPS callback on this page's origin; also the child's client ID.
    pub(crate) callback_url: String,
    /// Request lifetime in seconds: default 600, maximum 3600.
    #[tsify(optional)]
    pub(crate) lifetime_seconds: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum FlowStatus {
    AwaitingCallback,
    ExchangePending,
    Complete,
    Denied,
    Cancelled,
    Expired,
}

impl FlowStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingCallback => "awaitingCallback",
            Self::ExchangePending => "exchangePending",
            Self::Complete => "complete",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    const fn is_active(self) -> bool {
        matches!(self, Self::AwaitingCallback | Self::ExchangePending)
    }
}

/// A stored flow. The secrets are absent once it finishes.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FlowRecord {
    callback_url: String,
    version: String,
    status: FlowStatus,
    /// The request's public single-use state, which names this flow.
    state: String,
    capabilities: Vec<String>,
    created_at: f64,
    expires_at: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_public_key: Option<String>,
    /// The temporary HPKE secret, base64url.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_key_secret: Option<String>,
    /// The verified child approval, saved before the exchange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signed_approval: Option<String>,
    /// Public revocation material, saved before the first exchange request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    logout_record: Option<StoredSessionRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    finished_at: Option<f64>,
}

impl Drop for FlowRecord {
    fn drop(&mut self) {
        // JS/IndexedDB retain their own copies; clear the Rust-owned secrets.
        self.approval_key_secret.zeroize();
        self.signed_approval.zeroize();
    }
}

/// The part of a flow that the store compares before changing it.
#[derive(Serialize)]
struct FlowRef<'a> {
    status: FlowStatus,
    state: &'a str,
}

impl FlowRecord {
    fn awaiting(flow: &PubkyRedirectAuthFlow, saved: &DelegatedRedirectAuthFlowState) -> Self {
        let request = pubky::deep_links::ChildGrantRequest::parse(flow.authorization_url())
            .expect("invariant: the flow built this request");
        Self {
            callback_url: flow.callback().to_string(),
            version: FLOW_VERSION.into(),
            status: FlowStatus::AwaitingCallback,
            state: request.state().to_owned(),
            capabilities: flow
                .capabilities()
                .iter()
                .map(ToString::to_string)
                .collect(),
            created_at: flow.created_at() as f64,
            expires_at: flow.expires_at() as f64,
            authorization_url: Some(saved.authorization_url.clone()),
            key_id: Some(saved.key_id.clone()),
            client_public_key: Some(saved.client_pk.z32()),
            approval_key_secret: Some(URL_SAFE_NO_PAD.encode(saved.approval_key_secret)),
            signed_approval: None,
            logout_record: None,
            session_id: None,
            finished_at: None,
        }
    }

    fn exchange_pending(&self, signed_approval: &str) -> Self {
        let mut next = self.clone();
        next.status = FlowStatus::ExchangePending;
        next.signed_approval = Some(signed_approval.to_owned());
        next
    }

    /// The flow after it finished, without its secrets.
    fn finished(&self, status: FlowStatus, session_id: Option<String>) -> Self {
        Self {
            callback_url: self.callback_url.clone(),
            version: FLOW_VERSION.into(),
            status,
            state: self.state.clone(),
            capabilities: self.capabilities.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            authorization_url: None,
            key_id: None,
            client_public_key: None,
            approval_key_secret: None,
            signed_approval: None,
            logout_record: None,
            session_id,
            finished_at: Some(js_sys::Date::now() / 1000.0),
        }
    }

    fn is_due(&self) -> bool {
        self.status == FlowStatus::AwaitingCallback
            && js_sys::Date::now() / 1000.0 >= self.expires_at
    }

    fn saved_state(&self) -> JsResult<DelegatedRedirectAuthFlowState> {
        let (Some(url), Some(key_id), Some(public_key), Some(secret)) = (
            &self.authorization_url,
            &self.key_id,
            &self.client_public_key,
            &self.approval_key_secret,
        ) else {
            return Err(invalid_flow());
        };
        let mut bytes = URL_SAFE_NO_PAD.decode(secret).map_err(|_| invalid_flow())?;
        let approval_key_secret: [u8; 32] =
            bytes.as_slice().try_into().map_err(|_| invalid_flow())?;
        bytes.zeroize();
        Ok(DelegatedRedirectAuthFlowState {
            authorization_url: url.clone(),
            key_id: key_id.clone(),
            client_pk: pubky::PublicKey::try_from_z32(public_key).map_err(|_| invalid_flow())?,
            approval_key_secret,
            created_at: self.created_at as u64,
            expires_at: self.expires_at as u64,
        })
    }

    fn reference(&self) -> JsResult<JsValue> {
        to_js(&FlowRef {
            status: self.status,
            state: &self.state,
        })
    }
}

fn to_js<T: Serialize>(value: &T) -> JsResult<JsValue> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true))
        .map_err(|error| {
            PubkyError::new(
                PubkyErrorName::InternalError,
                format!("Failed to serialize the redirect sign-in: {error}"),
            )
        })
}

fn invalid_flow() -> PubkyError {
    PubkyError::new(
        PubkyErrorName::ClientStateError,
        "Invalid pending redirect sign-in.",
    )
}

/// A `ClientStateError` whose `data.reason` names the situation, and `data.status`
/// the flow's status when there is one.
fn flow_error(message: &str, reason: &str, status: Option<FlowStatus>) -> PubkyError {
    PubkyError::new(PubkyErrorName::ClientStateError, message).with_data(json!({
        "reason": reason,
        "status": status.map(FlowStatus::as_str),
    }))
}

/// Holds the callback's Web Lock until dropped.
struct RedirectLease {
    token: u32,
    callback_url: String,
}

impl Drop for RedirectLease {
    fn drop(&mut self) {
        js_redirect_release(self.token);
    }
}

impl RedirectLease {
    async fn acquire(callback_url: &str) -> JsResult<Self> {
        let token = js_redirect_acquire(callback_url).map_err(store_error)?;
        let lease = Self {
            token,
            callback_url: callback_url.to_owned(),
        };
        JsFuture::from(js_redirect_wait(token))
            .await
            .map_err(store_error)?;
        Ok(lease)
    }

    /// The callback's flow, after expiring it if its time is up.
    async fn load(&self) -> JsResult<Option<FlowRecord>> {
        let value = JsFuture::from(js_redirect_get(&self.callback_url))
            .await
            .map_err(store_error)?;
        if value.is_undefined() {
            return Ok(None);
        }
        let record: FlowRecord =
            serde_wasm_bindgen::from_value(value).map_err(|_| invalid_flow())?;
        if record.version != FLOW_VERSION || record.callback_url != self.callback_url {
            return Err(invalid_flow());
        }
        if record.is_due() {
            let expired = record.finished(FlowStatus::Expired, None);
            self.replace(Some(&record), Some(&expired), record.key_id.clone())
                .await?;
            return Ok(Some(expired));
        }
        Ok(Some(record))
    }

    /// Replace `current` with `next`, deleting `delete_key`, if it's still stored.
    async fn replace(
        &self,
        current: Option<&FlowRecord>,
        next: Option<&FlowRecord>,
        delete_key: Option<String>,
    ) -> JsResult<()> {
        let next = next.map(to_js).transpose()?.unwrap_or(JsValue::NULL);
        let applied = JsFuture::from(js_redirect_transition(
            self.token,
            &self.callback_url,
            current
                .map(FlowRecord::reference)
                .transpose()?
                .unwrap_or(JsValue::NULL),
            next,
            delete_key,
        ))
        .await
        .map_err(store_error)?;
        changed_unless(applied.is_truthy())
    }

    /// Save `session` and replace `current` with `next` in one transaction.
    async fn commit(
        &self,
        current: &FlowRecord,
        next: &FlowRecord,
        session: &StoredSessionRecord,
        session_lease: u32,
    ) -> JsResult<()> {
        let applied = JsFuture::from(js_redirect_commit(
            self.token,
            &self.callback_url,
            current.reference()?,
            to_js(next)?,
            session.to_js()?,
            session_lease,
        ))
        .await
        .map_err(store_error)?;
        changed_unless(applied.is_truthy())
    }
}

fn changed_unless(applied: bool) -> JsResult<()> {
    if applied {
        return Ok(());
    }
    // Sign-out and local deletion can invalidate a flow while its exchange runs.
    Err(flow_error(
        "The pending redirect sign-in was removed. Start a new sign-in.",
        "RedirectAuthFlowRemoved",
        None,
    ))
}

/// A pending redirect sign-in, as returned by `startRedirectAuthFlow()` and
/// `redirectAuthFlow()`.
#[wasm_bindgen]
pub struct RedirectAuthRequest {
    authorization_url: String,
    callback_url: String,
    capabilities: Vec<String>,
    expires_at: f64,
    status: FlowStatus,
}

#[wasm_bindgen]
impl RedirectAuthRequest {
    /// Where to send the user, for example with `location.assign()`. It holds
    /// only public keys and request parameters.
    #[wasm_bindgen(js_name = "authorizationUrl", getter)]
    pub fn authorization_url(&self) -> String {
        self.authorization_url.clone()
    }

    /// The app's exact callback URL.
    #[wasm_bindgen(js_name = "callbackUrl", getter)]
    pub fn callback_url(&self) -> String {
        self.callback_url.clone()
    }

    /// The requested capabilities.
    #[wasm_bindgen(getter)]
    pub fn capabilities(&self) -> Vec<String> {
        self.capabilities.clone()
    }

    /// When the request stops accepting its callback, in Unix seconds.
    #[wasm_bindgen(js_name = "expiresAt", getter)]
    pub fn expires_at(&self) -> f64 {
        self.expires_at
    }

    /// `awaitingCallback` until Accounts answers. `exchangePending` once a
    /// callback was accepted but the session isn't saved yet: finish it with
    /// `resumeRedirectAuthFlow()`.
    #[wasm_bindgen(
        getter,
        unchecked_return_type = "\"awaitingCallback\" | \"exchangePending\""
    )]
    pub fn status(&self) -> String {
        self.status.as_str().to_owned()
    }
}

impl RedirectAuthRequest {
    fn from_record(record: &FlowRecord) -> JsResult<Self> {
        Ok(Self {
            authorization_url: record.authorization_url.clone().ok_or_else(invalid_flow)?,
            callback_url: record.callback_url.clone(),
            capabilities: record.capabilities.clone(),
            expires_at: record.expires_at,
            status: record.status,
        })
    }
}

/// A completed redirect sign-in. The session is already saved in
/// `browserSessionStore`; after a reload, restore it with `storedSession.id`.
#[wasm_bindgen]
pub struct RedirectAuthResult {
    session: pubky::PubkySession,
    stored_session: SessionMetadata,
}

#[wasm_bindgen]
impl RedirectAuthResult {
    /// The signed-in session. Its encryption keys cover exactly the approved `e` scopes.
    #[wasm_bindgen(getter)]
    pub fn session(&self) -> Session {
        Session(self.session.clone())
    }

    /// The saved session record.
    #[wasm_bindgen(js_name = "storedSession", getter)]
    pub fn stored_session(&self) -> StoredSessionInfo {
        StoredSessionInfo(self.stored_session.clone())
    }
}

fn parse_callback(callback_url: &str) -> JsResult<ClientId> {
    ClientId::new(callback_url).map_err(|error| {
        PubkyError::new(
            PubkyErrorName::InvalidInput,
            format!("Invalid callback URL: {error}"),
        )
    })
}

/// Start a request and save it before returning its authorization URL.
pub(crate) async fn start(
    pubky: &pubky::Pubky,
    capabilities: &str,
    options: RedirectAuthFlowOptions,
    origin: Option<String>,
) -> JsResult<RedirectAuthRequest> {
    let caps = parse_capabilities(capabilities)?;
    let callback = parse_callback(&options.callback_url)?;
    let accounts_url = Url::parse(&options.accounts_url)?;
    // The callback page has to find the pending state this page saves.
    let callback_origin = Url::parse(callback.as_str())?
        .origin()
        .ascii_serialization();
    if origin.as_deref() != Some(callback_origin.as_str()) {
        return Err(PubkyError::new(
            PubkyErrorName::InvalidInput,
            "The callback URL must be on this page's origin.",
        ));
    }
    if !BrowserGrantKeyStore::can_use_delegation().await? {
        return Err(PubkyError::new(
            PubkyErrorName::ClientStateError,
            "Redirect sign-in needs a browser-held Ed25519 key in a secure context.",
        ));
    }

    let lease = RedirectLease::acquire(callback.as_str()).await?;
    let existing = lease.load().await?;
    if let Some(record) = existing
        .as_ref()
        .filter(|record| record.status == FlowStatus::ExchangePending)
    {
        return Err(flow_error(
            "This redirect sign-in already accepted its callback. Resume or cancel it.",
            "RedirectAuthFlowPending",
            Some(record.status),
        ));
    }
    // Cancelled children keep their logout-only session for separate revocation retries.
    let previous_key = existing.as_ref().and_then(|record| record.key_id.clone());

    let mut builder = PubkyRedirectAuthFlow::builder(&caps, callback, accounts_url)
        .client(pubky.client().clone());
    if let Some(seconds) = options.lifetime_seconds {
        builder = builder.lifetime(std::time::Duration::from_secs(u64::from(seconds)));
    }
    // Create the key last, and drop it if the flow can't be saved.
    let (key_id, public_key) = BrowserGrantKeyStore::ensure_key(None).await?;
    let sign = BrowserGrantKeyStore::signer(key_id.clone());
    let saved = builder
        .delegated_client_signer(key_id.clone(), public_key, sign)
        .start()
        .map_err(PubkyError::from)
        .map(|flow| {
            let saved = flow.save_delegated().expect("the flow holds a browser key");
            FlowRecord::awaiting(&flow, &saved)
        });
    let record = match saved {
        Ok(record) => record,
        Err(error) => {
            let _ = BrowserGrantKeyStore::delete_key(key_id).await;
            return Err(error);
        }
    };
    if let Err(error) = lease
        .replace(existing.as_ref(), Some(&record), previous_key)
        .await
    {
        let _ = BrowserGrantKeyStore::delete_key(key_id).await;
        return Err(error);
    }
    RedirectAuthRequest::from_record(&record)
}

/// Accept the callback in `href`, or resume an accepted one when there is none.
pub(crate) async fn complete(pubky: &pubky::Pubky, href: &str) -> JsResult<RedirectAuthResult> {
    let url = Url::parse(href)?;
    let callback = url
        .fragment()
        .map(|_| RedirectCallback::parse(&url))
        .transpose()?;
    let mut callback_url = url;
    callback_url.set_fragment(None);

    let lease = RedirectLease::acquire(callback_url.as_str()).await?;
    let record = lease.load().await?.ok_or_else(not_found)?;
    match (callback, record.status) {
        (Some(callback), FlowStatus::AwaitingCallback) => {
            accept(pubky, &lease, &record, &callback).await
        }
        (Some(_), FlowStatus::Expired) => Err(pubky::Error::from(AuthError::RequestExpired).into()),
        (Some(_), status) => Err(flow_error(
            "This redirect sign-in already received its response.",
            "RedirectCallbackHandled",
            Some(status),
        )),
        (None, FlowStatus::ExchangePending) => exchange(pubky, &lease, &record).await,
        (None, status) => Err(flow_error(
            "The URL holds no redirect sign-in response.",
            "RedirectCallbackMissing",
            Some(status),
        )),
    }
}

/// Finish a flow whose callback was accepted but whose session isn't saved yet.
pub(crate) async fn resume(
    pubky: &pubky::Pubky,
    callback_url: &str,
) -> JsResult<RedirectAuthResult> {
    let callback = parse_callback(callback_url)?;
    let lease = RedirectLease::acquire(callback.as_str()).await?;
    let record = lease.load().await?.ok_or_else(not_found)?;
    match record.status {
        FlowStatus::ExchangePending => exchange(pubky, &lease, &record).await,
        FlowStatus::AwaitingCallback => Err(flow_error(
            "This redirect sign-in is still waiting for its callback.",
            "RedirectAwaitingCallback",
            Some(record.status),
        )),
        _ => Err(not_found()),
    }
}

/// The callback's pending flow, if there is one.
pub(crate) async fn pending(callback_url: &str) -> JsResult<Option<RedirectAuthRequest>> {
    let callback = parse_callback(callback_url)?;
    let lease = RedirectLease::acquire(callback.as_str()).await?;
    lease
        .load()
        .await?
        .filter(|record| record.status.is_active())
        .map(|record| RedirectAuthRequest::from_record(&record))
        .transpose()
}

/// Cancel the callback's flow. Its keys are deleted, and a child whose exchange
/// may have reached the homeserver is revoked through the sign-out path.
pub(crate) async fn cancel(pubky: &pubky::Pubky, callback_url: &str) -> JsResult<()> {
    let callback = parse_callback(callback_url)?;
    let lease = RedirectLease::acquire(callback.as_str()).await?;
    let Some(record) = lease.load().await? else {
        return Ok(());
    };
    match record.status {
        FlowStatus::AwaitingCallback => {
            let cancelled = record.finished(FlowStatus::Cancelled, None);
            lease
                .replace(Some(&record), Some(&cancelled), record.key_id.clone())
                .await
        }
        FlowStatus::ExchangePending => cancel_exchange(pubky, &lease, &record).await,
        _ => finish_cancelled(pubky.client(), &record).await,
    }
}

fn not_found() -> PubkyError {
    flow_error(
        "No redirect sign-in is pending for this callback.",
        "RedirectAuthFlowNotFound",
        None,
    )
}

fn restore_flow(pubky: &pubky::Pubky, record: &FlowRecord) -> JsResult<PubkyRedirectAuthFlow> {
    let state = record.saved_state()?;
    let sign = BrowserGrantKeyStore::signer(state.key_id.clone());
    Ok(PubkyRedirectAuthFlow::restore_delegated(
        state,
        pubky.client().clone(),
        sign,
    )?)
}

async fn accept(
    pubky: &pubky::Pubky,
    lease: &RedirectLease,
    record: &FlowRecord,
    callback: &RedirectCallback,
) -> JsResult<RedirectAuthResult> {
    let flow = restore_flow(pubky, record)?;
    let approval = match flow.accept(callback) {
        Ok(approval) => approval,
        Err(error) => {
            // A response for this request ends it. Any other invalid callback
            // leaves the request waiting for the real one.
            let status = match &error {
                pubky::Error::Authentication(AuthError::RedirectDeclined(denial)) => {
                    Some(if *denial == RedirectDenial::Cancelled {
                        FlowStatus::Cancelled
                    } else {
                        FlowStatus::Denied
                    })
                }
                pubky::Error::Authentication(AuthError::RequestExpired) => {
                    Some(FlowStatus::Expired)
                }
                _ => None,
            };
            if let Some(status) = status {
                lease
                    .replace(
                        Some(record),
                        Some(&record.finished(status, None)),
                        record.key_id.clone(),
                    )
                    .await?;
            }
            return Err(error.into());
        }
    };
    // Checkpoint the child before exchanging it: from now on this request can
    // only finish with this child.
    let accepted = record.exchange_pending(approval.signed_approval());
    lease.replace(Some(record), Some(&accepted), None).await?;
    exchange(pubky, lease, &accepted).await
}

/// Exchange the accepted child with a fresh proof and save the session.
async fn exchange(
    pubky: &pubky::Pubky,
    lease: &RedirectLease,
    record: &FlowRecord,
) -> JsResult<RedirectAuthResult> {
    let flow = restore_flow(pubky, record)?;
    let approval =
        flow.accept_signed_approval(record.signed_approval.as_deref().ok_or_else(invalid_flow)?)?;
    let key_id = record.key_id.clone().ok_or_else(invalid_flow)?;
    if BrowserGrantKeyStore::load_public_key(key_id).await? != approval.claims().cnf {
        return Err(invalid_flow());
    }
    let mut prepared = record.clone();
    if prepared.logout_record.is_none() {
        prepared.logout_record = Some(logout_record(pubky, record, &approval).await?);
        lease.replace(Some(record), Some(&prepared), None).await?;
    }
    let credential = flow.exchange(&approval).await?;
    let session = pubky::PubkySession::from_grant_credential(pubky.client().clone(), credential);
    let grant = session.as_grant().expect("grant credential");
    let stored = StoredSessionRecord::for_session(&grant).await?;
    let coordinator = Arc::new(BrowserSessionCoordinator::new(
        &stored.metadata.id,
        &stored.metadata.homeserver,
    ));
    let session_lease = coordinator.acquire_browser(true).await?;
    let complete = record.finished(FlowStatus::Complete, Some(stored.metadata.id.clone()));
    lease
        .commit(&prepared, &complete, &stored, session_lease.token)
        .await?;
    grant.coordinate(coordinator, &session_lease).await?;
    drop(session_lease);
    Ok(RedirectAuthResult {
        stored_session: stored.metadata.clone(),
        session,
    })
}

/// Prepare enough public material to revoke a possibly interrupted exchange.
async fn logout_record(
    pubky: &pubky::Pubky,
    record: &FlowRecord,
    approval: &pubky::ChildGrantApproval,
) -> JsResult<StoredSessionRecord> {
    let claims = approval.claims();
    let homeserver = pubky.get_homeserver_of(&claims.iss).await?.ok_or_else(|| {
        pubky::Error::from(AuthError::Validation("the user has no homeserver".into()))
    })?;
    let state = pubky::DelegatedGrantCredentialState {
        grant_jws: approval.child_grant().to_owned(),
        homeserver_pk: homeserver.clone(),
        key_id: record.key_id.clone().ok_or_else(invalid_flow)?,
        client_pk: claims.cnf.clone(),
    };
    let sign = BrowserGrantKeyStore::signer(state.key_id.clone());
    let credential = pubky::GrantCredential::from_shared_delegated_child_logout(
        state,
        approval.parent_grant(),
        sign,
    )?;
    let session = pubky::PubkySession::from_grant_credential(pubky.client().clone(), credential);
    let grant = session.as_grant().expect("grant credential");
    Ok(StoredSessionRecord::for_session(&grant)
        .await?
        .logout_only())
}

async fn cancel_exchange(
    pubky: &pubky::Pubky,
    lease: &RedirectLease,
    record: &FlowRecord,
) -> JsResult<()> {
    let Some(stored) = &record.logout_record else {
        // No exchange can start before its revocation material is saved.
        return lease
            .replace(
                Some(record),
                Some(&record.finished(FlowStatus::Cancelled, None)),
                record.key_id.clone(),
            )
            .await;
    };
    let id = stored.metadata.id.clone();
    let session_lease = BrowserSessionCoordinator::new(&id, &stored.metadata.homeserver)
        .acquire_browser(true)
        .await?;
    let cancelled = record.finished(FlowStatus::Cancelled, Some(id.clone()));
    lease
        .commit(record, &cancelled, stored, session_lease.token)
        .await?;
    drop(session_lease);
    finish_child_signout(pubky.client(), &id).await
}

async fn finish_cancelled(client: &pubky::PubkyHttpClient, record: &FlowRecord) -> JsResult<()> {
    if record.status == FlowStatus::Cancelled
        && let Some(id) = &record.session_id
    {
        finish_child_signout(client, id).await?;
    }
    Ok(())
}

pub(crate) async fn finish_signout(
    client: &pubky::PubkyHttpClient,
    callback: &str,
) -> JsResult<()> {
    let lease = RedirectLease::acquire(callback).await?;
    if let Some(record) = lease.load().await? {
        finish_cancelled(client, &record).await?;
    }
    Ok(())
}
