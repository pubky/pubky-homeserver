use pubky::{DelegatedGrantAuthFlowState, GrantAuthFlowState, PubkyGrantAuthFlow};
use pubky_common::auth::jws::ClientId;
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, rc::Rc};
use tsify::Tsify;
use url::Url;

use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::{
    auth_flow::AuthFlowKind, browser_grant_key_store::BrowserGrantKeyStore,
    in_flight::InFlightGuard, session::Session,
};
use crate::{
    js_error::{JsResult, PubkyError, PubkyErrorName},
    wrappers::capabilities::parse_capabilities,
};

/// Options for starting a grant-backed pubkyauth flow.
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct GrantAuthFlowOptions {
    /// App identifier shown in the user's grant/session list, typically a domain.
    pub(crate) client_id: String,
    /// Optional HTTP relay base, e.g. `"https://demo.httprelay.io/inbox/"`.
    /// Defaults to the default Synonym-hosted relay when omitted.
    #[tsify(optional, type = "string | null")]
    pub(crate) relay: Option<String>,
}

/// Start and control a grant-backed pubkyauth authorization flow.
///
/// Typical flow:
/// 1) `GrantAuthFlow.start(...)` or `pubky.startGrantAuthFlow(...)`
/// 2) Show `authorizationUrl()` as QR/deeplink to the user's signing device
/// 3) `awaitApproval()` to receive a grant-backed, self-refreshing `Session`
#[wasm_bindgen]
pub struct GrantAuthFlow {
    inner: RefCell<Option<Rc<PubkyGrantAuthFlow>>>,
    in_flight: RefCell<bool>,
    authorization_url: String,
}

#[wasm_bindgen]
impl GrantAuthFlow {
    /// Whether delegated grant auth is available in the current JS runtime.
    ///
    /// This checks for a secure browser context with WebCrypto `crypto.subtle`
    /// and IndexedDB. It is a coarse synchronous feature-detection helper only;
    /// some runtimes expose those primitives without Ed25519 support.
    #[wasm_bindgen(js_name = "isDelegationAvailable", getter)]
    pub fn is_delegation_available() -> bool {
        BrowserGrantKeyStore::is_available()
    }

    /// Start a grant-backed flow with a new DHT client.
    /// Prefer `pubky.startGrantAuthFlow()` to reuse a facade DHT client.
    ///
    /// @param {string} capabilities
    /// Comma-separated capabilities, e.g. `"/pub/app/:rw,/priv/foo.txt:r"`.
    /// Empty string is allowed (no scopes).
    ///
    /// @param {AuthFlowKind} kind
    /// The kind of authentication flow to perform.
    ///
    /// @param {GrantAuthFlowOptions} options
    /// Options for the grant flow: `{ clientId, relay? }`.
    ///
    /// @returns {GrantAuthFlow}
    /// A running grant auth flow. Call `authorizationUrl()` to show the deep link,
    /// then `awaitApproval()` to receive a grant-backed `Session`.
    #[wasm_bindgen(js_name = "start")]
    pub fn start(
        #[wasm_bindgen(unchecked_param_type = "Capabilities")] capabilities: String,
        kind: AuthFlowKind,
        options: GrantAuthFlowOptions,
    ) -> JsResult<GrantAuthFlow> {
        Self::start_with_client(capabilities, kind, options, None)
    }

    /// Internal helper that threads an explicit transport.
    pub(crate) fn start_with_client(
        capabilities: String,
        kind: AuthFlowKind,
        options: GrantAuthFlowOptions,
        client: Option<pubky::PubkyHttpClient>,
    ) -> JsResult<GrantAuthFlow> {
        let caps = parse_capabilities(&capabilities)?;
        let client_id = ClientId::new(&options.client_id).map_err(|e| {
            pubky::Error::Authentication(pubky::errors::AuthError::Validation(e.to_string()))
        })?;

        let mut builder = PubkyGrantAuthFlow::builder(&caps, kind.0, client_id);
        if let Some(c) = client {
            builder = builder.client(c);
        }

        if let Some(r) = options.relay {
            builder = builder.relay(Url::parse(&r)?);
        }

        let flow = builder.start()?;
        Ok(flow.into())
    }

    /// Start a browser delegated grant-backed flow.
    ///
    /// The SDK creates a fresh non-extractable WebCrypto Ed25519 key in
    /// IndexedDB and uses that key for grant Proof-of-Possession signing.
    ///
    /// Runtime: delegated grant keys require a secure browser context with
    /// WebCrypto `crypto.subtle` and IndexedDB. Unsupported runtimes reject
    /// with `ClientStateError`.
    #[wasm_bindgen(js_name = "startDelegated")]
    pub async fn start_delegated(
        #[wasm_bindgen(unchecked_param_type = "Capabilities")] capabilities: String,
        kind: AuthFlowKind,
        options: GrantAuthFlowOptions,
    ) -> JsResult<GrantAuthFlow> {
        Self::start_delegated_with_client(capabilities, kind, options, None).await
    }

    pub(crate) async fn start_delegated_with_client(
        capabilities: String,
        kind: AuthFlowKind,
        options: GrantAuthFlowOptions,
        client: Option<pubky::PubkyHttpClient>,
    ) -> JsResult<GrantAuthFlow> {
        let caps = parse_capabilities(&capabilities)?;
        let client_id = ClientId::new(&options.client_id).map_err(|e| {
            pubky::Error::Authentication(pubky::errors::AuthError::Validation(e.to_string()))
        })?;
        let (key_id, public_key) = BrowserGrantKeyStore::ensure_key(None).await?;
        let sign = BrowserGrantKeyStore::signer(key_id.clone());

        let mut builder = PubkyGrantAuthFlow::builder(&caps, kind.0, client_id)
            .delegated_client_signer(key_id, public_key, sign);
        if let Some(c) = client {
            builder = builder.client(c);
        }

        if let Some(r) = options.relay {
            builder = builder.relay(Url::parse(&r)?);
        }

        let flow = builder.start()?;
        Ok(flow.into())
    }

    /// Resume a previously saved pending grant auth flow (standalone).
    /// Prefer `pubky.resumeGrantAuthFlow()` to reuse a facade client.
    ///
    /// **Security:** `savedState` contains the relay secret and PoP client private key.
    /// Store it only temporarily and delete it once the flow completes or is abandoned.
    ///
    /// @param {string} savedState A string produced by `grantFlow.saveLocal()`.
    /// @returns {GrantAuthFlow} A flow reconnected to the original relay channel.
    #[wasm_bindgen(js_name = "resume")]
    pub fn resume(saved_state: String) -> JsResult<GrantAuthFlow> {
        Self::resume_with_client(saved_state, None)
    }

    /// Internal helper that threads an explicit transport for resume.
    pub(crate) fn resume_with_client(
        saved_state: String,
        client: Option<pubky::PubkyHttpClient>,
    ) -> JsResult<GrantAuthFlow> {
        let state: GrantAuthFlowState = serde_json::from_str(&saved_state).map_err(|e| {
            PubkyError::new(
                PubkyErrorName::InvalidInput,
                format!("Invalid grant auth flow state: {e}"),
            )
        })?;
        let client = match client {
            Some(c) => c,
            None => pubky::PubkyHttpClient::new()?,
        };
        Ok(PubkyGrantAuthFlow::restore(state, client)?.into())
    }

    /// Resume a previously saved pending delegated grant auth flow.
    ///
    /// Runtime: delegated grant keys require a secure browser context with
    /// WebCrypto `crypto.subtle` and IndexedDB. The saved `keyId` must still
    /// exist in IndexedDB for the same origin. Unsupported runtimes reject with
    /// `ClientStateError`.
    #[wasm_bindgen(js_name = "resumeDelegated")]
    pub async fn resume_delegated(saved_state: String) -> JsResult<GrantAuthFlow> {
        Self::resume_delegated_with_client(saved_state, None).await
    }

    pub(crate) async fn resume_delegated_with_client(
        saved_state: String,
        client: Option<pubky::PubkyHttpClient>,
    ) -> JsResult<GrantAuthFlow> {
        let state: DelegatedGrantAuthFlowState =
            serde_json::from_str(&saved_state).map_err(|e| {
                PubkyError::new(
                    PubkyErrorName::InvalidInput,
                    format!("Invalid delegated grant auth flow state: {e}"),
                )
            })?;
        let stored_public_key = BrowserGrantKeyStore::load_public_key(state.key_id.clone()).await?;
        if stored_public_key != state.client_pk {
            return Err(PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Delegated grant key public key does not match saved flow.",
            ));
        }
        let client = match client {
            Some(c) => c,
            None => pubky::PubkyHttpClient::new()?,
        };
        let sign = BrowserGrantKeyStore::signer(state.key_id.clone());
        Ok(PubkyGrantAuthFlow::restore_delegated(state, client, sign)?.into())
    }

    /// Return the authorization deep link (URL) to show as QR or open on the signer device.
    #[wasm_bindgen(js_name = "authorizationUrl", getter)]
    pub fn authorization_url(&self) -> String {
        self.authorization_url.clone()
    }

    /// Save sensitive state required to resume this pending local grant flow.
    ///
    /// @returns {string} Opaque state for `GrantAuthFlow.resume()` or
    /// `pubky.resumeGrantAuthFlow()`.
    #[wasm_bindgen(js_name = "saveLocal")]
    pub fn save_local(&self) -> JsResult<String> {
        let flow = self.borrow_inner()?;
        let state = flow.save_local().ok_or_else(|| {
            PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Delegated grant auth flows cannot export raw secret state. Use saveDelegated().",
            )
        })?;
        serde_json::to_string(&state).map_err(|e| {
            PubkyError::new(
                PubkyErrorName::InternalError,
                format!("Failed to serialize grant auth flow state: {e}"),
            )
        })
    }

    /// Save sensitive state required to resume this delegated pending grant flow.
    ///
    /// This does not export the delegated private key, but it includes the relay
    /// secret in the authorization URL. Store it only temporarily and delete it
    /// once the flow completes or is abandoned.
    #[wasm_bindgen(js_name = "saveDelegated")]
    pub fn save_delegated(&self) -> JsResult<String> {
        let flow = self.borrow_inner()?;
        let state = flow.save_delegated().ok_or_else(|| {
            PubkyError::new(
                PubkyErrorName::ClientStateError,
                "This grant auth flow is not delegated.",
            )
        })?;
        serde_json::to_string(&state).map_err(|e| {
            PubkyError::new(
                PubkyErrorName::InternalError,
                format!("Failed to serialize delegated grant auth flow state: {e}"),
            )
        })
    }

    /// Block until the user approves on their signer device; returns a grant-backed `Session`.
    #[wasm_bindgen(js_name = "awaitApproval")]
    pub async fn await_approval(&self) -> JsResult<Session> {
        let _guard = self.begin_call("awaitApproval")?;
        let flow = self.take_inner("awaitApproval")?;

        match Rc::try_unwrap(flow) {
            Ok(flow) => Ok(Session(flow.await_approval().await?)),
            Err(flow) => {
                self.restore_inner(flow);
                Err(self.in_use_error("awaitApproval"))
            }
        }
    }

    /// Non-blocking single poll step (advanced UIs).
    ///
    /// @returns {Promise<Session|undefined>} A session if the approval arrived, otherwise `undefined`.
    #[wasm_bindgen(js_name = "tryPollOnce")]
    pub async fn try_poll_once(&self) -> JsResult<Option<Session>> {
        let _guard = self.begin_call("tryPollOnce")?;
        let _ = JsFuture::from(js_sys::Promise::resolve(&JsValue::NULL)).await;
        let flow = self.borrow_inner()?;
        let result = flow.try_poll_once().await?.map(Session);
        let _ = JsFuture::from(js_sys::Promise::resolve(&JsValue::NULL)).await;
        Ok(result)
    }
}

impl From<PubkyGrantAuthFlow> for GrantAuthFlow {
    fn from(flow: PubkyGrantAuthFlow) -> Self {
        let auth_url = flow.authorization_url().as_str().to_string();
        GrantAuthFlow {
            authorization_url: auth_url,
            in_flight: RefCell::new(false),
            inner: RefCell::new(Some(Rc::new(flow))),
        }
    }
}

impl GrantAuthFlow {
    fn begin_call(&self, caller: &str) -> JsResult<InFlightGuard<'_>> {
        InFlightGuard::begin(&self.in_flight, || self.in_use_error(caller))
    }

    fn borrow_inner(&self) -> JsResult<Rc<PubkyGrantAuthFlow>> {
        self.inner
            .borrow()
            .as_ref()
            .cloned()
            .ok_or_else(|| self.consumed_error())
    }

    fn take_inner(&self, caller: &str) -> JsResult<Rc<PubkyGrantAuthFlow>> {
        self.inner
            .borrow_mut()
            .take()
            .ok_or_else(|| self.already_taken_error(caller))
    }

    fn restore_inner(&self, flow: Rc<PubkyGrantAuthFlow>) {
        let mut inner = self.inner.borrow_mut();
        *inner = Some(flow);
    }

    fn consumed_error(&self) -> PubkyError {
        PubkyError::new(
            PubkyErrorName::ClientStateError,
            "GrantAuthFlow has already completed; start a new flow for another login.",
        )
    }

    fn already_taken_error(&self, caller: &str) -> PubkyError {
        PubkyError::new(
            PubkyErrorName::ClientStateError,
            format!("GrantAuthFlow.{caller}() was already called; create a new GrantAuthFlow."),
        )
    }

    fn in_use_error(&self, caller: &str) -> PubkyError {
        PubkyError::new(
            PubkyErrorName::ClientStateError,
            format!("GrantAuthFlow.{caller}() cannot run while another call is in-flight."),
        )
    }
}
