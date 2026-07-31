use wasm_bindgen::prelude::*;

use crate::actors::{
    auth_flow::{AuthFlow, AuthFlowKind},
    browser_grant_key_store::BrowserGrantKeyStore,
    deep_links::XCallbackParams,
    event_stream::EventStreamBuilder,
    grant_auth_flow::{GrantAuthFlow, GrantAuthFlowOptions},
    session::Session,
    session_store::BrowserSessionStore,
    signer::Signer,
    storage::PublicStorage,
};
use crate::wrappers::keys::PublicKey;
use crate::{client::constructor::Client, js_error::JsResult, wrappers::keys::Keypair};

/// High-level entrypoint to the Pubky SDK.
#[wasm_bindgen]
pub struct Pubky(pub(crate) pubky::Pubky);

#[wasm_bindgen]
impl Pubky {
    /// Create a Pubky facade wired for **mainnet** defaults (public relays).
    ///
    /// Prefer to instantiate only once and use trough your application a single shared `Pubky`
    /// instead of constructing one per request. This avoids reinitializing transports and keeps
    /// the same client available for repeated usage.
    ///
    /// @returns {Pubky}
    /// A new facade instance. Use this to create signers, start auth flows, etc.
    ///
    /// @example
    /// const pubky = new Pubky();
    /// const signer = pubky.signer(Keypair.random());
    #[wasm_bindgen(constructor)]
    pub fn new() -> JsResult<Pubky> {
        let client = Client::new(None)?;
        Ok(Pubky(pubky::Pubky::with_client(client.0)))
    }

    /// Create a Pubky facade preconfigured for a **local testnet**.
    ///
    /// If `host` is provided, PKARR and HTTP endpoints are derived as `http://<host>:ports/...`.
    /// If omitted, `"localhost"` is assumed (handy for `cargo install pubky-testnet`).
    ///
    /// @param {string=} host Optional host (e.g. `"localhost"`, `"docker-host"`, `"127.0.0.1"`).
    /// @returns {Pubky}
    ///
    /// @example
    /// const pubky = Pubky.testnet();              // localhost default
    /// const pubky = Pubky.testnet("docker-host"); // custom hostname/IP
    #[wasm_bindgen(js_name = "testnet")]
    pub fn testnet(host: Option<String>) -> JsResult<Pubky> {
        let client = Client::testnet(host)?;
        Ok(Pubky(pubky::Pubky::with_client(client.0)))
    }

    /// Wrap an existing configured HTTP client into a Pubky facade.
    ///
    /// @param {Client} client A previously constructed client.
    /// @returns {Pubky}
    ///
    /// @example
    /// const client = Client.testnet();
    /// const pubky = Pubky.withClient(client);
    #[wasm_bindgen(js_name = "withClient")]
    pub fn with_client(client: &Client) -> Pubky {
        Pubky(pubky::Pubky::with_client(client.0.clone()))
    }

    /// Start a **pubkyauth** flow.
    ///
    /// Provide a **capabilities string** and (optionally) a relay base URL.
    /// The capabilities string is a comma-separated list of entries:
    /// `"<scope>:<actions>"`, where:
    /// - `scope` starts with `/` (e.g. `/pub/example.com/`).
    /// - `actions` is any combo of `r` and/or `w` (order normalized; `wr` -> `rw`).
    /// Pass `""` for no scopes (read-only public session).
    ///
    /// **Security:** `authorizationUrl` contains the `client_secret` in plaintext.
    /// If you need resume after refresh/app switch, save it in `sessionStorage`
    /// (not `localStorage`), then delete it once approval arrives or is abandoned.
    ///
    /// @param {string} capabilities Comma-separated caps, e.g. `"/pub/app/:rw,/pub/foo/file:r"`.
    /// @param {AuthFlowKind} kind The kind of authentication flow to perform.
    /// Examples:
    /// - `AuthFlowKind.signin()` - Sign in to an existing account.
    /// - `AuthFlowKind.signup(homeserverPublicKey, signupToken)` - Sign up for a new account.
    /// @param {string=} relay Optional HTTP relay base (e.g. `"https://…/inbox/"`).
    /// @param {XCallbackParams=} xCallback Optional app return destinations.
    /// @returns {AuthFlow}
    /// A running auth flow. Show `authorizationUrl` as QR/deeplink,
    /// then `awaitApproval()` to obtain a `Session`.
    ///
    /// @throws {PubkyError}
    /// - `{ name: "InvalidInput" }` for malformed capabilities or bad relay URL
    /// - `{ name: "RequestError" }` if the flow cannot be started (network/relay)
    ///
    /// @example
    /// const flow = pubky.startCookieAuthFlow("/pub/my-cool-app/:rw");
    /// renderQr(flow.authorizationUrl);
    /// const session = await flow.awaitApproval();
    ///
    #[wasm_bindgen(js_name = "startCookieAuthFlow")]
    pub fn start_cookie_auth_flow(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Capabilities")] capabilities: String,
        kind: AuthFlowKind,
        relay: Option<String>,
        x_callback: Option<XCallbackParams>,
    ) -> JsResult<AuthFlow> {
        let flow = AuthFlow::start_with_client(
            capabilities,
            kind,
            relay,
            x_callback,
            Some(self.0.client().clone()),
        )?;
        Ok(flow)
    }

    /// Start a grant-backed **pubkyauth** flow.
    ///
    /// Grant auth uses a user-signed grant JWS plus Proof-of-Possession and
    /// returns a self-refreshing session.
    ///
    /// @param {string} capabilities Comma-separated caps, e.g. `"/pub/app/:rw,/pub/foo/file:r"`.
    /// @param {AuthFlowKind} kind The kind of authentication flow to perform.
    /// @param {GrantAuthFlowOptions} options Options for the grant flow:
    /// `{ clientId, relay?, xCallback? }`.
    /// @returns {Promise<GrantAuthFlow>}
    /// A running grant auth flow. Show `authorizationUrl` as QR/deeplink,
    /// then `awaitApproval()` to obtain a grant-backed `Session`.
    ///
    /// @example
    /// const flow = await pubky.startGrantAuthFlow(
    ///   "/pub/my-cool-app/:rw",
    ///   AuthFlowKind.signin(),
    ///   { clientId: "my-cool-app.example" },
    /// );
    #[wasm_bindgen(js_name = "startGrantAuthFlow")]
    pub async fn start_grant_auth_flow(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Capabilities")] capabilities: String,
        kind: AuthFlowKind,
        options: GrantAuthFlowOptions,
    ) -> JsResult<GrantAuthFlow> {
        if BrowserGrantKeyStore::can_use_delegation().await {
            let delegated = GrantAuthFlow::start_delegated_with_client(
                capabilities.clone(),
                kind.clone(),
                options.clone(),
                Some(self.0.client().clone()),
            )
            .await;
            if delegated.is_ok() {
                return delegated;
            }
        }

        GrantAuthFlow::start_with_client(capabilities, kind, options, Some(self.0.client().clone()))
    }

    /// Resume a previously started **pubkyauth** flow from its saved `authorizationUrl`.
    ///
    /// If the user refreshes or navigates away mid-flow, WASM memory is lost and
    /// the original `AuthFlow` object is gone. You can reconnect to the same relay
    /// channel by saving the `authorizationUrl` beforehand and calling this method
    /// after reload.
    ///
    /// The relay inbox retains messages for **~5 minutes**. Resume is only
    /// viable within that window; afterwards start a fresh flow.
    ///
    /// **Security:** The URL contains the `client_secret` in plaintext.
    /// Store it in `sessionStorage` (scoped to the tab), **not** `localStorage`,
    /// and delete it as soon as the resumed flow completes or is abandoned.
    /// See `startCookieAuthFlow()` docs for full storage guidance.
    ///
    /// @param {string} authorizationUrl The `pubkyauth://…` URL from a previous flow.
    /// @returns {AuthFlow} A flow reconnected to the original relay channel.
    /// @throws {PubkyError}
    /// - `{ name: "AuthenticationError" }` if the URL is invalid or not a signin/signup link
    /// - `{ name: "RequestError" }` on network/relay failure
    ///
    /// @example
    /// // 1) Before a potential refresh, persist the URL.
    /// const flow = pubky.startCookieAuthFlow("/pub/my-cool-app/:rw", AuthFlowKind.signin());
    /// sessionStorage.setItem("pubky-auth-url", flow.authorizationUrl);
    /// renderQr(flow.authorizationUrl);
    ///
    /// // 2) After reload, resume from the saved URL.
    /// const savedUrl = sessionStorage.getItem("pubky-auth-url");
    /// if (savedUrl) {
    ///   try {
    ///     const resumed = pubky.resumeCookieAuthFlow(savedUrl);
    ///     const session = await resumed.awaitApproval();
    ///   } finally {
    ///     sessionStorage.removeItem("pubky-auth-url");
    ///   }
    /// }
    #[wasm_bindgen(js_name = "resumeCookieAuthFlow")]
    pub fn resume_cookie_auth_flow(&self, authorization_url: String) -> JsResult<AuthFlow> {
        AuthFlow::resume_with_client(authorization_url, Some(self.0.client().clone()))
    }

    /// Resume a previously saved pending grant auth flow.
    ///
    /// **Security:** `savedState` contains the relay secret and PoP client private key.
    /// Delete it from storage as soon as the resumed flow completes.
    ///
    /// @param {string} savedState A string produced by `grantFlow.saveLocal()`.
    /// @returns {GrantAuthFlow} A flow reconnected to the original relay channel.
    #[wasm_bindgen(js_name = "resumeGrantAuthFlow")]
    pub fn resume_grant_auth_flow(&self, saved_state: String) -> JsResult<GrantAuthFlow> {
        GrantAuthFlow::resume_with_client(saved_state, Some(self.0.client().clone()))
    }

    /// Resume a previously saved pending delegated grant auth flow.
    ///
    /// Runtime: delegated grant keys require a secure browser context with
    /// WebCrypto `crypto.subtle` and IndexedDB. The saved `keyId` must still
    /// exist in IndexedDB for the same origin. Unsupported runtimes reject with
    /// `ClientStateError`.
    #[wasm_bindgen(js_name = "resumeDelegatedGrantAuthFlow")]
    pub async fn resume_delegated_grant_auth_flow(
        &self,
        saved_state: String,
    ) -> JsResult<GrantAuthFlow> {
        GrantAuthFlow::resume_delegated_with_client(saved_state, Some(self.0.client().clone()))
            .await
    }

    /// Create a `Signer` from an existing `Keypair`.
    ///
    /// @param {Keypair} keypair The user’s keys.
    /// @returns {Signer}
    ///
    /// @example
    /// const signer = pubky.signer(Keypair.random());
    /// await signer.signup(homeserverPk);
    #[wasm_bindgen(js_name = "signer")]
    pub fn signer(&self, keypair: &Keypair) -> Signer {
        Signer(self.0.signer(keypair.as_inner().clone()))
    }

    /// Public, unauthenticated storage API.
    ///
    /// Use for **read-only** public access via addressed paths:
    /// `"pubky<user>/pub/…"`.
    ///
    /// @returns {PublicStorage}
    ///
    /// @example
    /// const text = await pubky.publicStorage.getText(`${userPk.toString()}/pub/example.com/hello.txt`);
    #[wasm_bindgen(js_name = "publicStorage", getter)]
    pub fn public_storage(&self) -> PublicStorage {
        PublicStorage(self.0.public_storage())
    }

    /// Browser-backed store for explicitly persisted completed grant sessions.
    ///
    /// Use `browserSessionStore.save(session)` after a successful grant auth flow to make
    /// the session restorable after reload. The store supports multiple accounts
    /// and multiple grants per account.
    #[wasm_bindgen(js_name = "browserSessionStore", getter)]
    pub fn browser_session_store(&self) -> BrowserSessionStore {
        BrowserSessionStore(self.0.clone())
    }

    /// Resolve the homeserver for a given public key (read-only).
    ///
    /// Uses an internal read-only Pkdns actor.
    ///
    /// @param {PublicKey} user
    /// @returns {Promise<PublicKey|undefined>} Homeserver public key or `undefined` if not found.
    #[wasm_bindgen(js_name = "getHomeserverOf")]
    pub async fn get_homeserver_of(&self, user_public_key: &PublicKey) -> Option<PublicKey> {
        self.0
            .get_homeserver_of(user_public_key.as_inner())
            .await
            .map(Into::into)
    }

    /// Access the underlying HTTP client (advanced).
    ///
    /// @returns {Client}
    /// Use this for low-level `fetch()` calls or testing with raw URLs.
    ///
    /// @example
    /// const r = await pubky.client.fetch(`pubky://${userPk.z32()}/pub/app/file.txt`, { credentials: "include" });
    #[wasm_bindgen(getter)]
    pub fn client(&self) -> Client {
        Client(self.0.client().clone())
    }

    /// Restore a session from a previously exported token or snapshot, using this instance's client.
    ///
    /// Accepts grant secret tokens from `session.exportLocalSecret()` and legacy cookie
    /// secret tokens. Also accepts legacy cookie metadata snapshots from `session.export()`.
    /// Grant restore mints a fresh short-lived bearer.
    ///
    /// @param {string} exported A string produced by `session.exportLocalSecret()` or legacy `session.export()`.
    /// @returns {Promise<Session>}
    /// A rehydrated session bound to this SDK's HTTP client.
    ///
    /// @example
    /// const restored = await pubky.restoreSession(localStorage.getItem("pubky-session")!);
    #[wasm_bindgen(js_name = "restoreSession")]
    pub async fn restore_session(&self, exported: String) -> JsResult<Session> {
        let session = if exported.starts_with("pubky-grant-credential-") || exported.contains(':') {
            self.0.restore_session(&exported).await?
        } else {
            pubky::PubkySession::import(&exported, Some(self.0.client().clone())).await?
        };
        Ok(Session(session))
    }

    /// Create an event stream builder for a single user.
    ///
    /// This is the simplest way to subscribe to events for one user. The homeserver
    /// is automatically resolved from the user's Pkarr record.
    ///
    /// @param {PublicKey} user - The user's public key
    /// @param {string | null} cursor - Optional cursor position to start from
    /// @returns {EventStreamBuilder} - Builder for configuring and subscribing to the stream
    ///
    /// @example
    /// ```typescript
    /// const user = PublicKey.from("o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo");
    /// const stream = await pubky.eventStreamForUser(user, null)
    ///   .live()
    ///   .subscribe();
    ///
    /// for await (const event of stream) {
    ///   console.log(`${event.eventType}: ${event.resource.path}`);
    /// }
    /// ```
    #[wasm_bindgen(js_name = "eventStreamForUser")]
    pub fn event_stream_for_user(
        &self,
        user: &PublicKey,
        cursor: Option<String>,
    ) -> Result<EventStreamBuilder, JsValue> {
        let event_cursor = cursor
            .map(|c| {
                c.parse::<pubky::EventCursor>()
                    .map_err(|e| JsValue::from_str(&format!("Invalid cursor: {e}")))
            })
            .transpose()?;
        Ok(EventStreamBuilder(pubky::EventStreamBuilder::for_user(
            self.0.client().clone(),
            user.as_inner(),
            event_cursor,
        )))
    }

    /// Create an event stream builder for a specific homeserver.
    ///
    /// Use this when you already know the homeserver pubkey. This avoids
    /// Pkarr resolution overhead. Obtain a homeserver pubkey via `getHomeserverOf()`.
    ///
    /// @param {PublicKey} homeserver - The homeserver public key
    /// @returns {EventStreamBuilder} - Builder for configuring and subscribing to the stream
    ///
    /// @example
    /// ```typescript
    /// const homeserver = await pubky.getHomeserverOf(user1);
    /// const stream = await pubky.eventStreamFor(homeserver)
    ///   .addUsers([[user1.z32(), null], [user2.z32(), null]])
    ///   .live()
    ///   .subscribe();
    ///
    /// for await (const event of stream) {
    ///   console.log(`${event.eventType}: ${event.resource.path}`);
    /// }
    /// ```
    #[wasm_bindgen(js_name = "eventStreamFor")]
    pub fn event_stream_for(&self, homeserver: &PublicKey) -> EventStreamBuilder {
        EventStreamBuilder(pubky::EventStreamBuilder::for_homeserver(
            self.0.client().clone(),
            homeserver.as_inner(),
        ))
    }
}
