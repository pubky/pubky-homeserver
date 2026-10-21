use wasm_bindgen::prelude::*;

use super::encryption_keys::EncryptionKeys;

use crate::custom_pop::{CustomPop, JsonValue};
use crate::js_error::{JsResult, PubkyError, PubkyErrorName};
use crate::wrappers::keys::PublicKey;
use serde::{Deserialize, Serialize};
use tsify::Ts;

const DELEGATED_GRANT_CREDENTIAL_VERSION: &str = "pubky-delegated-grant-credential-v1";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DelegatedGrantCredentialJson {
    version: String,
    grant_jws: String,
    homeserver_public_key: String,
    client_public_key: String,
    key_id: String,
}

/// Grant-only view over a grant-backed `Session`.
///
/// Cookie-backed sessions do not expose this view; use `session.grant` and
/// check for `undefined` before calling grant-session methods.
#[wasm_bindgen]
pub struct GrantSession(pub(crate) pubky::PubkySession);

#[wasm_bindgen]
impl GrantSession {
    /// Sign JSON data and return both the custom proof and its root-signed grant.
    /// Data follows `JSON.stringify` semantics, e.g. `undefined` properties are omitted.
    /// Each proof carries its signing time (`iat`) and a random `nonce`.
    /// Makes no network requests. Your applications handle freshness and replay protection.
    #[wasm_bindgen(js_name = "createCustomPop")]
    pub async fn create_custom_pop(&self, data: JsonValue) -> JsResult<Ts<CustomPop>> {
        let data = json_value_from_js(&data.into())?;
        let proof = self.as_grant()?.create_custom_pop(data).await?;
        crate::js_error::serialize_ts(&CustomPop {
            grant: proof.grant,
            pop: proof.pop,
        })
    }

    /// Return scoped keys with the same derivation API as offline recovered keys.
    /// Bare grants return `undefined`; signed approvals without `e` scopes
    /// return an object with empty scopes.
    /// Each access creates an owned copy. Keep it for repeated use and call
    /// `free()` when finished. It remains usable after this view or its session
    /// is freed, signed out, or revoked; freeing it does not affect the session.
    #[wasm_bindgen(js_name = "encryptionKeys", getter)]
    pub fn encryption_keys(&self) -> JsResult<Option<EncryptionKeys>> {
        Ok(self
            .as_grant()?
            .encryption_keys()
            .cloned()
            .map(EncryptionKeys))
    }

    /// Full grant session metadata.
    ///
    /// @returns {Promise<GrantSessionInfo>}
    #[wasm_bindgen(js_name = "sessionInfo")]
    pub async fn session_info(&self) -> JsResult<GrantSessionInfo> {
        let grant = self.as_grant()?;
        Ok(GrantSessionInfo(grant.session_info().await))
    }

    /// Current grant id (`jti`) backing this session.
    ///
    /// @returns {Promise<string>}
    #[wasm_bindgen(js_name = "grantId")]
    pub async fn grant_id(&self) -> JsResult<String> {
        let grant = self.as_grant()?;
        Ok(grant.grant_id().await.to_string())
    }

    /// Export the portable local secret material needed to restore this grant session.
    ///
    /// Treat the returned string as bearer-equivalent secret material until the
    /// grant expires or is revoked. Included scoped keys remain sensitive after
    /// expiry or revocation.
    ///
    /// @returns {Promise<string>}
    #[wasm_bindgen(js_name = "exportLocalSecret")]
    pub async fn export_local_secret(&self) -> JsResult<String> {
        let grant = self.as_grant()?;
        grant.export_local_secret().await.ok_or_else(|| {
            PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Delegated grant sessions cannot export raw secret material. Use BrowserSessionStore.",
            )
        })
    }
}

impl GrantSession {
    fn as_grant(&self) -> JsResult<pubky::GrantSessionView<'_>> {
        self.0.as_grant().ok_or_else(|| {
            PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Session is not grant-backed.",
            )
        })
    }
}

pub(crate) fn encode_delegated_grant_state(
    state: pubky::DelegatedGrantCredentialState,
) -> JsResult<String> {
    let json = DelegatedGrantCredentialJson {
        version: DELEGATED_GRANT_CREDENTIAL_VERSION.to_string(),
        grant_jws: state.grant_jws,
        homeserver_public_key: state.homeserver_pk.z32(),
        client_public_key: state.client_pk.z32(),
        key_id: state.key_id,
    };
    serde_json::to_string(&json).map_err(|e| {
        PubkyError::new(
            PubkyErrorName::InternalError,
            format!("Failed to serialize delegated grant state: {e}"),
        )
    })
}

pub(crate) fn decode_delegated_grant_state(
    saved_state: &str,
) -> JsResult<pubky::DelegatedGrantCredentialState> {
    let json: DelegatedGrantCredentialJson = serde_json::from_str(saved_state).map_err(|e| {
        PubkyError::new(
            PubkyErrorName::InvalidInput,
            format!("Invalid delegated grant state: {e}"),
        )
    })?;
    if json.version != DELEGATED_GRANT_CREDENTIAL_VERSION {
        return Err(PubkyError::new(
            PubkyErrorName::InvalidInput,
            "Unsupported delegated grant state version.",
        ));
    }
    Ok(pubky::DelegatedGrantCredentialState {
        grant_jws: json.grant_jws,
        homeserver_pk: pubky::PublicKey::try_from_z32(&json.homeserver_public_key)
            .map_err(|e| PubkyError::new(PubkyErrorName::InvalidInput, e))?,
        client_pk: pubky::PublicKey::try_from_z32(&json.client_public_key)
            .map_err(|e| PubkyError::new(PubkyErrorName::InvalidInput, e))?,
        key_id: json.key_id,
    })
}

/// Summary of an active grant returned by `GrantManager.list()`.
#[wasm_bindgen]
pub struct GrantInfo(pub(crate) pubky_common::auth::grant_session_responses::GrantInfo);

#[wasm_bindgen]
impl GrantInfo {
    /// Grant identifier used for revocation.
    #[wasm_bindgen(js_name = "grantId", getter)]
    pub fn grant_id(&self) -> String {
        self.0.grant_id.to_string()
    }

    /// Application identifier.
    #[wasm_bindgen(js_name = "clientId", getter)]
    pub fn client_id(&self) -> String {
        self.0.client_id.clone()
    }

    /// Comma-separated capabilities authorized by the grant.
    #[wasm_bindgen(getter)]
    pub fn capabilities(&self) -> String {
        self.0.capabilities.clone()
    }

    /// Issued-at timestamp, in Unix seconds.
    #[wasm_bindgen(js_name = "issuedAt", getter)]
    pub fn issued_at(&self) -> f64 {
        self.0.issued_at as f64
    }

    /// Expiry timestamp, in Unix seconds.
    #[wasm_bindgen(js_name = "expiresAt", getter)]
    pub fn expires_at(&self) -> f64 {
        self.0.expires_at as f64
    }
}

/// Grant-specific session metadata returned by `grant.sessionInfo()`.
#[wasm_bindgen]
pub struct GrantSessionInfo(
    pub(crate) pubky_common::auth::grant_session_responses::GrantSessionInfo,
);

#[wasm_bindgen]
impl GrantSessionInfo {
    /// Homeserver that issued this session.
    #[wasm_bindgen(getter)]
    pub fn homeserver(&self) -> PublicKey {
        self.0.homeserver.clone().into()
    }

    /// User public key for this session.
    #[wasm_bindgen(js_name = "publicKey", getter)]
    pub fn public_key(&self) -> PublicKey {
        self.0.pubky.clone().into()
    }

    /// Application identifier.
    #[wasm_bindgen(js_name = "clientId", getter)]
    pub fn client_id(&self) -> String {
        self.0.client_id.to_string()
    }

    /// Authorized capabilities for this session.
    #[wasm_bindgen(getter)]
    pub fn capabilities(&self) -> Vec<String> {
        self.0
            .capabilities
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Grant id this session was minted from.
    #[wasm_bindgen(js_name = "grantId", getter)]
    pub fn grant_id(&self) -> String {
        self.0.grant_id.to_string()
    }

    /// Bearer token expiry timestamp, in Unix seconds.
    #[wasm_bindgen(js_name = "tokenExpiresAt", getter)]
    pub fn token_expires_at(&self) -> f64 {
        self.0.token_expires_at as f64
    }

    /// Underlying grant expiry timestamp, in Unix seconds.
    #[wasm_bindgen(js_name = "grantExpiresAt", getter)]
    pub fn grant_expires_at(&self) -> f64 {
        self.0.grant_expires_at as f64
    }

    /// Session creation timestamp, in Unix seconds.
    #[wasm_bindgen(js_name = "createdAt", getter)]
    pub fn created_at(&self) -> f64 {
        self.0.created_at as f64
    }
}

/// Convert through `JSON.stringify` so signed data matches what JSON transports carry.
fn json_value_from_js(value: &JsValue) -> JsResult<serde_json::Value> {
    let invalid = || {
        PubkyError::new(
            PubkyErrorName::InvalidInput,
            "Data must be JSON-serializable",
        )
    };
    let json = js_sys::JSON::stringify(value)
        .map_err(|_error| invalid())?
        .as_string()
        .ok_or_else(invalid)?;
    serde_json::from_str(&json)
        .map_err(|error| PubkyError::new(PubkyErrorName::InvalidInput, error))
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use pubky_common::{
        auth::{
            grant::GrantClaims,
            jws::{ClientId, GRANT_JWS_TYP, GrantId, sign_jws},
        },
        capabilities::Capabilities,
        crypto::Keypair,
        encryption_keys::ScopedEncryptionKeyBundle,
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen(inline_js = r#"
export function checkOwnedSessionKeys(grant, recovered) {
    const path = "/pub/chat/message";
    const first = grant.encryptionKeys;
    const retained = grant.encryptionKeys;
    first.free();
    // Freeing one copy must not clear the session's keys or another copy.
    const later = grant.encryptionKeys;
    const expected = recovered.keys.deriveForPath(path);
    for (const keys of [retained, later]) {
        const actual = keys.deriveForPath(path);
        if (keys.scopes.join() !== "/pub/chat/" ||
            !actual.every((byte, index) => byte === expected[index])) {
            throw new Error("Session and recovery must expose the same scoped keys.");
        }
        actual.fill(0);
    }
    later.free();
    grant.free();
    const actual = retained.deriveForPath(path);
    if (!actual.every((byte, index) => byte === expected[index])) {
        throw new Error("Owned keys must survive freeing the grant session.");
    }
    actual.fill(0);
    expected.fill(0);
    retained.free();
    recovered.keys.free();
}

export function checkRecoveredIdentity(first, second, firstUser, firstGrant, secondUser, secondGrant) {
    try {
        if (first.publicKey !== firstUser || first.grantId !== firstGrant ||
            second.publicKey !== secondUser || second.grantId !== secondGrant) {
            throw new Error("Recovery must retain the authenticated account and grant.");
        }
        if (first.publicKey === second.publicKey || first.grantId === second.grantId) {
            throw new Error("A substituted token must expose a different identity.");
        }
        if (first.keys.scopes.join() !== "/pub/chat/" ||
            second.keys.scopes.join() !== first.keys.scopes.join()) {
            throw new Error("Both accounts must have identical approved scopes.");
        }
        const firstKey = first.keys.deriveForPath("/pub/chat/message");
        const secondKey = second.keys.deriveForPath("/pub/chat/message");
        const sameKey = firstKey.every((byte, index) => byte === secondKey[index]);
        firstKey.fill(0);
        secondKey.fill(0);
        if (sameKey) throw new Error("Different accounts must recover different keys.");
    } finally {
        first.keys.free();
        second.keys.free();
    }
}

export function checkAbsentAndEmptySessionKeys(bare, signed, bareRecovery, signedRecovery) {
    if (bare.encryptionKeys !== undefined) {
        throw new Error("Bare grants must have no key object.");
    }
    const keys = signed.encryptionKeys;
    if (keys === undefined || keys.scopes.length !== 0) {
        throw new Error("Signed approvals without e must retain an empty object.");
    }
    if (bareRecovery !== undefined || signedRecovery.keys.scopes.length !== 0) {
        throw new Error("Recovery must distinguish bare grants from empty signed approvals.");
    }
    signedRecovery.keys.free();
    keys.free();
    bare.free();
    signed.free();
}
"#)]
    extern "C" {
        #[wasm_bindgen(catch, js_name = checkOwnedSessionKeys)]
        fn check_owned_keys(grant: JsValue, recovered: JsValue) -> Result<(), JsValue>;
        #[wasm_bindgen(catch, js_name = checkAbsentAndEmptySessionKeys)]
        fn check_absent_and_empty(
            bare: JsValue,
            signed: JsValue,
            bare_recovery: JsValue,
            signed_recovery: JsValue,
        ) -> Result<(), JsValue>;
        #[wasm_bindgen(catch, js_name = checkRecoveredIdentity)]
        fn check_recovered_identity(
            first: JsValue,
            second: JsValue,
            first_user: &str,
            first_grant: &str,
            second_user: &str,
            second_grant: &str,
        ) -> Result<(), JsValue>;
    }

    /// Build valid restore material without a homeserver exchange.
    fn grant_session(caps: &str, signed_approval: bool) -> (GrantSession, String, GrantClaims) {
        let identity = Keypair::random();
        let client = Keypair::random();
        let claims = GrantClaims {
            iss: identity.public_key(),
            client_id: ClientId::new("owned-keys.test").unwrap(),
            caps: caps.parse::<Capabilities>().unwrap().into(),
            cnf: client.public_key(),
            jti: GrantId::generate(),
            iat: 1,
            exp: 4_000_000_000,
        };
        let grant = claims.sign(&identity, GRANT_JWS_TYP);
        let mut token = format!(
            "pubky-grant-credential-v{}:{}:{}:{grant}",
            if signed_approval { 2 } else { 1 },
            identity.public_key().z32(),
            URL_SAFE_NO_PAD.encode(client.secret()),
        );
        if signed_approval {
            let keys = ScopedEncryptionKeyBundle::from_identity_secret(
                &identity.secret(),
                claims
                    .caps
                    .iter()
                    .filter(|cap| cap.grants_encryption_keys())
                    .map(|cap| cap.scope()),
            );
            let approval = sign_jws(
                &identity,
                "pubky-grant-approval",
                &serde_json::json!({ "version": "v1", "grant": grant, "encryption_keys": keys }),
            );
            token.push(':');
            token.push_str(&approval);
        }
        let credential = pubky::GrantCredential::from_shared_secret(&token).unwrap();
        let session = pubky::PubkySession::from_grant_credential(
            pubky::PubkyHttpClient::new().unwrap(),
            credential,
        );
        (GrantSession(session), token, claims)
    }

    #[wasm_bindgen_test]
    fn session_keys_share_the_recovery_api_with_independent_lifetimes() {
        let (grant, token, _) = grant_session("/pub/chat/:re", true);
        let recovered = EncryptionKeys::from_local_secret(&token).unwrap().unwrap();
        check_owned_keys(grant.into(), recovered.into()).unwrap();
    }

    #[wasm_bindgen_test]
    fn offline_recovery_preserves_identity_for_accounts_with_identical_scopes() {
        let (_, first_token, first_claims) = grant_session("/pub/chat/:re", true);
        let (_, second_token, second_claims) = grant_session("/pub/chat/:re", true);
        let first = EncryptionKeys::from_local_secret(&first_token)
            .unwrap()
            .unwrap();
        let second = EncryptionKeys::from_local_secret(&second_token)
            .unwrap()
            .unwrap();
        check_recovered_identity(
            first.into(),
            second.into(),
            &first_claims.iss.z32(),
            &first_claims.jti.to_string(),
            &second_claims.iss.z32(),
            &second_claims.jti.to_string(),
        )
        .unwrap();
    }

    #[wasm_bindgen_test]
    fn session_keys_distinguish_bare_grants_from_empty_signed_approvals() {
        let (bare, bare_token, _) = grant_session("/pub/chat/:rw", false);
        let (signed, signed_token, _) = grant_session("/pub/chat/:rw", true);
        let bare_recovery = EncryptionKeys::from_local_secret(&bare_token).unwrap();
        let signed_recovery = EncryptionKeys::from_local_secret(&signed_token)
            .unwrap()
            .unwrap();
        check_absent_and_empty(
            bare.into(),
            signed.into(),
            bare_recovery.map_or(JsValue::UNDEFINED, Into::into),
            signed_recovery.into(),
        )
        .unwrap();
    }
}
