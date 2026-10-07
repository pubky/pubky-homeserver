//! External-service verification and JavaScript replay-store adaptation.

use js_sys::{Function, Reflect, Uint8Array};
use pubky::service_auth::{self as native, ReplayStore as _};
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

use crate::actors::grant_session::ServiceAuthProof;
use crate::js_error::{JsResult, PubkyError, PubkyErrorName, deserialize_ts, serialize_ts};

/// Optional overrides for the Rust verifier's default acceptance policy.
#[derive(Default, Deserialize, Tsify)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationPolicy {
    /// Default: 180 seconds. Must be between 1 and 86400.
    #[tsify(optional, type = "number")]
    pub max_proof_age_seconds: Option<u32>,
    /// Default: 30 seconds. Must be at most 86400.
    #[tsify(optional, type = "number")]
    pub future_clock_skew_seconds: Option<u32>,
    /// Default: 65536 bytes. Must be positive.
    #[tsify(optional, type = "number")]
    pub max_grant_bytes: Option<u32>,
    /// Default: 16384 bytes. Must be positive.
    #[tsify(optional, type = "number")]
    pub max_proof_bytes: Option<u32>,
}

impl VerificationPolicy {
    fn into_native(self) -> native::VerificationPolicy {
        let defaults = native::VerificationPolicy::default();
        native::VerificationPolicy {
            max_proof_age_seconds: self
                .max_proof_age_seconds
                .map_or(defaults.max_proof_age_seconds, u64::from),
            future_clock_skew_seconds: self
                .future_clock_skew_seconds
                .map_or(defaults.future_clock_skew_seconds, u64::from),
            max_grant_bytes: self
                .max_grant_bytes
                .map_or(defaults.max_grant_bytes, |value| value as usize),
            max_proof_bytes: self
                .max_proof_bytes
                .map_or(defaults.max_proof_bytes, |value| value as usize),
        }
    }
}

/// Authenticated identity and all verified claims. Timestamps are Unix seconds.
/// Apply your own authorization policy and cap sessions at `grantExpiresAt`.
#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedServiceAuth {
    /// Root public key encoded as z-base-32.
    pub identity: String,
    /// Root-signed application identifier; not a verified web origin.
    pub client_id: String,
    /// Identifier of the verified grant, matching `grantClaims.jti`.
    pub grant_id: String,
    /// Latest permitted service-session expiry, in Unix seconds.
    pub grant_expires_at: u64,
    /// Root-signed claims; storage capabilities do not grant service permissions.
    #[tsify(type = "VerifiedGrantClaims")]
    pub grant_claims: pubky::GrantClaims,
    /// Audience-bound claims whose nonce has already been consumed.
    #[tsify(type = "VerifiedServiceProofClaims")]
    pub proof_claims: native::ServiceProofClaims,
}

#[wasm_bindgen(typescript_custom_section)]
const STORE_TYPES: &str = r#"
/** Root-signed grant claims. Public keys use z-base-32; timestamps use Unix seconds. */
export interface VerifiedGrantClaims {
  /** User's root public key, which signed the grant. */
  iss: string;
  /** Root-signed application identifier; not a verified web origin. */
  client_id: string;
  /** Homeserver storage capabilities, not service-specific permissions. */
  caps: string[];
  /** Client public key bound to the grant and used to verify the proof. */
  cnf: string;
  /** Grant identifier. */
  jti: string;
  /** Grant issue time in Unix seconds. */
  iat: number;
  /** Grant expiry in Unix seconds, without grace. */
  exp: number;
}
/** Verified audience-bound proof claims. The nonce has already been consumed. */
export interface VerifiedServiceProofClaims {
  /** Exact service audience, without normalization. */
  aud: string;
  /** Identifier of the supplied grant. */
  gid: string;
  /** Single-use identifier, encoded as unpadded base64url. */
  nonce: string;
  /** Proof issue time in Unix seconds. */
  iat: number;
}
export type ConsumeOutcome = "consumed" | "alreadyConsumed";
/**
 * Atomically consume a verified proof. Under the consumption lock/transaction,
 * check time bounds, reject clock rollback and incompatible policy fingerprints,
 * and retain keys until expiresAt. Never evict live keys to recover capacity.
 * Persistent stores must commit before returning consumed. Throw on failure.
 * All service instances must share the same authoritative replay state.
 */
export interface ReplayStore {
  consumeOnce(request: ReplayRequest): Promise<ConsumeOutcome>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "ReplayStore")]
    pub type ReplayStoreInput;
}

/// Immutable consumption request created only after credential verification.
#[wasm_bindgen]
pub struct ReplayRequest(native::ReplayRequest);

#[wasm_bindgen]
impl ReplayRequest {
    /// Stable 32-byte key. Each read returns a copy.
    #[wasm_bindgen(getter)]
    pub fn key(&self) -> Uint8Array {
        Uint8Array::from(self.0.key().as_bytes().as_slice())
    }

    /// Identifies the audience and verification settings bound to the store.
    /// Reject requests whose fingerprint differs from the existing binding.
    /// Each read returns a copy of 32 bytes.
    #[wasm_bindgen(getter, js_name = policyFingerprint)]
    pub fn policy_fingerprint(&self) -> Uint8Array {
        Uint8Array::from(self.0.policy_fingerprint().as_slice())
    }

    /// Earliest accepted Unix second, inclusive.
    #[wasm_bindgen(getter, js_name = notBefore)]
    pub fn not_before(&self) -> f64 {
        self.0.not_before() as f64
    }

    /// Retention deadline and latest accepted Unix second, exclusive.
    #[wasm_bindgen(getter, js_name = expiresAt)]
    pub fn expires_at(&self) -> f64 {
        self.0.expires_at() as f64
    }
}

/// Bounded replay protection for this WASM instance. Keep it between requests.
/// Restarts lose replay history; separate workers do not share this store.
#[wasm_bindgen]
pub struct MemoryReplayStore(native::MemoryReplayStore);

#[wasm_bindgen]
impl MemoryReplayStore {
    /// Create a store with a positive maximum number of live replay entries.
    #[wasm_bindgen(constructor)]
    pub fn new(capacity: f64) -> JsResult<MemoryReplayStore> {
        if !capacity.is_finite()
            || capacity.fract() != 0.0
            || capacity < 1.0
            || capacity > u32::MAX as f64
        {
            return Err(native::ReplayStoreError::InvalidConfiguration(
                "capacity must be a positive 32-bit integer",
            )
            .into());
        }
        Ok(Self(native::MemoryReplayStore::new(capacity as usize)?))
    }

    /// Consume a request issued by the verifier, sharing state across callers.
    #[wasm_bindgen(js_name = consumeOnce, unchecked_return_type = "ConsumeOutcome")]
    pub async fn consume_once(&self, request: &ReplayRequest) -> JsResult<String> {
        Ok(match self.0.consume_once(request.0.clone()).await? {
            native::ConsumeOutcome::Consumed => "consumed",
            native::ConsumeOutcome::AlreadyConsumed => "alreadyConsumed",
        }
        .into())
    }
}

/// Verifies both signatures and claims, then consumes the proof before returning.
/// No network requests are made. Keep the verifier between exchange attempts.
#[wasm_bindgen]
pub struct ServiceAuthVerifier(native::ServiceAuthVerifier<VerifierReplayStore>);

#[wasm_bindgen]
impl ServiceAuthVerifier {
    /// Bind an exact audience, memory store, and optional policy overrides.
    /// The verifier retains a shared-state handle; the supplied store stays usable.
    #[wasm_bindgen(constructor)]
    pub fn new(
        audience: String,
        store: &MemoryReplayStore,
        policy: Option<Ts<VerificationPolicy>>,
    ) -> JsResult<ServiceAuthVerifier> {
        Self::with_replay_store(
            audience,
            VerifierReplayStore::Memory(store.0.clone()),
            policy,
        )
    }

    /// Bind an async custom store. Callback failures reject authentication.
    /// During verification, thrown or rejected callback errors report
    /// `data.reason: "Storage"` with `data.storageReason: "Backend"`.
    /// Non-Promise returns and unsupported outcomes report `InvalidResponse`
    /// as the storage reason.
    #[wasm_bindgen(js_name = withStore)]
    pub fn with_store(
        audience: String,
        store: ReplayStoreInput,
        policy: Option<Ts<VerificationPolicy>>,
    ) -> JsResult<ServiceAuthVerifier> {
        Self::with_replay_store(
            audience,
            VerifierReplayStore::Custom(JsReplayStore::new(store.into())?),
            policy,
        )
    }

    /// Verify and atomically consume credentials. Replays and store failures reject.
    /// Failures expose `PubkyError.data.reason`. Retry with a fresh proof even if
    /// the previous attempt failed: an ambiguous exchange may consume its nonce.
    /// Grant expirations above `Number.MAX_SAFE_INTEGER` reject with
    /// `TimestampOutOfRange` rather than returning rounded claims.
    #[wasm_bindgen(js_name = verifyAndConsume)]
    pub async fn verify_and_consume(
        &self,
        credentials: Ts<ServiceAuthProof>,
    ) -> JsResult<Ts<VerifiedServiceAuth>> {
        let credentials = deserialize_ts(&credentials)?;
        let verified = self
            .0
            .verify_and_consume(&pubky::ServiceAuthProof {
                grant: credentials.grant,
                pop: credentials.pop,
            })
            .await?;
        // Claims are returned as JavaScript numbers. Never return a rounded
        // expiration that differs from the root-signed value.
        if verified.grant_expires_at() > 9_007_199_254_740_991 {
            return Err(PubkyError::new(
                PubkyErrorName::InvalidInput,
                "Grant expiration exceeds JavaScript's maximum safe integer",
            )
            .with_data(serde_json::json!({ "reason": "TimestampOutOfRange" })));
        }
        serialize_ts(&VerifiedServiceAuth {
            identity: verified.identity().z32(),
            client_id: verified.client_id().to_string(),
            grant_id: verified.grant_id().to_string(),
            grant_expires_at: verified.grant_expires_at(),
            grant_claims: verified.grant_claims().clone(),
            proof_claims: verified.proof_claims().clone(),
        })
    }
}

impl ServiceAuthVerifier {
    fn with_replay_store(
        audience: String,
        store: VerifierReplayStore,
        policy: Option<Ts<VerificationPolicy>>,
    ) -> JsResult<Self> {
        let policy = policy
            .as_ref()
            .map(deserialize_ts)
            .transpose()?
            .unwrap_or_default();
        Ok(Self(native::ServiceAuthVerifier::new(
            audience,
            policy.into_native(),
            store,
        )?))
    }
}

/// Built-in storage stays in Rust; only custom stores cross the JS boundary.
#[derive(Debug)]
enum VerifierReplayStore {
    Memory(native::MemoryReplayStore),
    Custom(JsReplayStore),
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl native::ReplayStore for VerifierReplayStore {
    async fn consume_once(
        &self,
        request: native::ReplayRequest,
    ) -> Result<native::ConsumeOutcome, native::ReplayStoreError> {
        match self {
            Self::Memory(store) => store.consume_once(request).await,
            Self::Custom(store) => store.consume_once(request).await,
        }
    }
}

/// Retains the JS receiver so custom methods can use `this` during async calls.
#[derive(Debug)]
struct JsReplayStore {
    #[cfg(target_arch = "wasm32")]
    receiver: JsValue,
    #[cfg(target_arch = "wasm32")]
    consume_once: Function,
}

impl JsReplayStore {
    fn new(receiver: JsValue) -> JsResult<Self> {
        let consume_once = Reflect::get(&receiver, &"consumeOnce".into())
            .map_err(|_| {
                PubkyError::new(
                    PubkyErrorName::InvalidInput,
                    "Cannot read replay store consumeOnce method",
                )
            })?
            .dyn_into::<Function>()
            .map_err(|_| {
                PubkyError::new(
                    PubkyErrorName::InvalidInput,
                    "Replay store must provide a consumeOnce method",
                )
            })?;
        #[cfg(target_arch = "wasm32")]
        {
            Ok(Self {
                receiver,
                consume_once,
            })
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = consume_once;
            Ok(Self {})
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl native::ReplayStore for JsReplayStore {
    async fn consume_once(
        &self,
        request: native::ReplayRequest,
    ) -> Result<native::ConsumeOutcome, native::ReplayStoreError> {
        #[cfg(target_arch = "wasm32")]
        {
            let request = JsValue::from(ReplayRequest(request));
            let pending = self
                .consume_once
                .call1(&self.receiver, &request)
                .map_err(backend_error)?;
            let promise = pending.dyn_into::<js_sys::Promise>().map_err(|_| {
                native::ReplayStoreError::InvalidResponse("consumeOnce must return a Promise")
            })?;
            let outcome = wasm_bindgen_futures::JsFuture::from(promise)
                .await
                .map_err(backend_error)?;
            match outcome.as_string().as_deref() {
                Some("consumed") => Ok(native::ConsumeOutcome::Consumed),
                Some("alreadyConsumed") => Ok(native::ConsumeOutcome::AlreadyConsumed),
                _ => Err(native::ReplayStoreError::InvalidResponse(
                    "consumeOnce must resolve to 'consumed' or 'alreadyConsumed'",
                )),
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = request;
            Err(native::ReplayStoreError::Backend(
                "JavaScript replay stores require WASM".into(),
            ))
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn backend_error(value: JsValue) -> native::ReplayStoreError {
    let message = value
        .as_string()
        .or_else(|| {
            Reflect::get(&value, &"message".into())
                .ok()
                .and_then(|message| message.as_string())
        })
        .unwrap_or_else(|| "consumeOnce failed".into());
    native::ReplayStoreError::Backend(message)
}
