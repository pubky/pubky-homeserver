//! JavaScript bindings for custom proof bundles and offline verification.

use crate::js_error::{JsResult, deserialize_ts, serialize_ts};
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
/** Root-signed grant claims. Public keys are z-base-32; times are Unix seconds. */
export interface VerifiedGrantClaims {
  iss: string;
  client_id: string;
  caps: string[];
  cnf: string;
  jti: string;
  iat: number;
  exp: number;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "JsonValue")]
    pub type JsonValue;
}

/// Self-contained credentials for offline custom-proof verification.
#[derive(Serialize, Deserialize, Tsify)]
#[serde(deny_unknown_fields)]
pub struct CustomPop {
    /// Original root-signed grant JWS.
    pub grant: String,
    /// Client-signed custom proof JWS.
    pub pop: String,
}

/// Verified provenance and data; applications validate the data's meaning.
#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedCustomPop {
    /// Root public key encoded as z-base-32.
    pub identity: String,
    /// Root-signed claims; storage capabilities do not grant service permissions.
    #[tsify(type = "VerifiedGrantClaims")]
    pub grant_claims: pubky::GrantClaims,
    /// Signed JSON data, without application-specific validation.
    #[tsify(type = "JsonValue")]
    pub data: serde_json::Value,
}

/// Options for verifying custom grant proofs.
#[derive(Default, Deserialize, Tsify)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomPopVerificationOptions {
    /// Allow the grant's issue time this many seconds ahead of the local clock.
    /// Defaults to 30; zero disables the allowance. Expiry remains strict.
    /// Must be an integer between 0 and 4294967295.
    #[tsify(optional)]
    #[serde(default, deserialize_with = "deserialize_clock_skew_seconds")]
    pub clock_skew_seconds: Option<u32>,
}

// Missing options use the default; explicitly supplied values must be integers.
fn deserialize_clock_skew_seconds<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u32>, D::Error> {
    u32::deserialize(deserializer).map(Some)
}

/// Verify both signatures, grant binding, and grant validity against the local clock.
/// Allows 30 seconds of future clock skew by default; never extends grant expiry.
/// Does not check replay, application authorization, or homeserver revocation.
#[wasm_bindgen(js_name = "verifyCustomGrantPop")]
pub fn verify_custom_grant_pop(
    credentials: Ts<CustomPop>,
    options: Option<Ts<CustomPopVerificationOptions>>,
) -> JsResult<Ts<VerifiedCustomPop>> {
    let credentials: CustomPop = deserialize_ts(&credentials)?;
    let options = options
        .as_ref()
        .map(deserialize_ts)
        .transpose()?
        .unwrap_or_default();
    let clock_skew = options.clock_skew_seconds.map_or(
        pubky::custom_pop::DEFAULT_CUSTOM_POP_CLOCK_SKEW,
        |seconds| std::time::Duration::from_secs(u64::from(seconds)),
    );
    let verified = pubky::verify_custom_grant_pop(
        &pubky::CustomPop {
            grant: credentials.grant,
            pop: credentials.pop,
        },
        clock_skew,
    )?;
    serialize_ts(&VerifiedCustomPop {
        identity: verified.identity().to_z32(),
        grant_claims: verified.grant_claims().clone(),
        data: verified.data().clone(),
    })
}
