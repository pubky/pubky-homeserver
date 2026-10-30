//! Conditional revocation of the grant behind an original, still-current bearer.

use serde::{Deserialize, Serialize};

use crate::{
    auth::jws::{ClientId, GrantId, RandomId},
    crypto::PublicKey,
};

/// Preconditions for `POST /auth/grant/session-revocation`.
///
/// The bearer is sent separately in the Authorization header. The operation ID
/// correlates a response; it is not a credential or permission to retry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalGrantRevocation {
    /// Fresh client-generated identifier for this one logical operation.
    pub operation_id: RandomId,
    /// Original grant identifier.
    pub grant_id: GrantId,
    /// Original grant owner.
    pub pubky: PublicKey,
    /// Original application identifier.
    pub client_id: ClientId,
}

/// An affirmative result from the conditional endpoint, never a legacy no-op.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantRevocationDisposition {
    /// The original bearer was current at the atomic authorization point and
    /// its grant revocation committed.
    #[serde(rename = "original_bearer_revoked_v1")]
    OriginalBearerRevoked,
}

/// Receipt returned only after conditional grant revocation commits.
///
/// Clients must match every binding and the operation ID. A missing or invalid
/// receipt is unknown, including when a response is lost after commit. Neither
/// this receipt nor the operation ID authorizes another mutation or local erase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRevocationReceipt {
    /// The successfully committed conditional operation.
    pub disposition: GrantRevocationDisposition,
    /// The request's operation identifier.
    pub operation_id: RandomId,
    /// Homeserver that committed the revocation.
    pub homeserver: PublicKey,
    /// Original grant identifier.
    pub grant_id: GrantId,
    /// Original grant owner.
    pub pubky: PublicKey,
    /// Original application identifier.
    pub client_id: ClientId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn conditional_revocation_requires_a_complete_versioned_receipt() {
        let receipt = GrantRevocationReceipt {
            disposition: GrantRevocationDisposition::OriginalBearerRevoked,
            operation_id: RandomId::generate(),
            homeserver: Keypair::random().public_key(),
            grant_id: GrantId::generate(),
            pubky: Keypair::random().public_key(),
            client_id: ClientId::new("conditional.test").unwrap(),
        };
        let value = serde_json::to_value(&receipt).unwrap();
        assert_eq!(value["disposition"], "original_bearer_revoked_v1");
        assert_eq!(
            serde_json::from_value::<GrantRevocationReceipt>(value.clone()).unwrap(),
            receipt
        );
        for field in [
            "disposition",
            "operation_id",
            "homeserver",
            "grant_id",
            "pubky",
            "client_id",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<GrantRevocationReceipt>(missing).is_err());
        }
        for legacy in ["", "{}", "{\"ok\":true}"] {
            assert!(serde_json::from_str::<GrantRevocationReceipt>(legacy).is_err());
        }
        for id in ["", "contains spaces", "12345678901234567890123"] {
            let mut invalid = value.clone();
            invalid["operation_id"] = serde_json::json!(id);
            assert!(serde_json::from_value::<GrantRevocationReceipt>(invalid).is_err());
        }
        let mut invalid = value.clone();
        invalid["disposition"] = serde_json::json!("revoked");
        assert!(serde_json::from_value::<GrantRevocationReceipt>(invalid).is_err());
        let mut extra = value;
        extra["unrecognized"] = serde_json::json!(true);
        assert!(serde_json::from_value::<GrantRevocationReceipt>(extra).is_err());
    }
}
