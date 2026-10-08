use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::{
    auth::grant::GrantClaims,
    capabilities::Action,
    crypto::{PublicKey, Signature},
    encryption_keys::ScopedEncryptionKeyBundle,
};
use serde::{Deserialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use super::approval_envelope::{APPROVAL_JWS_TYP, GrantApprovalEnvelope};
use crate::actors::auth::{deep_links::GrantApprovalFormat, relay::AuthRelayMessage};
use crate::errors::{AuthError, Result};

/// Decoded grant with an optional verified signed approval and its key bundle.
/// Signed approval envelopes authenticate the grant and keys together.
/// The homeserver verifies the inner grant itself.
#[derive(Debug)]
pub(crate) struct GrantApproval {
    pub(crate) grant_jws: String,
    pub(crate) claims: GrantClaims,
    pub(crate) verified_approval: Option<VerifiedApproval>,
}

/// Verified signed approval and its possibly empty scoped-key bundle.
/// Retained after signature and scope validation.
#[derive(Debug)]
pub(crate) struct VerifiedApproval {
    pub(crate) encryption_keys: ScopedEncryptionKeyBundle,
    pub(crate) signed_approval: SignedApproval,
}

/// Confidential signed approval retained for authenticated key restoration.
/// May contain raw scoped secrets. Debug output is redacted and the owned
/// buffer is wiped on drop. Construction does not verify its signature.
#[derive(Clone)]
pub(crate) struct SignedApproval(Zeroizing<String>);

impl SignedApproval {
    pub(crate) fn new(text: &str) -> Self {
        Self(Zeroizing::new(text.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SignedApproval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl GrantApproval {
    /// Decode the selected format, verifying the outer signature and key scopes
    /// for signed approval V1 envelopes. Inner grant verification belongs to the homeserver;
    /// the auth flow checks client binding and requested permissions.
    pub(crate) fn decode(message: &AuthRelayMessage, format: GrantApprovalFormat) -> Result<Self> {
        let text = std::str::from_utf8(message.as_bytes())
            .map_err(|_err| invalid_approval("invalid approval encoding"))?;
        Self::decode_text(text, format)
    }

    /// Decode a borrowed compact approval without copying it into a relay buffer.
    /// Performs the same signature and scope checks as relay decoding.
    pub(crate) fn decode_text(text: &str, format: GrantApprovalFormat) -> Result<Self> {
        match format {
            GrantApprovalFormat::BareGrant => {
                let claims = GrantClaims::decode(text).map_err(|err| {
                    AuthError::Validation(format!("invalid grant payload: {err}"))
                })?;
                Ok(Self {
                    grant_jws: text.to_owned(),
                    claims,
                    verified_approval: None,
                })
            }
            GrantApprovalFormat::SignedApprovalV1 => {
                // Skip the key bundle until its issuer has authenticated it.
                // Serde ignores the other fields without decoding scoped keys.
                #[derive(Deserialize)]
                struct ApprovalGrant {
                    grant: String,
                }

                let unverified: ApprovalGrant = decode_payload(text)?;
                // The outer signature binds the issuer, exact grant, and keys.
                let claims: GrantClaims = decode_payload(&unverified.grant)?;
                verify_approval_signature(text, &claims.iss)?;
                let envelope: GrantApprovalEnvelope = decode_payload(text)?;
                validate_key_scopes_match_grant(&envelope.encryption_keys, &claims)?;
                Ok(Self {
                    grant_jws: envelope.grant,
                    claims,
                    verified_approval: Some(VerifiedApproval {
                        encryption_keys: envelope.encryption_keys,
                        signed_approval: SignedApproval::new(text),
                    }),
                })
            }
        }
    }
}

fn validate_key_scopes_match_grant(
    keys: &ScopedEncryptionKeyBundle,
    claims: &GrantClaims,
) -> Result<()> {
    // Compare scope sets, ignoring order and repeated capabilities.
    // Missing keys must not silently downgrade the approval.
    let has_unapproved_scope = keys.scopes().any(|scope| {
        !claims
            .caps
            .iter()
            .any(|cap| cap.actions().contains(&Action::EncryptionKeys) && cap.scope() == scope)
    });
    let has_missing_scope = claims
        .caps
        .iter()
        .filter(|cap| cap.actions().contains(&Action::EncryptionKeys))
        .any(|cap| !keys.scopes().any(|scope| scope == cap.scope()));
    if has_unapproved_scope || has_missing_scope {
        return Err(invalid_approval(
            "encryption key scopes do not match the approved grant",
        ));
    }
    Ok(())
}

// Do not include parser errors: malformed secret-bearing fields can appear
// verbatim in Serde diagnostics.
fn invalid_approval(message: &str) -> crate::errors::Error {
    AuthError::Validation(message.into()).into()
}

/// Decode secret-bearing JSON into its typed representation without leaving
/// the temporary decoded payload in an ordinary allocation or error message.
fn decode_payload<T: DeserializeOwned>(compact: &str) -> Result<T> {
    let (_, payload, _) = jws_parts(compact)?;
    let mut decoded = Zeroizing::new(vec![0; base64::decoded_len_estimate(payload.len())]);
    let length = URL_SAFE_NO_PAD
        .decode_slice(payload, decoded.as_mut_slice())
        .map_err(|_err| invalid_approval("invalid approval payload encoding"))?;
    serde_json::from_slice(&decoded[..length])
        .map_err(|_err| invalid_approval("invalid approval payload or unsupported version"))
}

fn jws_parts(compact: &str) -> Result<(&str, &str, &str)> {
    let (input, signature) = compact
        .rsplit_once('.')
        .ok_or_else(|| invalid_approval("invalid compact JWS"))?;
    let (header, payload) = input
        .split_once('.')
        .ok_or_else(|| invalid_approval("invalid compact JWS"))?;
    if header.is_empty() || payload.is_empty() || signature.is_empty() || payload.contains('.') {
        return Err(invalid_approval("invalid compact JWS"));
    }
    Ok((header, payload, signature))
}

fn verify_approval_signature(compact: &str, issuer: &PublicKey) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Header {
        alg: String,
        typ: String,
    }

    let (header, _, signature) = jws_parts(compact)?;
    let header = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_err| invalid_approval("invalid JWS header encoding"))?;
    let header: Header = serde_json::from_slice(&header)
        .map_err(|_err| invalid_approval("invalid or unsupported JWS header"))?;
    if header.alg != "EdDSA" || header.typ != APPROVAL_JWS_TYP {
        return Err(invalid_approval("unexpected JWS algorithm or type"));
    }
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_err| invalid_approval("invalid JWS signature encoding"))?
        .try_into()
        .map_err(|_err| invalid_approval("invalid JWS signature length"))?;
    // Borrow the original signing input; an approval payload contains secrets.
    let (input, _) = compact.rsplit_once('.').expect("JWS was split above");
    issuer
        .verify(input.as_bytes(), &Signature::from_bytes(&signature))
        .map_err(|_err| invalid_approval("invalid JWS signature"))
}

#[cfg(test)]
mod tests {
    use pubky_common::{
        StoragePath,
        auth::jws::{ClientId, GRANT_JWS_TYP, GrantId, decode_jws_payload, sign_jws},
        capabilities::Capability,
    };

    use super::super::credential::now_unix;
    use super::*;
    use pubky_common::crypto::Keypair;

    fn claims(user: &Keypair) -> GrantClaims {
        GrantClaims {
            iss: user.public_key(),
            client_id: ClientId::new("test.app").unwrap(),
            caps: vec!["/pub/app/:rwe".parse().unwrap()],
            cnf: Keypair::from_secret(&[8; 32]).public_key(),
            jti: GrantId::generate(),
            iat: now_unix(),
            exp: now_unix() + 3600,
        }
    }

    fn message(user: &Keypair, claims: &GrantClaims) -> AuthRelayMessage {
        AuthRelayMessage::new(
            GrantApprovalEnvelope::sign(user, claims)
                .as_bytes()
                .to_vec(),
        )
    }

    fn decode_signed_approval(message: &AuthRelayMessage) -> Result<GrantApproval> {
        GrantApproval::decode(message, GrantApprovalFormat::SignedApprovalV1)
    }

    #[test]
    fn received_approvals_preserve_verified_recovery_material() {
        let user = Keypair::random();
        for capability in ["/pub/app/:rwe", "/pub/app/:rw"] {
            let mut claims = claims(&user);
            claims.caps = vec![capability.parse().unwrap()];
            let received = decode_signed_approval(&message(&user, &claims)).unwrap();
            let retained = received.verified_approval.as_ref().unwrap();
            let restored = GrantApproval::decode_text(
                retained.signed_approval.as_str(),
                GrantApprovalFormat::SignedApprovalV1,
            )
            .unwrap();
            assert_eq!(received.grant_jws, restored.grant_jws);
            assert_eq!(received.claims, restored.claims);
            let path = StoragePath::new("/pub/app/file").unwrap();
            let received_key = retained.encryption_keys.derive_for_path(&path);
            let restored_key = restored
                .verified_approval
                .unwrap()
                .encryption_keys
                .derive_for_path(&path);
            assert_eq!(received_key, restored_key);
            assert_eq!(received_key.is_ok(), capability.ends_with('e'));
        }
    }

    // Construct correctly signed but semantically invalid envelopes to ensure
    // rejection comes from the receiving policy, not just signature checking.
    fn changed_envelope(
        user: &Keypair,
        change: impl FnOnce(&mut serde_json::Value),
    ) -> AuthRelayMessage {
        let signed = GrantApprovalEnvelope::sign(user, &claims(user));
        let mut payload: serde_json::Value = decode_jws_payload(&signed).unwrap();
        change(&mut payload);
        AuthRelayMessage::new(
            sign_jws(user, APPROVAL_JWS_TYP, &payload)
                .as_bytes()
                .to_vec(),
        )
    }

    #[test]
    fn explicit_key_scopes_are_independent_of_storage_scopes() {
        let user = Keypair::random();
        let mut claims = claims(&user);
        claims.caps = "/:rw,/pub/chat/:e"
            .parse::<pubky_common::capabilities::Capabilities>()
            .unwrap()
            .to_vec();
        let approval = decode_signed_approval(&message(&user, &claims)).unwrap();
        let keys = approval.verified_approval.unwrap().encryption_keys;
        assert_eq!(
            keys.scopes().map(ToString::to_string).collect::<Vec<_>>(),
            ["/pub/chat/"]
        );
        keys.derive_for_path(&StoragePath::new("/pub/chat/message").unwrap())
            .unwrap();
        keys.derive_for_path(&StoragePath::new("/pub/backup/file").unwrap())
            .unwrap_err();
    }

    #[test]
    fn storage_only_approval_contains_no_keys_and_rejects_unsolicited_keys() {
        let user = Keypair::random();
        let mut storage_claims = claims(&user);
        storage_claims.caps = vec![Capability::read_write("/pub/app/").unwrap()];
        let approval = decode_signed_approval(&message(&user, &storage_claims)).unwrap();
        assert_eq!(
            approval
                .verified_approval
                .unwrap()
                .encryption_keys
                .scopes()
                .len(),
            0
        );

        let signed = GrantApprovalEnvelope::sign(&user, &claims(&user));
        let mut payload: serde_json::Value = decode_jws_payload(&signed).unwrap();
        payload["grant"] = serde_json::json!(sign_jws(&user, GRANT_JWS_TYP, &storage_claims));
        let excessive = sign_jws(&user, APPROVAL_JWS_TYP, &payload);
        GrantApproval::decode_text(&excessive, GrantApprovalFormat::SignedApprovalV1).unwrap_err();
    }

    #[test]
    fn verified_approval_retains_keys_and_only_the_inner_grant() {
        let user = Keypair::from_secret(&[7; 32]);
        let claims = claims(&user);
        let approval = decode_signed_approval(&message(&user, &claims)).unwrap();
        assert_eq!(approval.claims, claims);
        assert_eq!(GrantClaims::decode(&approval.grant_jws).unwrap(), claims);
        let path = StoragePath::new("/pub/app/file").unwrap();
        let expected = ScopedEncryptionKeyBundle::from_identity_secret(&user.secret(), [&path]);
        assert_eq!(
            *approval
                .verified_approval
                .unwrap()
                .encryption_keys
                .derive_for_path(&path)
                .unwrap(),
            *expected.derive_for_path(&path).unwrap(),
        );
        let payload: serde_json::Value = decode_jws_payload(&approval.grant_jws).unwrap();
        assert!(payload.get("encryption_keys").is_none());
    }

    #[test]
    fn bare_grants_are_decoded_without_local_signature_verification() {
        let user = Keypair::random();
        let claims = claims(&user);
        let message = AuthRelayMessage::new(
            sign_jws(&Keypair::random(), GRANT_JWS_TYP, &claims).into_bytes(),
        );
        let approval = GrantApproval::decode(&message, GrantApprovalFormat::BareGrant).unwrap();
        assert_eq!(approval.claims, claims);
        assert!(approval.verified_approval.is_none());
        assert!(
            decode_signed_approval(&message).is_err(),
            "SignedApprovalV1 must reject a bare-grant downgrade"
        );
    }

    #[test]
    fn key_scopes_must_match_the_approved_grant() {
        let user = Keypair::random();
        for scope in ["/", "/pub/app/file", "/pub/other/"] {
            let changed = changed_envelope(&user, |payload| {
                payload["encryption_keys"]["keys"][0]["scope"] = serde_json::json!(scope);
            });
            assert!(
                decode_signed_approval(&changed)
                    .unwrap_err()
                    .to_string()
                    .contains("key scopes"),
                "{scope}"
            );
        }
        let missing = changed_envelope(&user, |payload| {
            payload["encryption_keys"]["keys"] = serde_json::json!([]);
        });
        decode_signed_approval(&missing).unwrap_err();
        let extra = changed_envelope(&user, |payload| {
            let mut key = payload["encryption_keys"]["keys"][0].clone();
            key["scope"] = serde_json::json!("/pub/other/");
            payload["encryption_keys"]["keys"]
                .as_array_mut()
                .unwrap()
                .push(key);
        });
        decode_signed_approval(&extra).unwrap_err();
    }

    #[test]
    fn outer_signature_must_belong_to_the_inner_issuer() {
        let user = Keypair::random();
        let other = Keypair::random();
        let payload: serde_json::Value =
            decode_jws_payload(&GrantApprovalEnvelope::sign(&user, &claims(&user))).unwrap();
        let wrong_outer = AuthRelayMessage::new(
            sign_jws(&other, APPROVAL_JWS_TYP, &payload)
                .as_bytes()
                .to_vec(),
        );
        assert!(
            decode_signed_approval(&wrong_outer)
                .unwrap_err()
                .to_string()
                .contains("signature")
        );
    }

    #[test]
    fn signature_is_verified_before_key_bundle_validation() {
        let user = Keypair::random();
        let other = Keypair::random();
        let signed = GrantApprovalEnvelope::sign(&user, &claims(&user));
        let original: serde_json::Value = decode_jws_payload(&signed).unwrap();

        let mut malformed = original.clone();
        malformed["encryption_keys"]["keys"][0]["secret"] = serde_json::json!("invalid-secret");

        let mut conflicting = original;
        let mut conflicting_key = conflicting["encryption_keys"]["keys"][0].clone();
        conflicting_key["secret"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0; 32]));
        conflicting["encryption_keys"]["keys"]
            .as_array_mut()
            .unwrap()
            .push(conflicting_key);

        for payload in [malformed, conflicting] {
            let wrong_signature = sign_jws(&other, APPROVAL_JWS_TYP, &payload);
            let error =
                GrantApproval::decode_text(&wrong_signature, GrantApprovalFormat::SignedApprovalV1)
                    .unwrap_err()
                    .to_string();
            assert!(error.contains("invalid JWS signature"), "{error}");

            // Authentication must not bypass the later bundle checks.
            let correct_signature = sign_jws(&user, APPROVAL_JWS_TYP, &payload);
            let error = GrantApproval::decode_text(
                &correct_signature,
                GrantApprovalFormat::SignedApprovalV1,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("invalid approval payload"), "{error}");
        }
    }

    #[test]
    fn inner_grant_verification_is_left_to_the_homeserver() {
        let user = Keypair::random();
        for grant in [
            sign_jws(&Keypair::random(), GRANT_JWS_TYP, &claims(&user)),
            sign_jws(&user, "other-type", &claims(&user)),
        ] {
            let message = changed_envelope(&user, |payload| {
                payload["grant"] = serde_json::json!(grant);
            });
            let approval = decode_signed_approval(&message).unwrap();
            assert_eq!(approval.grant_jws, grant);
        }
    }

    #[test]
    fn tampering_with_keys_or_grant_is_rejected() {
        let user = Keypair::random();
        let signed = GrantApprovalEnvelope::sign(&user, &claims(&user));
        let parts = signed.split('.').collect::<Vec<_>>();
        for pointer in ["/grant", "/encryption_keys/keys/0/secret"] {
            let mut payload: serde_json::Value = decode_jws_payload(&signed).unwrap();
            let replacement = if pointer == "/grant" {
                serde_json::json!(sign_jws(&user, GRANT_JWS_TYP, &claims(&user)))
            } else {
                let secret = payload.pointer(pointer).unwrap().as_str().unwrap();
                let mut bytes = URL_SAFE_NO_PAD.decode(secret).unwrap();
                bytes[0] ^= 1;
                serde_json::json!(URL_SAFE_NO_PAD.encode(bytes))
            };
            *payload.pointer_mut(pointer).unwrap() = replacement;
            let changed = format!(
                "{}.{}.{}",
                parts[0],
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap()),
                parts[2]
            );
            assert!(
                decode_signed_approval(&AuthRelayMessage::new(changed.into_bytes())).is_err(),
                "{pointer}"
            );
        }
    }

    #[test]
    fn unsupported_versions_types_algorithms_and_headers_are_rejected() {
        let user = Keypair::random();
        for pointer in ["/version", "/encryption_keys/version"] {
            let changed = changed_envelope(&user, |payload| {
                *payload.pointer_mut(pointer).unwrap() = serde_json::json!("v999");
            });
            assert!(decode_signed_approval(&changed).is_err(), "{pointer}");
        }
        let payload: serde_json::Value =
            decode_jws_payload(&GrantApprovalEnvelope::sign(&user, &claims(&user))).unwrap();
        let wrong_type =
            AuthRelayMessage::new(sign_jws(&user, GRANT_JWS_TYP, &payload).as_bytes().to_vec());
        decode_signed_approval(&wrong_type).unwrap_err();
        for header in [
            serde_json::json!({"alg": "none", "typ": APPROVAL_JWS_TYP}),
            serde_json::json!({"alg": "EdDSA", "typ": APPROVAL_JWS_TYP, "crit": ["b64"], "b64": false}),
        ] {
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
            );
            let signature = URL_SAFE_NO_PAD.encode(user.sign(input.as_bytes()).to_bytes());
            decode_signed_approval(&AuthRelayMessage::new(
                format!("{input}.{signature}").into_bytes(),
            ))
            .unwrap_err();
        }
    }

    #[test]
    fn malformed_secret_fields_are_not_exposed_in_errors() {
        let user = Keypair::random();
        let changed = changed_envelope(&user, |payload| {
            payload["encryption_keys"]["keys"][0]["secret"] = serde_json::json!("sensitive-value");
        });
        let error = decode_signed_approval(&changed).unwrap_err().to_string();
        assert!(!error.contains("sensitive-value"));
        assert!(error.contains("invalid approval payload"));
    }

    #[test]
    fn malformed_approvals_return_errors_and_debug_redacts_the_relay_payload() {
        for bytes in [
            vec![0xff],
            b"not-a-jws".to_vec(),
            b"a.b.c.d".to_vec(),
            b"a.b.".to_vec(),
        ] {
            decode_signed_approval(&AuthRelayMessage::new(bytes)).unwrap_err();
        }
        let message = AuthRelayMessage::new(b"secret payload".to_vec());
        assert!(!format!("{message:?}").contains("secret payload"));
    }
}
