//! Signed, confidential grant approval payload for delivery through the relay.

use pubky_common::{
    auth::{
        grant::GrantClaims,
        jws::{GRANT_JWS_TYP, sign_jws},
    },
    capabilities::Capability,
    crypto::Keypair,
    encryption_keys::ScopedEncryptionKeyBundle,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Distinct JWS type prevents confusing approvals containing secrets with grants.
pub(crate) const APPROVAL_JWS_TYP: &str = "pubky-grant-approval";

/// Claims signed together so keys cannot be detached from their grant or client.
///
/// The inner grant binds the identity, approved capabilities, client ID, and
/// client public key. The outer signature binds that exact grant to the keys
/// and approval version. Encrypt the signed envelope before sending it; only
/// the inner `grant` JWS belongs in a homeserver exchange request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantApprovalEnvelope {
    version: ApprovalVersion,
    pub(crate) grant: String,
    pub(crate) encryption_keys: ScopedEncryptionKeyBundle,
}

impl GrantApprovalEnvelope {
    /// Sign a grant with keys only for scopes explicitly approved with `e`.
    pub(crate) fn sign(keypair: &Keypair, claims: &GrantClaims) -> Zeroizing<String> {
        let identity_secret = Zeroizing::new(keypair.secret());
        let envelope = Self {
            version: ApprovalVersion::V1,
            grant: sign_jws(keypair, GRANT_JWS_TYP, claims),
            encryption_keys: ScopedEncryptionKeyBundle::from_identity_secret(
                &identity_secret,
                claims
                    .caps
                    .iter()
                    .filter(|cap| cap.grants_encryption_keys())
                    .map(Capability::scope),
            ),
        };
        Zeroizing::new(sign_jws(keypair, APPROVAL_JWS_TYP, &envelope))
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum ApprovalVersion {
    #[serde(rename = "v1")]
    V1,
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use pubky_common::{
        StoragePath,
        auth::jws::{ClientId, GrantId, decode_jws_payload},
        capabilities::Capabilities,
        crypto::{PublicKey, Signature},
    };

    use super::*;

    fn claims(user: &Keypair) -> GrantClaims {
        GrantClaims {
            iss: user.public_key(),
            client_id: ClientId::new("test.app").unwrap(),
            caps: Capabilities::builder()
                .read("/pub/read/")
                .unwrap()
                .encryption_keys("/pub/read/")
                .unwrap()
                .write("/priv/write/")
                .unwrap()
                .encryption_keys("/priv/write/")
                .unwrap()
                .read_write("/pub/both/file")
                .unwrap()
                .encryption_keys("/pub/both/file")
                .unwrap()
                .finish()
                .to_vec(),
            cnf: Keypair::random().public_key(),
            jti: GrantId::generate(),
            iat: 1,
            exp: 2,
        }
    }

    fn verify_signature(jws: &str, public_key: &PublicKey, typ: &str) -> bool {
        let parts = jws.split('.').collect::<Vec<_>>();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], typ);
        let signature: [u8; 64] = URL_SAFE_NO_PAD
            .decode(parts[2])
            .unwrap()
            .try_into()
            .unwrap();
        public_key
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &Signature::from_bytes(&signature),
            )
            .is_ok()
    }

    #[test]
    fn approval_binds_the_exact_grant_and_keys_to_the_signer() {
        let user = Keypair::from_secret(&[7; 32]);
        let claims = claims(&user);
        let signed = GrantApprovalEnvelope::sign(&user, &claims);
        assert!(verify_signature(
            &signed,
            &user.public_key(),
            APPROVAL_JWS_TYP
        ));
        assert!(!verify_signature(
            &signed,
            &Keypair::random().public_key(),
            APPROVAL_JWS_TYP
        ));

        let envelope: GrantApprovalEnvelope = decode_jws_payload(&signed).unwrap();
        assert!(verify_signature(
            &envelope.grant,
            &user.public_key(),
            GRANT_JWS_TYP
        ));
        assert_eq!(GrantClaims::decode(&envelope.grant).unwrap(), claims);
        let scopes = claims
            .caps
            .iter()
            .map(Capability::scope)
            .collect::<Vec<_>>();
        assert_eq!(
            envelope.encryption_keys.scopes().collect::<Vec<_>>(),
            scopes
        );
        for target in ["/pub/read/file", "/priv/write/file", "/pub/both/file"] {
            let path = StoragePath::new(target).unwrap();
            let expected = ScopedEncryptionKeyBundle::from_identity_secret(
                &user.secret(),
                std::slice::from_ref(&path),
            );
            assert_eq!(
                *envelope.encryption_keys.derive_for_path(&path).unwrap(),
                *expected.derive_for_path(&path).unwrap(),
            );
        }
        envelope
            .encryption_keys
            .derive_for_path(&StoragePath::root())
            .unwrap_err();
        // Secrets are only in the outer approval, never in the homeserver grant.
        let grant: serde_json::Value = decode_jws_payload(&envelope.grant).unwrap();
        assert!(grant.get("encryption_keys").is_none());
        assert!(format!("{envelope:?}").contains("<redacted>"));
    }

    #[test]
    fn modifying_the_grant_keys_scope_or_version_invalidates_the_outer_signature() {
        let user = Keypair::from_secret(&[7; 32]);
        let signed = GrantApprovalEnvelope::sign(&user, &claims(&user));
        let parts = signed.split('.').collect::<Vec<_>>();
        let payload: serde_json::Value = decode_jws_payload(&signed).unwrap();
        for field in ["grant", "secret", "scope", "version"] {
            let mut changed = payload.clone();
            match field {
                "grant" => changed["grant"] = serde_json::json!("different-grant"),
                "secret" => {
                    let secret = changed["encryption_keys"]["keys"][0]["secret"]
                        .as_str()
                        .unwrap();
                    let mut bytes = URL_SAFE_NO_PAD.decode(secret).unwrap();
                    bytes[0] ^= 1;
                    changed["encryption_keys"]["keys"][0]["secret"] =
                        serde_json::json!(URL_SAFE_NO_PAD.encode(bytes));
                }
                "scope" => changed["encryption_keys"]["keys"][0]["scope"] = serde_json::json!("/"),
                "version" => changed["version"] = serde_json::json!("v2"),
                _ => unreachable!(),
            }
            let changed = format!(
                "{}.{}.{}",
                parts[0],
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed).unwrap()),
                parts[2]
            );
            assert!(!verify_signature(
                &changed,
                &user.public_key(),
                APPROVAL_JWS_TYP
            ));
        }
    }

    #[test]
    fn decoding_rejects_unknown_versions_and_fields() {
        let user = Keypair::random();
        let signed = GrantApprovalEnvelope::sign(&user, &claims(&user));
        let payload: serde_json::Value = decode_jws_payload(&signed).unwrap();
        for version in ["v0", "v2", ""] {
            let mut changed = payload.clone();
            changed["version"] = serde_json::json!(version);
            serde_json::from_value::<GrantApprovalEnvelope>(changed).unwrap_err();
        }
        let mut changed = payload;
        changed["extra"] = serde_json::json!(true);
        serde_json::from_value::<GrantApprovalEnvelope>(changed).unwrap_err();
    }

    #[test]
    fn empty_capabilities_deliver_no_keys() {
        let user = Keypair::random();
        let mut claims = claims(&user);
        claims.caps.clear();
        let signed = GrantApprovalEnvelope::sign(&user, &claims);
        let envelope: GrantApprovalEnvelope = decode_jws_payload(&signed).unwrap();
        assert_eq!(envelope.encryption_keys.scopes().len(), 0);
    }

    #[test]
    fn ordinary_multi_scope_approvals_fit_the_default_relay_limit() {
        use pubky_common::crypto::encrypt;

        let user = Keypair::from_secret(&[7; 32]);
        for count in [4, 5] {
            let mut capabilities = Capabilities::builder();
            for index in 0..count {
                capabilities = capabilities
                    .read_write(format!("/pub/app{index}.example/"))
                    .unwrap()
                    .encryption_keys(format!("/pub/app{index}.example/"))
                    .unwrap();
            }
            let mut claims = claims(&user);
            claims.caps = capabilities.finish().to_vec();
            claims.iat = 1_700_000_000;
            claims.exp = 1_731_536_000;
            let signed = GrantApprovalEnvelope::sign(&user, &claims);
            let wire = encrypt(signed.as_bytes(), &[77; 32]);
            assert!(
                wire.len() <= 2048,
                "{count} scopes need {} bytes",
                wire.len()
            );
        }
    }
}
