//! Parent grant credential: authority to issue child grants, without a session.
//!
//! The holder, such as Pubky Accounts, keeps the signed approval that Ring sent
//! it, with the keys for every approved `e` scope. It signs each child grant with
//! the key in the parent's `cnf`, and narrows the keys to the child's `e` scopes.
//! A parent can't create storage sessions.
//!
//! The holder can decrypt existing and future data under its approved scopes, so
//! only trust it with scopes the user agreed to. Signing out revokes the grant
//! but can't take back keys that were already delivered.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::{
    auth::{
        grant::{ChildGrantClaims, GrantClaims, caps_within},
        jws::{CHILD_GRANT_JWS_TYP, ClientId, GrantId, PopNonce, RECONNECT_JWS_TYP},
        pop::{PopProofClaims, ReconnectProofClaims},
    },
    crypto::{Keypair, PublicKey},
    encryption_keys::ScopedEncryptionKeyBundle,
};
use reqwest::Method;
use url::Url;
use zeroize::Zeroizing;

use super::{
    approval::{ParentApproval, SignedApproval},
    approval_encryption,
    approval_envelope::{CHILD_APPROVAL_JWS_TYP, ChildApprovalEnvelope, key_scopes},
    credential::{GRANT_SESSION_PATH, now_unix, sign_pop_for_grant},
    pop_signer::{DelegatedSignFn, GrantPopSigner},
};
use crate::{
    PubkyHttpClient,
    actors::{Pkdns, auth::deep_links::ChildGrantRequest},
    errors::{AuthError, RedirectDenial, Result},
};

const RECONNECT_PATH: &str = "/auth/grant/reconnect";

/// Verified parent grant, its keys and the signer for its `cnf` key.
///
/// Debug output redacts secrets. Keep [`Self::signed_approval`] out of logs, URLs
/// and public metadata.
#[derive(Clone, Debug)]
pub struct ParentGrantCredential {
    parent_jws: String,
    claims: GrantClaims,
    client_signer: GrantPopSigner,
    encryption_keys: ScopedEncryptionKeyBundle,
    signed_approval: SignedApproval,
}

impl ParentGrantCredential {
    pub(crate) fn new(approval: ParentApproval, client_signer: GrantPopSigner) -> Result<Self> {
        if client_signer.public_key() != approval.claims.cnf {
            return Err(AuthError::Validation(
                "signing key does not match the parent grant cnf".into(),
            )
            .into());
        }
        Ok(Self {
            parent_jws: approval.parent_jws,
            claims: approval.claims,
            client_signer,
            encryption_keys: approval.encryption_keys,
            signed_approval: approval.signed_approval,
        })
    }

    /// Verified parent claims.
    #[must_use]
    pub const fn claims(&self) -> &GrantClaims {
        &self.claims
    }

    /// The public parent grant JWS.
    #[must_use]
    pub fn parent_grant(&self) -> &str {
        &self.parent_jws
    }

    /// Keys for the parent's approved `e` scopes. Empty if the user declined `e`.
    #[must_use]
    pub const fn encryption_keys(&self) -> &ScopedEncryptionKeyBundle {
        &self.encryption_keys
    }

    /// The confidential signed approval, for secure persistence. Contains raw keys.
    ///
    /// Restore the credential with [`Self::from_signed_approval`].
    #[must_use]
    pub fn signed_approval(&self) -> &str {
        self.signed_approval.as_str()
    }

    /// Restore a credential from its [`Self::signed_approval`] and the signing
    /// key you set with the flow builder's `client_keypair`.
    ///
    /// Verifies the approval's signatures, limits and key scopes again.
    ///
    /// # Errors
    /// Returns [`AuthError::Validation`] if the approval is invalid or `keypair`
    /// isn't the key in the parent's `cnf`.
    pub fn from_signed_approval(signed_approval: &str, keypair: Keypair) -> Result<Self> {
        Self::new(
            ParentApproval::decode(signed_approval)?,
            GrantPopSigner::local(keypair),
        )
    }

    /// Restore a credential whose signing key is held outside the SDK.
    #[doc(hidden)]
    pub fn from_delegated(
        signed_approval: &str,
        key_id: String,
        public_key: PublicKey,
        sign: DelegatedSignFn,
    ) -> Result<Self> {
        Self::new(
            ParentApproval::decode(signed_approval)?,
            GrantPopSigner::delegated(key_id, public_key, sign),
        )
    }

    /// The id of the externally held signing key, if there is one.
    #[doc(hidden)]
    #[must_use]
    pub fn delegated_key_id(&self) -> Option<String> {
        self.client_signer
            .delegated_state()
            .map(|signer| signer.key_id)
    }

    /// Issue a child grant and return the callback URL that delivers it to the app.
    ///
    /// The child gets exactly the requested capabilities, and keys for exactly
    /// its `e` scopes. It lasts until `expires_at`, or until the parent expires
    /// when that's `None`. Check the request against your app catalog first.
    /// If you can't issue to an app in your catalog, send the user to
    /// [`ChildGrantRequest::declined_url`]. Never redirect to a callback that
    /// isn't in your catalog.
    ///
    /// The approval is encrypted to the app, and the returned URL carries it in
    /// the fragment. Don't log the URL.
    ///
    /// # Errors
    /// - [`AuthError::RedirectDeclined`] with
    ///   [`RedirectDenial::InsufficientPermissions`] if the request exceeds the parent.
    /// - [`AuthError::Validation`] if the parent has expired or `expires_at` is
    ///   invalid, or if signing or encryption fails.
    pub async fn issue_child(
        &self,
        request: &ChildGrantRequest,
        expires_at: Option<u64>,
    ) -> Result<Url> {
        let parent = &self.claims;
        let now = now_unix();
        if parent.exp <= now {
            return Err(AuthError::Validation("parent grant has expired".into()).into());
        }
        if !caps_within(
            &parent.caps.clone().into(),
            request.capabilities().as_slice(),
        ) {
            return Err(
                AuthError::RedirectDeclined(RedirectDenial::InsufficientPermissions).into(),
            );
        }
        // The homeserver requires `parent.iat <= child.iat < child.exp <= parent.exp`.
        let iat = now.max(parent.iat);
        let exp = expires_at.unwrap_or(parent.exp);
        if exp <= iat || exp > parent.exp {
            return Err(AuthError::Validation(
                "child grant must expire after it is issued and no later than its parent".into(),
            )
            .into());
        }

        let claims = ChildGrantClaims {
            grant: GrantClaims {
                iss: parent.iss.clone(),
                client_id: request.callback().clone(),
                caps: request.capabilities().to_vec(),
                cnf: request.client_pk().clone(),
                jti: GrantId::generate(),
                iat,
                exp,
            },
            parent_jti: parent.jti.clone(),
        };
        let encryption_keys = self
            .encryption_keys
            .narrow(key_scopes(&claims.grant.caps))
            .map_err(|error| AuthError::Validation(error.to_string()))?;
        let envelope = ChildApprovalEnvelope {
            parent: self.parent_jws.clone(),
            child: self.sign(CHILD_GRANT_JWS_TYP, &claims).await?,
            recipient: URL_SAFE_NO_PAD.encode(request.ephemeral_public_key()),
            state: request.state().to_owned(),
            encryption_keys,
        };
        let signed = Zeroizing::new(self.sign(CHILD_APPROVAL_JWS_TYP, &envelope).await?);
        let sealed = approval_encryption::seal(request.ephemeral_public_key(), signed.as_bytes())?;
        Ok(request.approved_url(&sealed))
    }

    async fn sign<T: serde::Serialize>(&self, typ: &str, claims: &T) -> Result<String> {
        self.client_signer
            .sign_jws(typ, claims)
            .await
            .map_err(|error| AuthError::Validation(error.to_string()).into())
    }

    /// Revoke this parent, all its children and their sessions.
    ///
    /// Works after the parent expires and can be retried. Delivered keys can't be
    /// taken back, so delete your local copy of the approval first. Keep
    /// [`Self::parent_grant`] and the signing key until this succeeds, so that
    /// [`Self::revoke_with_keypair`] can retry after a restart.
    ///
    /// # Errors
    /// Propagates homeserver lookup, signing, transport and server errors.
    pub async fn signout(&self, client: &PubkyHttpClient) -> Result<()> {
        revoke(client, &self.parent_jws, &self.claims, &self.client_signer).await
    }

    /// Let an app sign in again after the user removed it, for example in Ring.
    ///
    /// Removing an app blocks new child grants for that callback under this
    /// parent. Call this only after the user confirms the reconnection, then issue
    /// a new child. A revoked child stays revoked. Clearing a block that doesn't
    /// exist succeeds, so you can retry this call.
    ///
    /// # Errors
    /// Propagates homeserver lookup, signing, transport and server errors.
    pub async fn reconnect_app(&self, client: &PubkyHttpClient, callback: &ClientId) -> Result<()> {
        let homeserver = Pkdns::with_client(client.clone())
            .require_homeserver_of(&self.claims.iss)
            .await?;
        let claims = ReconnectProofClaims {
            pop: PopProofClaims {
                aud: homeserver.clone(),
                gid: self.claims.jti.clone(),
                nonce: PopNonce::generate(),
                iat: now_unix(),
            },
            client_id: callback.clone(),
        };
        let proof = self.sign(RECONNECT_JWS_TYP, &claims).await?;
        let response = client
            .cross_request_via_homeserver(
                Method::POST,
                &homeserver,
                &self.claims.iss,
                RECONNECT_PATH,
            )
            .await?
            .json(&serde_json::json!({ "parent": self.parent_jws, "proof": proof }))
            .send()
            .await?;
        client.check_http_status(response).await?;
        Ok(())
    }

    /// Revoke a parent from its public grant ([`Self::parent_grant`]) and signing
    /// key, to retry a sign-out after the confidential approval was deleted.
    ///
    /// # Errors
    /// Returns [`AuthError::Validation`] for a malformed grant, and otherwise
    /// fails like [`Self::signout`].
    pub async fn revoke_with_keypair(
        client: &PubkyHttpClient,
        parent_grant: &str,
        keypair: Keypair,
    ) -> Result<()> {
        let claims = decode_parent(parent_grant)?;
        revoke(
            client,
            parent_grant,
            &claims,
            &GrantPopSigner::local(keypair),
        )
        .await
    }

    /// Like [`Self::revoke_with_keypair`], for a signing key held outside the SDK.
    ///
    /// The parent's `cnf` names the signing key, so only its id is needed.
    #[doc(hidden)]
    pub async fn revoke_delegated(
        client: &PubkyHttpClient,
        parent_jws: &str,
        key_id: String,
        sign: DelegatedSignFn,
    ) -> Result<()> {
        let claims = decode_parent(parent_jws)?;
        let signer = GrantPopSigner::delegated(key_id, claims.cnf.clone(), sign);
        revoke(client, parent_jws, &claims, &signer).await
    }
}

fn decode_parent(parent_jws: &str) -> Result<GrantClaims> {
    GrantClaims::decode(parent_jws)
        .map_err(|error| AuthError::Validation(format!("invalid parent grant: {error}")).into())
}

async fn revoke(
    client: &PubkyHttpClient,
    parent_jws: &str,
    claims: &GrantClaims,
    client_signer: &GrantPopSigner,
) -> Result<()> {
    let homeserver = Pkdns::with_client(client.clone())
        .require_homeserver_of(&claims.iss)
        .await?;
    let pop = sign_pop_for_grant(client_signer, &homeserver, &claims.jti).await?;
    let response = client
        .cross_request_via_homeserver(Method::DELETE, &homeserver, &claims.iss, GRANT_SESSION_PATH)
        .await?
        .json(&serde_json::json!({ "grant": parent_jws, "pop": pop }))
        .send()
        .await?;
    client.check_http_status(response).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use pubky_common::{StoragePath, auth::jws::decode_jws_payload};

    use super::*;
    use crate::actors::auth::grant::{
        approval::verify_jws, approval_encryption::ApprovalRecipientSecret,
        approval_envelope::ParentApprovalEnvelope,
    };

    const ACCOUNTS: &str = "https://accounts.example/auth/callback";
    const CHAT: &str = "https://chat.example/auth/callback";

    fn holder(user: &Keypair, caps: &str) -> ParentGrantCredential {
        let key = Keypair::random();
        let now = now_unix();
        let claims = GrantClaims {
            iss: user.public_key(),
            client_id: ClientId::new(ACCOUNTS).unwrap(),
            caps: caps.parse::<crate::Capabilities>().unwrap().to_vec(),
            cnf: key.public_key(),
            jti: GrantId::generate(),
            iat: now,
            exp: now + 3600,
        };
        let signed = ParentApprovalEnvelope::sign(user, &claims, &[1; 32]);
        ParentGrantCredential::new(
            ParentApproval::decode(&signed).unwrap(),
            GrantPopSigner::local(key),
        )
        .unwrap()
    }

    fn request(caps: &str) -> (ChildGrantRequest, ApprovalRecipientSecret) {
        let (secret, public_key) = ApprovalRecipientSecret::generate();
        let request = ChildGrantRequest::new(
            caps.parse().unwrap(),
            ClientId::new(CHAT).unwrap(),
            Keypair::random().public_key(),
            public_key,
            "state-1".into(),
        );
        (request, secret)
    }

    fn open(url: &Url, secret: &ApprovalRecipientSecret) -> Zeroizing<String> {
        let (_, sealed) = url
            .fragment()
            .unwrap()
            .split('&')
            .find_map(|pair| pair.split_once('=').filter(|(key, _)| *key == "approval"))
            .unwrap();
        let plain = secret
            .open(&URL_SAFE_NO_PAD.decode(sealed).unwrap())
            .unwrap();
        Zeroizing::new(String::from_utf8(plain.to_vec()).unwrap())
    }

    /// Check both signatures, then read the approval and the child's claims.
    fn delivered(
        signed: &str,
        holder: &ParentGrantCredential,
    ) -> (ChildApprovalEnvelope, ChildGrantClaims) {
        let cnf = &holder.claims().cnf;
        verify_jws(signed, cnf, CHILD_APPROVAL_JWS_TYP).unwrap();
        let envelope: ChildApprovalEnvelope = decode_jws_payload(signed).unwrap();
        verify_jws(&envelope.child, cnf, CHILD_GRANT_JWS_TYP).unwrap();
        let claims = decode_jws_payload(&envelope.child).unwrap();
        (envelope, claims)
    }

    #[tokio::test]
    async fn issued_child_gets_only_the_keys_it_was_granted() {
        let user = Keypair::random();
        let holder = holder(&user, "/pub/:rwe,/priv/:rwe");
        let (request, secret) = request("/pub/chat/:rw,/priv/chat/v1/:rwe");

        let signed = open(&holder.issue_child(&request, None).await.unwrap(), &secret);
        let (envelope, child) = delivered(&signed, &holder);

        assert_eq!(envelope.state, "state-1");
        assert_eq!(
            envelope.recipient,
            URL_SAFE_NO_PAD.encode(request.ephemeral_public_key())
        );
        assert_eq!(envelope.parent, holder.parent_grant());
        assert_eq!(child.parent_jti, holder.claims().jti);
        assert_eq!(child.grant.iss, user.public_key());
        assert_eq!(&child.grant.cnf, request.client_pk());
        assert_eq!(&child.grant.client_id, request.callback());
        assert_eq!(child.grant.exp, holder.claims().exp);
        let scope = StoragePath::new("/priv/chat/v1/").unwrap();
        assert!(envelope.encryption_keys.scopes().eq([&scope]));

        // The app's key equals the one the signer would derive for that file.
        let file = StoragePath::new("/priv/chat/v1/message").unwrap();
        let direct = ScopedEncryptionKeyBundle::from_identity_secret(
            &user.secret(),
            std::slice::from_ref(&scope),
        );
        assert_eq!(
            *envelope.encryption_keys.derive_for_path(&file).unwrap(),
            *direct.derive_for_path(&file).unwrap(),
        );
        // A sibling of the granted scope stays out of reach.
        envelope
            .encryption_keys
            .derive_for_path(&StoragePath::new("/priv/shop/order").unwrap())
            .unwrap_err();
    }

    #[tokio::test]
    async fn child_delivery_holds_no_parent_secrets() {
        let holder = holder(&Keypair::random(), "/pub/:rwe,/priv/:rwe");
        let (request, secret) = request("/pub/chat/:r");
        let signed = open(&holder.issue_child(&request, None).await.unwrap(), &secret);

        let payload: serde_json::Value = decode_jws_payload(&signed).unwrap();
        assert_eq!(payload["encryption_keys"]["keys"], serde_json::json!([]));
        assert!(!signed.contains(holder.signed_approval()));
    }

    #[tokio::test]
    async fn requests_beyond_the_parent_are_declined() {
        // The user approved storage but declined `e`.
        let holder = holder(&Keypair::random(), "/pub/:rw,/priv/:rw");
        assert_eq!(holder.encryption_keys().scopes().len(), 0);
        for caps in ["/priv/chat/:rwe", "/:r", "/other/:r"] {
            let (request, _) = request(caps);
            assert!(
                matches!(
                    holder.issue_child(&request, None).await.unwrap_err(),
                    crate::Error::Authentication(AuthError::RedirectDeclined(
                        RedirectDenial::InsufficientPermissions
                    ))
                ),
                "{caps}"
            );
        }
        let (request, _) = request("/priv/chat/:rw");
        holder.issue_child(&request, None).await.unwrap();
    }

    #[tokio::test]
    async fn child_expiry_must_fit_inside_the_parent() {
        let holder = holder(&Keypair::random(), "/pub/:rw");
        let (request, secret) = request("/pub/chat/:r");
        let parent_exp = holder.claims().exp;

        for invalid in [now_unix() - 1, parent_exp + 1] {
            holder
                .issue_child(&request, Some(invalid))
                .await
                .unwrap_err();
        }
        let sooner = parent_exp - 60;
        let url = holder.issue_child(&request, Some(sooner)).await.unwrap();
        let (_, child) = delivered(&open(&url, &secret), &holder);
        assert_eq!(child.grant.exp, sooner);
    }

    #[tokio::test]
    async fn signing_failures_never_produce_a_child() {
        let user = Keypair::random();
        let local = holder(&user, "/pub/:rw");
        let delegated = ParentGrantCredential::from_delegated(
            local.signed_approval(),
            "missing".into(),
            local.claims().cnf.clone(),
            crate::delegated_sign_callback(|_| async {
                Err(crate::GrantSigningError::KeyUnavailable("gone".into()))
            }),
        )
        .unwrap();
        let (request, _) = request("/pub/chat/:r");
        delegated.issue_child(&request, None).await.unwrap_err();
    }

    #[tokio::test]
    async fn saved_approval_and_key_restore_the_credential() {
        let user = Keypair::random();
        let key = Keypair::random();
        let now = now_unix();
        let claims = GrantClaims {
            iss: user.public_key(),
            client_id: ClientId::new(ACCOUNTS).unwrap(),
            caps: vec!["/priv/:rwe".parse().unwrap()],
            cnf: key.public_key(),
            jti: GrantId::generate(),
            iat: now,
            exp: now + 3600,
        };
        let saved = ParentApprovalEnvelope::sign(&user, &claims, &[1; 32]);

        let restored = ParentGrantCredential::from_signed_approval(&saved, key).unwrap();
        assert_eq!(restored.claims(), &claims);
        assert_eq!(restored.encryption_keys().scopes().len(), 1);
        let (request, _) = request("/priv/chat/:rwe");
        restored.issue_child(&request, None).await.unwrap();

        // Another key can't stand in for the one in the parent's `cnf`.
        ParentGrantCredential::from_signed_approval(&saved, Keypair::random()).unwrap_err();
        ParentGrantCredential::from_signed_approval("not an approval", Keypair::random())
            .unwrap_err();
    }

    #[tokio::test]
    async fn signed_payloads_fit_the_relay_and_a_url() {
        let holder = holder(&Keypair::random(), "/pub/:rwe,/priv/:rwe");
        let (_, recipient) = ApprovalRecipientSecret::generate();
        let sealed =
            approval_encryption::seal(&recipient, holder.signed_approval().as_bytes()).unwrap();
        assert!(
            sealed.len() < 2048,
            "a parent approval of {} bytes must fit the relay's default 2 KiB body limit",
            sealed.len()
        );

        let (request, _) = request("/pub/chat/v1/:rw,/priv/chat/v1/:rwe,/priv/chat/v2/:rwe");
        let url = holder.issue_child(&request, None).await.unwrap();
        assert!(
            url.as_str().len() < 8 * 1024,
            "a callback URL of {} bytes must stay short enough for browsers",
            url.as_str().len()
        );
    }
}
