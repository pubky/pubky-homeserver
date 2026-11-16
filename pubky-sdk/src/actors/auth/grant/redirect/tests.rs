use pubky_common::{StoragePath, auth::jws::GrantId, encryption_keys::ScopedEncryptionKeyBundle};

use super::super::{
    approval::ParentApproval, approval_envelope::ParentApprovalEnvelope,
    parent_credential::ParentGrantCredential,
};
use super::*;

const CHAT: &str = "https://chat.example/auth/callback";
const ACCOUNTS: &str = "https://accounts.example/authorize?tenant=a";

fn holder(user: &Keypair, caps: &str) -> ParentGrantCredential {
    let key = Keypair::random();
    let now = now_unix();
    let claims = GrantClaims {
        iss: user.public_key(),
        client_id: ClientId::new("https://accounts.example/auth/callback").unwrap(),
        caps: caps.parse::<Capabilities>().unwrap().to_vec(),
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

fn builder(caps: &str) -> RedirectAuthFlowBuilder {
    PubkyRedirectAuthFlow::builder(
        &caps.parse().unwrap(),
        ClientId::new(CHAT).unwrap(),
        Url::parse(ACCOUNTS).unwrap(),
    )
    .client(PubkyHttpClient::new().unwrap())
}

fn flow(caps: &str) -> PubkyRedirectAuthFlow {
    builder(caps).start().unwrap()
}

/// What the holder receives: the request parsed from the authorization URL.
fn received(flow: &PubkyRedirectAuthFlow) -> ChildGrantRequest {
    ChildGrantRequest::parse(flow.authorization_url()).unwrap()
}

async fn approved(flow: &PubkyRedirectAuthFlow, holder: &ParentGrantCredential) -> Url {
    holder.issue_child(&received(flow), None).await.unwrap()
}

fn accept(flow: &PubkyRedirectAuthFlow, callback: &Url) -> Result<ChildGrantApproval> {
    flow.accept(&RedirectCallback::parse(callback)?)
}

fn with_fragment(url: &Url, fragment: &str) -> Url {
    let mut url = url.clone();
    url.set_fragment(Some(fragment));
    url
}

#[test]
fn the_request_keeps_accounts_configuration_and_only_public_values() {
    let flow = flow("/pub/chat/:rw,/priv/chat/:rwe");
    let url = flow.authorization_url();
    assert_eq!(url.host_str(), Some("accounts.example"));
    assert_eq!(url.path(), "/authorize");
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "tenant")
            .unwrap()
            .1,
        "a"
    );
    let request = received(&flow);
    assert_eq!(request.callback().as_str(), CHAT);
    assert_eq!(request.capabilities(), flow.capabilities());
    assert_eq!(request.state().len(), 43, "32 random bytes, base64url");
    assert_eq!(flow.expires_at() - flow.created_at(), 600);

    // Neither private key appears in the URL.
    let saved = flow.save_local().unwrap();
    for secret in [saved.client_key_secret, saved.approval_key_secret] {
        assert!(!url.as_str().contains(&URL_SAFE_NO_PAD.encode(secret)));
    }
    assert_ne!(
        received(&self::flow("/pub/chat/:r")).state(),
        request.state()
    );
    assert!(!format!("{flow:?}").contains(request.state()));
    assert!(!format!("{saved:?}").contains(request.state()));
}

#[test]
fn start_rejects_inexact_urls_conflicts_and_wide_capabilities() {
    let start = |callback: &str, accounts: &str, caps: &str| {
        PubkyRedirectAuthFlow::builder(
            &caps.parse().unwrap(),
            ClientId::new(callback).unwrap(),
            Url::parse(accounts).unwrap(),
        )
        .client(PubkyHttpClient::new().unwrap())
        .start()
    };
    for (callback, accounts, caps) in [
        ("http://chat.example/cb", ACCOUNTS, "/pub/chat/:r"),
        ("https://CHAT.example/cb", ACCOUNTS, "/pub/chat/:r"),
        ("https://user@chat.example/cb", ACCOUNTS, "/pub/chat/:r"),
        ("chat.example", ACCOUNTS, "/pub/chat/:r"),
        (CHAT, "http://accounts.example/authorize", "/pub/chat/:r"),
        (
            CHAT,
            "https://user:pw@accounts.example/authorize",
            "/pub/chat/:r",
        ),
        (CHAT, "https://accounts.example/authorize#x", "/pub/chat/:r"),
        (
            CHAT,
            "https://accounts.example/authorize?state=x",
            "/pub/chat/:r",
        ),
        (
            CHAT,
            "https://accounts.example/authorize?cid=x",
            "/pub/chat/:r",
        ),
        (
            CHAT,
            "https://accounts.example/authorize?epk=x",
            "/pub/chat/:r",
        ),
        (CHAT, ACCOUNTS, "/:rw"),
        (CHAT, ACCOUNTS, "/other/:r"),
    ] {
        assert!(
            start(callback, accounts, caps).is_err(),
            "{callback} {accounts} {caps}"
        );
    }
    for lifetime in [Duration::ZERO, Duration::from_secs(3601)] {
        builder("/pub/chat/:r")
            .lifetime(lifetime)
            .start()
            .unwrap_err();
    }
    builder("/pub/chat/:r")
        .lifetime(Duration::from_secs(3600))
        .start()
        .unwrap();
}

#[test]
fn saved_state_restores_the_same_request_and_rejects_other_keys() {
    let flow = flow("/pub/chat/:rw");
    let saved = flow.save_local().unwrap();
    assert!(flow.save_delegated().is_none());
    let client = PubkyHttpClient::new().unwrap();
    let restored = PubkyRedirectAuthFlow::restore(saved.clone(), client.clone()).unwrap();
    assert_eq!(restored.authorization_url(), flow.authorization_url());
    assert_eq!(restored.expires_at(), flow.expires_at());

    let mut other_key = saved.clone();
    other_key.client_key_secret = Keypair::random().secret();
    let mut other_recipient = saved.clone();
    other_recipient.approval_key_secret = ApprovalRecipientSecret::generate().0.to_bytes();
    let mut bad_times = saved.clone();
    bad_times.expires_at = bad_times.created_at;
    let mut bad_url = saved;
    bad_url.authorization_url = bad_url.authorization_url.replacen("https", "http", 1);
    for state in [other_key, other_recipient, bad_times, bad_url] {
        PubkyRedirectAuthFlow::restore(state, client.clone()).unwrap_err();
    }
}

#[test]
fn callbacks_must_hold_one_known_response_and_a_state() {
    let base = Url::parse(CHAT).unwrap();
    let approved = RedirectCallback::parse(&with_fragment(&base, "approval=AAAA&state=s")).unwrap();
    assert_eq!(approved.callback(), CHAT);
    assert_eq!(approved.denial(), None);
    for code in ["access_denied", "cancelled", "insufficient_permissions"] {
        let declined =
            RedirectCallback::parse(&with_fragment(&base, &format!("error={code}&state=s")))
                .unwrap();
        assert_eq!(declined.denial().unwrap().as_str(), code);
    }

    let oversized = format!(
        "approval={}&state=s",
        "A".repeat(MAX_CALLBACK_FRAGMENT_BYTES)
    );
    for fragment in [
        "",
        "state=s",
        "approval=AAAA",
        "approval=AAAA&error=access_denied&state=s",
        "approval=AAAA&approval=AAAA&state=s",
        "approval=AAAA&state=s&state=t",
        "approval=AAAA&state=",
        "approval=not+base64&state=s",
        "error=server_error&state=s",
        "approval=AAAA&state=s&next=/home",
        oversized.as_str(),
    ] {
        let error = RedirectCallback::parse(&with_fragment(&base, fragment))
            .unwrap_err()
            .to_string();
        assert!(
            !error.contains("AAAA") && !error.contains("server_error"),
            "{error}"
        );
    }
    RedirectCallback::parse(&base).unwrap_err();
    assert!(!format!("{approved:?}").contains("AAAA"));
}

#[tokio::test]
async fn an_issued_child_is_accepted_with_exactly_its_keys() {
    let user = Keypair::random();
    let holder = holder(&user, "/pub/:rwe,/priv/:rwe");
    let flow = flow("/pub/chat/:rw,/priv/chat/:rwe");
    let approval = accept(&flow, &approved(&flow, &holder).await).unwrap();

    assert_eq!(approval.claims().iss, user.public_key());
    assert_eq!(approval.claims().client_id.as_str(), CHAT);
    assert_eq!(approval.parent_claims(), holder.claims());
    let scope = StoragePath::new("/priv/chat/").unwrap();
    assert!(approval.0.encryption_keys.scopes().eq([&scope]));
    let file = StoragePath::new("/priv/chat/message").unwrap();
    let direct = ScopedEncryptionKeyBundle::from_identity_secret(
        &user.secret(),
        std::slice::from_ref(&scope),
    );
    assert_eq!(
        *approval.0.encryption_keys.derive_for_path(&file).unwrap(),
        *direct.derive_for_path(&file).unwrap()
    );
    // Neither a sibling nor an ancestor of the approved scope.
    for path in ["/priv/shop/order", "/priv/other"] {
        approval
            .0
            .encryption_keys
            .derive_for_path(&StoragePath::new(path).unwrap())
            .unwrap_err();
    }
    assert!(!format!("{approval:?}").contains(approval.signed_approval()));

    // The saved approval resumes after the request has expired.
    let mut saved = flow.save_local().unwrap();
    saved.created_at = 1;
    saved.expires_at = 2;
    let expired = PubkyRedirectAuthFlow::restore(saved, PubkyHttpClient::new().unwrap()).unwrap();
    expired
        .accept_signed_approval(approval.signed_approval())
        .unwrap();
    assert!(matches!(
        accept(&expired, &approved(&expired, &holder).await).unwrap_err(),
        crate::Error::Authentication(AuthError::RequestExpired)
    ));
}

#[tokio::test]
async fn storage_only_approvals_succeed_and_declines_keep_their_code() {
    let holder = holder(&Keypair::random(), "/pub/:rw,/priv/:rw");
    let flow = flow("/pub/chat/:rw");
    let approval = accept(&flow, &approved(&flow, &holder).await).unwrap();
    assert_eq!(approval.0.encryption_keys.scopes().len(), 0);

    // A parent without `e` can't serve a key request: an explicit denial, no retry.
    let flow = self::flow("/priv/chat/:rwe");
    let error = holder
        .issue_child(&received(&flow), None)
        .await
        .unwrap_err();
    let denial = match error {
        crate::Error::Authentication(AuthError::RedirectDeclined(denial)) => denial,
        other => panic!("{other:?}"),
    };
    let callback = received(&flow).declined_url(denial);
    assert!(matches!(
        accept(&flow, &callback).unwrap_err(),
        crate::Error::Authentication(AuthError::RedirectDeclined(
            RedirectDenial::InsufficientPermissions
        ))
    ));
}

#[tokio::test]
async fn callbacks_for_other_requests_or_callbacks_are_rejected_without_consuming() {
    let holder = holder(&Keypair::random(), "/pub/:rwe,/priv/:rwe");
    let flow = flow("/pub/chat/:rw");
    let other = self::flow("/pub/chat/:rw");
    let valid = approved(&flow, &holder).await;
    let state = received(&flow).state().to_owned();

    // Another request's approval, delivered with this request's state.
    let foreign = approved(&other, &holder).await;
    let sealed = foreign.fragment().unwrap().split('&').next().unwrap();
    let swapped = with_fragment(&valid, &format!("{sealed}&state={state}"));
    // This request's approval at another callback, or with another state.
    let mut wrong_path = valid.clone();
    wrong_path.set_path("/auth/callback/");
    let wrong_state = with_fragment(
        &valid,
        &valid
            .fragment()
            .unwrap()
            .replace(&state, received(&other).state()),
    );
    for callback in [foreign, swapped, wrong_path, wrong_state] {
        accept(&flow, &callback).unwrap_err();
    }
    // None of those used up the request.
    accept(&flow, &valid).unwrap();
}

#[tokio::test]
async fn approvals_must_bind_this_requests_key_state_and_capabilities() {
    let user = Keypair::random();
    let holder = holder(&user, "/pub/:rwe,/priv/:rwe");
    let flow = flow("/pub/chat/:rw");
    let request = received(&flow);
    // A holder that changes the request before signing: wider capabilities,
    // another app key, another state or another recipient key.
    let (_, other_recipient) = ApprovalRecipientSecret::generate();
    for (caps, cpk, epk, state) in [
        (
            "/pub/chat/:rwe",
            request.client_pk().clone(),
            *request.ephemeral_public_key(),
            request.state(),
        ),
        (
            "/pub/:rw",
            request.client_pk().clone(),
            *request.ephemeral_public_key(),
            request.state(),
        ),
        (
            "/pub/chat/:rw",
            Keypair::random().public_key(),
            *request.ephemeral_public_key(),
            request.state(),
        ),
        (
            "/pub/chat/:rw",
            request.client_pk().clone(),
            *request.ephemeral_public_key(),
            "other",
        ),
        (
            "/pub/chat/:rw",
            request.client_pk().clone(),
            other_recipient,
            request.state(),
        ),
    ] {
        let changed = ChildGrantRequest::new(
            caps.parse().unwrap(),
            request.callback().clone(),
            cpk,
            epk,
            state.to_owned(),
        );
        let url = holder.issue_child(&changed, None).await.unwrap();
        // Deliver it with the real state, so only the approval differs.
        let sealed = url
            .fragment()
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_owned();
        let url = with_fragment(&url, &format!("{sealed}&state={}", request.state()));
        assert!(accept(&flow, &url).is_err(), "{caps} {state}");
    }

    // A narrower approval is fine.
    let narrower = ChildGrantRequest::new(
        "/pub/chat/:r".parse().unwrap(),
        request.callback().clone(),
        request.client_pk().clone(),
        *request.ephemeral_public_key(),
        request.state().to_owned(),
    );
    let url = holder.issue_child(&narrower, None).await.unwrap();
    assert_eq!(accept(&flow, &url).unwrap().claims().caps.len(), 1);
}

#[tokio::test]
async fn exchange_rejects_an_approval_for_another_request() {
    let holder = holder(&Keypair::random(), "/pub/:rwe,/priv/:rwe");
    let flow = flow("/pub/chat/:rw");
    let other = self::flow("/pub/chat/:rw");
    let approval = accept(&other, &approved(&other, &holder).await).unwrap();
    let error = flow.exchange(&approval).await.unwrap_err().to_string();
    assert!(error.contains("another sign-in"), "{error}");
}
