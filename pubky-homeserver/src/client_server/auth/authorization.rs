//! Authorization checks for storage requests.
//!
//! [`has_write_permission`] and [`has_read_permission`] are pure predicates —
//! they answer "may this session write/read this path on this tenant?" without
//! touching axum, request extensions, or any framework concern.
//!
//! Writes always require a session, so the [`AuthSession`] extractor returns the
//! 401 for "no session" and [`has_write_permission`] only does authorization (a
//! failure is always a 403). Reads have two tiers — `/pub/` is world-readable
//! while `/priv/` requires auth — so read handlers take `Option<AuthSession>`
//! and [`has_read_permission`] decides authentication too: 401 for an anonymous
//! `/priv/` read, 403 for a wrong-tenant or under-scoped one.
//!
//! Both predicates take the tenant as a [`PublicKey`]: storage handlers pass the
//! key from the `Host` header, the event stream passes the `user=` query key.
//!
//! [`AuthenticationLayer`]: super::AuthenticationLayer

use pubky_common::capabilities::Action;
use pubky_common::crypto::PublicKey;

use crate::client_server::auth::AuthSession;
use crate::constants::{PRIVATE_ROOT, PUBLIC_ROOT};
use crate::shared::webdav::StoragePath;
use crate::shared::HttpError;

/// Storage roots a write may target.
const STORAGE_ROOTS: [&str; 2] = [PUBLIC_ROOT, PRIVATE_ROOT];

/// Authorize a write to `path` for `session` on tenant `pubky`.
///
/// Returns `Ok(())` when the path is under one of [`STORAGE_ROOTS`], the
/// session targets the same tenant, and the session holds a capability whose
/// scope covers `path` with [`Action::Write`]. Returns a 403 `HttpError`
/// otherwise.
///
/// The writable root requirement is enforced here (not at the path extractor)
/// so that violations produce a 403 with a meaningful message — the SDK
/// contract expects `"Writing to directories other than '/pub/' and '/priv/'
/// is forbidden"` rather than axum's default 400 for a deserialization failure.
pub fn has_write_permission(
    session: &AuthSession,
    pubkey: &PublicKey,
    path: &StoragePath,
) -> Result<(), HttpError> {
    let path_str = path.as_str();

    if !STORAGE_ROOTS.iter().any(|root| path_str.starts_with(root)) {
        return Err(HttpError::forbidden_with_message(
            "Writing to directories other than '/pub/' and '/priv/' is forbidden",
        ));
    }

    session_has_action(session, pubkey, path, Action::Write)
}

/// Authorize a read of `path` for an optional `session` against an optional
/// tenant `pubkey`.
///
/// Read access has two tiers:
/// - [`PUBLIC_ROOT`] (`/pub/`) is world-readable — returns `Ok(())` for any
///   caller, authenticated or not.
/// - [`PRIVATE_ROOT`] (`/priv/`) is private — requires a `session` whose user
///   matches the tenant and that holds a capability whose scope covers `path`
///   with [`Action::Read`].
///
/// Returns a 401 `HttpError` for an anonymous `/priv/` read (no session) and a
/// 403 for a wrong-tenant, no-single-tenant, or under-scoped one. Paths outside
/// both roots get a 403, mirroring [`has_write_permission`].
pub fn has_read_permission(
    session: Option<&AuthSession>,
    pubkey: Option<&PublicKey>,
    path: &StoragePath,
) -> Result<(), HttpError> {
    let path_str = path.as_str();

    // `/pub/` is world-readable, anonymous reads are allowed.
    if path_str.starts_with(PUBLIC_ROOT) {
        return Ok(());
    }

    // Only `/priv/` is otherwise a valid read root.
    if !path_str.starts_with(PRIVATE_ROOT) {
        return Err(HttpError::forbidden_with_message(
            "Reading from directories other than '/pub/' and '/priv/' is forbidden",
        ));
    }

    // Authentication: a private read requires a session.
    let session = session.ok_or_else(|| {
        HttpError::unauthorized_with_message("Authentication required to read private storage")
    })?;

    // A private read is single-tenant. A caller that can address many users at
    // once passes `None` when the request names more than one.
    let pubkey = pubkey.ok_or_else(|| {
        HttpError::forbidden_with_message("A private read must be scoped to exactly one user")
    })?;

    session_has_action(session, pubkey, path, Action::Read)
}

/// Whether `session` targets tenant `pubkey` and holds a capability whose scope
/// covers `path` with `action`.
fn session_has_action(
    session: &AuthSession,
    pubkey: &PublicKey,
    path: &StoragePath,
    action: Action,
) -> Result<(), HttpError> {
    if session.user_key() != pubkey {
        return Err(HttpError::forbidden_with_message(
            "Session user does not match target tenant",
        ));
    }

    let granted = session
        .capabilities()
        .iter()
        .any(|cap| cap.scope_covers_path(path) && cap.actions().contains(&action));
    if granted {
        return Ok(());
    }

    let what = match action {
        Action::Read => "read access",
        Action::Write => "write access",
        Action::Unknown(_) => "access",
    };
    Err(HttpError::forbidden_with_message(format!(
        "Session does not have {what} to path"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_server::auth::grant::session::GrantSession;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use pubky_common::auth::jws::GrantId;
    use pubky_common::capabilities::{Capabilities, Capability};
    use pubky_common::crypto::{Keypair, PublicKey};

    fn dummy_pk() -> PublicKey {
        Keypair::random().public_key()
    }

    fn web_path(s: &str) -> StoragePath {
        StoragePath::new(s).expect("test path must be a syntactically valid webdav path")
    }

    fn session_with_key(pk: PublicKey, capabilities: Capabilities) -> AuthSession {
        AuthSession::Grant(GrantSession::test(
            pk,
            capabilities,
            GrantId::generate(),
            9999999999,
        ))
    }

    fn session_with_caps(capabilities: Capabilities) -> (AuthSession, PublicKey) {
        let pk = dummy_pk();
        let session = session_with_key(pk.clone(), capabilities);
        (session, pk)
    }

    fn root_caps() -> Capabilities {
        Capabilities::from(vec![Capability::root()])
    }

    fn scoped_caps(scope: &str) -> Capabilities {
        Capabilities::from(vec![Capability::write(scope).unwrap()])
    }

    fn read_only_caps() -> Capabilities {
        Capabilities::from(vec![Capability::read("/").unwrap()])
    }

    fn read_scoped_caps(scope: &str) -> Capabilities {
        Capabilities::from(vec![Capability::read(scope).unwrap()])
    }

    fn read_rejection_status(result: Result<(), HttpError>) -> StatusCode {
        result
            .expect_err("expected the read to be rejected")
            .into_response()
            .status()
    }

    #[test]
    fn root_capability_grants_access_to_any_pub_path() {
        let (session, pubky) = session_with_caps(root_caps());
        assert!(has_write_permission(&session, &pubky, &web_path("/pub/anything")).is_ok());
    }

    #[test]
    fn empty_capabilities_denies_access() {
        let (session, pubky) = session_with_caps(Capabilities::from(vec![]));
        assert!(has_write_permission(&session, &pubky, &web_path("/pub/file")).is_err());
    }

    #[test]
    fn read_only_capabilities_deny_write() {
        let (session, pubky) = session_with_caps(read_only_caps());
        assert!(has_write_permission(&session, &pubky, &web_path("/pub/file.txt")).is_err());
    }

    #[test]
    fn scoped_capability_grants_access_to_subpath() {
        let (session, pubky) = session_with_caps(scoped_caps("/pub/my.app/"));
        assert!(
            has_write_permission(&session, &pubky, &web_path("/pub/my.app/nested/file")).is_ok()
        );
    }

    #[test]
    fn scoped_capability_denies_access_to_sibling_path() {
        let (session, pubky) = session_with_caps(scoped_caps("/pub/my.app/"));
        assert!(has_write_permission(&session, &pubky, &web_path("/pub/other.app/file")).is_err());
    }

    #[test]
    fn scoped_capability_without_slash_rejects_prefix_attack() {
        let (session, pubky) = session_with_caps(scoped_caps("/pub/app"));
        assert!(has_write_permission(&session, &pubky, &web_path("/pub/app-evil/file")).is_err());
    }

    #[test]
    fn scoped_capability_without_slash_allows_exact_match() {
        let (session, pubky) = session_with_caps(scoped_caps("/pub/app"));
        assert!(has_write_permission(&session, &pubky, &web_path("/pub/app")).is_ok());
    }

    #[test]
    fn directory_scope_denies_write_to_directory_path_without_trailing_slash() {
        // Regression for the e2e auth tests (`tests::auth::authz`,
        // `signup_authz`, `authz_timeout_reconnect`): a capability granted
        // for `/pub/pubky.app/` (the directory) must NOT cover a write to
        // `/pub/pubky.app` (treated as a file at the parent level).
        let (session, pubky) = session_with_caps(scoped_caps("/pub/pubky.app/"));
        assert!(has_write_permission(&session, &pubky, &web_path("/pub/pubky.app")).is_err());
    }

    #[test]
    fn file_scope_denies_write_to_descendant() {
        // A file scope (no trailing `/`) is not a directory namespace —
        // granting `/pub/app:rw` does not authorize writes to `/pub/app/foo`.
        let (session, pubky) = session_with_caps(scoped_caps("/pub/app"));
        assert!(has_write_permission(&session, &pubky, &web_path("/pub/app/foo")).is_err());
    }

    #[test]
    fn cross_tenant_write_is_rejected() {
        // Session owned by user A, target tenant is user B.
        let session = session_with_key(dummy_pk(), root_caps());
        let pubky = dummy_pk();
        assert!(has_write_permission(&session, &pubky, &web_path("/pub/file.txt")).is_err());
    }

    #[test]
    fn same_tenant_write_with_root_caps_is_allowed() {
        let pk = dummy_pk();
        let session = session_with_key(pk.clone(), root_caps());
        let pubky = pk;
        assert!(has_write_permission(&session, &pubky, &web_path("/pub/file.txt")).is_ok());
    }

    #[test]
    fn write_outside_writable_roots_is_rejected() {
        // SDK contract: writes to roots other than `/pub/` and `/priv/` must
        // return 403 with a message containing `"Writing to directories other
        // than '/pub/' and '/priv/'"`. The HTTP shape is
        // covered end-to-end by that SDK test; here we just verify the
        // predicate rejects the path before any tenant/capability check.
        let (session, pubky) = session_with_caps(root_caps());
        assert!(has_write_permission(&session, &pubky, &web_path("/foo/example.com/x")).is_err());
    }

    #[test]
    fn root_capability_grants_access_to_any_priv_path() {
        let (session, pubky) = session_with_caps(root_caps());
        assert!(has_write_permission(&session, &pubky, &web_path("/priv/anything")).is_ok());
    }

    #[test]
    fn priv_path_with_covering_cap_is_allowed() {
        // A write cap scoped to `/priv/app/` authorizes writes beneath it,
        // exactly as it does under `/pub/`.
        let (session, pubky) = session_with_caps(scoped_caps("/priv/app/"));
        assert!(has_write_permission(&session, &pubky, &web_path("/priv/app/x")).is_ok());
    }

    #[test]
    fn priv_path_with_only_pub_caps_is_denied() {
        // A `/pub/`-scoped cap does not cover a `/priv/` write. Uses a scoped
        // cap rather than root, since a root `/` cap would cover `/priv/` too.
        let (session, pubky) = session_with_caps(scoped_caps("/pub/app/"));
        assert!(has_write_permission(&session, &pubky, &web_path("/priv/app/x")).is_err());
    }

    #[test]
    fn pub_read_is_allowed_anonymously() {
        // no session required.
        let pubky = dummy_pk();
        assert!(has_read_permission(None, Some(&pubky), &web_path("/pub/anything")).is_ok());
    }

    #[test]
    fn pub_read_is_allowed_with_session() {
        let (session, pubky) = session_with_caps(root_caps());
        assert!(has_read_permission(Some(&session), Some(&pubky), &web_path("/pub/x")).is_ok());
    }

    #[test]
    fn priv_read_without_session_is_unauthorized() {
        // No session → 401.
        let pubky = dummy_pk();
        let status = read_rejection_status(has_read_permission(
            None,
            Some(&pubky),
            &web_path("/priv/x"),
        ));
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn priv_read_cross_tenant_is_forbidden() {
        // Session owned by user A, target tenant is user B → 403.
        let session = session_with_key(dummy_pk(), root_caps());
        let pubky = dummy_pk();
        let status = read_rejection_status(has_read_permission(
            Some(&session),
            Some(&pubky),
            &web_path("/priv/x"),
        ));
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn priv_read_with_only_write_cap_is_forbidden() {
        // A write-only cap covering the path does not grant reads → 403.
        let (session, pubky) = session_with_caps(scoped_caps("/priv/app/"));
        let status = read_rejection_status(has_read_permission(
            Some(&session),
            Some(&pubky),
            &web_path("/priv/app/x"),
        ));
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn priv_read_with_covering_read_cap_is_allowed() {
        let (session, pubky) = session_with_caps(read_scoped_caps("/priv/app/"));
        assert!(
            has_read_permission(Some(&session), Some(&pubky), &web_path("/priv/app/x")).is_ok()
        );
    }

    #[test]
    fn priv_read_with_root_cap_is_allowed() {
        let (session, pubky) = session_with_caps(root_caps());
        assert!(
            has_read_permission(Some(&session), Some(&pubky), &web_path("/priv/anything")).is_ok()
        );
    }

    #[test]
    fn priv_read_cap_does_not_cover_sibling() {
        // A read cap scoped to `/priv/app/` must not cover `/priv/other/` → 403.
        let (session, pubky) = session_with_caps(read_scoped_caps("/priv/app/"));
        let status = read_rejection_status(has_read_permission(
            Some(&session),
            Some(&pubky),
            &web_path("/priv/other/x"),
        ));
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn read_outside_writable_roots_is_forbidden() {
        // Anything outside `/pub/` and `/priv/` → 403, mirroring writes.
        let (session, pubky) = session_with_caps(root_caps());
        let status = read_rejection_status(has_read_permission(
            Some(&session),
            Some(&pubky),
            &web_path("/foo/x"),
        ));
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn priv_read_cap_does_not_cover_parent_dir() {
        // a read cap on `/priv/app/` must not authorize listing the
        // parent `/priv/`
        let (session, pubky) = session_with_caps(read_scoped_caps("/priv/app/"));
        let status = read_rejection_status(has_read_permission(
            Some(&session),
            Some(&pubky),
            &web_path("/priv/"),
        ));
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn pub_read_without_a_tenant_is_allowed() {
        assert!(has_read_permission(None, None, &web_path("/pub/anything")).is_ok());
    }

    #[test]
    fn priv_read_without_a_single_tenant_is_forbidden() {
        let (session, _pubky) = session_with_caps(root_caps());
        let status = read_rejection_status(has_read_permission(
            Some(&session),
            None,
            &web_path("/priv/x"),
        ));
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn priv_read_without_session_or_tenant_is_unauthorized() {
        let status = read_rejection_status(has_read_permission(None, None, &web_path("/priv/x")));
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
