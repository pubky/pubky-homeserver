//! Demo user provisioning for a test homeserver.
//!
//! `POST /generate_demo_user` creates a throwaway identity, seeds it with a
//! little sample content, and hands back a long-lived personal access token so
//! the caller can immediately mount the drive over WebDAV.
//!
//! This exists because minting a normal session needs a Ring-signed Grant JWS,
//! which standard WebDAV clients cannot produce. Everything here is a
//! deliberate shortcut for demos:
//!
//! - The homeserver generates the identity, so it briefly holds a secret key
//!   that is meant to be the user's alone. The secret is returned in the
//!   response and not stored.
//! - User creation bypasses signup-token policy — the admin password already
//!   authorized the call.
//!
//! Admin auth (see [`AdminAuthLayer`]) is the only gate, so keep the admin port
//! off the public internet.
//!
//! [`AdminAuthLayer`]: crate::admin_server::auth_middleware::AdminAuthLayer
mod pubky_app;

use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json,
};
use bytes::Bytes;
use futures_util::stream;
use pubky_common::{
    auth::jws::ClientId,
    capabilities::Capabilities,
    crypto::{Keypair, PublicKey},
};
use serde::{Deserialize, Serialize};

use super::super::app_state::AppState;
use crate::client_server::auth::{GrantAuthService, SignupService};
use crate::persistence::files::WriteStreamError;
use crate::persistence::sql::signup_code::{SignupCode, SignupCodeRepository};
use crate::shared::{
    quota::UserQuota,
    webdav::{EntryPath, StoragePath},
    HttpError, HttpResult,
};
use crate::SignupMode;

/// Capabilities a demo token carries unless the caller asks for narrower ones.
const DEFAULT_CAPABILITIES: &str = "/:rw";

/// Client id recorded on the demo grant, so these are easy to spot in `/sessions`.
const DEFAULT_CLIENT_ID: &str = "demo.webdav";

/// How long a demo token stays valid by default.
const DEFAULT_LIFETIME_DAYS: u64 = 365;

/// Content written into the new drive, shaped like a drive someone actually uses:
/// a public half anyone can read and a private half only the owner can, both
/// nested deeply enough to be worth navigating.
///
/// Kept small on purpose — the whole set is a few kilobytes, so provisioning a
/// demo user stays a single fast request.
const SEED_FILES: [(&str, &[u8]); 12] = [
    // ── /pub/ — world-readable, so these are live on the web immediately ──
    (
        "/pub/README.txt",
        b"Welcome to your Pubky demo drive.\n\n\
          Everything under /pub/ is world-readable: anyone can fetch it at\n\
          <homeserver>/storage/<your-public-key>/pub/... with no credentials.\n\
          /priv/ is yours alone.\n\n\
          Both halves are the same files you see over WebDAV, the REST API and\n\
          the Pubky SDK. Move things around from your file manager and the\n\
          public URLs follow.\n",
    ),
    (
        "/pub/index.html",
        b"<!doctype html>\n<meta charset=\"utf-8\">\n<title>A page on my drive</title>\n\
          <style>body{font:16px/1.6 system-ui;margin:5rem auto;max-width:34rem;padding:0 1rem}\n\
          code{background:#eee;padding:.1em .3em;border-radius:3px}</style>\n\
          <h1>This page lives on a Pubky drive</h1>\n\
          <p>It was written to <code>/pub/index.html</code> and served straight from\n\
          the homeserver. Edit it in your file manager and reload.</p>\n",
    ),
    (
        "/pub/photos/harbour.png",
        include_bytes!("../../../../assets/demo/harbour.png"),
    ),
    (
        "/pub/photos/ridge.png",
        include_bytes!("../../../../assets/demo/ridge.png"),
    ),
    (
        "/pub/photos/orchard.png",
        include_bytes!("../../../../assets/demo/orchard.png"),
    ),
    (
        "/pub/photos/captions.txt",
        b"harbour.png  Early light, low tide.\n\
          ridge.png    The long way round.\n\
          orchard.png  Late summer, before the pick.\n",
    ),
    // ── /priv/ — owner only ──
    (
        "/priv/drive/documents/welcome.md",
        b"# Your private folder\n\n\
          Nothing under `/priv/` is readable without your token. Try it: copy a\n\
          public URL from `/pub/`, change `pub` to `priv`, and open it in a\n\
          browser tab where you are not signed in. You will get a 401.\n\n\
          Files you drag in here from your file manager land the same way.\n",
    ),
    (
        "/priv/drive/documents/reading-list.md",
        b"# Reading list\n\n\
          - [ ] Credible exit, and why it needs the data to be portable\n\
          - [ ] PKARR: public keys as sovereign domain names\n\
          - [x] WebDAV (RFC 4918) - the parts everyone actually implements\n\
          - [ ] Capability-scoped tokens vs. all-or-nothing sessions\n",
    ),
    (
        "/priv/drive/documents/expenses.csv",
        b"date,description,category,amount\n\
          2026-08-04,Coffee and a long think,food,3.40\n\
          2026-08-09,Train to the coast,travel,28.50\n\
          2026-08-17,Second-hand paperback,books,6.00\n\
          2026-08-23,Film developing,photography,14.25\n\
          2026-09-01,Domain renewal,infrastructure,11.00\n",
    ),
    (
        "/priv/drive/photos/scan-0001.png",
        include_bytes!("../../../../assets/demo/scan-0001.png"),
    ),
    (
        "/priv/drive/projects/pubky-demo/notes.md",
        b"# Demo notes\n\n\
          The drive is mounted over WebDAV, so this file is open in a normal\n\
          editor from a normal folder. No sync client, no vendor app.\n\n\
          Worth showing: create a folder here, drop a file in it, then run\n\
          `curl <homeserver>/storage/<key>/priv/drive/projects/` with your token\n\
          and watch the same tree come back over the REST API.\n",
    ),
    (
        "/priv/drive/projects/pubky-demo/todo.txt",
        b"- move the photos folder somewhere else, watch the URLs follow\n\
          - delete this file from the file manager\n\
          - put it back\n",
    ),
];

#[derive(Debug, Deserialize)]
pub(crate) struct DemoUserParams {
    /// Capabilities string, e.g. `/pub/:rw`. Defaults to root.
    capabilities: Option<String>,
    /// Client id recorded on the grant.
    client_id: Option<String>,
    /// Token lifetime in days.
    lifetime_days: Option<u64>,
    /// Whether to write the sample files. Defaults to true.
    seed: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DemoUserResponse {
    /// The new identity, z-base32. Doubles as the WebDAV username.
    public_key: String,
    /// The identity's 32-byte secret, hex. Returned once and never stored —
    /// it lets the caller keep using this identity with the SDK or Ring.
    secret_key: String,
    /// The bearer token. Doubles as the WebDAV password.
    token: String,
    /// The grant behind the token, for revoking it later.
    grant_id: String,
    /// Unix seconds at which the token expires.
    expires_at: u64,
    /// `Authorization: Basic` value, precomputed for convenience.
    basic_auth: String,
    /// Where to point a WebDAV client, when the homeserver knows its own
    /// public ICANN address.
    #[serde(skip_serializing_if = "Option::is_none")]
    webdav_url: Option<String>,
    /// The browser file explorer, with the public key prefilled — the link to
    /// hand someone who just wants to look at their files.
    #[serde(skip_serializing_if = "Option::is_none")]
    drive_url: Option<String>,
    /// The files seeded into the drive.
    seeded_files: Vec<String>,
}

/// `POST /generate_demo_user` — create a user, seed it, and return a token.
pub async fn generate_demo_user(
    State(state): State<AppState>,
    Query(params): Query<DemoUserParams>,
) -> HttpResult<impl IntoResponse> {
    let capabilities: Capabilities = params
        .capabilities
        .as_deref()
        .unwrap_or(DEFAULT_CAPABILITIES)
        .parse()
        .map_err(|e| HttpError::bad_request(format!("Invalid capabilities: {e}")))?;
    let client_id = ClientId::new(params.client_id.as_deref().unwrap_or(DEFAULT_CLIENT_ID))
        .map_err(|e| HttpError::bad_request(format!("Invalid client_id: {e}")))?;
    let lifetime_days = params.lifetime_days.unwrap_or(DEFAULT_LIFETIME_DAYS);
    let lifetime_secs = lifetime_days
        .checked_mul(24 * 60 * 60)
        .ok_or_else(|| HttpError::bad_request("lifetime_days is too large"))?;

    let keypair = Keypair::random();
    let public_key = keypair.public_key();

    let user = create_user(&state, &public_key).await?;

    let seeded_files = if params.seed.unwrap_or(true) {
        seed_drive(&state, &public_key).await?
    } else {
        Vec::new()
    };

    let pat = GrantAuthService::from_context(&state.context)
        .mint_personal_access_token(user.id, client_id, capabilities, lifetime_secs)
        .await?;

    let origin = state
        .pkarr_icann_domain()
        .map(|domain| format!("http://{domain}"));

    Ok(Json(DemoUserResponse {
        basic_auth: basic_auth_value(&public_key.z32(), &pat.token),
        webdav_url: origin
            .as_ref()
            .map(|origin| format!("{origin}/dav/{}/", public_key.z32())),
        drive_url: origin
            .as_ref()
            .map(|origin| format!("{origin}/drive?user={}", public_key.z32())),
        public_key: public_key.z32(),
        secret_key: hex(&keypair.secret()),
        token: pat.token,
        grant_id: pat.grant_id.to_string(),
        expires_at: pat.expires_at,
        seeded_files,
    }))
}

/// Create the demo user through the ordinary signup path.
///
/// Signup goes through [`SignupService`] rather than the repository directly so
/// the user gets its initial quota and the whole thing stays transactional. On a
/// token-gated homeserver we mint the token we then spend — the admin password
/// already authorized this, so making the caller fetch one first would be
/// ceremony with no security value.
async fn create_user(
    state: &AppState,
    public_key: &PublicKey,
) -> HttpResult<crate::services::user_service::UserEntity> {
    let signup_token = if state.context.config_toml.general.signup_mode == SignupMode::TokenRequired
    {
        let code = SignupCode::random();
        SignupCodeRepository::create(
            &code,
            &UserQuota::default(),
            &mut state.context.sql_db.pool().into(),
        )
        .await?;
        Some(code)
    } else {
        None
    };

    Ok(SignupService::from_context(&state.context)
        .create_new_user(public_key, signup_token.as_ref())
        .await?)
}

/// Write [`SEED_FILES`] and the generated pubky.app tree into the new user's
/// drive, returning the paths written.
async fn seed_drive(state: &AppState, public_key: &PublicKey) -> HttpResult<Vec<String>> {
    let plain = SEED_FILES
        .iter()
        .map(|(path, content)| ((*path).to_string(), content.to_vec()));
    let social = pubky_app::seed_files(public_key)
        .into_iter()
        .map(|file| (file.path, file.body));

    let mut written = Vec::new();
    for (path, content) in plain.chain(social) {
        let storage_path = StoragePath::new(&path)
            .map_err(|e| HttpError::internal_server_and_log(format!("Seed path {path}: {e}")))?;
        let entry_path = EntryPath::new(public_key.clone(), storage_path);
        // `stream::iter` rather than `once` so the stream is `Unpin`.
        let body = stream::iter([Ok::<Bytes, WriteStreamError>(Bytes::from(content))]);

        state
            .context
            .file_service
            .write_stream(&entry_path, body)
            .await
            .map_err(|e| HttpError::internal_server_and_log(format!("Seed write {path}: {e}")))?;
        written.push(path);
    }

    Ok(written)
}

/// The value for an `Authorization: Basic` header, ready to paste.
fn basic_auth_value(username: &str, password: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    format!(
        "Basic {}",
        STANDARD.encode(format!("{username}:{password}"))
    )
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encodes_all_32_bytes_lowercase() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x0a;
        bytes[31] = 0xff;
        let encoded = hex(&bytes);

        assert_eq!(encoded.len(), 64);
        assert!(encoded.starts_with("0a"));
        assert!(encoded.ends_with("ff"));
        assert_eq!(Keypair::from_secret(&bytes).secret(), bytes);
    }

    #[test]
    fn basic_auth_value_is_a_pastable_header() {
        // base64("alice:secret")
        assert_eq!(
            basic_auth_value("alice", "secret"),
            "Basic YWxpY2U6c2VjcmV0"
        );
    }

    #[test]
    fn seed_files_are_valid_writable_storage_paths() {
        let mut seen = std::collections::HashSet::new();

        for (path, content) in SEED_FILES {
            let parsed = StoragePath::new(path).expect("seed path must be valid");
            assert!(parsed.is_file(), "{path} must not be directory-shaped");
            assert!(
                path.starts_with("/pub/") || path.starts_with("/priv/"),
                "{path} must live under a writable root"
            );
            assert!(!content.is_empty(), "{path} must not be empty");
            assert!(seen.insert(path), "{path} is seeded twice");
        }
    }

    #[test]
    fn seed_covers_both_roots_and_nests_deeply_enough_to_navigate() {
        // The demo exists to be browsed, so a flat public-only tree would
        // undersell it.
        assert!(SEED_FILES.iter().any(|(p, _)| p.starts_with("/pub/")));
        assert!(SEED_FILES.iter().any(|(p, _)| p.starts_with("/priv/")));

        let deepest = SEED_FILES
            .iter()
            .map(|(p, _)| p.matches('/').count())
            .max()
            .unwrap_or(0);
        assert!(
            deepest >= 4,
            "expected nested folders, deepest was {deepest}"
        );
    }

    #[test]
    fn seeded_images_are_real_pngs() {
        const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

        let images: Vec<_> = SEED_FILES
            .iter()
            .filter(|(path, _)| path.ends_with(".png"))
            .collect();
        assert!(!images.is_empty(), "the drive should contain real images");

        for (path, content) in images {
            assert!(content.starts_with(PNG_MAGIC), "{path} is not a PNG");
        }
    }

    #[test]
    fn defaults_parse() {
        let caps: Capabilities = DEFAULT_CAPABILITIES
            .parse()
            .expect("default capabilities must parse");
        assert!(caps.iter().any(|cap| cap.is_root()));
        ClientId::new(DEFAULT_CLIENT_ID).expect("default client id must be valid");
    }
}
