//! A browser file explorer for a user's drive.
//!
//! `GET /drive` serves a self-contained page that signs in with a public key
//! and token and then talks to [`/dav`](super::dav) to browse, preview, upload
//! and delete.
//!
//! It is served from the homeserver on purpose. The `/dav` endpoint sets no
//! CORS headers — a browser preflight there is answered before credentials are
//! even read — so a page hosted anywhere else could not call it. Served from
//! here, its requests are same-origin and CORS never applies.
//!
//! The page holds no state of its own: it is one static asset, and every
//! listing, read and write is a WebDAV request the user's own token authorizes.
use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
};

/// The explorer, inlined at compile time so the binary stays self-contained.
const DRIVE_HTML: &str = include_str!("drive.html");

/// `GET /drive` — the file explorer.
pub(crate) async fn get() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // The page is a versioned asset but carries no user data; revalidate
            // so an upgraded homeserver never serves a stale explorer.
            (header::CACHE_CONTROL, "no-cache"),
            // It only ever talks to its own origin.
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; img-src 'self' blob: data:; \
                 style-src 'unsafe-inline'; script-src 'unsafe-inline'; \
                 connect-src 'self'; form-action 'none'; frame-ancestors 'none'",
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        DRIVE_HTML,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_is_self_contained_and_same_origin() {
        // Every byte ships with the binary: an external stylesheet, script or
        // font would be a request the CSP above blocks anyway.
        assert!(
            !DRIVE_HTML.contains("http://"),
            "page must not load over http"
        );
        assert!(
            !DRIVE_HTML.contains("https://"),
            "page must not reference external origins"
        );
        // It reaches the drive through the relative WebDAV path.
        assert!(DRIVE_HTML.contains("\"/dav/\""));
    }

    #[test]
    fn page_has_the_sign_in_fields_it_advertises() {
        for id in ["id=\"key\"", "id=\"token\"", "id=\"signin-form\""] {
            assert!(DRIVE_HTML.contains(id), "missing {id}");
        }
    }
}
