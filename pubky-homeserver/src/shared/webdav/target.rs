//! What a `/dav` URL names: which drive, and where inside it.
use percent_encoding::percent_decode_str;
use pubky_common::crypto::PublicKey;

use crate::constants::PUBLIC_ROOT;
use crate::shared::{
    webdav::{endpoint::DAV_PREFIX, StoragePath},
    HttpError,
};

/// A parsed `/dav/{user_z32}/...` request path.
pub(crate) struct DavTarget {
    tenant: PublicKey,
    path: StoragePath,
}

impl DavTarget {
    /// Parse a `/dav/...` URL path into its drive and the path within it.
    ///
    /// The drive segment is taken before the path is canonicalized, so `..`
    /// is judged by where it lands *inside* the drive and can never climb into
    /// another one: a path that tries is malformed, not a different drive.
    pub(crate) fn parse(uri_path: &str) -> Result<Self, HttpError> {
        let decoded = percent_decode_str(uri_path)
            .decode_utf8()
            .map_err(|_| HttpError::bad_request("WebDAV path is not valid UTF-8"))?;

        let (tenant, path) = decoded
            .strip_prefix(DAV_PREFIX)
            .and_then(|rest| rest.strip_prefix('/'))
            .map(|rest| rest.split_once('/').unwrap_or((rest, "")))
            .filter(|(tenant, _)| !tenant.is_empty())
            .ok_or_else(|| HttpError::bad_request("WebDAV paths are `/dav/{user}/...`"))?;

        let tenant = PublicKey::try_from_z32(tenant)
            .map_err(|e| HttpError::bad_request(format!("Invalid user in WebDAV path: {e}")))?;
        let path = StoragePath::normalize(&format!("/{path}"))
            .map_err(|e| HttpError::bad_request(format!("Invalid WebDAV path: {e}")))?;

        Ok(Self { tenant, path })
    }

    /// The drive this names.
    pub(crate) fn tenant(&self) -> &PublicKey {
        &self.tenant
    }

    /// Whether this names the public folder or something inside it.
    ///
    /// The folder itself counts with or without its trailing slash, since
    /// clients spell the thing they mount both ways.
    pub(crate) fn is_public(&self) -> bool {
        let path = self.path.as_str();
        path.starts_with(PUBLIC_ROOT) || path == PUBLIC_ROOT.trim_end_matches('/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, response::IntoResponse};
    use pubky_common::crypto::Keypair;

    fn status(result: Result<DavTarget, HttpError>) -> StatusCode {
        result
            .err()
            .expect("expected a rejection")
            .into_response()
            .status()
    }

    fn is_public(path: &str) -> bool {
        DavTarget::parse(path)
            .unwrap_or_else(|e| panic!("{path} should parse: {e:?}"))
            .is_public()
    }

    #[test]
    fn the_public_folder_and_everything_in_it_is_public() {
        let z32 = Keypair::random().public_key().z32();

        for path in [
            format!("/dav/{z32}/pub/"),
            format!("/dav/{z32}/pub"),
            format!("/dav/{z32}/pub/notes/a.txt"),
            format!("/dav/{z32}/pub/deep/nested/dir/"),
        ] {
            assert!(is_public(&path), "{path} should be public");
        }
    }

    #[test]
    fn nothing_outside_the_public_folder_is_public() {
        let z32 = Keypair::random().public_key().z32();

        for path in [
            // The drive root would list `/priv/` alongside `/pub/`.
            format!("/dav/{z32}"),
            format!("/dav/{z32}/"),
            format!("/dav/{z32}/priv/"),
            format!("/dav/{z32}/priv/secret.txt"),
            format!("/dav/{z32}/.DS_Store"),
            // A traversal that climbs out of the public folder lands outside it.
            format!("/dav/{z32}/pub/../priv/secret.txt"),
            format!("/dav/{z32}/pub/%2e%2e/priv/secret.txt"),
            // A name that merely starts with `pub` is not the public folder.
            format!("/dav/{z32}/public/x"),
            format!("/dav/{z32}/pubx"),
        ] {
            assert!(!is_public(&path), "{path} should not be public");
        }
    }

    #[test]
    fn a_path_that_climbs_out_of_its_drive_is_malformed() {
        // The drive is fixed before the path is canonicalized, so `..` can
        // never reach another drive or the storage root — it is simply a
        // traversal above the root of this one.
        let z32 = Keypair::random().public_key().z32();
        let other = Keypair::random().public_key().z32();

        for path in [
            format!("/dav/{z32}/../{other}/pub/file.txt"),
            format!("/dav/{z32}/../../etc/passwd"),
            format!("/dav/{z32}/pub/%2e%2e/%2e%2e/{other}/pub/x"),
        ] {
            assert_eq!(
                status(DavTarget::parse(&path)),
                StatusCode::BAD_REQUEST,
                "{path} should be rejected"
            );
        }
    }

    #[test]
    fn paths_that_do_not_name_a_drive_are_rejected() {
        for path in [
            "/storage/whatever",
            "/dav",
            "/dav/",
            "/davos/x",
            "/dav/not-a-pubkey/pub/",
        ] {
            assert_eq!(
                status(DavTarget::parse(path)),
                StatusCode::BAD_REQUEST,
                "{path} should not parse"
            );
        }
    }
}
