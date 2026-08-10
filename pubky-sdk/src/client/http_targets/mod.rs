use crate::{PublicKey, Result};
use url::Url;

#[cfg(not(target_arch = "wasm32"))]
pub mod native;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

fn homeserver_url(homeserver: &PublicKey, path: &str) -> Result<Url> {
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Ok(Url::parse(&format!(
        "https://{}{}",
        homeserver.z32(),
        path
    ))?)
}

pub(crate) fn user_endpoint_url(user: &PublicKey, path: &str) -> Result<Url> {
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Ok(Url::parse(&format!(
        "https://_pubky.{}{}",
        user.z32(),
        path
    ))?)
}

#[inline]
fn is_path_addressed_storage(url: &Url) -> bool {
    url.path().starts_with("/storage/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_only_path_addressed_storage_routes() {
        assert!(is_path_addressed_storage(
            &Url::parse("https://example.com/storage/user/pub/file.txt").unwrap()
        ));
        assert!(!is_path_addressed_storage(
            &Url::parse("https://example.com/storage-user/pub/file.txt").unwrap()
        ));
        assert!(!is_path_addressed_storage(
            &Url::parse("https://example.com/session").unwrap()
        ));
    }

    #[test]
    fn user_endpoints_keep_authority_addressing() {
        let user = crate::Keypair::random().public_key();
        let url = user_endpoint_url(&user, "/auth/grant/session").unwrap();
        let expected_host = format!("_pubky.{}", user.z32());

        assert_eq!(url.host_str(), Some(expected_host.as_str()));
        assert_eq!(url.path(), "/auth/grant/session");
    }
}
