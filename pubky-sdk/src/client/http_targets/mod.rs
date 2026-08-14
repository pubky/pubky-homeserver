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
