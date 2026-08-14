use wasm_bindgen::prelude::*;

use crate::js_error::JsResult;
use crate::wrappers::keys::{Keypair, PublicKey};

/// Resolve/publish `_pubky` PKDNS records (homeserver pointers).
#[wasm_bindgen]
pub struct Pkdns(pub(crate) pubky::Pkdns);

#[wasm_bindgen]
impl Pkdns {
    /// Read-only PKDNS actor (no keypair; resolve only).
    #[wasm_bindgen(constructor)]
    pub fn new() -> JsResult<Pkdns> {
        Ok(Pkdns(pubky::Pkdns::new()?))
    }

    /// PKDNS actor with publishing enabled (requires a keypair).
    #[wasm_bindgen(js_name = "fromKeypair")]
    pub fn from_keypair(keypair: &Keypair) -> JsResult<Pkdns> {
        Ok(Pkdns(pubky::Pkdns::new_with_keypair(
            keypair.as_inner().clone(),
        )?))
    }

    // -------------------- Reads --------------------

    /// Resolve the homeserver for a given public key (read-only).
    ///
    /// @param {PublicKey} user
    /// @returns {Promise<PublicKey|undefined>} Homeserver public key, or `undefined` when the
    ///   user has no resolvable homeserver record.
    /// @throws When Pkarr resolution fails or a resolved `_pubky` target is malformed.
    #[wasm_bindgen(js_name = "getHomeserverOf")]
    pub async fn get_homeserver_of(&self, pubky: &PublicKey) -> JsResult<Option<PublicKey>> {
        Ok(self
            .0
            .get_homeserver_of(pubky.as_inner())
            .await?
            .map(Into::into))
    }

    /// Resolve the homeserver for **this** user (requires keypair).
    ///
    /// @returns {Promise<PublicKey|undefined>} Homeserver public key or `undefined` if not found.
    /// @throws When no keypair is attached, Pkarr resolution fails, or a resolved `_pubky` target
    ///   is malformed.
    #[wasm_bindgen(js_name = "getHomeserver")]
    pub async fn get_homeserver(&self) -> JsResult<Option<PublicKey>> {
        Ok(self.0.get_homeserver().await?.map(Into::into))
    }

    // -------------------- Publishing --------------------

    /// Force publish homeserver immediately (even if fresh).
    ///
    /// Requires keypair or to be signer bound.
    ///
    /// @param {PublicKey=} overrideHost Optional new homeserver to publish (migration).
    /// @returns {Promise<void>}
    #[wasm_bindgen(js_name = "publishHomeserverForce")]
    pub async fn publish_homeserver_force(&self, host_override: Option<PublicKey>) -> JsResult<()> {
        let host_ref = host_override.as_ref().map(|h| h.as_inner());
        self.0.publish_homeserver_force(host_ref).await?;
        Ok(())
    }

    /// Republish homeserver if record is missing/stale.
    ///
    /// Requires keypair or to be signer bound.
    ///
    /// @param {PublicKey=} overrideHost Optional new homeserver to publish (migration).
    /// @returns {Promise<void>}
    #[wasm_bindgen(js_name = "publishHomeserverIfStale")]
    pub async fn publish_homeserver_if_stale(
        &self,
        host_override: Option<PublicKey>,
    ) -> JsResult<()> {
        let host_ref = host_override.as_ref().map(|h| h.as_inner());
        self.0.publish_homeserver_if_stale(host_ref).await?;
        Ok(())
    }
}

impl From<pubky::Pkdns> for Pkdns {
    fn from(inner: pubky::Pkdns) -> Self {
        Pkdns(inner)
    }
}
