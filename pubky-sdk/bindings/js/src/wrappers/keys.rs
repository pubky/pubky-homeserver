use wasm_bindgen::prelude::*;

use crate::js_error::{JsResult, PubkyError, PubkyErrorName};
use js_sys::Uint8Array;
use pubky::{Keypair as NativeKeypair, PublicKey as NativePublicKey};

#[wasm_bindgen]
pub struct Keypair(NativeKeypair);

#[wasm_bindgen]
impl Keypair {
    #[wasm_bindgen]
    /// Generate a random [Keypair]
    pub fn random() -> Self {
        Self(NativeKeypair::random())
    }

    /// Generate a [Keypair] from a 32-byte secret.
    #[wasm_bindgen(js_name = "fromSecret")]
    pub fn from_secret(secret: Vec<u8>) -> Result<Keypair, JsValue> {
        let secret_len = secret.len();
        let secret: [u8; 32] = secret
            .try_into()
            .map_err(|_| format!("Expected secret to be 32 bytes, got {}", secret_len))?;
        Ok(Self(NativeKeypair::from_secret(&secret)))
    }

    /// Returns the secret of this keypair.
    #[wasm_bindgen(js_name = "secret")]
    pub fn secret(&self) -> Uint8Array {
        Uint8Array::from(self.0.secret_key().as_ref())
    }

    /// Returns the [PublicKey] of this keypair.
    ///
    /// Use `.toString()` or `.z32()` on the returned `PublicKey` to get its z-base32 encoding.
    ///
    /// @example
    /// const who = keypair.publicKey.toString();
    #[wasm_bindgen(js_name = "publicKey", getter)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    /// Create a recovery file for this keypair (encrypted with the given passphrase).
    #[wasm_bindgen(js_name = "createRecoveryFile")]
    pub fn create_recovery_file(&self, passphrase: &str) -> Uint8Array {
        pubky_common::recovery_file::create_recovery_file(&self.0, passphrase)
            .as_slice()
            .into()
    }

    /// Decrypt a recovery file and return a Keypair (decrypted with the given passphrase).
    #[wasm_bindgen(js_name = "fromRecoveryFile")]
    pub fn from_recovery_file(recovery_file: &[u8], passphrase: &str) -> JsResult<Keypair> {
        let keypair =
            pubky_common::recovery_file::decrypt_recovery_file(recovery_file, passphrase)?;
        Ok(Keypair::from(keypair))
    }
}

impl Keypair {
    pub fn as_inner(&self) -> &NativeKeypair {
        &self.0
    }
}

impl From<NativeKeypair> for Keypair {
    fn from(keypair: NativeKeypair) -> Self {
        Self(keypair)
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct PublicKey(pub(crate) NativePublicKey);

#[wasm_bindgen]
impl PublicKey {
    /// Convert the PublicKey to Uint8Array
    #[wasm_bindgen(js_name = "toUint8Array")]
    pub fn to_uint8array(&self) -> Uint8Array {
        Uint8Array::from(self.0.as_inner().as_bytes().as_ref())
    }

    #[wasm_bindgen]
    /// Returns the z-base32 encoding of this public key
    pub fn z32(&self) -> String {
        self.0.z32()
    }

    #[wasm_bindgen(js_name = "toString")]
    /// Returns the canonical z-base32 encoding.
    pub fn to_string_js(&self) -> String {
        self.0.to_string()
    }

    #[wasm_bindgen(js_name = "from")]
    /// @throws
    pub fn try_from(value: String) -> JsResult<PublicKey> {
        if value.starts_with("pubky://") {
            return Err(PubkyError::new(
                PubkyErrorName::InvalidInput,
                "public key must be raw z32 or legacy pubky<z32>; pubky:// is not supported",
            ));
        }
        let value = if NativePublicKey::is_pubky_prefixed(&value) {
            value
                .strip_prefix("pubky")
                .unwrap_or(value.as_str())
                .to_string()
        } else {
            value
        };
        let native_pk = NativePublicKey::try_from(value)?;
        Ok(PublicKey(native_pk))
    }
}

impl PublicKey {
    pub fn as_inner(&self) -> &NativePublicKey {
        &self.0
    }
}

impl From<NativePublicKey> for PublicKey {
    fn from(value: NativePublicKey) -> Self {
        PublicKey(value)
    }
}
