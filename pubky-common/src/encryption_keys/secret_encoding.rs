//! Encode secrets as base64url in JSON and fixed 32-byte arrays in Postcard.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub(super) fn serialize<S: serde::Serializer>(
    secret: &[u8; 32],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret));
        serializer.serialize_str(&encoded)
    } else {
        secret.serialize(serializer)
    }
}

pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Box<Zeroizing<[u8; 32]>>, D::Error> {
    if !deserializer.is_human_readable() {
        return Box::<Zeroizing<[u8; 32]>>::deserialize(deserializer);
    }
    let encoded = Zeroizing::new(String::deserialize(deserializer)?);
    let invalid = || serde::de::Error::custom("invalid base64url encryption secret");
    if encoded.len() != 43 {
        return Err(invalid());
    }
    let mut secret = Box::new(Zeroizing::new([0; 32]));
    let decoded_len = URL_SAFE_NO_PAD
        .decode_slice(encoded.as_bytes(), secret.as_mut().as_mut())
        .map_err(|_| invalid())?;
    if decoded_len != 32 {
        return Err(invalid());
    }
    Ok(secret)
}
