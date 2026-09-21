use reqwest::Response;

use super::core::{PublicStorage, SessionStorage};
use super::resource::{IntoPubkyResource, IntoResourcePath};
use crate::Result;

//
// SessionStorage (as-me)
//

impl SessionStorage {
    /// GET and deserialize JSON from an **absolute path**.
    ///
    /// Sets `Accept: application/json` and returns `T` via `resp.json()`.
    ///
    /// *Requires the **`json`** crate feature.*
    ///
    /// # Errors
    /// Missing resources (404 or 410) are server errors. Reading the response body
    /// or deserializing invalid JSON (including a mismatch with `T`) can also
    /// fail with [`crate::Error::Request`]. See [`SessionStorage`] for shared
    /// path, credential, transport, and HTTP failures.
    pub async fn get_json<P, T>(&self, path: P) -> Result<T>
    where
        P: IntoResourcePath + Send,
        T: serde::de::DeserializeOwned,
    {
        let resp = self
            .request(reqwest::Method::GET, path)
            .await?
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        let resp = self.client.check_http_status(resp).await?;
        Ok(resp.json::<T>().await?)
    }

    /// PUT JSON to an **absolute path** and return the raw `Response`.
    ///
    /// Serializes `body` as JSON and creates or replaces a file. Requires write
    /// permission; directory targets are unsupported.
    ///
    /// *Requires the **`json`** crate feature.*
    ///
    /// # Errors
    /// Serialization and request-body failures return [`crate::Error::Request`].
    /// See [`Self::put`] for write-specific server errors and [`SessionStorage`]
    /// for shared path, credential, transport, and HTTP failures.
    pub async fn put_json<P, B>(&self, path: P, body: &B) -> Result<Response>
    where
        P: IntoResourcePath + Send,
        B: serde::Serialize + Sync + ?Sized,
    {
        let resp = self
            .request(reqwest::Method::PUT, path)
            .await?
            .json(body)
            .send()
            .await?;
        self.client.check_http_status(resp).await
    }
}

//
// PublicStorage (read-only)
//

impl PublicStorage {
    /// GET and deserialize JSON from an **addressed resource**.
    ///
    /// *Requires the **`json`** crate feature.*
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Parse`] if `addr` cannot be converted into a valid addressed resource.
    /// - Propagates transport failures or JSON deserialization errors from the underlying HTTP request.
    pub async fn get_json<A, T>(&self, addr: A) -> Result<T>
    where
        A: IntoPubkyResource + Send,
        T: serde::de::DeserializeOwned,
    {
        let resp = self
            .request(reqwest::Method::GET, addr)
            .await?
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?;
        let resp = self.client.check_http_status(resp).await?;
        Ok(resp.json::<T>().await?)
    }
}
