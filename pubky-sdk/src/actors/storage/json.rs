use reqwest::Response;

use super::core::{PublicStorage, SessionStorage};
use super::resource::{IntoPubkyResource, IntoResourcePath};
use crate::Result;
use crate::util::check_http_status;

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
    /// - Returns [`crate::errors::Error::Parse`] if `path` cannot be converted into a valid resource path.
    /// - Propagates transport failures or JSON deserialization errors from the underlying HTTP request.
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
        let resp = check_http_status(resp).await?;
        Ok(resp.json::<T>().await?)
    }

    /// PUT JSON to an **absolute path** and return the raw `Response`.
    ///
    /// Serializes `body` as JSON.
    ///
    /// *Requires the **`json`** crate feature.*
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Parse`] if `path` cannot be converted into a valid resource path.
    /// - Propagates transport failures or serialization errors encountered while sending the request.
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
        check_http_status(resp).await
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
        let resp = check_http_status(resp).await?;
        Ok(resp.json::<T>().await?)
    }
}
