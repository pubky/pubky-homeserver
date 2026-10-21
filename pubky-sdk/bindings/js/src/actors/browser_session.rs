//! Web Locks and IndexedDB backing for shared grant credentials.

use pubky::{GrantSessionCoordinator, GrantSessionLease, SharedGrantSession};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

use super::session_store::{js_session_acquire, js_session_release, js_session_wait, store_error};
#[cfg(target_arch = "wasm32")]
use super::session_store::{js_shared_load, js_shared_remove, js_shared_store};

#[derive(Debug)]
pub(crate) struct BrowserSessionCoordinator {
    id: String,
    homeserver: String,
}

impl BrowserSessionCoordinator {
    pub(crate) fn new(id: &str, homeserver: &str) -> Self {
        Self {
            id: id.into(),
            homeserver: homeserver.into(),
        }
    }

    pub(crate) async fn acquire_browser(
        &self,
        exclusive: bool,
    ) -> pubky::Result<BrowserSessionLease> {
        let token =
            js_session_acquire(&self.id, &self.homeserver, exclusive).map_err(browser_error)?;
        // Drop cancels a queued acquisition as well as releasing a held lock.
        let lease = BrowserSessionLease { token };
        JsFuture::from(js_session_wait(token))
            .await
            .map_err(browser_error)?;
        Ok(lease)
    }
}

#[derive(Debug)]
pub(crate) struct BrowserSessionLease {
    pub(crate) token: u32,
}

impl Drop for BrowserSessionLease {
    fn drop(&mut self) {
        js_session_release(self.token);
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
impl GrantSessionCoordinator for BrowserSessionCoordinator {
    async fn acquire(&self, exclusive: bool) -> pubky::Result<Box<dyn GrantSessionLease>> {
        Ok(Box::new(self.acquire_browser(exclusive).await?))
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
impl GrantSessionLease for BrowserSessionLease {
    async fn load(&self) -> pubky::Result<Option<SharedGrantSession>> {
        let value = JsFuture::from(js_shared_load(self.token))
            .await
            .map_err(browser_error)?;
        if value.is_undefined() {
            return Ok(None);
        }
        serde_wasm_bindgen::from_value(value)
            .map(Some)
            .map_err(|error| {
                pubky::errors::AuthError::Validation(format!(
                    "Invalid shared browser session: {error}"
                ))
                .into()
            })
    }

    async fn store(&self, session: &SharedGrantSession) -> pubky::Result<()> {
        let value = serde_wasm_bindgen::to_value(session).map_err(|error| {
            pubky::errors::AuthError::Validation(format!("Invalid shared browser session: {error}"))
        })?;
        JsFuture::from(js_shared_store(self.token, value))
            .await
            .map_err(browser_error)?;
        Ok(())
    }

    async fn remove(&self) -> pubky::Result<()> {
        JsFuture::from(js_shared_remove(self.token))
            .await
            .map_err(browser_error)?;
        Ok(())
    }
}

fn browser_error(error: JsValue) -> pubky::Error {
    pubky::errors::AuthError::Validation(store_error(error).message).into()
}

// Native workspace checks compile the bindings, but cannot call browser APIs.
#[cfg(not(target_arch = "wasm32"))]
fn browser_required() -> pubky::Error {
    pubky::errors::AuthError::Validation("Shared sessions require a WASM browser build.".into())
        .into()
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl GrantSessionCoordinator for BrowserSessionCoordinator {
    async fn acquire(&self, _: bool) -> pubky::Result<Box<dyn GrantSessionLease>> {
        Err(browser_required())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl GrantSessionLease for BrowserSessionLease {
    async fn load(&self) -> pubky::Result<Option<SharedGrantSession>> {
        Err(browser_required())
    }
    async fn store(&self, _: &SharedGrantSession) -> pubky::Result<()> {
        Err(browser_required())
    }
    async fn remove(&self) -> pubky::Result<()> {
        Err(browser_required())
    }
}
