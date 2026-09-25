//! Keep a tab's session ID across reloads and detect copies in other tabs.
use pubky_common::auth::jws::RandomId;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::js_error::{JsResult, PubkyError, PubkyErrorName};

#[wasm_bindgen(inline_js = r#"
const slots = new Map();

// A lifetime Web Lock detects sessionStorage copied by Duplicate Tab/window.open.
// Browsers release the lock when the document is destroyed, including on reload.
function claim(scope, id) {
  return new Promise((resolve, reject) => {
    navigator.locks.request(`pubky-session:${scope}:${id}`, { ifAvailable: true }, lock => {
      resolve(!!lock);
      if (lock) return new Promise(() => {});
    }).catch(reject);
  });
}

export async function __pubkyBrowserSessionSlot(scope, proposed) {
  if (!globalThis.navigator?.locks || !globalThis.sessionStorage) {
    throw new Error("Browser session restore requires Web Locks and sessionStorage in a secure context.");
  }
  if (slots.has(scope)) return slots.get(scope);
  // BrowserSessionStore's mutex serializes calls, including lock acquisition.
  const key = `pubky-session-slot:${scope}`;
  const saved = sessionStorage.getItem(key);
  let id = saved && /^[A-Za-z0-9_-]{22}$/.test(saved) ? saved : proposed;
  if (!await claim(scope, id)) {
    // Another document owns the copied ID. Try the caller's proposed ID.
    id = proposed;
    if (!await claim(scope, id)) throw new Error("Browser session slot is already owned by another tab.");
  }
  sessionStorage.setItem(key, id);
  slots.set(scope, id);
  return id;
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = __pubkyBrowserSessionSlot)]
    fn js_slot(scope: &str, proposed: &str) -> js_sys::Promise;
}

pub(crate) async fn session_id(scope: &str, proposed: Option<RandomId>) -> JsResult<RandomId> {
    let proposed = proposed.unwrap_or_else(RandomId::generate);
    let result = JsFuture::from(js_slot(scope, &proposed.to_string()))
        .await
        .map_err(super::session_store::store_error)?;
    let id = result.as_string().unwrap_or_default();
    RandomId::parse(&id)
        .map_err(|error| PubkyError::new(PubkyErrorName::ClientStateError, error.to_string()))
}
