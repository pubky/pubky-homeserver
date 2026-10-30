use futures_util::future::{Either, select};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{AbortController, AbortSignal};

use super::{GrantRevocation, GrantRevocationError, MAX_RECEIPT_BYTES, PATH};

// Fetch must reject redirects before forwarding authority; reqwest's WASM
// request builder does not expose the redirect policy.
#[wasm_bindgen(inline_js = r#"
export function pubkyWatchAbort(signal) {
    let abort;
    const promise = new Promise(resolve => {
        abort = () => resolve();
        signal.addEventListener('abort', abort, { once: true });
        if (signal.aborted) abort();
    });
    return { promise, remove() { signal.removeEventListener('abort', abort); } };
}
export async function pubkyRevokeOnce(url, bearer, owner, body, controller, externalSignal, limit) {
    const abort = () => controller.abort();
    if (externalSignal) {
        if (externalSignal.aborted) { abort(); throw new Error("Cancelled before dispatch"); }
        externalSignal.addEventListener('abort', abort, { once: true });
    }
    let reader;
    let status;
    try {
        const response = await globalThis.fetch(url, {
            method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store',
            headers: { authorization: `Bearer ${bearer}`, 'pubky-host': owner,
                       'content-type': 'application/json' },
            body, signal: controller.signal
        });
        status = response.status;
        if (status !== 200) throw status;
        reader = response.body.getReader();
        const chunks = [];
        let length = 0;
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            if (value.byteLength > limit - length) throw 200;
            length += value.byteLength;
            chunks.push(value);
        }
        const bytes = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (error) {
        throw status === undefined ? error : status;
    } finally {
        if (reader) { try { await reader.cancel(); } catch (_) {} reader.releaseLock(); }
        if (externalSignal) externalSignal.removeEventListener('abort', abort);
    }
}
"#)]
extern "C" {
    type AbortWait;
    #[wasm_bindgen(js_name = pubkyWatchAbort)]
    fn watch_abort(signal: &AbortSignal) -> AbortWait;
    #[wasm_bindgen(method, getter)]
    fn promise(this: &AbortWait) -> js_sys::Promise;
    #[wasm_bindgen(method)]
    fn remove(this: &AbortWait);

    #[wasm_bindgen(js_name = pubkyRevokeOnce)]
    fn send_once(
        url: &str,
        bearer: &str,
        owner: &str,
        body: &str,
        controller: &AbortController,
        external_signal: Option<&AbortSignal>,
        limit: usize,
    ) -> js_sys::Promise;
}

struct AbortListener(AbortWait);
impl Drop for AbortListener {
    fn drop(&mut self) {
        self.0.remove();
    }
}

struct AbortOnDrop(AbortController);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) async fn send(
    operation: &GrantRevocation,
    external: Option<AbortSignal>,
) -> Result<Vec<u8>, GrantRevocationError> {
    let unknown = GrantRevocationError::Unacknowledged { status: None };
    if external.as_ref().is_some_and(AbortSignal::aborted) {
        return Err(unknown);
    }
    let listener = external
        .as_ref()
        .map(|signal| AbortListener(watch_abort(signal)));
    let prepare = operation
        .client
        .homeserver_mutation_url(&operation.homeserver, PATH);
    let prepared = if let Some(listener) = &listener {
        match select(
            Box::pin(prepare),
            Box::pin(JsFuture::from(listener.0.promise())),
        )
        .await
        {
            Either::Left((result, _)) => result,
            Either::Right(_) => return Err(unknown),
        }
    } else {
        prepare.await
    };
    let url = prepared.map_err(|_error| GrantRevocationError::Preparation)?;
    let controller =
        AbortOnDrop(AbortController::new().map_err(|_error| GrantRevocationError::Preparation)?);
    let body = serde_json::to_string(&operation.binding)
        .map_err(|_error| GrantRevocationError::Preparation)?;
    let response = JsFuture::from(send_once(
        url.as_str(),
        operation.bearer.as_str(),
        &operation.binding.pubky.z32(),
        &body,
        &controller.0,
        external.as_ref(),
        MAX_RECEIPT_BYTES,
    ))
    .await
    .map_err(|error| GrantRevocationError::Unacknowledged {
        status: observed_status(&error),
    })?;
    response
        .as_string()
        .map(String::into_bytes)
        .ok_or(GrantRevocationError::Unacknowledged { status: Some(200) })
}

// JavaScript rejects with a number only after observing an HTTP response.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "range and integer checks precede the narrowing conversion"
)]
fn observed_status(error: &JsValue) -> Option<u16> {
    error
        .as_f64()
        .filter(|status| status.fract() == 0.0 && (100.0..=599.0).contains(status))
        .map(|status| status as u16)
}
