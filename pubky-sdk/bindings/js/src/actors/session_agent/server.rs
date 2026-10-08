//! Agent side: serve one grant-backed session to allowlisted origins.

use std::{cell::RefCell, rc::Rc};

use pubky::PubkySession;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use super::{AgentMethod, BearerParams, agent_failure, decode, encode, transport};
use crate::actors::session::Session;
use crate::actors::session_store::stored_session_id;
use crate::js_error::{JsResult, PubkyError, PubkyErrorName, js_error_message};

/// The session currently served, shared with the JS callbacks.
type ServedSession = Rc<RefCell<Option<PubkySession>>>;

/// `detail` of the SDK's `pubky-session-changed` event.
#[derive(Deserialize)]
struct SessionChange {
    id: Option<String>,
    action: String,
}

/// Agent-side server for one shared grant session.
///
/// Created with `pubky.serveSessionAgent(allowedOrigins)`. Call `setSession`
/// once the stored session is restored. The agent stops serving on its own
/// when the browser store removes that session (signout or removal from any
/// tab); `clearSession` does the same explicitly. `stop` detaches from
/// `window` events.
#[wasm_bindgen]
pub struct SessionAgent {
    stop: js_sys::Function,
    session: ServedSession,
    // Keep the JS callbacks alive for as long as the agent serves.
    _handler: Closure<dyn FnMut(JsValue, JsValue) -> js_sys::Promise>,
    _on_session_change: Closure<dyn FnMut(JsValue)>,
}

#[wasm_bindgen]
impl SessionAgent {
    /// Share `session` with connecting apps.
    #[wasm_bindgen(js_name = "setSession")]
    pub fn set_session(&self, session: &Session) {
        *self.session.borrow_mut() = Some(session.0.clone());
    }

    /// Stop sharing; connected apps fail on their next bearer request.
    #[wasm_bindgen(js_name = "clearSession")]
    pub fn clear_session(&self) {
        self.session.borrow_mut().take();
    }

    /// Whether a session is currently being served.
    #[wasm_bindgen(js_name = "hasSession", getter)]
    pub fn has_session(&self) -> bool {
        self.session.borrow().is_some()
    }

    /// Detach from `window` events. Existing connections get no more answers.
    #[wasm_bindgen]
    pub fn stop(&self) {
        let _ = self.stop.call0(&JsValue::NULL);
    }
}

pub(crate) fn serve(allowed_origins: Vec<String>) -> JsResult<SessionAgent> {
    for origin in &allowed_origins {
        validate_origin(origin)?;
    }
    let session: ServedSession = Rc::default();

    let served = session.clone();
    let handler = Closure::new(move |method: JsValue, params: JsValue| {
        let served = served.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            handle(method, params, served)
                .await
                .map_err(|error| JsValue::from(js_sys::Error::new(&error.to_string())))
        })
    });

    let served = session.clone();
    let on_session_change = Closure::new(move |detail: JsValue| {
        wasm_bindgen_futures::spawn_local(drop_if_removed(detail, served.clone()));
    });

    let origins = allowed_origins.iter().map(JsValue::from).collect();
    let stop = transport::serve(origins, handler.as_ref(), on_session_change.as_ref()).map_err(
        |error| {
            PubkyError::new(
                PubkyErrorName::ClientStateError,
                js_error_message(&error, "Serving a session agent failed."),
            )
        },
    )?;
    Ok(SessionAgent {
        stop,
        session,
        _handler: handler,
        _on_session_change: on_session_change,
    })
}

/// Allowed origins must match `event.origin` exactly, so accept nothing but
/// the serialized origin form (no path, no trailing slash, no default port).
fn validate_origin(origin: &str) -> JsResult<()> {
    let serialized = url::Url::parse(origin)
        .map(|url| url.origin().ascii_serialization())
        .map_err(|error| {
            PubkyError::new(
                PubkyErrorName::InvalidInput,
                format!("Invalid allowed origin `{origin}`: {error}"),
            )
        })?;
    if serialized != origin {
        return Err(PubkyError::new(
            PubkyErrorName::InvalidInput,
            format!("Allowed origin `{origin}` must be written as `{serialized}`."),
        ));
    }
    Ok(())
}

/// Answer one request from a connected app.
async fn handle(method: JsValue, params: JsValue, served: ServedSession) -> pubky::Result<JsValue> {
    let current = served.borrow().clone();
    match decode::<AgentMethod>(method)? {
        AgentMethod::Session => match current {
            None => Ok(JsValue::NULL),
            Some(session) => encode(&grant(&session)?.bearer_for_remote(None).await?),
        },
        AgentMethod::Bearer => {
            let session = current.ok_or_else(no_session)?;
            let BearerParams { rejected } = decode(params)?;
            encode(
                &grant(&session)?
                    .bearer_for_remote(rejected.as_deref())
                    .await?,
            )
        }
        AgentMethod::Signout => {
            let session = current.ok_or_else(no_session)?;
            session.signout().await.map_err(|(error, _)| error)?;
            served.borrow_mut().take();
            Ok(JsValue::NULL)
        }
    }
}

/// Stop serving a session whose browser record another tab removed.
async fn drop_if_removed(detail: JsValue, served: ServedSession) {
    let Ok(change) = decode::<SessionChange>(detail) else {
        return;
    };
    let current = served.borrow().clone();
    let Some(session) = current else {
        return;
    };
    let removed = match change.action.as_str() {
        "cleared" => true,
        "removed" => match grant(&session) {
            Ok(grant) => {
                change.id.as_deref() == Some(&stored_session_id(&grant.session_info().await))
            }
            Err(_) => false,
        },
        _ => false,
    };
    if removed {
        served.borrow_mut().take();
    }
}

fn grant(session: &PubkySession) -> pubky::Result<pubky::GrantSessionView<'_>> {
    session
        .as_grant()
        .ok_or_else(|| agent_failure("Session agent can only share grant-backed sessions."))
}

fn no_session() -> pubky::Error {
    agent_failure("Session agent holds no session.")
}
