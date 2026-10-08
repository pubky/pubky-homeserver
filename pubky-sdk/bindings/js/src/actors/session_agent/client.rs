//! App side: a [`RemoteBearerProvider`] that forwards to the agent frame.

use std::sync::Arc;

use pubky::RemoteBearerProvider;
use pubky_common::auth::grant_session_responses::GrantSessionResponse;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

use super::{AgentMethod, SessionAgentOptions, agent_error, decode, encode, transport};
use crate::actors::session::Session;
use crate::js_error::{JsResult, PubkyError, PubkyErrorName, js_error_message};

const DEFAULT_CONNECT_TIMEOUT_MS: f64 = 5_000.0;

/// One accepted connection to an agent frame. Dropping it closes the port.
#[derive(Debug)]
struct AgentProvider {
    token: u32,
}

impl AgentProvider {
    async fn request<T>(
        &self,
        method: AgentMethod,
        params: &impl serde::Serialize,
    ) -> pubky::Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let value = JsFuture::from(transport::request(
            self.token,
            encode(&method)?,
            encode(params)?,
        ))
        .await
        .map_err(agent_error)?;
        decode(value)
    }

    /// The agent's current session, or `None` when nobody is signed in there.
    async fn current_session(&self) -> pubky::Result<Option<GrantSessionResponse>> {
        self.request(AgentMethod::Session, &()).await
    }
}

impl Drop for AgentProvider {
    fn drop(&mut self) {
        transport::close(self.token);
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
impl RemoteBearerProvider for AgentProvider {
    async fn bearer(&self, rejected: Option<&str>) -> pubky::Result<GrantSessionResponse> {
        let params = super::BearerParams {
            rejected: rejected.map(str::to_owned),
        };
        self.request(AgentMethod::Bearer, &params).await
    }

    async fn signout(&self) -> pubky::Result<()> {
        self.request(AgentMethod::Signout, &()).await
    }
}

// Native workspace checks compile the bindings, but cannot call browser APIs.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl RemoteBearerProvider for AgentProvider {
    async fn bearer(&self, _: Option<&str>) -> pubky::Result<GrantSessionResponse> {
        Err(super::agent_failure(
            "Session agents require a WASM browser build.",
        ))
    }

    async fn signout(&self) -> pubky::Result<()> {
        Err(super::agent_failure(
            "Session agents require a WASM browser build.",
        ))
    }
}

/// Connect to a session agent and build a session from the bearer it serves.
///
/// Returns `None` when the agent answers but holds no session.
pub(crate) async fn connect(
    client: pubky::PubkyHttpClient,
    agent_url: &str,
    options: SessionAgentOptions,
) -> JsResult<Option<Session>> {
    let timeout = options.timeout_ms.unwrap_or(DEFAULT_CONNECT_TIMEOUT_MS);
    let token = JsFuture::from(transport::connect_frame(agent_url, timeout))
        .await
        .map_err(connect_error)?
        .as_f64()
        .ok_or_else(|| {
            PubkyError::new(
                PubkyErrorName::InternalError,
                "Session agent connect returned no token.",
            )
        })? as u32;
    let provider = Arc::new(AgentProvider { token });
    let Some(current) = provider.current_session().await? else {
        return Ok(None);
    };
    let credential = pubky::RemoteBearerCredential::new(provider, current);
    let session = pubky::PubkySession::from_remote_bearer(client, credential);
    Ok(Some(Session(session)))
}

fn connect_error(value: JsValue) -> PubkyError {
    PubkyError::new(
        PubkyErrorName::ClientStateError,
        js_error_message(&value, "Connecting to the session agent failed."),
    )
}
