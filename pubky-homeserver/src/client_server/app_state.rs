use std::sync::Arc;

use axum::extract::FromRef;

use crate::client_server::auth::AuthState;
use crate::AppContext;

#[derive(Clone)]
pub(crate) struct AppState {
    /// Auth sub-state (extracted via `FromRef` by auth handlers).
    pub(crate) auth_state: AuthState,
    pub(crate) context: Arc<AppContext>,
}

impl AppState {
    pub(crate) fn new(context: Arc<AppContext>) -> Self {
        Self {
            auth_state: super::auth::AuthState::new(&context),
            context,
        }
    }
}

impl FromRef<AppState> for AuthState {
    fn from_ref(state: &AppState) -> Self {
        state.auth_state.clone()
    }
}
