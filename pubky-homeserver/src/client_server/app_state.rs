use std::sync::Arc;

use axum::extract::FromRef;
use dav_server::{fakels::FakeLs, DavHandler};
use dav_server_opendalfs::OpendalFs;

use crate::client_server::auth::AuthState;
use crate::client_server::routes::dav::DAV_PREFIX;
use crate::AppContext;

#[derive(Clone)]
pub(crate) struct AppState {
    /// Auth sub-state (extracted via `FromRef` by auth handlers).
    pub(crate) auth_state: AuthState,
    pub(crate) context: Arc<AppContext>,
    /// Shared handler behind `/dav`. Only `/dav` is stripped, so the tenant
    /// segment survives into the storage key; see [`crate::client_server::routes::dav`].
    pub(crate) dav_handler: DavHandler,
}

impl AppState {
    pub(crate) fn new(context: Arc<AppContext>) -> Self {
        let dav_handler = DavHandler::builder()
            // The app-facing operator, not the admin one: it keeps per-user
            // `allowed_write_paths` and write-collision checks in force.
            .filesystem(OpendalFs::new(
                context.file_service.opendal.operator.clone(),
            ))
            .locksystem(FakeLs::new())
            .strip_prefix(DAV_PREFIX)
            .autoindex(true)
            .build_handler();

        Self {
            auth_state: super::auth::AuthState::new(&context),
            context,
            dav_handler,
        }
    }
}

impl FromRef<AppState> for AuthState {
    fn from_ref(state: &AppState) -> Self {
        state.auth_state.clone()
    }
}
