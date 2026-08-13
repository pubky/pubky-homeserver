use axum::extract::FromRef;

use crate::client_server::auth::AuthState;
use crate::observability::Metrics;
use crate::persistence::files::events::EventsService;
use crate::persistence::files::FileService;
use crate::persistence::sql::SqlDb;
use crate::services::user_service::UserService;
use crate::SignupMode;

#[derive(Clone, Debug)]
pub(crate) struct AppState {
    /// Auth sub-state (extracted via `FromRef` by auth handlers).
    pub(crate) auth_state: AuthState,
    /// The SQL database connection.
    pub(crate) sql_db: SqlDb,
    pub(crate) file_service: FileService,
    pub(crate) signup_mode: SignupMode,
    pub(crate) events_service: EventsService,
    pub(crate) metrics: Metrics,
    /// User service for user lookups, creation, and cache access.
    pub(crate) user_service: UserService,
    /// Default per-user storage quota in MB (from `[storage].default_quota_mb`).
    pub(crate) default_storage_mb: Option<u64>,
}

impl AppState {
    pub(crate) fn new(context: &crate::AppContext) -> Self {
        Self {
            auth_state: super::auth::AuthState::new(context),
            sql_db: context.sql_db.clone(),
            file_service: context.file_service.clone(),
            signup_mode: context.config_toml.general.signup_mode.clone(),
            metrics: context.metrics.clone(),
            events_service: context.events_service.clone(),
            user_service: context.user_service.clone(),
            default_storage_mb: context.config_toml.storage.default_quota_mb,
        }
    }
}

impl FromRef<AppState> for AuthState {
    fn from_ref(state: &AppState) -> Self {
        state.auth_state.clone()
    }
}
