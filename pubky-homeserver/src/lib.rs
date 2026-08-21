//! Homeserver for Pubky
//!
//! This crate provides a homeserver for Pubky. It is responsible for handling user authentication,
//! authorization, and other core functionalities.
//!
//! This crate is part of the Pubky project.
//!
//! For more information, see the [Pubky project](https://github.com/pubky/pubky).

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(any(), deny(clippy::unwrap_used))]

mod admin_server;
mod app_context;
mod client_server;
mod constants;
mod data_directory;
mod homeserver_app;
mod metrics_server;
mod observability;
mod persistence;
mod republishers;
mod services;
mod shared;
pub mod tracing;

pub use admin_server::{AdminServer, AdminServerBuildError};
pub use app_context::{AppContext, AppContextConversionError};
pub use client_server::{ClientServer, ClientServerBuildError};
#[cfg(any(test, feature = "testing"))]
pub use data_directory::MockDataDir;
pub use data_directory::{
    storage_config, AdminToml, ConfigReadError, ConfigToml, DataDir, LoggingToml, MetricsToml,
    PersistentDataDir,
};
pub use homeserver_app::{HomeserverApp, HomeserverAppBuildError};
pub use metrics_server::{MetricsServer, MetricsServerBuildError};
pub use persistence::sql::ConnectionString;
pub use shared::quota::{
    BandwidthQuota, DefaultQuotasToml, GlobPattern, HttpMethod, LimitKey, LimitKeyType, PathLimit,
    RequestCountQuota, TimeUnit,
};
pub use shared::{Domain, DomainPort, SignupMode};
