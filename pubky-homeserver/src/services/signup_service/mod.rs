//! Signup service — owns the signup policy, signup tokens and user creation on signup.

mod service;

pub use service::{SignupService, SignupServiceError};
