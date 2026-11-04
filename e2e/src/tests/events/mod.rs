mod feed;
mod stream_all_users;
mod stream_filter;
mod stream_modes;
mod stream_multi_user;
mod stream_private;
mod stream_sdk;
mod stream_validation;

use super::build_full_testnet;
use pubky_testnet::pubky::{Keypair, Method, StatusCode};

/// The `cursor: <id>` line every SSE event carries in its data.
fn sse_cursor(data: &str) -> &str {
    data.lines()
        .find_map(|line| line.strip_prefix("cursor: "))
        .expect("every event carries its cursor")
}
