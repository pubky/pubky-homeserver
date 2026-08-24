#![warn(unused_crate_dependencies)]
// E2E tests
#[cfg(test)]
#[allow(
    deprecated,
    reason = "E2E tests intentionally cover legacy cookie compatibility alongside grant flows"
)]
mod tests;
