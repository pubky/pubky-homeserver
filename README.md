<h1 align="center"><a href="https://pubky.org/"><img alt="Pubky" src="./.svg/pubky-core-logo.svg" width="200" /></a></h1>

<h3 align="center">
  Homeserver and SDKs for Pubky.
</h3>

<div align="center">
  <h3>
    <a href="https://pubky.org/">Docs</a>
    <span> | </span>
    <a href="https://docs.rs/pubky">Rust SDK</a>
    <span> | </span>
    <a href="https://www.npmjs.com/package/@synonymdev/pubky">JavaScript SDK</a>
  </h3>
  <a href="https://github.com/pubky/pubky-core/blob/main/LICENSE"><img src="https://img.shields.io/github/license/pubky/pubky-core" alt="GitHub License" /></a>
  <a href="https://github.com/pubky/pubky-core/releases/latest/"><img src="https://img.shields.io/github/v/release/pubky/pubky-core" alt="GitHub Release" /></a>
  <a href="https://crates.io/crates/pubky"><img src="https://img.shields.io/crates/v/pubky" alt="Crates.io Version" /></a>
  <a href="https://www.npmjs.com/package/@synonymdev/pubky"><img src="https://img.shields.io/npm/v/@synonymdev/pubky" alt="npm Version" /></a>
  <br/>
  <a href="https://t.me/pubkycore"><img src="https://img.shields.io/badge/Chat-Telegram-violet" alt="Telegram Chat Group" /></a>
  <a href="https://deepwiki.com/pubky/pubky-core"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki" /></a>
</div>

<br/>

[Pubky](https://pubky.org) is an open protocol for building censorship-resistant applications where users own their identity, data, and connections. No platform lock-in, no losing everything when a service shuts down. Your keys are your identity, and you choose where your data lives.

To learn more about the vision, see [What is Pubky?](https://pubky.org/tldr/), [Censorship Resistance](https://pubky.org/explore/concepts/censorship/), and [Credible Exit](https://pubky.org/explore/concepts/credible-exit/).

This repository contains the core infrastructure: a homeserver that stores and serves user data, Rust and JavaScript SDKs for building apps, a local testnet, and examples.

## Who Is This For?

- **Operators**: [Install and run a homeserver](./docs/INSTALL.md), then [deploy it publicly](./docs/DEPLOY.md).
- **App developers**: Use the [SDK](https://pubky.org/explore/pubkycore/sdk/) to build apps that read and write user data on homeservers. Guides coming soon.

## What Is a Homeserver?

A Pubky homeserver stores and serves user data. Users choose which homeserver holds their data, and can move to another at any time. The homeserver exposes HTTP APIs for authenticated writes and public reads, and publishes [PKARR](https://github.com/pubky/pkarr) records so other clients can discover where a user's data lives.

- Public-key based sign-up, sign-in and third-party app authorization.
- File storage via HTTP `PUT`, `GET`, `DELETE`, and listing APIs (WebDAV-like).
- PKARR/PKDNS publishing for homeserver discovery.
- Admin and metrics endpoints for operators.

## Repository Layout

| Path | Purpose |
| --- | --- |
| [`pubky-homeserver`](./pubky-homeserver) | Homeserver binary and library crate. |
| [`pubky-sdk`](./pubky-sdk) | Rust client for Pubky apps, plus JS/WASM bindings. |
| [`pubky-common`](./pubky-common) | Shared types and helpers used by the SDK and homeserver. |
| [`pubky-testnet`](./pubky-testnet) | Local ephemeral Pubky network for development and tests. |
| [`examples`](./examples) | Rust and JavaScript examples for signup, auth, storage, and requests. |
| [`e2e`](./e2e) | End-to-end tests covering cross-crate workflows. |
| [`docs`](./docs) | Install guides, local development, and testing docs. |
