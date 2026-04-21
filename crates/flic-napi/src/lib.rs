//! `flic-napi` — Node.js bindings for `flic-core`.
//!
//! The binding stays deliberately thin. Rust exposes primitives (commands +
//! a typed event stream); the Node/Electron host owns all product policy
//! (press → action mapping, arming, persistence location).
//!
//! This file currently exposes only a `version()` probe for the de-risking
//! step — "does the .node load from a Node / utilityProcess context at all?"
//! The `FlicManager` wrapper lands next, once the loader is proven.

#![deny(clippy::all)]

use napi_derive::napi;

/// Returns the crate version. Present as a smoke-test probe: if this call
/// resolves from JS, the native module loaded cleanly.
#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
