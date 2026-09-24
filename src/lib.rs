//! Library half of `zoom_capture`: the retina-independent modules
//! (header parsing, classification, CSV output, stats, IP prechecking)
//! that have their own `#[cfg(test)]` unit tests and don't need DPDK,
//! `retina-core`, or the `#[filter]`/`#[retina_main]` macros to compile.
//!
//! This split exists specifically so `cargo test --lib` can run those
//! tests without also compiling `src/main.rs` — `cargo test` (with no
//! target filter) rebuilds *every* target, including the `zoom_capture`
//! binary, as a test binary, which means all of `main.rs`'s
//! macro-generated `#[retina_main]`/`#[filter]` code has to type-check
//! too. That's where a type-inference edge case around
//! `Runtime::new(config, filter)` was hit (see main.rs's comment on that
//! call) — entirely unrelated to whether the actual unit tests pass, but
//! it blocks `cargo test` from completing regardless. `cargo test --lib`
//! sidesteps it: it only builds this lib target, never touches
//! `main.rs`'s retina-macro code, and still exercises every real test
//! this crate has (`common::headers`, `common::ip_ranges`,
//! `capture_logic::zoom::udp` — the only three modules with `#[test]`s;
//! confirmed by grepping the crate for `#[cfg(test)]`).
//!
//! `groundtruths` stays out of this lib and declared directly in
//! `main.rs` — it has no tests of its own, so there's no reason to
//! expose it here.
pub mod capture_logic;
pub mod common;
