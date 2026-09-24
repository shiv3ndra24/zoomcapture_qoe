//! zoom_capture — Retina-based Zoom traffic capture for research / education.
//!
//! Header-parsing and classification logic (src/common/headers.rs,
//! src/capture_logic/zoom/udp.rs) is grounded in two sources — see their
//! doc comments for exactly which claim comes from which:
//!   1. The "Zoom header-format re-validation, Sept 2026" deck — a fresh
//!      9-scenario x 2-device re-capture that independently re-derived
//!      the wire format and scored the 2022 paper's claims.
//!   2. Michel et al., "Enabling Passive Measurement of Zoom Performance
//!      in Production Networks", IMC'22 — the original reverse-engineering.
//!
//! P2P traffic (src/groundtruths/zoom/) is wired up but deprioritized:
//! the 2026 re-validation found zero STUN packets and zero direct
//! device-to-device UDP across 18 captures — everything was SFU-relayed.
//! So the real-time path (src/capture_logic/zoom/) is what actually runs
//! today; groundtruths stays in the tree in case P2P shows up on a
//! network/client version this hasn't been checked against.
//!
//! This is the only binary. It's used for both live capture (DPDK NIC,
//! hugepages, sudo) and offline replay of a previously-captured
//! `.pcap`/`.pcapng` file — same `#[filter]` callbacks, same
//! `Runtime::new(config, filter)` call either way. Which mode runs is
//! controlled entirely by which config file is passed to `-c`:
//! `config.toml` (`[online]`) for live capture, `config.offline.toml`
//! (`[offline]`) for replay — see README's "Running" section.
//!
//! The retina-independent modules (`common`, `capture_logic`) live in
//! this crate's `[lib]` target (`src/lib.rs`) rather than being declared
//! as plain `mod`s here, so `cargo test --lib` can run their real unit
//! tests without also compiling this file's `#[retina_main]`/`#[filter]`
//! macro-generated code — see `Runtime::new`'s call site below for why
//! that separation currently matters.
//!
//! An earlier pass of this crate had a second, hand-rolled binary
//! (`pcap_offline`) that parsed pcap files directly with the `pcap-file`
//! crate, specifically to get *exact* per-packet capture timestamps —
//! every timestamp `retina-datatypes` exposes is wall-clock
//! (`Instant::now()`), even during Retina's own offline replay. That
//! binary is removed: exact timestamps aren't needed for now (project
//! decision), so the simpler path — one binary, one code path, Retina's
//! own tested protocol stack instead of a hand-rolled Ethernet/VLAN/IP
//! parser — wins. See `CAPTURE_START` below for how `time_offset` works
//! now in both modes.

#![allow(dead_code)]

use clap::Parser;
use lazy_static::lazy_static;
// `L4Context`/`FiveTuple` aren't re-exported through `retina_datatypes`
// (they're internal to how `retina-datatypes` itself is implemented —
// see the reasoning in `build_packet_meta_and_payload` below), so they're
// imported directly from `retina-core`, which this crate already depends
// on directly in Cargo.toml.
use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::L4Context;
use retina_core::{config::load_config, CoreId, Runtime};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

// common/capture_logic live in this crate's lib target — see the module
// doc above for why. groundtruths has no tests of its own and stays
// declared directly here.
use zoom_capture::{capture_logic, common};
mod groundtruths;

use capture_logic::zoom::udp::{classify_and_record, PacketMeta};
use common::stats::Stats;
use common::writer::CsvWriter;

lazy_static! {
    static ref STATS: Stats = Stats::default();
    static ref WRITER: Mutex<CsvWriter> = {
        let dir = common::writer::output_dir().expect("failed to create captures/ output dir");
        let path = dir.join("zoom_udp.csv");
        Mutex::new(CsvWriter::create(&path).expect("failed to create output CSV"))
    };
    /// Reference point for `time_offset` in the output CSV, in *both*
    /// online and offline mode. There's no real per-packet capture
    /// timestamp available in this callback — `#[filter]` callbacks fire
    /// as Retina hands them packets, and that's true whether the packets
    /// come live off a NIC or are being replayed from a pcap file, so
    /// "wall-clock time since this process started" is the only timeline
    /// available either way (see `retina-datatypes`' own `ConnRecord` doc
    /// comment: its timestamps are `Instant::now()`-based and explicitly
    /// "does not reflect timestamps read from a packet capture in offline
    /// analysis").
    ///
    /// Known limitation, accepted for now: in offline mode this makes
    /// `time_offset` reflect how fast Retina replays the file (and system
    /// load while doing so), not the pcap's real inter-packet timing —
    /// so it's good for "did X happen before Y" but not for lining events
    /// up against an external ground-truth timeline with real clock
    /// values. Revisit with a real pcap-timestamp-reading path (what the
    /// removed `pcap_offline` binary did) if that precision is needed
    /// later.
    static ref CAPTURE_START: Instant = Instant::now();
}

// ── Retina capture callbacks ────────────────────────────────────────────────
// Zoom media is UDP-only per both reference sources (RTP/RTCP under the
// SFU/Media Encapsulation headers) — no signaling-over-TCP path is
// implemented yet, so the TCP callback is a placeholder. See tcp.rs.

#[filter("udp")]
fn capture_udp(packet: &ZcFrame, _core_id: &CoreId) {
    let Some((meta, payload)) = build_packet_meta_and_payload(packet) else {
        // Not enough of an L4 context to make sense of (e.g. a malformed
        // or truncated packet) — nothing to classify, and not worth a
        // stats counter of its own since it means "couldn't even look",
        // as distinct from packets_unmatched ("looked, wasn't Zoom").
        return;
    };
    let mut writer = WRITER.lock().expect("WRITER mutex poisoned");
    classify_and_record(meta, payload, &mut writer, &STATS);
}

#[filter("tcp")]
fn capture_tcp(packet: &ZcFrame, _core_id: &CoreId) {
    // Not implemented: neither reference source documents a Zoom
    // signaling channel over TCP that this project currently needs.
    // Kept registered (not deleted) so retina_main's callback count
    // stays accurate if TCP-side detection becomes relevant later.
    let _ = packet;
}

/// Pulls a plain `PacketMeta` + the raw UDP payload out of a raw `ZcFrame`
/// (`retina_core::Mbuf`), for packets that reach `#[filter("udp")]` before
/// any connection tracking has run.
///
/// This used to be an honest `todo!()` — the exact accessor wasn't
/// confirmed against this repo's `retina-core` version, and guessing one
/// risked silently compiling wrong (e.g. reading the wrong byte offset)
/// rather than failing loudly. It's resolved now, from `retina-datatypes`'
/// *own* source (`a3.zip`, not guessed):
///
/// - `retina_datatypes::packet::Payload`'s `FromMbuf` impl does exactly
///   this extraction for the payload half:
///   ```ignore
///   if let Ok(ctxt) = L4Context::new(mbuf) {
///       let offset = ctxt.offset;
///       let payload_len = ctxt.length;
///       if let Ok(data) = mbuf.get_data_slice(offset, payload_len) { ... }
///   }
///   ```
///   The same three calls are used below directly, rather than adding
///   `payload: &Payload` as a second filter parameter, because the
///   5-tuple (below) needs the same `L4Context` value — computing it once
///   here avoids Retina (or this function) parsing the packet's L4 header
///   twice for one callback invocation.
/// - `FiveTuple::from_ctxt(ctxt)` is called the same way — on a value
///   named `ctxt` — in two independent places in `retina-datatypes`
///   (`connection.rs`'s `ConnRecord::new` and `static_type.rs`), both
///   passing `first_pkt.ctxt`, an `L4Context`-typed field of `L4Pdu`.
///   Cross-referencing those two call sites against `L4Context::new(mbuf)`
///   above is what justifies using its result as `from_ctxt`'s input:
///   both are named/typed the same way, and it's the only place in this
///   crate's source that a `FiveTuple` is ever constructed. This crate
///   doesn't have `retina-core`'s own source to confirm `L4Pdu`'s field
///   layout more directly than that, so treat this line as very likely
///   correct rather than fully proven.
///
/// One nuance flagged but not yet checked against real traffic: whether
/// `.orig`/`.resp` on a `FiveTuple` built from a *bare*, non-connection-
/// tracked `L4Context` (as opposed to one accumulated over a tracked
/// flow) reliably means "this packet's source" / "this packet's
/// destination" — which is what `src_ip`/`dst_ip` below assume — or some
/// flow-level "who sent the first packet" semantic that could stay fixed
/// across both directions of one exchange. `L4Context::new` takes only
/// the raw `mbuf` with no connection state threaded through it, so
/// per-packet accuracy is the expected reading, but it's worth a quick
/// empirical check the first time this runs against real traffic:
/// capture a few packets of one exchange and confirm `orig`/`resp` swap
/// between the two directions rather than staying fixed.
fn build_packet_meta_and_payload(packet: &ZcFrame) -> Option<(PacketMeta, &[u8])> {
    let ctxt = L4Context::new(packet).ok()?;
    let payload = packet.get_data_slice(ctxt.offset, ctxt.length).ok()?;
    let five_tuple = FiveTuple::from_ctxt(ctxt);

    let meta = PacketMeta {
        time_offset: Instant::now().saturating_duration_since(*CAPTURE_START),
        frame_len: packet.data_len(),
        src_ip: five_tuple.orig.ip().to_string(),
        dst_ip: five_tuple.resp.ip().to_string(),
        src_port: five_tuple.orig.port(),
        dst_port: five_tuple.resp.port(),
    };
    Some((meta, payload))
}

// ── CLI ─────────────────────────────────────────────────────────────────────
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
}

// NOTE: the number in retina_main(N) is the count of #[filter] callbacks
// above (currently 2: udp + tcp). Keep this in sync if you add/remove one.
#[retina_main(2)]
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);

    println!("zoom_capture (research / education)");
    println!("====================================");
    // Touch CAPTURE_START before the runtime starts handing packets to
    // callbacks, so the first packet's time_offset is ~0 rather than
    // reflecting whatever lazy_static's first-access moment happened to be.
    lazy_static::initialize(&CAPTURE_START);

    // CONFIRMED (not a `cargo test` artifact): a genuine, non-test
    // `cargo build --release --bin zoom_capture` hits the identical
    // error, so this was a real build blocker for live capture, not
    // just for `cargo test`. Fixed with an explicit turbofish below —
    // reasoning, since past mistakes in this crate came from guessing at
    // retina internals instead of reading them, and this fix is
    // different in kind from those:
    //
    // The bare error already named the type. `E0283`'s help text reads
    // "the trait `Subscribable` is implemented for `SubscribedWrapper`"
    // — that's rustc reporting, from the real macro-expanded code it just
    // compiled, that exactly one type in this crate implements the
    // `Subscribable` bound `Runtime<S>` requires. That's not a guess
    // pulled from outside the compiler's own output; it's the compiler
    // naming the concrete type for us.
    //
    // Why inference didn't just pick that one type on its own: Rust's
    // "only one candidate" shortcut applies to *trait method* resolution
    // on an already-known receiver type (e.g. `x.some_trait_method()`
    // when only one in-scope impl provides it) — it does not apply to
    // inferring a free struct type parameter like `Runtime<S>`'s `S`.
    // For that, inference needs something *after* the call that pins `S`
    // down: a declared variable type, a function argument position, a
    // return type, etc. Here `Runtime::new(config, filter)` was
    // immediately `.unwrap()`-ed into a `let mut runtime = ...` with no
    // annotation, so there was nothing downstream to unify `S` against —
    // hence "type annotations needed" even though only one valid answer
    // exists in the whole crate.
    //
    // Caveat, stated plainly: this crate still doesn't have
    // `core/src/runtime/mod.rs` or `retina_filtergen`'s macro source, so
    // I can't compile this fix myself the way `ip_ranges.rs`'s fix was
    // verified (in a throwaway crate, both broken and fixed). If
    // `SubscribedWrapper` turns out not to be a bare, accessible name at
    // this point in `main.rs` (i.e. `#[retina_main]` doesn't generate it
    // directly into this module's scope), the next compile error will be
    // "cannot find type `SubscribedWrapper` in this scope" — and that
    // error's own suggestion will name the exact module path to import
    // it from, since rustc only suggests paths for types that genuinely
    // exist somewhere in the crate graph. Either way, the next build
    // output is enough to finish this, no further guessing needed.
    let mut runtime = Runtime::<SubscribedWrapper>::new(config, filter).unwrap();
    runtime.run();

    STATS.print_summary();
    let _ = WRITER.lock().map(|mut w| w.flush());
}
