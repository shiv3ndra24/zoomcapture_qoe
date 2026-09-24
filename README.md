# zoom_capture

Retina-based passive capture of Zoom traffic, for research/education —
same purpose as `vpn_capture`, targeted at a different application.

## Status

One binary (`src/main.rs`), used for both live capture and offline replay
of a previously-captured `.pcap`/`.pcapng` file — same `#[filter]`
callbacks, same `Runtime::new(config, filter)` call. Which mode runs is
controlled entirely by which config file is passed to `-c`: `config.toml`
(`[online]`) for live capture, `config.offline.toml` (`[offline]`) for
replay — `retina-core`'s own `load_config()` requires exactly one of
`online`/`offline` to be set (confirmed from `core/src/config.rs`), so
they're two files rather than one toggled back and forth.

Header parsing, classification, and the 5-tuple/payload extraction from
a packet are all implemented (the extraction was, until a previous pass,
an honest `todo!()` rather than a guess — see `main.rs`'s doc comment on
`build_packet_meta_and_payload` for exactly which `retina-datatypes`
source justifies each call, and the one remaining nuance worth a quick
empirical check against real traffic).

An earlier pass of this crate had a separate `pcap_offline` binary that
hand-parsed pcap files directly (via the `pcap-file` crate) to get exact
per-packet capture timestamps, bypassing Retina's offline mode entirely.
That's removed: exact timestamps aren't needed for now (project
decision), so this crate is back to one binary, one code path, reusing
Retina's own offline replay (`core/src/runtime/offline.rs`, now read and
confirmed) instead of a hand-rolled parser — see "A note on offline
timestamps" below for the tradeoff this accepts.

**First real-workspace compile pass found two issues, both now fixed:**
a type-inference ambiguity in `common/ip_ranges.rs` (see its code
comment), and a type-inference gap in `main.rs`'s
`Runtime::new(config, filter)` call, which turned out to block a real
`cargo build --release --bin zoom_capture`, not just `cargo test` — see
"Testing → Resolved: `Runtime::new` type inference" below for the fix
and why it isn't fully compile-verified here yet. Everything else — all
11 unit tests, both config files' schemas, the 5-tuple extraction's
reasoning — is unaffected.

Capture-only scope for now: dump matched traffic to a per-packet CSV,
like `vpn_capture` does. No session/QoE-metric engine and no
InfluxDB/Grafana export yet — see `Video_Conferencing/services/capture_data`
(Teams/Meet) if/when that becomes the next step; its `sessions/` module is
the template to follow.

## Setup checklist

1. **Register this crate in the workspace.** Add `"zoom_capture"` to the
   `[workspace] members` list in the retina root `Cargo.toml` — the same
   entry `vpn_capture` has. Without this, `cargo build` from this
   directory won't share the root `target/`, and `run.sh` (which looks
   for the binary at `../target/release/zoom_capture`) will fail.
2. For live capture: adjust `config.toml`'s `[[online.ports]]` (`device`,
   `cores`) to the NIC you're capturing on. For offline replay: point
   `config.offline.toml`'s `[offline] pcap` at the file you want to
   replay.
3. For live capture: `./build.sh` (builds + runs) or `./run.sh` (runs an
   existing build) — both are hardcoded to `config.toml`. For offline
   replay: build once (`cargo build --release --bin zoom_capture`) and
   run the binary directly with `-c config.offline.toml` (see "Running"
   below) — the scripts don't cover this mode. `cargo test --lib` (not
   bare `cargo test` — see "Testing" below) runs the header-parsing/
   classification tests without needing any of the above.

## Why this crate lives here and not in `examples/`

`examples/` holds retina's own demo crates. Research projects that need
their own build/run scripts and a non-trivial `src/` live as top-level
workspace members instead — `vpn_capture` is the existing precedent this
crate follows.

## Running

### Live capture

```sh
./build.sh      # builds + runs
# or, if already built:
./run.sh
```

Both scripts exec `zoom_capture` via `sudo -E`, since DPDK needs root to
touch the NIC and hugepages. Before the first run:

- Hugepages must be configured for DPDK (however this lab's `core`
  crate/other capture crates expect them set up — same prerequisite
  `vpn_capture` has, not something specific to this crate).
- `config.toml`'s `[[online.ports]] device` must name the NIC you're
  capturing on, bound to a DPDK-compatible driver.
- Run as a user that can `sudo` (both scripts already wrap the binary in
  `sudo -E`).

Output lands in `captures/run_<unix_ts>/zoom_udp.csv`.

### Offline replay (previously-captured pcap/pcapng files)

```sh
cargo build --release --bin zoom_capture
sudo -E ./target/release/zoom_capture -c config.offline.toml
```

`config.offline.toml`'s `[offline] pcap` field points at the single
`.pcap`/`.pcapng` file to replay (edit it per run, or copy the file to
one fixed path) — confirmed from `core/src/config.rs`'s `OfflineConfig`
struct (`pcap: String`, `mtu: usize`) and `core/src/runtime/offline.rs`
(`OfflineRuntime::run()` opens it with `pcap::Capture::from_file`, one
file per run, no directory or glob support). Retina replays it through
the identical `#[filter("udp")]`/`#[filter("tcp")]` callbacks live
capture uses — no code in this crate differs between the two modes, only
which config file is passed to `-c`.

**Still needs `sudo -E` and DPDK/hugepages set up, same as live
capture.** This was the assumption to double check rather than carry
over from the removed `pcap_offline` binary (which genuinely didn't need
any of that, since it bypassed Retina entirely) — and checking
`offline.rs` confirms offline mode is *not* DPDK-free: it still
allocates every packet's `Mbuf` from a DPDK mempool
(`OfflineRuntime::get_mempool_raw()` calls `dpdk::rte_mempool_lookup`),
and `config.rs`'s `get_eal_params()` still builds full DPDK EAL init args
regardless of mode. The only thing offline mode skips is binding a live
NIC/PCI device. Output lands in `captures/run_<unix_ts>/zoom_udp.csv`,
same as live capture (same `WRITER`/`STATS` in `main.rs`, unconditional
on mode).

One more thing to know about, not to fix: this lab's
`core/src/runtime/offline.rs` runs a CAPWAP-preprocessing step
(`preprocess_capwap_packet_advanced`) on every replayed packet before it
reaches `#[filter]` callbacks, stripping CAPWAP tunnel headers if
present. Transparent to this crate's own code — `main.rs`'s callbacks
only ever see the CAPWAP-stripped inner packet — but worth knowing if a
replay's packet counts look lower than a raw `tcpdump -r` count of the
same file.

### A note on offline timestamps

Replaying a pcap through Retina's offline mode means `time_offset` in the
output CSV is *not* the pcap's real embedded per-packet timestamp — every
timestamp type `retina-datatypes` exposes (`ConnRecord`, `FlowAccumulator`)
is `Instant::now()`-based, and `ConnRecord`'s own doc comment says
offline mode is no exception ("does not reflect timestamps read from a
packet capture in offline analysis"). In practice this means
`time_offset` reflects how fast Retina replays the file, not real
inter-packet timing from the original capture.

That's an accepted tradeoff for now (project decision) in exchange for
the simplicity of one binary and Retina's own tested protocol stack
instead of a hand-rolled parser. If exact timestamps become necessary
later — e.g. to reproduce the re-validation deck's own methodology of
matching packet events against a ground-truth timeline — the fix is a
separate code path that reads the pcap's real timestamp directly (via
the `pcap-file` crate, whose `PcapPacket.timestamp`/
`EnhancedPacketBlock.timestamp` are real, EPOCH-relative, nanosecond
resolution — confirmed by reading its v2.0.0 source) instead of routing
through Retina's replay. That's exactly what the now-removed
`pcap_offline` binary did; reintroducing something like it is the thing
to revisit if this tradeoff stops being acceptable.

### Testing

**Use `cargo test --lib`, not bare `cargo test`.** Bare `cargo test`
rebuilds every target, including the `zoom_capture` binary — which means
all of `main.rs`'s `#[retina_main]`/`#[filter]` macro-generated code has
to type-check under `--test` cfg too, and that used to hit a compile
error unrelated to the tests themselves (`Runtime::new(config, filter)`
— see the comment on that line in `main.rs`; fixed, see "Resolved:
`Runtime::new` type inference" below). `common` and `capture_logic` — the only two
modules with actual `#[test]`s — live in this crate's `[lib]` target
specifically so `cargo test --lib` can run them without touching
`main.rs` at all:

```sh
cargo test --lib
```

This exercises header parsing and classification directly
(`src/common/headers.rs`, `src/common/ip_ranges.rs`,
`src/capture_logic/zoom/udp.rs`) with synthetic byte buffers — no NIC,
no pcap file, no retina runtime, no sudo required.

#### Resolved: `Runtime::new(config, filter)` type inference

This turned out to be a real build blocker, not a `cargo test` artifact
— a genuine `cargo build --release --bin zoom_capture` hit the same
error:

```
error[E0283]: type annotations needed for `Runtime<_>`
    cannot satisfy `_: Subscribable`
    help: the trait `Subscribable` is implemented for `SubscribedWrapper`
```

**Fix:** an explicit turbofish at the call site in `main.rs`:

```rust
let mut runtime = Runtime::<SubscribedWrapper>::new(config, filter).unwrap();
```

**Why:** the error's own help text names the concrete type —
`SubscribedWrapper` is the one and only type in this crate's compiled
output that implements `Subscribable`, which is the bound `Runtime<S>`
requires. That's not an outside guess; it's rustc reporting on the real
macro-expanded code it just compiled. What it *doesn't* do automatically
is pick that one type for `S` — Rust's "only one candidate" shortcut
applies to resolving a trait *method* on an already-known receiver type,
not to inferring a free struct type parameter. `Runtime::new(config,
filter)` was immediately `.unwrap()`-ed into an unannotated `let`, so
inference had nothing downstream to pin `S` against, even though only
one valid answer exists in the whole crate. Giving it explicitly closes
that gap.

**Caveat:** this crate still doesn't have `core/src/runtime/mod.rs` or
`retina_filtergen`'s macro source, so this fix hasn't been compiled here
the way `ip_ranges.rs`'s fix was (verified broken-then-fixed in a
throwaway crate). If `SubscribedWrapper` isn't a bare, accessible name
at that point in `main.rs` — i.e. `#[retina_main]` doesn't generate it
directly into this module's scope — the next error will be "cannot find
type `SubscribedWrapper` in this scope", and its own suggestion will
name the exact module path to import it from. Rebuild
(`cargo build --release --bin zoom_capture`) and report back either way.

## What the Sept 2026 re-validation changed here

A separate effort re-captured Zoom traffic (9 scenarios x 2 devices, 18
pcaps, ~990K packets) and independently re-derived every field the
IMC'22 paper claims, scoring each one Holds / Refined / Does NOT hold
against the paper's own artifact. That scorecard is what `headers.rs`
and `capture_logic/zoom/udp.rs` are actually built against — not the
2022 paper directly — because it's the one checked against traffic this
project will see today. Highlights, and why each one shows up in code
the way it does:

- **Architecture holds.** Two-layer header (SFU Encapsulation, 8B outer,
  server-relayed only → Media Encapsulation, variable, P2P+server), 1-byte
  Type fields, offset-based RTP/RTCP location — all confirmed. Implemented
  as designed.
- **SFU direction byte (byte 7) is a bitmask, not `0x00`/`0x04`.** Real
  traffic shows `dir==5` (`4|1`) alongside the paper's `0` and `4`. Code
  tests the `0x04` bit (`SfuHeader::from_sfu()`), never `==`.
- **Audio payload-type constants from 2022 are gone.** PT 112/99 (0%
  in 2026) replaced by PT 116/113. `headers.rs` deliberately does *not*
  encode payload-type numbers as constants — only the outer Media Type
  byte (15/16/13/30/33/34) is used for classification, since that's what
  held up.
- **Type 21 is new, ~21% of traffic, and always on** — present even with
  zero media active (90-94% of the no-media control baseline). It's
  excluded from `MediaType::is_active_media_signal()` on purpose: a
  classifier that keys off "any inner-typed traffic" instead of the
  specific media types would read as permanently active and be useless
  for inferring audio/video/screenshare state.
- **Type 30 isn't P2P.** The paper's own code calls it
  `P2P_SCREEN_SHARE_TYPE`; 2026 traffic shows every Type-30 packet going
  to a published Zoom server IP. It's screenshare-with-"optimize for
  video clip", grouped with Type 13 in `MediaType` rather than routed
  through a P2P-specific path.
- **P2P (STUN, direct device-to-device UDP) wasn't observed at all** —
  0/18 captures. `groundtruths/zoom/` is left in the tree but is not
  where the real work happens right now; see its module doc.
- **The practical technique — classify each packet by type, infer
  media start/stop from presence over time — "strongly holds"** across
  all 9 scenarios, including the hardest ones (rapid toggling, 3
  participants). That's the one number worth trusting completely, and
  it's why `writer.rs`'s CSV schema is `(time_offset, media_type, ...)`
  rather than something keyed to the exact 2022 byte constants.
- **IP-range filtering is now wired in as a hard gate, by explicit
  instruction — correction from this README's earlier drafts.** The
  first draft assumed Zoom's server ranges were too broad (multi-cloud/
  AWS) to be a useful precheck; a later pass baked in the real list
  (`common/ip_ranges.rs`: 48 IPv4 + 3 IPv6 CIDR blocks, plus the TCP/UDP
  port sets, verified against the exact endpoint `144.195.28.40` the
  deck cross-checked on slide 59) but deliberately left it disconnected
  from `capture_logic::zoom::udp`, on the reasoning that the
  re-validation's "type-byte classification strongly holds" finding was
  about classification accuracy, not about whether IP-gating is safe.
  That reasoning didn't change — but the requirement did: this build now
  calls `ip_ranges::is_known_zoom_server_ip_str` at the top of
  `classify_and_record`, before header parsing, and drops (does not
  record) any packet where neither `src_ip` nor `dst_ip` is on the list.
  Tradeoff accepted, explicitly: a genuinely-Zoom packet whose server IP
  is missing from the list (stale data, or an IP Zoom hasn't published)
  is now silently dropped rather than still captured. `Stats.packets_ip_filtered`
  counts these drops separately from `packets_unmatched` (endpoint OK,
  header didn't parse), so the two failure modes stay visible in
  `print_summary`'s output rather than being conflated.
- **VLAN-tag capture artifact (Device A, slide 8) — open question again
  now that offline replay goes through Retina.** A hardcoded 14-byte
  Ethernet header (as the paper's own C++ tool assumes) silently drops a
  large fraction of one device's captures, because that device's frames
  carry a spurious 4-byte 802.1Q tag. The previous `pcap_offline` binary
  fixed this explicitly with its own VLAN-tag-aware Ethernet parser
  (tested against exactly this scenario). Now that offline replay goes
  through Retina's own protocol stack instead, whether *that* parser
  handles stacked VLAN tags correctly is untested here — worth checking
  against one of Device A's captures once offline replay is wired up, in
  case the artifact resurfaces.

## Module layout and what each one does

| Module | Purpose | Reference |
|---|---|---|
| `src/main.rs` | CLI, `retina_main` filter registration, 5-tuple/payload extraction from `ZcFrame` — used for both live capture and offline replay | `retina-datatypes` source (`a3.zip`) |
| `src/common/headers.rs` | SFU/Media Encapsulation header parsing — `MediaType` classification, RTP/RTCP offset lookup | IMC'22 paper §4.1–4.2 + Sept 2026 re-validation deck |
| `src/common/ip_ranges.rs` | Hard IP filter — `classify_and_record` drops any packet where neither endpoint is a published Zoom server IP, before parsing headers | `zoom_ip_list.txt` |
| `src/common/writer.rs` | Per-packet CSV output (`PacketRecord`) | `vpn_capture/src/common/writer.rs`, shaped to match the re-validation deck's own `(time, media_type)` analysis pipeline |
| `src/common/stats.rs` | Atomic packet counters (seen/matched/unmatched/active-media) | `vpn_capture/src/common/stats.rs` |
| `src/capture_logic/zoom/udp.rs` | The real detection path — classifies every UDP payload via `common::headers`, writes a record | — |
| `src/capture_logic/zoom/tcp.rs` | Not implemented — no TCP signaling channel documented by either source | — |
| `src/groundtruths/zoom/` | P2P-endpoint validation path — currently idle (not wired into either mode's callbacks) | `vpn_capture/src/groundtruths/openvpn/` |

## Sources

- `3517745.3561414.pdf` (IMC'22, Michel et al., "Enabling Passive
  Measurement of Zoom Performance in Production Networks") — original
  protocol reverse-engineering.
- "Zoom header-format re-validation, Sept 2026" deck — independent
  re-capture and per-claim scoring against the paper's own artifact;
  primary source for `headers.rs` where it disagrees with the paper.
- `zoom_ip_list.txt` — Zoom's officially published TCP/UDP port and
  IP-range list; source for `common/ip_ranges.rs`.
- `retina-datatypes` crate source (`a3.zip`) — source for `main.rs`'s
  5-tuple/payload extraction and for the offline-timestamp reasoning above.
- `core/src/runtime/offline.rs`, `core/src/config.rs` — source for
  `config.offline.toml`'s schema and the DPDK/hugepage and CAPWAP notes
  in "Running → Offline replay" above.
- `MTP_thesis.pdf` — network_metrics.rs-style throughput/loss/bitrate
  formulas (ch. 4), for whenever a metrics/session engine gets added.
