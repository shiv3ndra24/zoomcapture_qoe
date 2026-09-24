//! Running counters, printed periodically or on shutdown. Mirrors
//! vpn_capture's stats module, sized to the specific counters
//! `capture_logic::zoom::udp` needs.
//!
//! Uses `AtomicU64` rather than a mutex'd struct because retina invokes
//! `#[filter]` callbacks per-core — these counters get hit from
//! multiple threads concurrently, and a mutex here would serialize the
//! hot path for no benefit over a relaxed atomic counter.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Default)]
pub struct Stats {
    /// Every UDP payload handed to `classify_and_record`, matched or not.
    pub packets_seen: Counter,
    /// Parsed successfully as a Zoom SFU/Media header.
    pub packets_matched: Counter,
    /// Dropped before header parsing was even attempted, because neither
    /// endpoint was on the known-Zoom-server list (`common::ip_ranges`).
    /// Kept separate from `packets_unmatched` so "wrong endpoint" and
    /// "right endpoint, but the bytes didn't parse as Zoom's header
    /// format" stay distinguishable in `print_summary`.
    pub packets_ip_filtered: Counter,
    /// Passed the IP filter but didn't parse as Zoom's header format at
    /// all.
    pub packets_unmatched: Counter,
    /// Matched AND classified as one of the "media is active" types
    /// (video/audio/screenshare) — i.e. `MediaType::is_active_media_signal()`.
    /// Deliberately excludes Type 21, RTCP, and unknown types; see the
    /// reasoning in `common::headers::MediaType::Unknown21`.
    pub packets_active_media: Counter,
}

impl Stats {
    pub fn print_summary(&self) {
        println!(
            "zoom_capture stats: seen={} ip_filtered={} matched={} unmatched={} active_media={}",
            self.packets_seen.get(),
            self.packets_ip_filtered.get(),
            self.packets_matched.get(),
            self.packets_unmatched.get(),
            self.packets_active_media.get(),
        );
    }
}
