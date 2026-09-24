//! Real-time Zoom UDP classification — the actual detection path, since
//! the 2026 re-validation found zero P2P traffic in 18 captures (see
//! `groundtruths/zoom/`), so "traffic to/from an uncontrolled endpoint"
//! is effectively the only path that matters right now.
//!
//! Deliberately decoupled from retina's `ZcFrame`/`CoreId` types: this
//! module takes plain `PacketMeta` + a `&[u8]` UDP payload, so the
//! header-parsing logic in `common::headers` can be exercised in tests
//! without needing a live retina runtime. `main.rs`'s `#[filter("udp")]`
//! callback is responsible for pulling those plain values out of
//! whatever retina hands it — see the TODO there, since the exact
//! accessor for source/dest IP/port and packet timestamp on `ZcFrame`
//! wasn't confirmed against this repo's retina-core version.
//!
//! **IP-gated, by explicit instruction.** `classify_and_record` now
//! drops a packet outright — before even trying to parse it as a Zoom
//! header — unless `meta.src_ip` or `meta.dst_ip` is on the published
//! Zoom server list (`common::ip_ranges::is_known_zoom_server_ip_str`).
//! See that module's doc comment for the tradeoff this accepts (a
//! genuinely-Zoom packet from an IP that's missing from the list, e.g.
//! stale data, is now silently dropped rather than still recorded).

use crate::common::headers::parse_zoom_headers;
use crate::common::ip_ranges::is_known_zoom_server_ip_str;
use crate::common::writer::{CsvWriter, PacketRecord};
use crate::common::stats::Stats;
use std::time::Duration;

/// Per-packet metadata the retina callback must supply. Kept minimal and
/// retina-agnostic on purpose (see module doc).
#[derive(Debug, Clone)]
pub struct PacketMeta {
    pub time_offset: Duration,
    pub frame_len: usize,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Parse `udp_payload` as Zoom traffic and, if it classifies, write a
/// `PacketRecord`. Returns `true` if a record was written.
///
/// Two independent ways this returns `false` without writing anything,
/// counted separately in `stats` so they stay distinguishable:
/// - neither `meta.src_ip` nor `meta.dst_ip` is a published Zoom server
///   IP (`packets_ip_filtered`) — checked first, and cheaply, so a
///   packet from an unrelated endpoint never reaches header parsing;
/// - the endpoint matched, but the payload didn't parse as Zoom's
///   header format at all (`packets_unmatched`).
pub fn classify_and_record(
    meta: PacketMeta,
    udp_payload: &[u8],
    out: &mut CsvWriter,
    stats: &Stats,
) -> bool {
    stats.packets_seen.inc();

    if !is_known_zoom_server_ip_str(&meta.src_ip) && !is_known_zoom_server_ip_str(&meta.dst_ip) {
        stats.packets_ip_filtered.inc();
        return false;
    }

    let Some((media, sfu, _rest)) = parse_zoom_headers(udp_payload) else {
        stats.packets_unmatched.inc();
        return false;
    };

    stats.packets_matched.inc();
    if media.media_type.is_active_media_signal() {
        stats.packets_active_media.inc();
    }

    let record = PacketRecord::from_headers(
        meta.time_offset,
        meta.frame_len,
        meta.src_ip,
        meta.dst_ip,
        meta.src_port,
        meta.dst_port,
        sfu,
        media,
    );

    if let Err(e) = out.write_record(&record) {
        // Writer errors (disk full, permissions) shouldn't take down the
        // capture loop — log and keep going, same posture vpn_capture
        // takes for its writer.
        eprintln!("zoom_capture: failed to write record: {e}");
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::headers::{SFU_HEADER_LEN, SFU_TYPE_MEDIA_FOLLOWS};

    fn video_packet() -> Vec<u8> {
        let mut buf = vec![0u8; SFU_HEADER_LEN + 24];
        buf[0] = SFU_TYPE_MEDIA_FOLLOWS;
        buf[7] = 0x04; // from SFU
        buf[SFU_HEADER_LEN] = 16; // media type = Video
        buf
    }

    #[test]
    fn classifies_video_and_counts_as_active_media() {
        let tmp = std::env::temp_dir().join("zoom_capture_test.csv");
        let mut writer = CsvWriter::create(&tmp).unwrap();
        let stats = Stats::default();
        let meta = PacketMeta {
            time_offset: Duration::from_secs(1),
            frame_len: 200,
            src_ip: "10.184.0.181".into(),
            dst_ip: "144.195.28.40".into(),
            src_port: 8801,
            dst_port: 8801,
        };
        let matched = classify_and_record(meta, &video_packet(), &mut writer, &stats);
        assert!(matched);
        assert_eq!(stats.packets_matched.get(), 1);
        assert_eq!(stats.packets_active_media.get(), 1);
        let _ = std::fs::remove_file(tmp);
    }

    /// Known-Zoom endpoint (dst_ip on the list), but a payload that isn't
    /// shaped like a Zoom header at all — exercises `packets_unmatched`,
    /// distinct from the IP-filter path below.
    #[test]
    fn bad_payload_from_a_known_zoom_ip_is_counted_unmatched_not_dropped_silently() {
        let tmp = std::env::temp_dir().join("zoom_capture_test2.csv");
        let mut writer = CsvWriter::create(&tmp).unwrap();
        let stats = Stats::default();
        let meta = PacketMeta {
            time_offset: Duration::from_secs(0),
            frame_len: 4,
            src_ip: "10.184.0.181".into(),
            dst_ip: "144.195.28.40".into(), // known Zoom server IP
            src_port: 1,
            dst_port: 2,
        };
        let matched = classify_and_record(meta, &[0x00, 0x00], &mut writer, &stats);
        assert!(!matched);
        assert_eq!(stats.packets_unmatched.get(), 1);
        assert_eq!(stats.packets_ip_filtered.get(), 0);
        let _ = std::fs::remove_file(tmp);
    }

    /// A perfectly well-formed Zoom video packet, but between two IPs
    /// neither of which is on the published Zoom server list — must be
    /// dropped by the IP filter before header parsing even runs, and
    /// counted as `packets_ip_filtered`, not `packets_matched`.
    #[test]
    fn valid_header_from_unlisted_ip_is_ip_filtered_not_captured() {
        let tmp = std::env::temp_dir().join("zoom_capture_test3.csv");
        let mut writer = CsvWriter::create(&tmp).unwrap();
        let stats = Stats::default();
        let meta = PacketMeta {
            time_offset: Duration::from_secs(0),
            frame_len: 200,
            src_ip: "1.2.3.4".into(),
            dst_ip: "5.6.7.8".into(),
            src_port: 8801,
            dst_port: 8801,
        };
        let matched = classify_and_record(meta, &video_packet(), &mut writer, &stats);
        assert!(!matched);
        assert_eq!(stats.packets_ip_filtered.get(), 1);
        assert_eq!(stats.packets_matched.get(), 0);
        assert_eq!(stats.packets_unmatched.get(), 0);
        let _ = std::fs::remove_file(tmp);
    }

    /// The client side (`src_ip`) is never on the published server list —
    /// only the far-end Zoom server is. Confirms the filter is `src OR
    /// dst`, not `AND`, since requiring both would drop every real packet.
    #[test]
    fn matches_on_either_endpoint_not_both() {
        let tmp = std::env::temp_dir().join("zoom_capture_test4.csv");
        let mut writer = CsvWriter::create(&tmp).unwrap();
        let stats = Stats::default();
        let meta = PacketMeta {
            time_offset: Duration::from_secs(0),
            frame_len: 200,
            src_ip: "144.195.28.40".into(), // known Zoom server, now as src
            dst_ip: "10.184.0.181".into(),  // capture-device LAN IP
            src_port: 8801,
            dst_port: 8801,
        };
        let matched = classify_and_record(meta, &video_packet(), &mut writer, &stats);
        assert!(matched);
        assert_eq!(stats.packets_ip_filtered.get(), 0);
        let _ = std::fs::remove_file(tmp);
    }
}
