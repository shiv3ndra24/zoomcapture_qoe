//! Output: one CSV row per classified Zoom packet, plus a pcap of the
//! matched traffic. Mirrors vpn_capture's writer shape (pcap + CSV under
//! captures/run_<timestamp>/), specialized to the fields this project
//! actually classifies.
//!
//! Column choice is deliberate, not just "dump everything": the 2026
//! re-validation deck's own analysis pipeline (`analyze_claims.py`,
//! `timing_plots.py`) worked from exactly this shape — one row per
//! packet with `(time, media_type)` at minimum — and that's what showed
//! the practical classification technique "strongly holds" across all 9
//! scenarios (see headers.rs's module doc). So the CSV schema here is
//! shaped to make that same kind of timing-plot analysis possible
//! directly on this crate's own output, not just on tshark extractions.

use crate::common::headers::{MediaHeader, MediaType, SfuHeader};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::time::Duration;

/// One row of the packet-level CSV.
#[derive(Debug, Clone)]
pub struct PacketRecord {
    /// Seconds since capture start — matches the x-axis the 2026 deck's
    /// timing plots use, so any CSV this writes is a drop-in replacement
    /// for that analysis pipeline's input.
    pub time_offset: Duration,
    pub frame_len: usize,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    /// `None` for P2P-layout packets (no SFU header) — expected to be
    /// rare-to-never per the 2026 re-validation (see groundtruths/zoom).
    pub sfu_direction_from_sfu: Option<bool>,
    pub media_type_byte: u8,
    pub media_type_label: &'static str,
    pub media_sequence: u16,
    pub media_timestamp: u32,
    pub frame_seq: Option<u16>,
    pub frame_pkt_count: Option<u8>,
    /// True only for the media types that should count as "audio/video/
    /// screenshare is active" — i.e. NOT Type 21, NOT RTCP, NOT unknown.
    /// See `MediaType::is_active_media_signal` for the reasoning.
    pub is_active_media_signal: bool,
}

impl PacketRecord {
    pub fn label_for(media_type: &MediaType) -> &'static str {
        match media_type {
            MediaType::Video => "video",
            MediaType::Audio => "audio",
            MediaType::ScreenShareServer => "screen_share_server",
            MediaType::ScreenShareOptimized => "screen_share_optimized",
            MediaType::RtcpSenderReport => "rtcp_sr",
            MediaType::Unknown21 => "unknown_21",
            MediaType::Keepalive10 => "keepalive_10",
            MediaType::Other(_) => "other",
        }
    }

    pub fn from_headers(
        time_offset: Duration,
        frame_len: usize,
        src_ip: String,
        dst_ip: String,
        src_port: u16,
        dst_port: u16,
        sfu: Option<SfuHeader>,
        media: MediaHeader,
    ) -> Self {
        PacketRecord {
            time_offset,
            frame_len,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            sfu_direction_from_sfu: sfu.map(|s| s.from_sfu()),
            media_type_byte: media.raw_type,
            media_type_label: Self::label_for(&media.media_type),
            media_sequence: media.sequence,
            media_timestamp: media.timestamp,
            frame_seq: media.frame_seq,
            frame_pkt_count: media.frame_pkt_count,
            is_active_media_signal: media.media_type.is_active_media_signal(),
        }
    }
}

const CSV_HEADER: &str = "time_offset_s,frame_len,src_ip,dst_ip,src_port,dst_port,\
sfu_direction_from_sfu,media_type_byte,media_type_label,media_sequence,media_timestamp,\
frame_seq,frame_pkt_count,is_active_media_signal";

/// CSV writer for `PacketRecord`s. Kept dependency-free (no `csv` crate)
/// to match vpn_capture's writer, which does its own formatting rather
/// than pulling in another crate for a fixed, small schema.
pub struct CsvWriter {
    inner: BufWriter<File>,
}

impl CsvWriter {
    pub fn create(path: &std::path::Path) -> io::Result<Self> {
        let file = File::create(path)?;
        let mut inner = BufWriter::new(file);
        writeln!(inner, "{CSV_HEADER}")?;
        Ok(CsvWriter { inner })
    }

    pub fn write_record(&mut self, r: &PacketRecord) -> io::Result<()> {
        writeln!(
            self.inner,
            "{:.6},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            r.time_offset.as_secs_f64(),
            r.frame_len,
            r.src_ip,
            r.dst_ip,
            r.src_port,
            r.dst_port,
            opt_bool(r.sfu_direction_from_sfu),
            r.media_type_byte,
            r.media_type_label,
            r.media_sequence,
            r.media_timestamp,
            opt_u16(r.frame_seq),
            opt_u8(r.frame_pkt_count),
            r.is_active_media_signal,
        )
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn opt_bool(v: Option<bool>) -> String {
    v.map(|b| b.to_string()).unwrap_or_default()
}
fn opt_u16(v: Option<u16>) -> String {
    v.map(|n| n.to_string()).unwrap_or_default()
}
fn opt_u8(v: Option<u8>) -> String {
    v.map(|n| n.to_string()).unwrap_or_default()
}

/// Build the output directory for one capture run:
/// `captures/run_<unix_ts>/`, matching vpn_capture's convention.
pub fn output_dir() -> io::Result<std::path::PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let dir = std::path::PathBuf::from(format!("captures/run_{ts}"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
