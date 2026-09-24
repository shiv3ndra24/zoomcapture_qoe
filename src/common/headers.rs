//! Zoom's proprietary UDP header — parsing logic.
//!
//! Source of truth, in order of precedence:
//!   1. "Zoom header-format re-validation, Sept 2026" (`deck.pdf`) — a
//!      2026 re-capture (9 scenarios x 2 devices, ~990K packets) that
//!      independently re-derived every field against the IMC'22 paper's
//!      own artifact and scored each claim Holds / Refined / Does NOT hold.
//!   2. Michel, Sengupta, Kim, Netravali, Rexford, "Enabling Passive
//!      Measurement of Zoom Performance in Production Networks", IMC'22
//!      (`3517745.3561414.pdf`) — the original reverse-engineering.
//!
//! Where the two disagree, this file follows the 2026 re-validation and
//! says so in a comment, because that's the one checked against traffic
//! this project will actually see. Re-check periodically: the format is
//! undocumented and proprietary, so it can (and did, once already) drift.
//!
//! ## Wire layout
//!
//! Two headers stack before the real RTP/RTCP packet, on every Zoom UDP
//! payload:
//!
//! ```text
//! [ SFU Encapsulation (8B, server-relayed only) ] [ Media Encapsulation (variable) ] [ RTP / RTCP ]
//! ```
//!
//! - Server-relayed traffic: SFU Encapsulation, then Media Encapsulation.
//! - P2P traffic: Media Encapsulation directly (no SFU header) — per the
//!   2026 re-validation this path was never observed in 18 captures (see
//!   `groundtruths/zoom/`), so treat it as unverified/theoretical for now
//!   rather than dead code to delete outright.
//!
//! Both headers open with a 1-byte Type; the inner one also fixes where
//! the real RTP/RTCP header begins, via a type-dependent byte offset.

/// SFU Encapsulation is a fixed 8 bytes.
pub const SFU_HEADER_LEN: usize = 8;

/// SFU byte 0 == this value means "Media Encapsulation follows".
/// Re-validation: holds for 96.44% of server-relayed packets (n=900,144),
/// down slightly from the paper's 98.4% — stable enough to gate on.
pub const SFU_TYPE_MEDIA_FOLLOWS: u8 = 0x05;

/// SFU byte 7 ("Direction") bit meaning "packet is FROM the SFU"
/// (downlink). The paper claimed this byte is strictly 0x00 (to SFU) or
/// 0x04 (from SFU). Re-validation found dir==0 (49.4%) and dir==4 (46.4%)
/// cover 95.9% together, but dir==1 (2.1%) and dir==5 (2.1%) also appear,
/// and 5 == 4 | 1. That means byte 7 is a small **bitmask**, not a binary
/// enum — the 0x01 bit's meaning is unidentified. Decision: test this bit
/// with `&`, not `==`, so an unidentified extra flag doesn't misclassify
/// direction.
pub const SFU_DIR_FROM_SFU_BIT: u8 = 0x04;

/// Parsed SFU Encapsulation header (outer, server-relayed only).
#[derive(Debug, Clone, Copy)]
pub struct SfuHeader {
    pub raw_type: u8,
    /// Outer packet sequence number (bytes 1-2). Endianness not
    /// independently re-verified in the 2026 pass — treated as
    /// big-endian per the paper's dissector; revisit if sequence deltas
    /// look wrong on real traffic.
    pub sequence: u16,
    /// Byte 7, unmodified — use `from_sfu()` rather than comparing this
    /// directly, since it's a bitmask (see `SFU_DIR_FROM_SFU_BIT`).
    pub direction_raw: u8,
}

impl SfuHeader {
    /// `true` if this packet is server -> client (downlink).
    pub fn from_sfu(&self) -> bool {
        self.direction_raw & SFU_DIR_FROM_SFU_BIT != 0
    }
}

/// Parse an 8-byte SFU Encapsulation header. Returns `None` if `buf` is
/// too short or byte 0 isn't the "Media Encapsulation follows" type —
/// callers should fall back to treating `buf` as starting directly with
/// a Media Encapsulation header (the P2P layout) in that case.
pub fn parse_sfu_header(buf: &[u8]) -> Option<SfuHeader> {
    if buf.len() < SFU_HEADER_LEN {
        return None;
    }
    let raw_type = buf[0];
    if raw_type != SFU_TYPE_MEDIA_FOLLOWS {
        return None;
    }
    Some(SfuHeader {
        raw_type,
        sequence: u16::from_be_bytes([buf[1], buf[2]]),
        direction_raw: buf[7],
    })
}

/// Media Encapsulation Type byte (byte 0) values seen in the 2026
/// re-validation, with each one's share of inner-typed traffic and
/// whether the 2022 paper documented it. `n` is unlabeled below where
/// the deck didn't give an exact reproducible figure.
///
/// | Type | Share (2026) | In paper? |
/// |------|-------------|-----------|
/// | 16 (Video)          | 30.34% | yes |
/// | 21 (unknown)         | 21.13% | NO — new |
/// | 30 (Screen Share)    | 17.87% | no (paper's "P2P" label is wrong — see below) |
/// | 13 (Screen Share)    | 13.25% | yes |
/// | 15 (Audio)           | 8.17%  | yes |
/// | 10 / 7 (unknown)     | 4.22% / 4.13% | no |
/// | 32 (unknown)         | 0.42%  | no |
/// | 34 / 33 (RTCP)       | 0.27% / 0.09% | yes |
/// | 35 / 12 / 1 (unknown)| <0.1% each | no |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    /// Type 16 — RTP video. PT 98 ("main") + PT 110 ("FEC") in both eras;
    /// internal main/FEC split (89.98% / 10.02%) matches the paper's
    /// 91.0% / 9.0% closely enough that Table 3's video verdict is
    /// "Holds" outright — safe to key "is video on" off this type alone.
    Video,
    /// Type 15 — RTP audio. **Payload-type numbers changed**: the paper's
    /// PT 112 ("speaking", 22%) and PT 99 ("silent", 2.6%) are entirely
    /// absent in 2026; PT 116 (71.34%, new) and PT 113 (28.66%, was rare/
    /// mobile-only in the paper) now cover it. Don't hardcode PT112/99 as
    /// "the" audio payload types — if a payload-type check is added
    /// later, source it from a fresh capture, not the paper's Table 3.
    Audio,
    /// Type 13 — RTP screen share, server path. PT 99 "main" = 99.99%,
    /// matching the paper. New in 2026: an FEC substream on PT 110
    /// (3.84%) that the paper never lists for screen share — treat FEC
    /// as expected on this type, not an anomaly.
    ScreenShareServer,
    /// Type 30 (0x1e) — the paper's own code labels this
    /// `P2P_SCREEN_SHARE_TYPE`. That label does not hold: in the 2026
    /// captures every Type-30 packet's IP pair was
    /// `10.184.0.181 <-> 144.195.28.40`, and .40 is inside Zoom's
    /// published server subnets, not a peer. Type 30 tracks with
    /// screen-share-with-"optimize for video clip"-enabled instead,
    /// independent of P2P/SFU routing. Payload types match Type 13
    /// (PT 99 main 96.16%, PT 110 FEC 3.84%), so it's grouped as a
    /// screen-share variant here rather than its own capture_logic path.
    ScreenShareOptimized,
    /// Types 34 (SR+SDES) / 33 (SR) — RTCP. Holds: sender reports only,
    /// receiver reports are 0.055% noise (structural check, see below).
    RtcpSenderReport,
    /// Type 21 — **new, unexplained, 21.1% of inner-typed traffic** (the
    /// largest non-video category). Dominates the no-media control
    /// baseline (90-94% of `meet1`'s inner-typed packets) and stays
    /// continuous through every scenario regardless of audio/video/
    /// screen-share state (large packets too: mean 1023B, max 1088B —
    /// not a small keepalive). The paper's own Lua dissector already
    /// flags it "unclear what this type is".
    ///
    /// Decision that matters for capture_logic: **never treat Type-21
    /// presence as a "media is active" signal** — it's on the whole time
    /// the meeting is open, media or not. Any classifier keying off
    /// "is *any* inner-typed traffic present" instead of the specific
    /// media types above will read as "always on" and be useless.
    Unknown21,
    /// Type 10 — small (~70B), fixed-size, plausibly a keepalive.
    /// Unexplained in the paper. Not investigated further — out of scope
    /// for this pass, same as the rest of `Other`.
    Keepalive10,
    /// Every other type byte seen (7, 12, 32, 35, 1, ...) — together
    /// ~9% of inner-typed traffic, unexplained in both the paper and the
    /// 2026 re-validation. Carries the raw byte for logging/curiosity,
    /// but nothing downstream should branch on a specific value here
    /// without first confirming it against a fresh capture.
    Other(u8),
}

impl MediaType {
    pub fn from_type_byte(b: u8) -> Self {
        match b {
            16 => MediaType::Video,
            15 => MediaType::Audio,
            13 => MediaType::ScreenShareServer,
            30 => MediaType::ScreenShareOptimized,
            34 | 33 => MediaType::RtcpSenderReport,
            21 => MediaType::Unknown21,
            10 => MediaType::Keepalive10,
            other => MediaType::Other(other),
        }
    }

    /// `true` for the media types that should count toward "is this
    /// meeting doing audio/video/screenshare right now" — deliberately
    /// excludes `Unknown21`, `Keepalive10`, `RtcpSenderReport`, and
    /// `Other`, per the reasoning on `Unknown21` above.
    pub fn is_active_media_signal(&self) -> bool {
        matches!(
            self,
            MediaType::Video
                | MediaType::Audio
                | MediaType::ScreenShareServer
                | MediaType::ScreenShareOptimized
        )
    }

    /// Offset, in bytes from the *start of the Media Encapsulation
    /// header*, where the real RTP/RTCP header begins — Fig. 7 / Table 1
    /// of the paper, re-confirmed in the 2026 pass except where noted.
    ///
    /// Returns `RtpOffset::None` for types that aren't RTP/RTCP at all
    /// (Unknown21, Keepalive10, Other) so callers don't accidentally
    /// parse RTP out of an opaque channel.
    pub fn rtp_offset(&self) -> RtpOffset {
        match self {
            MediaType::Video => RtpOffset::Confirmed(24),
            MediaType::Audio => RtpOffset::Confirmed(19),
            MediaType::ScreenShareServer => RtpOffset::Confirmed(27),
            // The 2026 deck lists this offset as "conditional — label
            // turned out wrong" rather than giving a fixed +N the way it
            // does for the other types (slide 15). Best-effort guess:
            // reuse Type 13's offset, since Table 3 shows Type 30 shares
            // Type 13's RTP payload-type distribution (PT 99/110). Marked
            // Unconfirmed rather than Confirmed so callers can choose to
            // skip RTP parsing on this type until it's checked against a
            // real capture.
            MediaType::ScreenShareOptimized => RtpOffset::Unconfirmed(27),
            MediaType::RtcpSenderReport => RtpOffset::Confirmed(16),
            MediaType::Unknown21 | MediaType::Keepalive10 | MediaType::Other(_) => RtpOffset::None,
        }
    }
}

/// How much to trust a `MediaType::rtp_offset()` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtpOffset {
    /// Directly re-validated against 2026 traffic.
    Confirmed(usize),
    /// Best-effort, not independently confirmed — see the type's doc
    /// comment for why. Fine to try, but don't assert on the result.
    Unconfirmed(usize),
    /// This type isn't RTP/RTCP; there's nothing to offset into.
    None,
}

impl RtpOffset {
    pub fn value(&self) -> Option<usize> {
        match self {
            RtpOffset::Confirmed(n) | RtpOffset::Unconfirmed(n) => Some(*n),
            RtpOffset::None => None,
        }
    }
}

/// Media Encapsulation header (inner; present on both P2P and
/// server-relayed traffic). Only the fields this project currently uses
/// are pulled out — the full byte range up to `rtp_offset()` may contain
/// more, per the paper.
#[derive(Debug, Clone, Copy)]
pub struct MediaHeader {
    /// Byte 0, unparsed — kept alongside `media_type` so callers (e.g.
    /// the CSV writer) can log/inspect a raw value the `Other(u8)`
    /// variant would otherwise discard the meaning of.
    pub raw_type: u8,
    pub media_type: MediaType,
    /// Inner sequence number, bytes 9-10.
    pub sequence: u16,
    /// Media sampling timestamp, bytes 11-14.
    pub timestamp: u32,
    /// Frame sequence number, bytes 21-22 — video only (`None`
    /// otherwise; also `None` if the buffer is too short to contain it,
    /// which is expected for audio/RTCP where the header is shorter).
    pub frame_seq: Option<u16>,
    /// Packets in this frame, byte 23 — video only, same caveats.
    pub frame_pkt_count: Option<u8>,
}

/// Minimum length to safely read the fields this project uses (through
/// byte 14, the timestamp). The video-only fields at 21-23 are read
/// opportunistically and left `None` if the buffer doesn't reach them.
const MEDIA_HEADER_MIN_LEN: usize = 15;

/// Parse a Media Encapsulation header from `buf`, which must start at
/// the Media Encapsulation Type byte (i.e., already past the SFU header
/// if one was present).
pub fn parse_media_header(buf: &[u8]) -> Option<MediaHeader> {
    if buf.len() < MEDIA_HEADER_MIN_LEN {
        return None;
    }
    let raw_type = buf[0];
    let media_type = MediaType::from_type_byte(raw_type);
    let sequence = u16::from_be_bytes([buf[9], buf[10]]);
    let timestamp = u32::from_be_bytes([buf[11], buf[12], buf[13], buf[14]]);

    let frame_seq = if buf.len() >= 23 {
        Some(u16::from_be_bytes([buf[21], buf[22]]))
    } else {
        None
    };
    let frame_pkt_count = if buf.len() >= 24 { Some(buf[23]) } else { None };

    Some(MediaHeader {
        raw_type,
        media_type,
        sequence,
        timestamp,
        frame_seq,
        frame_pkt_count,
    })
}

/// Given `buf` = the full UDP payload, unwrap the SFU header (if
/// present) and locate the Media Encapsulation header. Returns
/// `(media_header, sfu_header, remaining_after_media_header)` where
/// `remaining_after_media_header` starts at the Media Encapsulation
/// Type byte — callers use `media_header.media_type.rtp_offset()` from
/// there to find RTP/RTCP.
pub fn parse_zoom_headers(buf: &[u8]) -> Option<(MediaHeader, Option<SfuHeader>, &[u8])> {
    if let Some(sfu) = parse_sfu_header(buf) {
        let rest = &buf[SFU_HEADER_LEN..];
        let media = parse_media_header(rest)?;
        Some((media, Some(sfu), rest))
    } else {
        // No SFU header recognized — either P2P traffic (per the 2026
        // re-validation, not observed in 18 captures, so treat this
        // branch as unverified) or `buf` isn't Zoom traffic at all.
        let media = parse_media_header(buf)?;
        Some((media, None, buf))
    }
}

/// Loose sanity check that `bytes`, read as an RTP header, has version 2
/// (the constant part of RFC 3550's first byte: top two bits == `10`).
/// Re-validation: holds for 99.72% of packets at a confirmed RTP offset;
/// the remaining ~0.3% is attributed to the offset heuristic locking
/// onto the wrong spot, not real protocol violations. Treat a `false`
/// here as "this offset was probably wrong", not "drop the packet" —
/// counting mismatches is more useful than filtering on them silently.
pub fn looks_like_rtp_version_2(bytes: &[u8]) -> bool {
    bytes.first().map(|b| (b >> 6) & 0b11 == 2).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sfu_and_media(media_type: u8, dir: u8) -> Vec<u8> {
        let mut buf = vec![0u8; SFU_HEADER_LEN + MEDIA_HEADER_MIN_LEN + 16];
        buf[0] = SFU_TYPE_MEDIA_FOLLOWS;
        buf[1] = 0x00;
        buf[2] = 0x2a; // outer seq = 42
        buf[7] = dir;
        buf[SFU_HEADER_LEN] = media_type; // media type byte
        buf
    }

    #[test]
    fn parses_sfu_then_media_video() {
        let buf = make_sfu_and_media(16, 0x05); // dir = from_sfu | unknown bit
        let (media, sfu, _rest) = parse_zoom_headers(&buf).expect("should parse");
        let sfu = sfu.expect("SFU header should be present");
        assert_eq!(sfu.sequence, 0x2a);
        assert!(sfu.from_sfu(), "0x05 has the 0x04 bit set");
        assert_eq!(media.media_type, MediaType::Video);
        assert_eq!(media.media_type.rtp_offset(), RtpOffset::Confirmed(24));
    }

    #[test]
    fn direction_is_a_bitmask_not_an_equality() {
        // dir == 1 alone (no 0x04 bit) must NOT read as "from SFU".
        let buf = make_sfu_and_media(15, 0x01);
        let (_media, sfu, _rest) = parse_zoom_headers(&buf).expect("should parse");
        assert!(!sfu.unwrap().from_sfu());
    }

    #[test]
    fn unknown21_has_no_rtp_offset_and_is_not_an_active_signal() {
        let mt = MediaType::from_type_byte(21);
        assert_eq!(mt.rtp_offset(), RtpOffset::None);
        assert!(!mt.is_active_media_signal());
    }

    #[test]
    fn too_short_buffer_does_not_panic() {
        assert!(parse_zoom_headers(&[0x05, 0x00]).is_none());
    }
}
