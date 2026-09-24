#!/usr/bin/env python3
"""
pcap_to_zoom_csv.py -- independent, pure-Python reference implementation of
zoom_capture's classification pipeline, for cross-checking Risk #3 from the
project's zoom_capture code review (VLAN-tag handling in Retina's offline
replay path).

WHY THIS EXISTS
---------------
`zoom_capture` (the Rust/Retina crate) replays a .pcap/.pcapng file through
Retina's own Ethernet/VLAN/IP/UDP protocol stack before a packet ever
reaches this project's Zoom-header classification logic
(src/common/headers.rs, src/capture_logic/zoom/udp.rs). Whether that stack
correctly steps over a spurious 4-byte 802.1Q VLAN tag is untested here --
and it's exactly the bug class that silently dropped up to 53% of Device
A's frames in the *original* IMC'22 C++ tool, which hardcoded a 14-byte
Ethernet header and never accounted for the tag (deck.pdf slide 8; see also
this project's zoom_capture-code-review.md, risk #3).

This script re-implements the same classification pipeline from scratch, in
plain Python with its own from-scratch Ethernet/VLAN/IPv4/IPv6/UDP parser
(no scapy, no dpkt, no Retina, no DPDK) -- so it has no way to inherit
whatever bug Retina's parser might or might not have. Run it against the
same .pcapng file you feed to `zoom_capture -c config.offline.toml`, then
compare the two summary lines (and optionally the two CSVs) -- see "HOW TO
USE THIS FOR THE CROSS-CHECK" below.

WHAT IT MIRRORS FROM THE RUST CODE (and why)
---------------------------------------------
- IP list: the exact 48 IPv4 + 3 IPv6 CIDR blocks from
  src/common/ip_ranges.rs (sourced from zoom_ip_list.txt), so the "is this
  a known Zoom server" decision is identical between the two
  implementations. That list's own correctness was already verified
  separately (see the code review) by testing it in isolation -- so if a
  *count* differs between this script and the Rust binary's output on the
  same file, the IP list itself isn't the variable; packet parsing is.
- The Zoom SFU Encapsulation / Media Encapsulation header parsing from
  src/common/headers.rs, byte-for-byte: same 8-byte SFU header with byte 0
  == 0x05 as the "Media Encapsulation follows" marker, same direction-byte
  bitmask fix (tested with `&`, not `==`), same Media header field offsets
  (sequence at 9-10, timestamp at 11-14, frame_seq at 21-22, frame packet
  count at 23), same fallback to a bare Media header when byte 0 isn't
  0x05 (the P2P layout).
- The hard IP-gate added to src/capture_logic/zoom/udp.rs
  (classify_and_record): a packet is only classified if `src_ip` OR
  `dst_ip` is on the list. Pass --no-ip-filter to reproduce the *old*
  (pre-fix) behavior instead, if that comparison is ever useful.
- The CSV schema and summary-line shape from src/common/writer.rs and
  src/common/stats.rs, so the two CSVs are diffable column-for-column and
  the two summary lines are directly comparable.

WHAT IT DOES NOT MIRROR (read before diffing)
-----------------------------------------------
- **time_offset_s here is real.** This script reads the pcap/pcapng file's
  own per-packet timestamps and reports true seconds-since-first-frame.
  zoom_capture's *offline* replay mode does NOT do this: main.rs's own doc
  comment says every retina-datatypes timestamp is wall-clock
  (Instant::now()-based) even during offline replay, so its time_offset_s
  reflects how fast Retina replayed the file, not real inter-packet
  timing. Exclude column 1 when diffing the two CSVs, e.g.:
      cut -d, -f2- rust_output.csv    | sort > rust.sorted
      cut -d, -f2- audio1a_pyref.csv  | sort > py.sorted
      diff rust.sorted py.sorted
- No RTP/RTCP field parsing -- matches the Rust CSV schema, which also
  stops at the Zoom Media Encapsulation header.

HOW TO USE THIS FOR THE CROSS-CHECK
------------------------------------
1. Run this script against one of Device A's captures (the ones with the
   VLAN artifact, per deck.pdf slide 8):

       python3 pcap_to_zoom_csv.py A_caps/audio1a.pcapng -o audio1a_pyref.csv

   It prints two summary lines to stderr, e.g.:

       vlan_report: frames=12345 vlan_tagged=6789 (1-tag=6789 2+-tag=0) non_ip_or_bad_l2=12 non_udp=234
       zoom_capture stats (python reference): seen=12099 ip_filtered=302 matched=11797 unmatched=0 active_media=8850

   The `vlan_report` line's vlan_tagged count is the same thing the deck's
   own sanity check measured with `tshark -r ... -Y vlan -T fields -e
   frame.number | wc -l` (slide 9) -- run that tshark command on the same
   file and confirm it agrees with this script before trusting anything
   else, since if this script mis-detects VLAN tags the rest of the
   comparison is meaningless.

2. Point config.offline.toml's `pcap` field at the *same* file and run the
   real binary:

       sudo -E ./target/release/zoom_capture -c config.offline.toml

   It prints a line like:
       zoom_capture stats: seen=... ip_filtered=... matched=... unmatched=... active_media=...

3. Compare the two summary lines:
   - If `seen` is much lower from the Rust binary than from this script,
     Retina's own parser is probably dropping VLAN-tagged frames the way
     the old C++ tool did -- that confirms risk #3.
   - If `seen` matches but `matched`/`unmatched` differ, the discrepancy
     is somewhere else (e.g. a header-parsing regression), not VLAN
     handling specifically.
   - For a finer-grained check, diff the two CSVs with column 1 (the
     non-comparable timestamp) stripped, as shown above.

Requires only the Python standard library.
"""
from __future__ import annotations

import argparse
import gzip
import ipaddress
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional


# ── 1. zoom_ip_list.txt, ported verbatim from src/common/ip_ranges.rs ──────
# Keep this in sync with ip_ranges.rs by hand if that file is ever updated --
# there is no shared source of truth between the Rust crate and this script.

ZOOM_IPV4_CIDRS = [
    "3.7.35.0/25", "3.235.82.0/23", "3.235.96.0/23", "15.220.80.0/24",
    "15.220.81.0/25", "18.254.23.128/25", "18.254.61.0/25",
    "20.203.158.80/28", "20.203.190.192/26", "52.61.100.128/25",
    "64.211.144.0/24", "64.224.32.0/19", "69.174.108.0/22",
    "101.36.167.0/24", "101.36.170.0/23", "103.122.166.0/23",
    "111.33.115.0/25", "111.33.181.0/25", "115.110.154.192/26",
    "115.114.56.192/26", "115.114.115.0/26", "115.114.131.0/26",
    "121.244.146.0/27", "134.224.0.0/16", "137.66.128.0/17",
    "144.195.0.0/16", "147.124.96.0/19", "149.137.0.0/17",
    "156.45.0.0/17", "159.124.0.0/16", "160.1.56.128/25",
    "161.199.136.0/22", "162.12.232.0/22", "162.255.36.0/22",
    "166.108.64.0/18", "168.140.0.0/17", "170.114.0.0/16",
    "173.231.80.0/20", "192.204.12.0/23", "198.251.128.0/17",
    "203.200.219.128/27", "204.80.104.0/21", "206.247.0.0/16",
    "221.122.63.0/24", "221.122.64.0/24", "221.122.88.64/27",
    "221.122.88.128/25", "221.122.89.128/25", "221.123.139.192/27",
]
ZOOM_IPV6_CIDRS = [
    "2407:30c0::/32", "2600:9000:2600::/48", "2620:123:2000::/40",
]

_V4_NETS = [ipaddress.ip_network(c) for c in ZOOM_IPV4_CIDRS]
_V6_NETS = [ipaddress.ip_network(c) for c in ZOOM_IPV6_CIDRS]


def is_known_zoom_server_ip(ip_str: str) -> bool:
    """Mirrors common::ip_ranges::is_known_zoom_server_ip_str exactly."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    nets = _V6_NETS if addr.version == 6 else _V4_NETS
    return any(addr in net for net in nets)


# ── 2. Zoom SFU/Media Encapsulation header parsing, ported from
#       src/common/headers.rs byte-for-byte ────────────────────────────────

SFU_HEADER_LEN = 8
SFU_TYPE_MEDIA_FOLLOWS = 0x05
SFU_DIR_FROM_SFU_BIT = 0x04
MEDIA_HEADER_MIN_LEN = 15

_MEDIA_TYPE_LABELS = {
    16: "video",
    15: "audio",
    13: "screen_share_server",
    30: "screen_share_optimized",
    34: "rtcp_sr",
    33: "rtcp_sr",
    21: "unknown_21",
    10: "keepalive_10",
}
_ACTIVE_MEDIA_TYPES = {16, 15, 13, 30}


def media_type_label(raw_type: int) -> str:
    return _MEDIA_TYPE_LABELS.get(raw_type, "other")


def is_active_media_signal(raw_type: int) -> bool:
    return raw_type in _ACTIVE_MEDIA_TYPES


@dataclass
class ParsedZoom:
    sfu_direction_from_sfu: Optional[bool]
    media_type_byte: int
    media_type_label: str
    media_sequence: int
    media_timestamp: int
    frame_seq: Optional[int]
    frame_pkt_count: Optional[int]
    is_active_media_signal: bool


def _parse_media_header_fields(buf: bytes):
    """Returns (raw_type, sequence, timestamp, frame_seq, frame_pkt_count)
    or None if buf is too short -- mirrors parse_media_header in
    headers.rs."""
    if len(buf) < MEDIA_HEADER_MIN_LEN:
        return None
    raw_type = buf[0]
    sequence = int.from_bytes(buf[9:11], "big")
    timestamp = int.from_bytes(buf[11:15], "big")
    frame_seq = int.from_bytes(buf[21:23], "big") if len(buf) >= 23 else None
    frame_pkt_count = buf[23] if len(buf) >= 24 else None
    return raw_type, sequence, timestamp, frame_seq, frame_pkt_count


def parse_zoom_headers(buf: bytes) -> Optional[ParsedZoom]:
    """Mirrors parse_zoom_headers in headers.rs: try the SFU-wrapped layout
    first (server-relayed traffic), fall back to a bare Media header (the
    P2P layout) if byte 0 isn't the SFU 'media follows' marker."""
    sfu_direction_from_sfu = None
    rest = buf
    if len(buf) >= SFU_HEADER_LEN and buf[0] == SFU_TYPE_MEDIA_FOLLOWS:
        direction_raw = buf[7]
        sfu_direction_from_sfu = bool(direction_raw & SFU_DIR_FROM_SFU_BIT)
        rest = buf[SFU_HEADER_LEN:]

    parsed = _parse_media_header_fields(rest)
    if parsed is None:
        return None
    raw_type, sequence, timestamp, frame_seq, frame_pkt_count = parsed
    return ParsedZoom(
        sfu_direction_from_sfu=sfu_direction_from_sfu,
        media_type_byte=raw_type,
        media_type_label=media_type_label(raw_type),
        media_sequence=sequence,
        media_timestamp=timestamp,
        frame_seq=frame_seq,
        frame_pkt_count=frame_pkt_count,
        is_active_media_signal=is_active_media_signal(raw_type),
    )


# ── 3. pcap / pcapng reading (stdlib only) ──────────────────────────────────
#
# IMPORTANT distinction kept throughout this file: the pcap/pcapng *file
# container's* own metadata (global header, block headers, timestamps) can
# be little- or big-endian depending on the machine that wrote the file --
# that's what the `endian` variable below tracks. The *packet bytes
# themselves* (Ethernet/IP/UDP headers, once we're inside `data`) are
# always network byte order (big-endian), unconditionally, regardless of
# the capture file's own endianness. Section 4 below always uses "!"
# (network order) for that reason, never `endian`.

LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113


@dataclass
class RawFrame:
    frame_number: int
    ts_seconds: float   # real capture timestamp (seconds, arbitrary epoch)
    orig_len: int
    data: bytes          # captured bytes (may be shorter than orig_len)
    linktype: int


def _open_maybe_gzip(path: Path):
    with open(path, "rb") as f:
        first_two = f.read(2)
    if first_two == b"\x1f\x8b":
        return gzip.open(path, "rb")
    return open(path, "rb")


def read_frames(path: Path) -> Iterator[RawFrame]:
    with _open_maybe_gzip(path) as f:
        head = f.read(4)
        if len(head) < 4:
            return
        magic = struct.unpack("<I", head)[0]
        f.seek(0)
        if magic == 0x0A0D0D0A:
            yield from _read_pcapng(f)
        elif magic in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1):
            yield from _read_classic_pcap(f)
        else:
            raise ValueError(
                f"{path}: not a recognized pcap/pcapng file (first 4 bytes "
                f"read as {magic:#010x}); if this is really a capture "
                f"file, it may be a format this script doesn't handle."
            )


def _read_classic_pcap(f) -> Iterator[RawFrame]:
    global_hdr = f.read(24)
    if len(global_hdr) < 24:
        return
    magic = struct.unpack("<I", global_hdr[:4])[0]
    if magic == 0xA1B2C3D4:
        endian, ns = "<", False
    elif magic == 0xD4C3B2A1:
        endian, ns = ">", False
    elif magic == 0xA1B23C4D:
        endian, ns = "<", True
    elif magic == 0x4D3CB2A1:
        endian, ns = ">", True
    else:
        raise ValueError(f"unrecognized classic pcap magic {magic:#x}")
    (linktype,) = struct.unpack(endian + "I", global_hdr[20:24])

    frame_number = 0
    while True:
        rec_hdr = f.read(16)
        if len(rec_hdr) < 16:
            return
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", rec_hdr)
        data = f.read(incl_len)
        if len(data) < incl_len:
            return
        frame_number += 1
        ts = ts_sec + ts_frac / (1_000_000_000 if ns else 1_000_000)
        yield RawFrame(frame_number, ts, orig_len, data, linktype)


def _read_pcapng(f) -> Iterator[RawFrame]:
    frame_number = 0
    interfaces: list[dict] = []
    endian = "<"  # a bare SHB block-type is palindromic under byte-swap,
                  # so this default is safe until the first SHB corrects it

    while True:
        hdr = f.read(8)
        if len(hdr) < 8:
            return
        block_type = struct.unpack(endian + "I", hdr[:4])[0]

        if block_type == 0x0A0D0D0A:
            # Section Header Block. byte_order_magic (next 4 bytes) tells
            # us the endianness for the rest of this section; only once we
            # know that can hdr[4:8] (block_total_length) be interpreted.
            bom_bytes = f.read(4)
            (bom_le,) = struct.unpack("<I", bom_bytes)
            if bom_le == 0x1A2B3C4D:
                endian = "<"
            elif bom_le == 0x4D3C2B1A:
                endian = ">"
            else:
                raise ValueError(f"bad pcapng byte-order magic {bom_le:#x}")
            block_total_len = struct.unpack(endian + "I", hdr[4:8])[0]
            already_read = 12  # block_type + block_total_length + bom
            f.read(block_total_len - already_read)  # body + trailer, unused
            interfaces = []  # a new section resets interface numbering
            continue

        block_total_len = struct.unpack(endian + "I", hdr[4:8])[0]
        body = f.read(block_total_len - 12)
        trailer = f.read(4)
        if len(body) < block_total_len - 12 or len(trailer) < 4:
            return

        if block_type == 0x00000001:
            # Interface Description Block
            linktype, _reserved, _snaplen = struct.unpack(endian + "HHI", body[:8])
            tsresol_pow10, tsresol_pow2 = 6, None  # default: microseconds
            opts, off = body[8:], 0
            try:
                while off + 4 <= len(opts):
                    opt_code, opt_len = struct.unpack(endian + "HH", opts[off:off + 4])
                    if opt_code == 0 and opt_len == 0:
                        break
                    val = opts[off + 4: off + 4 + opt_len]
                    if opt_code == 9 and val:  # if_tsresol
                        b = val[0]
                        if b & 0x80:
                            tsresol_pow10, tsresol_pow2 = None, b & 0x7F
                        else:
                            tsresol_pow10, tsresol_pow2 = b, None
                    off += 4 + opt_len + ((4 - opt_len % 4) % 4)
            except struct.error:
                tsresol_pow10, tsresol_pow2 = 6, None  # malformed options: fall back
            interfaces.append({
                "linktype": linktype,
                "tsresol_pow10": tsresol_pow10,
                "tsresol_pow2": tsresol_pow2,
            })
            continue

        if block_type == 0x00000006:
            # Enhanced Packet Block
            iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                endian + "IIIII", body[:20]
            )
            data = body[20:20 + cap_len]
            frame_number += 1
            if iface_id < len(interfaces):
                iface = interfaces[iface_id]
            else:
                iface = {"linktype": LINKTYPE_ETHERNET, "tsresol_pow10": 6, "tsresol_pow2": None}
            ts_raw = (ts_high << 32) | ts_low
            divisor = (
                10 ** iface["tsresol_pow10"]
                if iface["tsresol_pow10"] is not None
                else 2 ** iface["tsresol_pow2"]
            )
            yield RawFrame(frame_number, ts_raw / divisor, orig_len, data, iface["linktype"])
            continue

        # Any other block type (Simple Packet Block, Name Resolution Block,
        # Interface Statistics Block, custom blocks, ...): already consumed
        # exactly block_total_len bytes above, so just loop for the next one.


# ── 4. Ethernet / VLAN / IPv4 / IPv6 / UDP parsing (stdlib only) ───────────

_VLAN_TPIDS = {0x8100, 0x88A8, 0x9100}


def _strip_vlan_tags(data: bytes, offset: int, ethertype: int, max_tags: int = 4):
    """Unwinds 0+ stacked 802.1Q/802.1ad VLAN tags starting at `offset`,
    returning (new_offset, real_ethertype, [vlan_id, ...outer-to-inner]),
    or (None, ethertype, tags_so_far) if a tag claims more bytes than the
    frame actually has (truncated capture).

    This is the exact place a hardcoded '14-byte Ethernet header'
    assumption (the original IMC'22 C++ tool's bug -- deck.pdf slide 8)
    goes wrong: each VLAN tag shifts everything after it by 4 bytes, and a
    parser that doesn't check for 0x8100/0x88a8/0x9100 before assuming
    IPv4/IPv6 starts right after the source MAC will either misparse the
    IP header or bail out on what looks like a garbled packet.
    """
    vlan_tags = []
    tags_seen = 0
    while ethertype in _VLAN_TPIDS and tags_seen < max_tags:
        if offset + 4 > len(data):
            return None, ethertype, vlan_tags
        tci = struct.unpack("!H", data[offset:offset + 2])[0]
        vlan_tags.append(tci & 0x0FFF)
        ethertype = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        offset += 4
        tags_seen += 1
    return offset, ethertype, vlan_tags


def parse_ethernet(data: bytes):
    """Returns (payload_offset, ethertype, vlan_tags) for a standard
    Ethernet II frame, or None if the frame is too short to even have a
    14-byte Ethernet header."""
    if len(data) < 14:
        return None
    ethertype = struct.unpack("!H", data[12:14])[0]
    offset, ethertype, vlan_tags = _strip_vlan_tags(data, 14, ethertype)
    if offset is None:
        return None
    return offset, ethertype, vlan_tags


def parse_linux_sll(data: bytes):
    """Linux cooked capture (DLT_LINUX_SLL, linktype 113): 16-byte header,
    protocol type at bytes 14-16, no MAC addresses. Included for
    robustness in case a capture was taken on Linux's 'any' pseudo-
    interface and saved with this linktype instead of plain Ethernet --
    'any'-interface setups are exactly what produced Device A's VLAN
    artifact in the first place (deck.pdf slide 8), so it's worth handling
    either way this data could have been captured."""
    if len(data) < 16:
        return None
    ethertype = struct.unpack("!H", data[14:16])[0]
    offset, ethertype, vlan_tags = _strip_vlan_tags(data, 16, ethertype)
    if offset is None:
        return None
    return offset, ethertype, vlan_tags


def parse_ipv4(data: bytes, offset: int):
    if offset + 20 > len(data):
        return None
    b0 = data[offset]
    version, ihl = b0 >> 4, (b0 & 0x0F) * 4
    if version != 4 or ihl < 20 or offset + ihl > len(data):
        return None
    total_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
    protocol = data[offset + 9]
    src_ip = ".".join(str(b) for b in data[offset + 12:offset + 16])
    dst_ip = ".".join(str(b) for b in data[offset + 16:offset + 20])
    l4_offset = offset + ihl
    # Trust the captured bytes over the header's own total_length when they
    # disagree (a snapped/truncated capture) -- clamp, never overrun.
    l4_end = min(len(data), offset + total_len) if total_len >= ihl else len(data)
    return protocol, src_ip, dst_ip, l4_offset, l4_end


# IPv6 extension headers using a uniform "next header + length in 8-byte
# units" layout (Fragment is the one fixed-size exception, handled below):
# 0=Hop-by-Hop, 43=Routing, 44=Fragment, 60=Destination Options, 51=AH.
_IPV6_EXT_HEADERS = {0, 43, 44, 60, 51}


def parse_ipv6(data: bytes, offset: int):
    if offset + 40 > len(data):
        return None
    if (data[offset] >> 4) != 6:
        return None
    payload_len = struct.unpack("!H", data[offset + 4:offset + 6])[0]
    next_header = data[offset + 6]
    src_ip = str(ipaddress.IPv6Address(bytes(data[offset + 8:offset + 24])))
    dst_ip = str(ipaddress.IPv6Address(bytes(data[offset + 24:offset + 40])))
    cur = offset + 40
    end = min(len(data), offset + 40 + payload_len) if payload_len else len(data)
    guard = 0
    while next_header in _IPV6_EXT_HEADERS and guard < 8:
        if cur + 2 > len(data):
            return None
        nh = data[cur]
        ext_len = 8 if next_header == 44 else (data[cur + 1] + 1) * 8
        next_header = nh
        cur += ext_len
        guard += 1
    return next_header, src_ip, dst_ip, cur, end


def parse_udp(data: bytes, offset: int, end: int):
    if offset + 8 > end or offset + 8 > len(data):
        return None
    src_port, dst_port, length = struct.unpack("!HHH", data[offset:offset + 6])
    payload_start = offset + 8
    payload_end = min(end, offset + length, len(data)) if length >= 8 else min(end, len(data))
    return src_port, dst_port, data[payload_start:payload_end]


# ── 5. Driver: read frames, classify, write CSV + summary ──────────────────

CSV_HEADER = (
    "time_offset_s,frame_len,src_ip,dst_ip,src_port,dst_port,"
    "sfu_direction_from_sfu,media_type_byte,media_type_label,media_sequence,"
    "media_timestamp,frame_seq,frame_pkt_count,is_active_media_signal"
)


def _fmt_opt_bool(v: Optional[bool]) -> str:
    return "" if v is None else ("true" if v else "false")


def _fmt_opt_int(v) -> str:
    return "" if v is None else str(v)


def _fmt_bool(v: bool) -> str:
    return "true" if v else "false"


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Independent Python reference for zoom_capture's "
        "classification pipeline, for cross-checking VLAN-tag handling "
        "(risk #3 in zoom_capture-code-review.md) against the Rust/Retina "
        "binary's own output. See the module docstring for full usage.",
    )
    ap.add_argument("pcap", type=Path, help=".pcap or .pcapng file to read")
    ap.add_argument(
        "-o", "--output", type=Path, default=None,
        help="output CSV path (default: <pcap stem>_pyref.csv next to the input)",
    )
    ap.add_argument(
        "--no-ip-filter", action="store_true",
        help="disable the zoom_ip_list IP gate, to reproduce the crate's "
        "behavior from before that filter was added",
    )
    ap.add_argument(
        "--linktype-override", type=int, default=None,
        help="force a linktype for every frame (1=Ethernet, 113=Linux SLL) "
        "instead of trusting each frame's own interface metadata",
    )
    args = ap.parse_args()

    out_path = args.output or args.pcap.with_name(args.pcap.stem + "_pyref.csv")

    total_frames = 0
    vlan_1tag = 0
    vlan_2plus = 0
    non_ip_or_bad_l2 = 0
    non_udp = 0
    seen = 0
    ip_filtered = 0
    matched = 0
    unmatched = 0
    active_media = 0
    unsupported_linktypes: set[int] = set()

    with open(out_path, "w", newline="\n") as out:
        out.write(CSV_HEADER + "\n")
        first_ts = None

        for frame in read_frames(args.pcap):
            total_frames += 1
            if first_ts is None:
                first_ts = frame.ts_seconds
            time_offset = frame.ts_seconds - first_ts

            linktype = args.linktype_override if args.linktype_override is not None else frame.linktype
            if linktype == LINKTYPE_ETHERNET:
                l2 = parse_ethernet(frame.data)
            elif linktype == LINKTYPE_LINUX_SLL:
                l2 = parse_linux_sll(frame.data)
            else:
                unsupported_linktypes.add(linktype)
                non_ip_or_bad_l2 += 1
                continue

            if l2 is None:
                non_ip_or_bad_l2 += 1
                continue
            offset, ethertype, vlan_tags = l2
            if len(vlan_tags) == 1:
                vlan_1tag += 1
            elif len(vlan_tags) >= 2:
                vlan_2plus += 1

            if ethertype == 0x0800:
                ip_parsed = parse_ipv4(frame.data, offset)
            elif ethertype == 0x86DD:
                ip_parsed = parse_ipv6(frame.data, offset)
            else:
                non_ip_or_bad_l2 += 1  # e.g. ARP, or a malformed VLAN/ethertype
                continue
            if ip_parsed is None:
                non_ip_or_bad_l2 += 1
                continue
            protocol, src_ip, dst_ip, l4_offset, l4_end = ip_parsed

            if protocol != 17:  # UDP
                non_udp += 1
                continue
            udp_parsed = parse_udp(frame.data, l4_offset, l4_end)
            if udp_parsed is None:
                non_udp += 1
                continue
            src_port, dst_port, payload = udp_parsed

            seen += 1

            if not args.no_ip_filter:
                if not (is_known_zoom_server_ip(src_ip) or is_known_zoom_server_ip(dst_ip)):
                    ip_filtered += 1
                    continue

            parsed = parse_zoom_headers(payload)
            if parsed is None:
                unmatched += 1
                continue

            matched += 1
            if parsed.is_active_media_signal:
                active_media += 1

            out.write(
                f"{time_offset:.6f},{frame.orig_len},{src_ip},{dst_ip},"
                f"{src_port},{dst_port},"
                f"{_fmt_opt_bool(parsed.sfu_direction_from_sfu)},"
                f"{parsed.media_type_byte},{parsed.media_type_label},"
                f"{parsed.media_sequence},{parsed.media_timestamp},"
                f"{_fmt_opt_int(parsed.frame_seq)},{_fmt_opt_int(parsed.frame_pkt_count)},"
                f"{_fmt_bool(parsed.is_active_media_signal)}\n"
            )

    vlan_tagged = vlan_1tag + vlan_2plus
    if unsupported_linktypes:
        print(
            f"warning: this file uses linktype(s) {sorted(unsupported_linktypes)}, "
            f"which this script doesn't know how to parse (only Ethernet=1 "
            f"and Linux SLL=113 are supported) -- those frames are counted "
            f"under non_ip_or_bad_l2 below, not actually parsed. Use "
            f"--linktype-override if one of those two is actually correct.",
            file=sys.stderr,
        )
    print(
        f"vlan_report: frames={total_frames} vlan_tagged={vlan_tagged} "
        f"(1-tag={vlan_1tag} 2+-tag={vlan_2plus}) "
        f"non_ip_or_bad_l2={non_ip_or_bad_l2} non_udp={non_udp}",
        file=sys.stderr,
    )
    print(
        f"zoom_capture stats (python reference): seen={seen} "
        f"ip_filtered={ip_filtered} matched={matched} unmatched={unmatched} "
        f"active_media={active_media}",
        file=sys.stderr,
    )
    print(f"wrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()