//! Hard IP/port filter against Zoom's published server ranges.
//!
//! Source: `zoom_ip_list.txt` (Zoom's official published ranges, the
//! same document the Sept 2026 re-validation deck cross-checked
//! `144.195.28.40` against on slide 59). Hardcoded here rather than
//! loaded from a file at runtime — it's a small, infrequently-changing
//! list and baking it in avoids a startup file dependency for a
//! capture tool that may run as root from cron/systemd. Re-copy from a
//! fresh `zoom_ip_list.txt` periodically; Zoom does update these.
//!
//! **This is now a hard filter, by explicit instruction — not just a
//! precheck.** `capture_logic::zoom::udp::classify_and_record` calls
//! [`is_known_zoom_server_ip_str`] before it even tries to parse a
//! packet's SFU/Media Encapsulation headers, and drops (doesn't record)
//! any packet where neither endpoint is on this list, regardless of
//! whether the payload would otherwise look like a valid Zoom header.
//!
//! Worth stating plainly, since an earlier version of this module
//! argued the opposite: the re-validation deck's finding was that
//! *type-byte* classification "strongly holds" as the way to tell what
//! kind of Zoom media a packet is — that finding is about
//! classification accuracy, not about whether IP-gating is a safe
//! precondition. Gating on this list first means the crate will now
//! silently miss any genuinely-Zoom packet whose server IP isn't in the
//! list (a stale list entry, or traffic relayed through an IP Zoom
//! hasn't published) — accepted tradeoff, per instruction, in exchange
//! for not recording anything from an endpoint that isn't a confirmed
//! Zoom server. `Stats::packets_ip_filtered` counts exactly these
//! drops, separately from `packets_unmatched` (header didn't parse),
//! so the two failure modes stay distinguishable in the summary.

use lazy_static::lazy_static;

/// TCP ports Zoom clients use, per `zoom_ip_list.txt`.
pub const ZOOM_TCP_PORTS: [u16; 3] = [443, 8801, 8802];

/// UDP ports Zoom clients use, per `zoom_ip_list.txt`. 8801-8810 is a
/// range in the source list, not individually enumerated ports.
pub fn is_zoom_udp_port(port: u16) -> bool {
    port == 3478 || port == 3479 || (8801..=8810).contains(&port)
}

pub fn is_zoom_tcp_port(port: u16) -> bool {
    ZOOM_TCP_PORTS.contains(&port)
}

/// An IPv4 CIDR block: `base` is the network address, `prefix_len` the
/// mask length (0-32).
#[derive(Debug, Clone, Copy)]
struct Cidr4 {
    base: u32,
    prefix_len: u8,
}

impl Cidr4 {
    fn contains(&self, ip: u32) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let mask = u32::MAX << (32 - self.prefix_len);
        (ip & mask) == (self.base & mask)
    }
}

/// An IPv6 CIDR block, same idea as [`Cidr4`] but over a 128-bit space.
#[derive(Debug, Clone, Copy)]
struct Cidr6 {
    base: u128,
    prefix_len: u8,
}

impl Cidr6 {
    fn contains(&self, ip: u128) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let mask = u128::MAX << (128 - self.prefix_len);
        (ip & mask) == (self.base & mask)
    }
}

fn parse_cidr4(s: &str) -> Cidr4 {
    let (addr, len) = s.split_once('/').expect("malformed IPv4 CIDR literal");
    // Explicit turbofish, not just the `Vec<u8>` binding type: in this
    // workspace's real dependency graph (unlike the isolated throwaway
    // crate this was first verified in) something else in the tree
    // supplies extra `FromIterator` impls for `Vec<u8>` (e.g. an
    // encode_unicode-style crate collecting `Utf8Char`s into bytes),
    // which makes plain `.parse()` ambiguous under `.collect()` even
    // with the `Vec<u8>` annotation on `octets` — rustc can no longer
    // tell `F=u8` apart from the other impls' item types. Pinning `F`
    // directly on `.parse()` removes the ambiguity regardless of what
    // else is in the dependency tree.
    let octets: Vec<u8> = addr.split('.').map(|o| o.parse::<u8>().expect("bad octet")).collect();
    assert_eq!(octets.len(), 4, "malformed IPv4 address: {addr}");
    let base = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
    Cidr4 { base, prefix_len: len.parse().expect("bad prefix length") }
}

fn parse_cidr6(s: &str) -> Cidr6 {
    let (addr, len) = s.split_once('/').expect("malformed IPv6 CIDR literal");
    let ip: std::net::Ipv6Addr = addr.parse().expect("bad IPv6 address");
    Cidr6 { base: u128::from(ip), prefix_len: len.parse().expect("bad prefix length") }
}

/// IPv4 ranges from `zoom_ip_list.txt`. The source list repeats (almost)
/// the same set under its TCP and UDP sections; deduplicated here since
/// this module checks IP membership independent of port/protocol (call
/// `is_zoom_tcp_port`/`is_zoom_udp_port` separately if the protocol
/// matters for the check).
const ZOOM_IPV4_CIDR_STRS: &[&str] = &[
    "3.7.35.0/25",
    "3.235.82.0/23",
    "3.235.96.0/23",
    "15.220.80.0/24",
    "15.220.81.0/25",
    "18.254.23.128/25",
    "18.254.61.0/25",
    "20.203.158.80/28",
    "20.203.190.192/26",
    "52.61.100.128/25",
    "64.211.144.0/24",
    "64.224.32.0/19",
    "69.174.108.0/22",
    "101.36.167.0/24",
    "101.36.170.0/23",
    "103.122.166.0/23",
    "111.33.115.0/25",
    "111.33.181.0/25",
    "115.110.154.192/26",
    "115.114.56.192/26",
    "115.114.115.0/26",
    "115.114.131.0/26",
    "121.244.146.0/27",
    "134.224.0.0/16",
    "137.66.128.0/17",
    "144.195.0.0/16", // contains 144.195.28.40, the endpoint re-validated on slide 59
    "147.124.96.0/19",
    "149.137.0.0/17",
    "156.45.0.0/17",
    "159.124.0.0/16",
    "160.1.56.128/25",
    "161.199.136.0/22",
    "162.12.232.0/22",
    "162.255.36.0/22",
    "166.108.64.0/18",
    "168.140.0.0/17",
    "170.114.0.0/16",
    "173.231.80.0/20",
    "192.204.12.0/23",
    "198.251.128.0/17",
    "203.200.219.128/27",
    "204.80.104.0/21",
    "206.247.0.0/16",
    "221.122.63.0/24",
    "221.122.64.0/24",
    "221.122.88.64/27",
    "221.122.88.128/25",
    "221.122.89.128/25",
    "221.123.139.192/27",
];

const ZOOM_IPV6_CIDR_STRS: &[&str] = &["2407:30c0::/32", "2600:9000:2600::/48", "2620:123:2000::/40"];

lazy_static! {
    static ref ZOOM_IPV4_CIDRS: Vec<Cidr4> = ZOOM_IPV4_CIDR_STRS.iter().map(|s| parse_cidr4(s)).collect();
    static ref ZOOM_IPV6_CIDRS: Vec<Cidr6> = ZOOM_IPV6_CIDR_STRS.iter().map(|s| parse_cidr6(s)).collect();
}

pub fn is_known_zoom_server_ipv4(ip: [u8; 4]) -> bool {
    let ip_u32 = u32::from_be_bytes(ip);
    ZOOM_IPV4_CIDRS.iter().any(|c| c.contains(ip_u32))
}

pub fn is_known_zoom_server_ipv6(ip: std::net::Ipv6Addr) -> bool {
    let ip_u128 = u128::from(ip);
    ZOOM_IPV6_CIDRS.iter().any(|c| c.contains(ip_u128))
}

/// Same check as [`is_known_zoom_server_ipv4`]/[`is_known_zoom_server_ipv6`],
/// but taking an IP as text — the form `PacketMeta::src_ip`/`dst_ip` are
/// already stored in (`std::net::IpAddr::to_string()`, from `main.rs`'s
/// `FiveTuple`), so the capture path can call this directly without an
/// extra round trip through a typed `IpAddr`.
///
/// Returns `false` (never panics) if `ip` doesn't parse as an IPv4 or IPv6
/// address at all — that shouldn't happen for a string that came from a
/// real `IpAddr`, but a malformed/unexpected value should read as "not a
/// known Zoom endpoint," not crash the capture loop over a formatting
/// surprise.
pub fn is_known_zoom_server_ip_str(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => is_known_zoom_server_ipv4(v4.octets()),
        Ok(std::net::IpAddr::V6(v6)) => is_known_zoom_server_ipv6(v6),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn the_re_validated_endpoint_matches() {
        // 144.195.28.40 is the exact server IP the Sept 2026 deck
        // confirmed a Type-30 flow against (slide 59) — the one concrete
        // data point tying this list to real traffic this project saw.
        assert!(is_known_zoom_server_ipv4([144, 195, 28, 40]));
    }

    #[test]
    fn boundary_of_a_slash_25_is_exact() {
        // 3.7.35.0/25 covers .0-.127, not .128.
        assert!(is_known_zoom_server_ipv4([3, 7, 35, 0]));
        assert!(is_known_zoom_server_ipv4([3, 7, 35, 127]));
        assert!(!is_known_zoom_server_ipv4([3, 7, 35, 128]));
    }

    #[test]
    fn unrelated_ip_does_not_match() {
        assert!(!is_known_zoom_server_ipv4([8, 8, 8, 8]));
    }

    #[test]
    fn ipv6_prefix_matches() {
        let ip: Ipv6Addr = "2600:9000:2600::1234".parse().unwrap();
        assert!(is_known_zoom_server_ipv6(ip));
        let not_ip: Ipv6Addr = "2600:9001::1".parse().unwrap();
        assert!(!is_known_zoom_server_ipv6(not_ip));
    }

    #[test]
    fn port_helpers() {
        assert!(is_zoom_udp_port(8805));
        assert!(is_zoom_udp_port(3478));
        assert!(!is_zoom_udp_port(8811));
        assert!(is_zoom_tcp_port(443));
        assert!(!is_zoom_tcp_port(3478));
    }

    #[test]
    fn str_variant_matches_v4_and_v6() {
        assert!(is_known_zoom_server_ip_str("144.195.28.40"));
        assert!(is_known_zoom_server_ip_str("2600:9000:2600::1234"));
        assert!(!is_known_zoom_server_ip_str("10.184.0.181")); // a capture-device LAN IP, not a Zoom server
        assert!(!is_known_zoom_server_ip_str("8.8.8.8"));
    }

    #[test]
    fn str_variant_does_not_panic_on_garbage() {
        assert!(!is_known_zoom_server_ip_str("not an ip"));
        assert!(!is_known_zoom_server_ip_str(""));
    }
}
