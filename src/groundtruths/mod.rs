//! Detection against known Zoom call endpoints (controlled test calls
//! with known IPs/ports) — used to validate the heuristics in
//! capture_logic against ground truth. Mirrors
//! vpn_capture/src/groundtruths/.
//!
//! Status as of the Sept 2026 re-validation: this path is idle by
//! design, not by oversight. That re-validation looked specifically for
//! the P2P media path the IMC'22 paper describes (STUN on port 3478,
//! direct device-to-device UDP) across 9 scenarios x 2 devices and found
//! zero instances — every packet was SFU-relayed, all 18 captures. So
//! there's currently no known ground-truth-endpoint scenario this module
//! would need to distinguish from capture_logic's real-time path; kept
//! in the tree rather than deleted in case a different network path or
//! client version does trigger P2P.

pub mod zoom;
