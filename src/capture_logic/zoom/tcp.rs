//! Zoom signaling/fallback detection over TCP, if needed.
//!
//! Not implemented. Neither the IMC'22 paper nor the Sept 2026
//! re-validation documents a TCP-side Zoom signaling channel this
//! project currently needs to parse — both focus entirely on the UDP
//! SFU/Media Encapsulation headers (see common/headers.rs). Revisit if a
//! future capture needs something TCP carries (e.g. call setup) that UDP
//! alone doesn't expose.
