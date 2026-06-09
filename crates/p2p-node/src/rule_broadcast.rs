//! Outbound rule lifecycle event broadcasting over Gossipsub.
//!
//! Provides:
//! - `RuleEventRateLimiter`: sliding window rate limiter (10 events/min)
//! - `sign_rule_event()`: Ed25519 signing of outbound rule events
//! - `RuleBroadcaster`: combines rate limiting + signing into a single broadcast API

use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};

// Re-export canonical bridge types from rete-alpha.
use rete_alpha::bridge::OutboundRuleEvent;
#[cfg(test)]
use rete_alpha::bridge::RuleEventType;

// ============================================================================
// Constants
// ============================================================================

/// Maximum outbound rule events per minute.
pub const MAX_EVENTS_PER_MINUTE: usize = 10;

/// Wire protocol version.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Gossipsub P4 invalid message weight.
pub const P4_INVALID_MESSAGE_WEIGHT: f64 = -100.0;

/// Gossipsub P3 rate penalty threshold.
pub const P3_RATE_PENALTY_THRESHOLD: u32 = 20;

// ============================================================================
// BroadcastError
// ============================================================================

/// Errors that can occur during rule event broadcasting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastError {
    /// Rate limiter rejected the event (10/min cap exceeded).
    RateLimited,
    /// Ed25519 signing failed (should not happen with valid key).
    SigningError,
}

impl std::fmt::Display for BroadcastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BroadcastError::RateLimited => write!(f, "rate limited: exceeded 10 events/min"),
            BroadcastError::SigningError => write!(f, "Ed25519 signing error"),
        }
    }
}

impl std::error::Error for BroadcastError {}

// ============================================================================
// Timestamp helper
// ============================================================================

/// Current time in unix seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Current time in microseconds.
fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

// ============================================================================
// RuleEventRateLimiter
// ============================================================================

/// Sliding window rate limiter for outbound rule events.
///
/// Enforces the 10 events/minute cap.
/// Uses a VecDeque of timestamps to implement the sliding window.
pub struct RuleEventRateLimiter {
    /// Timestamps (unix seconds) of recent events within the window.
    events: VecDeque<u64>,
    /// Maximum events allowed per minute.
    max_per_minute: usize,
}

impl RuleEventRateLimiter {
    /// Create a new rate limiter with the standard 10/min cap.
    pub fn new() -> Self {
        Self {
            events: VecDeque::new(),
            max_per_minute: MAX_EVENTS_PER_MINUTE,
        }
    }

    /// Create a rate limiter with a custom cap (for testing).
    pub fn with_limit(max_per_minute: usize) -> Self {
        Self {
            events: VecDeque::new(),
            max_per_minute,
        }
    }

    /// Try to acquire a rate limit slot. Returns true if under the limit
    /// (and records the event), false if rate limited.
    pub fn try_acquire(&mut self) -> bool {
        self.try_acquire_at(now_secs())
    }

    /// Try to acquire at a specific timestamp (for deterministic testing).
    pub fn try_acquire_at(&mut self, now: u64) -> bool {
        let cutoff = now.saturating_sub(60);

        // Remove expired entries from the front
        while self.events.front().is_some_and(|&t| t < cutoff) {
            self.events.pop_front();
        }

        if self.events.len() < self.max_per_minute {
            self.events.push_back(now);
            true
        } else {
            false
        }
    }

    /// Current count of events in the sliding window.
    pub fn current_count(&self) -> usize {
        self.events.len()
    }

    /// Reset the rate limiter (clear all recorded events).
    pub fn reset(&mut self) {
        self.events.clear();
    }
}

impl Default for RuleEventRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// sign_rule_event -- create a signed Gossipsub message
// ============================================================================

/// Create a signed Gossipsub message from an OutboundRuleEvent.
///
/// Wire format:
/// - Byte 0:      protocol_version (0x01)
/// - Byte 1:      event_type (0x01-0x05)
/// - Bytes 2-9:   event_timestamp (u64 big-endian, microseconds)
/// - Bytes 10-13: shard_key_hash (u32 big-endian)
/// - Bytes 14-77: Ed25519 signature (64 bytes)
/// - Bytes 78-79: payload_length (u16 big-endian)
/// - Bytes 80+:   payload
///
/// The signature covers header (14 bytes) + payload (NOT the signature placeholder).
pub fn sign_rule_event(event: &OutboundRuleEvent, signing_key: &SigningKey) -> Vec<u8> {
    sign_rule_event_at(event, signing_key, now_micros())
}

/// Sign with an explicit timestamp (for deterministic testing).
pub fn sign_rule_event_at(
    event: &OutboundRuleEvent,
    signing_key: &SigningKey,
    timestamp_us: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80 + event.payload.len());

    // Header (14 bytes)
    buf.push(PROTOCOL_VERSION);
    buf.push(event.event_type as u8);
    buf.extend_from_slice(&timestamp_us.to_be_bytes());
    buf.extend_from_slice(&event.shard_key_hash.to_be_bytes());

    // Placeholder for signature (64 bytes)
    let sig_offset = buf.len();
    buf.extend_from_slice(&[0u8; 64]);

    // Payload length + payload
    buf.extend_from_slice(&(event.payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(&event.payload);

    // Compute signature over header + payload (NOT the signature placeholder)
    let mut sign_data = Vec::with_capacity(14 + event.payload.len());
    sign_data.extend_from_slice(&buf[..14]); // header
    sign_data.extend_from_slice(&event.payload); // payload
    let signature = signing_key.sign(&sign_data);
    buf[sig_offset..sig_offset + 64].copy_from_slice(&signature.to_bytes());

    buf
}

// ============================================================================
// RuleBroadcaster
// ============================================================================

/// Combines signing + rate limiting for outbound rule event broadcasting.
///
/// Usage:
/// ```ignore
/// let broadcaster = RuleBroadcaster::new(signing_key);
/// match broadcaster.broadcast(&event) {
///     Ok(wire_bytes) => gossipsub.publish(topic, wire_bytes),
///     Err(BroadcastError::RateLimited) => { /* back off */ }
///     Err(BroadcastError::SigningError) => { /* log error */ }
/// }
/// ```
pub struct RuleBroadcaster {
    signing_key: SigningKey,
    rate_limiter: RuleEventRateLimiter,
}

impl RuleBroadcaster {
    /// Create a new broadcaster with the given signing key and default rate limit.
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            signing_key,
            rate_limiter: RuleEventRateLimiter::new(),
        }
    }

    /// Create a broadcaster with a custom rate limit (for testing).
    pub fn with_rate_limit(signing_key: SigningKey, max_per_minute: usize) -> Self {
        Self {
            signing_key,
            rate_limiter: RuleEventRateLimiter::with_limit(max_per_minute),
        }
    }

    /// Broadcast a rule event: rate-limit check + sign + return wire bytes.
    ///
    /// Returns `Ok(Vec<u8>)` with the complete signed wire message ready
    /// for Gossipsub publish, or `Err(BroadcastError)` if rate limited.
    pub fn broadcast(&mut self, event: &OutboundRuleEvent) -> Result<Vec<u8>, BroadcastError> {
        if !self.rate_limiter.try_acquire() {
            return Err(BroadcastError::RateLimited);
        }
        Ok(sign_rule_event(event, &self.signing_key))
    }

    /// Broadcast with explicit timestamp (for deterministic testing).
    pub fn broadcast_at(
        &mut self,
        event: &OutboundRuleEvent,
        now_secs: u64,
        now_micros: u64,
    ) -> Result<Vec<u8>, BroadcastError> {
        if !self.rate_limiter.try_acquire_at(now_secs) {
            return Err(BroadcastError::RateLimited);
        }
        Ok(sign_rule_event_at(event, &self.signing_key, now_micros))
    }

    /// Get a reference to the rate limiter.
    pub fn rate_limiter(&self) -> &RuleEventRateLimiter {
        &self.rate_limiter
    }

    /// Get a mutable reference to the rate limiter.
    pub fn rate_limiter_mut(&mut self) -> &mut RuleEventRateLimiter {
        &mut self.rate_limiter
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // Fixed seed for deterministic key generation.
    const TEST_SEED: u64 = 0xCAFE_BABE_DEAD_BEEF;

    fn test_signing_key() -> SigningKey {
        let mut rng = ChaCha20Rng::seed_from_u64(TEST_SEED);
        SigningKey::generate(&mut rng)
    }

    fn make_test_event(event_type: RuleEventType) -> OutboundRuleEvent {
        OutboundRuleEvent {
            event_type,
            payload: vec![0xCA, 0xFE, 0xBA, 0xBE],
            shard_key_hash: 0xDEADBEEF,
        }
    }

    // ── Rate limiter tests ───────────────────────────────────────────────

    #[test]
    fn rate_limiter_allows_up_to_limit() {
        let mut rl = RuleEventRateLimiter::new();
        let now = 1000u64;
        for i in 0..MAX_EVENTS_PER_MINUTE {
            assert!(rl.try_acquire_at(now), "Event {} should be allowed", i + 1);
        }
        assert!(!rl.try_acquire_at(now), "Event 11 should be rejected");
    }

    #[test]
    fn rate_limiter_window_slides() {
        let mut rl = RuleEventRateLimiter::new();
        let t0 = 1000u64;

        // Fill up at t0
        for _ in 0..MAX_EVENTS_PER_MINUTE {
            assert!(rl.try_acquire_at(t0));
        }
        assert!(!rl.try_acquire_at(t0));

        // After 61 seconds, window should have slid past all t0 events
        assert!(rl.try_acquire_at(t0 + 61));
    }

    #[test]
    fn rate_limiter_partial_window_slide() {
        let mut rl = RuleEventRateLimiter::new();
        let t0 = 1000u64;

        // Insert 5 at t0
        for _ in 0..5 {
            assert!(rl.try_acquire_at(t0));
        }

        // Insert 5 at t0+30
        for _ in 0..5 {
            assert!(rl.try_acquire_at(t0 + 30));
        }

        // At t0+30, we have 10 events, should be full
        assert!(!rl.try_acquire_at(t0 + 30));

        // At t0+61, the first 5 expired, so 5 slots free
        assert!(rl.try_acquire_at(t0 + 61));
    }

    #[test]
    fn rate_limiter_custom_limit() {
        let mut rl = RuleEventRateLimiter::with_limit(3);
        let now = 1000u64;
        assert!(rl.try_acquire_at(now));
        assert!(rl.try_acquire_at(now));
        assert!(rl.try_acquire_at(now));
        assert!(!rl.try_acquire_at(now));
    }

    #[test]
    fn rate_limiter_current_count() {
        let mut rl = RuleEventRateLimiter::new();
        assert_eq!(rl.current_count(), 0);
        rl.try_acquire_at(1000);
        assert_eq!(rl.current_count(), 1);
        rl.try_acquire_at(1000);
        assert_eq!(rl.current_count(), 2);
    }

    #[test]
    fn rate_limiter_reset() {
        let mut rl = RuleEventRateLimiter::new();
        for _ in 0..5 {
            rl.try_acquire_at(1000);
        }
        assert_eq!(rl.current_count(), 5);
        rl.reset();
        assert_eq!(rl.current_count(), 0);
    }

    #[test]
    fn rate_limiter_default() {
        let rl = RuleEventRateLimiter::default();
        assert_eq!(rl.max_per_minute, MAX_EVENTS_PER_MINUTE);
        assert_eq!(rl.current_count(), 0);
    }

    // ── Sign rule event tests ────────────────────────────────────────────

    #[test]
    fn sign_rule_event_produces_valid_wire_format() {
        let sk = test_signing_key();
        let event = make_test_event(RuleEventType::NewRule);
        let ts = 1_000_000_000_000u64;
        let wire = sign_rule_event_at(&event, &sk, ts);

        // Check header
        assert_eq!(wire[0], PROTOCOL_VERSION);
        assert_eq!(wire[1], RuleEventType::NewRule as u8);

        // Check timestamp
        let parsed_ts = u64::from_be_bytes(wire[2..10].try_into().unwrap());
        assert_eq!(parsed_ts, ts);

        // Check shard_key_hash
        let parsed_hash = u32::from_be_bytes(wire[10..14].try_into().unwrap());
        assert_eq!(parsed_hash, 0xDEADBEEF);

        // Check payload_length
        let payload_len = u16::from_be_bytes(wire[78..80].try_into().unwrap());
        assert_eq!(payload_len as usize, event.payload.len());

        // Check payload content
        assert_eq!(&wire[80..80 + event.payload.len()], &event.payload);

        // Verify total size
        assert_eq!(wire.len(), 80 + event.payload.len());
    }

    #[test]
    fn sign_rule_event_signature_verifies() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let event = make_test_event(RuleEventType::ConfidenceUpdate);
        let ts = 2_000_000_000_000u64;
        let wire = sign_rule_event_at(&event, &sk, ts);

        // Extract signature
        let sig_bytes: [u8; 64] = wire[14..78].try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        // Build signed data (header + payload)
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&wire[..14]);
        signed_data.extend_from_slice(&event.payload);

        assert!(vk.verify(&signed_data, &signature).is_ok());
    }

    #[test]
    fn sign_rule_event_tampered_payload_fails_verify() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let event = make_test_event(RuleEventType::NewRule);
        let wire = sign_rule_event_at(&event, &sk, 1000000);

        // Extract signature
        let sig_bytes: [u8; 64] = wire[14..78].try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        // Tamper with payload in signed_data
        let mut tampered = Vec::new();
        tampered.extend_from_slice(&wire[..14]);
        tampered.extend_from_slice(&[0xFF; 4]); // wrong payload

        assert!(vk.verify(&tampered, &signature).is_err());
    }

    #[test]
    fn sign_rule_event_empty_payload() {
        let sk = test_signing_key();
        let event = OutboundRuleEvent {
            event_type: RuleEventType::Tombstone,
            payload: vec![],
            shard_key_hash: 0,
        };
        let wire = sign_rule_event_at(&event, &sk, 42);

        assert_eq!(wire.len(), 80); // header + sig + payload_len(0) + no payload
        let payload_len = u16::from_be_bytes(wire[78..80].try_into().unwrap());
        assert_eq!(payload_len, 0);
    }

    #[test]
    fn sign_rule_event_all_event_types() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();

        for et in [
            RuleEventType::NewRule,
            RuleEventType::ConfidenceUpdate,
            RuleEventType::StateTransition,
            RuleEventType::Tombstone,
            RuleEventType::Merge,
        ] {
            let event = make_test_event(et);
            let wire = sign_rule_event_at(&event, &sk, 1000000);

            assert_eq!(wire[1], et as u8);

            // Verify signature
            let sig_bytes: [u8; 64] = wire[14..78].try_into().unwrap();
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            let mut signed_data = Vec::new();
            signed_data.extend_from_slice(&wire[..14]);
            signed_data.extend_from_slice(&event.payload);
            assert!(vk.verify(&signed_data, &signature).is_ok());
        }
    }

    #[test]
    fn sign_rule_event_deterministic() {
        let sk = test_signing_key();
        let event = make_test_event(RuleEventType::NewRule);
        let ts = 999_999_999u64;

        let wire1 = sign_rule_event_at(&event, &sk, ts);
        let wire2 = sign_rule_event_at(&event, &sk, ts);

        // Ed25519 with dalek is deterministic (RFC 6979-style)
        assert_eq!(wire1, wire2);
    }

    // ── RuleBroadcaster tests ────────────────────────────────────────────

    #[test]
    fn broadcaster_signs_and_rate_limits() {
        let sk = test_signing_key();
        let mut broadcaster = RuleBroadcaster::new(sk);
        let event = make_test_event(RuleEventType::NewRule);

        // First 10 should succeed
        for i in 0..10 {
            let result = broadcaster.broadcast(&event);
            assert!(result.is_ok(), "Event {} should succeed", i + 1);
        }

        // 11th should be rate limited
        let result = broadcaster.broadcast(&event);
        assert_eq!(result.unwrap_err(), BroadcastError::RateLimited);
    }

    #[test]
    fn broadcaster_with_custom_rate_limit() {
        let sk = test_signing_key();
        let mut broadcaster = RuleBroadcaster::with_rate_limit(sk, 2);
        let event = make_test_event(RuleEventType::NewRule);

        assert!(broadcaster.broadcast(&event).is_ok());
        assert!(broadcaster.broadcast(&event).is_ok());
        assert_eq!(
            broadcaster.broadcast(&event).unwrap_err(),
            BroadcastError::RateLimited
        );
    }

    #[test]
    fn broadcaster_output_verifiable() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let mut broadcaster = RuleBroadcaster::new(sk);
        let event = make_test_event(RuleEventType::ConfidenceUpdate);

        let wire = broadcaster.broadcast(&event).unwrap();

        // Parse and verify
        assert_eq!(wire[0], PROTOCOL_VERSION);
        assert_eq!(wire[1], RuleEventType::ConfidenceUpdate as u8);

        let sig_bytes: [u8; 64] = wire[14..78].try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&wire[..14]);
        signed_data.extend_from_slice(&event.payload);
        assert!(vk.verify(&signed_data, &signature).is_ok());
    }

    #[test]
    fn broadcaster_verifying_key() {
        let sk = test_signing_key();
        let expected_vk = sk.verifying_key();
        let broadcaster = RuleBroadcaster::new(sk);
        assert_eq!(broadcaster.verifying_key(), expected_vk);
    }

    #[test]
    fn broadcaster_broadcast_at_deterministic() {
        let sk = test_signing_key();
        let mut broadcaster = RuleBroadcaster::new(sk);
        let event = make_test_event(RuleEventType::Tombstone);

        let now_s = 5000u64;
        let now_us = 5_000_000_000u64;

        let wire = broadcaster.broadcast_at(&event, now_s, now_us).unwrap();

        let parsed_ts = u64::from_be_bytes(wire[2..10].try_into().unwrap());
        assert_eq!(parsed_ts, now_us);
    }

    #[test]
    fn broadcaster_rate_limiter_accessible() {
        let sk = test_signing_key();
        let mut broadcaster = RuleBroadcaster::new(sk);
        assert_eq!(broadcaster.rate_limiter().current_count(), 0);

        let event = make_test_event(RuleEventType::NewRule);
        broadcaster.broadcast(&event).unwrap();
        assert_eq!(broadcaster.rate_limiter().current_count(), 1);

        broadcaster.rate_limiter_mut().reset();
        assert_eq!(broadcaster.rate_limiter().current_count(), 0);
    }

    // ── Scoring constants tests ──────────────────────────────────────────

    #[test]
    fn gossipsub_scoring_constants() {
        assert_eq!(P4_INVALID_MESSAGE_WEIGHT, -100.0);
        assert_eq!(P3_RATE_PENALTY_THRESHOLD, 20);
    }

    // ── BroadcastError display ───────────────────────────────────────────

    #[test]
    fn broadcast_error_display() {
        let rl = BroadcastError::RateLimited;
        assert!(format!("{}", rl).contains("rate limited"));

        let se = BroadcastError::SigningError;
        assert!(format!("{}", se).contains("signing"));
    }
}
