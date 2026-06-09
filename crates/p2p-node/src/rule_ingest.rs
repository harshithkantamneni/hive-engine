//! Inbound rule validation pipeline for Gossipsub rule events.
//!
//! Implements a 7-step validation pipeline:
//! 1. Ed25519 signature verification
//! 2. Event age check (reject > 7 days old)
//! 3. Size check (<= 512 bytes) [moved before parse]
//! 4. Wire format parse (postcard deserialize)
//! 5. Tombstone check
//! 6. Version check (reject if local version is newer)
//! 7. Content validation (CF bounds, evidence, conditions)

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

// Re-export canonical bridge types from rete-alpha.
use rete_alpha::bridge::{EvidenceSummary, RuleEventType};

// ============================================================================
// Constants
// ============================================================================

/// Maximum event age in microseconds (7 days).
pub const MAX_EVENT_AGE_MICROS: u64 = 604_800 * 1_000_000;

/// Maximum rule wire size in bytes.
pub const MAX_RULE_WIRE_SIZE: usize = 512;

/// Tombstone retention period in seconds (30 days).
pub const TOMBSTONE_RETENTION_SECS: u64 = 30 * 24 * 3600;

/// Maximum number of conditions per rule (V1 alpha-only Rete).
pub const MAX_CONDITIONS: u8 = 10;

/// CF ceiling multiplied by 10000 (0.98 * 10000 = 9800, max across tiers).
/// cf_ceiling = [0.95, 0.95, 0.97, 0.98] for [S1,S2,S3,S4].
/// We use the max (9800) as an upper bound; per-tier checks can be added later.
pub const CF_CEILING_X10K: u32 = 9800;

/// Wire format protocol version.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Minimum wire message size: header(14) + signature(64) + payload_length(2) = 80.
pub const MIN_WIRE_SIZE: usize = 80;

/// Gossipsub P4 invalid message weight.
pub const P4_INVALID_MESSAGE_WEIGHT: f64 = -100.0;

/// Gossipsub P3 rate penalty threshold.
pub const P3_RATE_PENALTY_THRESHOLD: u32 = 20;

/// Maximum inbound events per peer per minute.
pub const MAX_INBOUND_EVENTS_PER_PEER_PER_MINUTE: usize = 10;

/// Maximum number of tracked peers in the peer rate limiter.
/// Prevents unbounded growth if many transient peers connect.
const MAX_TRACKED_PEERS: usize = 4096;

// ============================================================================
// Per-peer inbound rate limiter
// ============================================================================

use std::collections::VecDeque;

/// Per-peer sliding-window rate limiter for inbound rule events.
///
/// Each peer gets a VecDeque of timestamps (unix seconds). When a new event
/// arrives, expired entries (older than 60s) are pruned and the count is
/// checked against `MAX_INBOUND_EVENTS_PER_PEER_PER_MINUTE`.
///
/// Follows the same pattern as `RuleEventRateLimiter` in `rule_broadcast.rs`.
pub struct PeerRateLimiter {
    /// Per-peer sliding windows. Key is serialized PeerId bytes.
    peers: HashMap<Vec<u8>, VecDeque<u64>>,
    /// Maximum events per peer per minute.
    max_per_minute: usize,
}

impl Default for PeerRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerRateLimiter {
    /// Create a new per-peer rate limiter with the standard 10/min cap.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            max_per_minute: MAX_INBOUND_EVENTS_PER_PEER_PER_MINUTE,
        }
    }

    /// Create a rate limiter with a custom cap (for testing).
    pub fn with_limit(max_per_minute: usize) -> Self {
        Self {
            peers: HashMap::new(),
            max_per_minute,
        }
    }

    /// Try to acquire a rate limit slot for the given peer.
    /// Returns `true` if under the limit (and records the event),
    /// `false` if the peer is rate limited.
    pub fn try_acquire(&mut self, peer_id: &[u8]) -> bool {
        self.try_acquire_at(peer_id, now_secs())
    }

    /// Try to acquire at a specific timestamp (for deterministic testing).
    pub fn try_acquire_at(&mut self, peer_id: &[u8], now: u64) -> bool {
        // Enforce bounded peer tracking: evict oldest-seen peer if at capacity
        // and this is a new peer.
        if !self.peers.contains_key(peer_id) && self.peers.len() >= MAX_TRACKED_PEERS {
            // Evict the peer with the oldest most-recent event.
            if let Some(oldest_key) = self
                .peers
                .iter()
                .min_by_key(|(_, v)| v.back().copied().unwrap_or(0))
                .map(|(k, _)| k.clone())
            {
                self.peers.remove(&oldest_key);
            }
        }

        let window = self.peers.entry(peer_id.to_vec()).or_default();
        let cutoff = now.saturating_sub(60);

        // Remove expired entries from the front
        while window.front().is_some_and(|&t| t < cutoff) {
            window.pop_front();
        }

        if window.len() < self.max_per_minute {
            window.push_back(now);
            true
        } else {
            false
        }
    }

    /// Number of peers currently tracked.
    pub fn tracked_peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Garbage-collect peers with no recent events (all entries expired).
    pub fn gc_at(&mut self, now: u64) {
        let cutoff = now.saturating_sub(60);
        self.peers.retain(|_, window| {
            while window.front().is_some_and(|&t| t < cutoff) {
                window.pop_front();
            }
            !window.is_empty()
        });
    }
}

// ============================================================================
// InboundRuleEvent -- p2p-node specific variant (uses parsed RuleEnvelope)
// NOTE: This differs from rete-alpha::bridge::InboundRuleEvent which uses
// raw envelope_bytes. The p2p-node version uses a parsed RuleEnvelope for
// the NewRule variant because validation has already parsed the wire bytes.
// ============================================================================

/// Inbound rule event after validation (p2p-node specific).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundRuleEvent {
    NewRule {
        envelope: RuleEnvelope,
        source_peer: Vec<u8>,
        received_at: u64,
    },
    ConfidenceUpdate {
        rule_id: u32,
        new_cf_x10k: u32,
        new_version: u32,
        evidence: EvidenceSummary,
    },
    StateTransition {
        rule_id: u32,
        old_status: u8,
        new_status: u8,
        version: u32,
        transition_time: u64,
    },
    Tombstone {
        rule_id: u32,
        tombstone_until: u64,
        version: u32,
    },
    MergeEvent {
        primary_id: u32,
        absorbed_id: u32,
        merged_version: u32,
        merged_cf_x10k: u32,
    },
}

// ============================================================================
// RuleEnvelope -- parsed from postcard wire bytes
// ============================================================================

/// Parsed rule envelope from postcard wire bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleEnvelope {
    pub rule_id: u32,
    pub version: u32,
    pub event_type: u8,
    pub cf_x10k: u32,
    pub evidence: EvidenceSummary,
    pub conditions_count: u8,
    /// Remaining payload bytes (rule-type-specific content).
    pub payload: Vec<u8>,
}

// ============================================================================
// ValidationError
// ============================================================================

/// Validation failure reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Ed25519 signature verification failed (Step 1).
    InvalidSignature,
    /// Event timestamp is older than MAX_EVENT_AGE (Step 2).
    StaleEvent,
    /// Payload exceeds MAX_RULE_WIRE_SIZE (Step 3).
    TooLarge,
    /// Wire format could not be parsed (Step 4).
    MalformedPayload,
    /// Rule ID is in the tombstone cache (Step 5).
    Tombstoned,
    /// Local version is newer than incoming (Step 6).
    StaleVersion,
    /// Content validation failed: CF out of bounds, bad conditions count (Step 7).
    InvalidContent,
    /// Unknown event_type byte.
    UnknownEventType,
    /// Peer has exceeded inbound rate limit.
    RateLimited,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidSignature => write!(f, "invalid Ed25519 signature"),
            ValidationError::StaleEvent => write!(f, "event age exceeds 7-day limit"),
            ValidationError::MalformedPayload => write!(f, "malformed wire format"),
            ValidationError::TooLarge => write!(f, "payload exceeds 512-byte limit"),
            ValidationError::Tombstoned => write!(f, "rule is tombstoned"),
            ValidationError::StaleVersion => write!(f, "local version is newer"),
            ValidationError::InvalidContent => write!(f, "content validation failed"),
            ValidationError::UnknownEventType => write!(f, "unknown event type"),
            ValidationError::RateLimited => write!(f, "peer inbound rate limit exceeded"),
        }
    }
}

impl std::error::Error for ValidationError {}

// ============================================================================
// IngestResult
// ============================================================================

/// Result of rule event ingestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestResult {
    Accepted(InboundRuleEvent),
    Rejected(ValidationError),
}

// ============================================================================
// EventHeader -- parsed from wire bytes
// ============================================================================

/// Parsed wire header (14 bytes).
#[derive(Debug, Clone)]
pub struct EventHeader {
    pub protocol_version: u8,
    pub event_type: u8,
    pub event_timestamp: u64,
    pub shard_key_hash: u32,
}

// ============================================================================
// TombstoneCache
// ============================================================================

/// Cache of tombstoned rule IDs with expiry timestamps.
/// Retains entries for 30 days.
pub struct TombstoneCache {
    /// Maps rule_id -> tombstone_until (unix seconds).
    entries: HashMap<u32, u64>,
}

impl TombstoneCache {
    /// Create an empty tombstone cache.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert a tombstone for a rule ID, expiring at `tombstone_until` (unix seconds).
    pub fn insert(&mut self, rule_id: u32, tombstone_until: u64) {
        self.entries.insert(rule_id, tombstone_until);
    }

    /// Check if a rule ID is currently tombstoned.
    pub fn contains(&self, rule_id: u32) -> bool {
        if let Some(&until) = self.entries.get(&rule_id) {
            until > now_secs()
        } else {
            false
        }
    }

    /// Check if a rule ID is tombstoned using a provided timestamp.
    pub fn contains_at(&self, rule_id: u32, now: u64) -> bool {
        if let Some(&until) = self.entries.get(&rule_id) {
            until > now
        } else {
            false
        }
    }

    /// Garbage-collect expired tombstone entries.
    pub fn gc(&mut self) {
        let now = now_secs();
        self.entries.retain(|_, &mut until| until > now);
    }

    /// Garbage-collect using a provided timestamp.
    pub fn gc_at(&mut self, now: u64) {
        self.entries.retain(|_, &mut until| until > now);
    }

    /// Number of entries in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for TombstoneCache {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RuleVersionStore trait
// ============================================================================

/// Trait for checking local rule versions.
/// Implemented by the local rule store to support version comparison.
pub trait RuleVersionStore {
    /// Get the current version of a rule by ID, if it exists locally.
    fn get_version(&self, rule_id: u32) -> Option<u32>;
    /// Get the current CF (x10k) of a rule by ID, if it exists locally.
    fn get_cf(&self, rule_id: u32) -> Option<u32>;
}

/// Mock implementation for testing.
pub struct MockRuleVersionStore {
    versions: HashMap<u32, u32>,
    cfs: HashMap<u32, u32>,
}

impl MockRuleVersionStore {
    pub fn new() -> Self {
        Self {
            versions: HashMap::new(),
            cfs: HashMap::new(),
        }
    }

    pub fn set_version(&mut self, rule_id: u32, version: u32) {
        self.versions.insert(rule_id, version);
    }

    pub fn set_cf(&mut self, rule_id: u32, cf_x10k: u32) {
        self.cfs.insert(rule_id, cf_x10k);
    }
}

impl Default for MockRuleVersionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleVersionStore for MockRuleVersionStore {
    fn get_version(&self, rule_id: u32) -> Option<u32> {
        self.versions.get(&rule_id).copied()
    }

    fn get_cf(&self, rule_id: u32) -> Option<u32> {
        self.cfs.get(&rule_id).copied()
    }
}

// ============================================================================
// Wire format parsing
// ============================================================================

/// Parse raw Gossipsub message bytes into header + payload + signature components.
///
/// Wire format:
/// - Byte 0:     protocol_version (0x01)
/// - Byte 1:     event_type (0x01-0x05)
/// - Bytes 2-9:  event_timestamp (u64 big-endian, microseconds)
/// - Bytes 10-13: shard_key_hash (u32 big-endian)
/// - Bytes 14-77: Ed25519 signature (64 bytes)
/// - Bytes 78-79: payload_length (u16 big-endian)
/// - Bytes 80+:  payload
pub fn parse_event_envelope(raw: &[u8]) -> Result<(EventHeader, &[u8], [u8; 64]), ValidationError> {
    if raw.len() < MIN_WIRE_SIZE {
        return Err(ValidationError::MalformedPayload);
    }

    let protocol_version = raw[0];
    if protocol_version != PROTOCOL_VERSION {
        return Err(ValidationError::MalformedPayload);
    }

    let event_type = raw[1];
    if RuleEventType::from_u8(event_type).is_none() {
        return Err(ValidationError::UnknownEventType);
    }

    let event_timestamp = u64::from_be_bytes(raw[2..10].try_into().unwrap());
    let shard_key_hash = u32::from_be_bytes(raw[10..14].try_into().unwrap());

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&raw[14..78]);

    let payload_length = u16::from_be_bytes(raw[78..80].try_into().unwrap()) as usize;

    if raw.len() < 80 + payload_length {
        return Err(ValidationError::MalformedPayload);
    }

    let payload = &raw[80..80 + payload_length];

    let header = EventHeader {
        protocol_version,
        event_type,
        event_timestamp,
        shard_key_hash,
    };

    Ok((header, payload, signature))
}

// ============================================================================
// Timestamp helpers
// ============================================================================

/// Current time in unix seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Current time in microseconds.
pub fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

// ============================================================================
// Validation pipeline
// ============================================================================

/// The 7-step validation pipeline.
///
/// Steps:
/// 1. Ed25519 signature verification
/// 2. Event age check (reject > 7 days)
/// 3. Wire format parse (postcard deserialize)
/// 4. Size check (<= 512 bytes)
/// 5. Tombstone check
/// 6. Version check (reject if local is newer)
/// 7. Content validation (CF bounds, evidence, conditions)
pub fn validate_rule_event(
    raw_bytes: &[u8],
    sender_pubkey: &VerifyingKey,
    tombstone_cache: &TombstoneCache,
    local_store: &dyn RuleVersionStore,
) -> IngestResult {
    validate_rule_event_at(
        raw_bytes,
        sender_pubkey,
        tombstone_cache,
        local_store,
        now_micros(),
    )
}

/// Validation pipeline with an explicit `now` timestamp (for deterministic testing).
pub fn validate_rule_event_at(
    raw_bytes: &[u8],
    sender_pubkey: &VerifyingKey,
    tombstone_cache: &TombstoneCache,
    local_store: &dyn RuleVersionStore,
    now_us: u64,
) -> IngestResult {
    // Step 1: Parse envelope (also checks protocol version and event type byte)
    let (header, payload, sig_bytes) = match parse_event_envelope(raw_bytes) {
        Ok(v) => v,
        Err(e) => return IngestResult::Rejected(e),
    };

    // Step 1 (cont): Ed25519 signature verification over header + payload
    let signature = Signature::from_bytes(&sig_bytes);
    // Signed data = header (14 bytes) + payload (NOT the signature placeholder)
    let mut signed_data = Vec::with_capacity(14 + payload.len());
    signed_data.extend_from_slice(&raw_bytes[..14]); // header
    signed_data.extend_from_slice(payload);

    if sender_pubkey.verify(&signed_data, &signature).is_err() {
        return IngestResult::Rejected(ValidationError::InvalidSignature);
    }

    // Step 2: Event age check
    if now_us.saturating_sub(header.event_timestamp) > MAX_EVENT_AGE_MICROS {
        return IngestResult::Rejected(ValidationError::StaleEvent);
    }

    // Step 3: Size check (moved BEFORE parse to reject oversized
    // payloads without allocating a postcard deserialization buffer).
    if payload.len() > MAX_RULE_WIRE_SIZE {
        return IngestResult::Rejected(ValidationError::TooLarge);
    }

    // Step 4: Wire format parse (postcard deserialize of payload)
    let envelope: RuleEnvelope = match postcard::from_bytes(payload) {
        Ok(e) => e,
        Err(_) => return IngestResult::Rejected(ValidationError::MalformedPayload),
    };

    // Step 5: Tombstone check
    let now_s = now_us / 1_000_000;
    if tombstone_cache.contains_at(envelope.rule_id, now_s) {
        return IngestResult::Rejected(ValidationError::Tombstoned);
    }

    // Step 6: Version check (reject if local version is newer)
    if let Some(local_version) = local_store.get_version(envelope.rule_id) {
        // For tombstone events, accept if version >= local.
        if header.event_type == RuleEventType::Tombstone as u8 {
            if envelope.version < local_version {
                return IngestResult::Rejected(ValidationError::StaleVersion);
            }
        } else if envelope.version <= local_version {
            return IngestResult::Rejected(ValidationError::StaleVersion);
        }
    }

    // Step 7: Content validation
    if envelope.cf_x10k > CF_CEILING_X10K {
        return IngestResult::Rejected(ValidationError::InvalidContent);
    }
    if envelope.conditions_count > MAX_CONDITIONS {
        return IngestResult::Rejected(ValidationError::InvalidContent);
    }

    // Build the appropriate InboundRuleEvent variant
    let event_type = match RuleEventType::from_u8(header.event_type) {
        Some(et) => et,
        None => return IngestResult::Rejected(ValidationError::UnknownEventType),
    };

    let event = match event_type {
        RuleEventType::NewRule => InboundRuleEvent::NewRule {
            envelope,
            source_peer: Vec::new(), // populated by caller with actual PeerId bytes
            received_at: now_s,
        },
        RuleEventType::ConfidenceUpdate => InboundRuleEvent::ConfidenceUpdate {
            rule_id: envelope.rule_id,
            new_cf_x10k: envelope.cf_x10k,
            new_version: envelope.version,
            evidence: envelope.evidence,
        },
        RuleEventType::StateTransition => {
            // old_status and new_status are encoded in the first 2 bytes of envelope.payload
            let (old_status, new_status) = if envelope.payload.len() >= 2 {
                (envelope.payload[0], envelope.payload[1])
            } else {
                (0, 0)
            };
            InboundRuleEvent::StateTransition {
                rule_id: envelope.rule_id,
                old_status,
                new_status,
                version: envelope.version,
                transition_time: header.event_timestamp / 1_000_000,
            }
        }
        RuleEventType::Tombstone => {
            // tombstone_until is encoded as first 8 bytes of envelope.payload (big-endian u64).
            // Reject tombstones with payload < 8 bytes as malformed.
            if envelope.payload.len() < 8 {
                return IngestResult::Rejected(ValidationError::MalformedPayload);
            }
            let tombstone_until =
                u64::from_be_bytes(envelope.payload[..8].try_into().unwrap_or([0u8; 8]));
            InboundRuleEvent::Tombstone {
                rule_id: envelope.rule_id,
                tombstone_until,
                version: envelope.version,
            }
        }
        RuleEventType::Merge => {
            // absorbed_id is encoded as first 4 bytes of envelope.payload (big-endian u32).
            // Reject short payloads instead of silently defaulting to 0.
            if envelope.payload.len() < 4 {
                return IngestResult::Rejected(ValidationError::MalformedPayload);
            }
            let absorbed_id =
                u32::from_be_bytes(envelope.payload[..4].try_into().unwrap_or([0u8; 4]));
            InboundRuleEvent::MergeEvent {
                primary_id: envelope.rule_id,
                absorbed_id,
                merged_version: envelope.version,
                merged_cf_x10k: envelope.cf_x10k,
            }
        }
    };

    IngestResult::Accepted(event)
}

// ============================================================================
// Test helper: build a signed wire message
// ============================================================================

/// Build a complete signed wire message from components (for testing).
pub fn build_signed_wire_message(
    event_type: RuleEventType,
    timestamp_us: u64,
    shard_key_hash: u32,
    payload: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
) -> Vec<u8> {
    use ed25519_dalek::Signer;

    let mut buf = Vec::with_capacity(80 + payload.len());

    // Header (14 bytes)
    buf.push(PROTOCOL_VERSION);
    buf.push(event_type as u8);
    buf.extend_from_slice(&timestamp_us.to_be_bytes());
    buf.extend_from_slice(&shard_key_hash.to_be_bytes());

    // Placeholder for signature (64 bytes)
    let sig_offset = buf.len();
    buf.extend_from_slice(&[0u8; 64]);

    // Payload length + payload
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);

    // Compute signature over header + payload (NOT the signature placeholder)
    let mut sign_data = Vec::with_capacity(14 + payload.len());
    sign_data.extend_from_slice(&buf[..14]);
    sign_data.extend_from_slice(payload);
    let signature = signing_key.sign(&sign_data);
    buf[sig_offset..sig_offset + 64].copy_from_slice(&signature.to_bytes());

    buf
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // Fixed seed for deterministic key generation.
    const TEST_SEED: u64 = 0xDEAD_BEEF_CAFE_1234;

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let mut rng = ChaCha20Rng::seed_from_u64(TEST_SEED);
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn make_test_envelope(
        event_type: RuleEventType,
        rule_id: u32,
        version: u32,
        cf_x10k: u32,
        conditions_count: u8,
    ) -> RuleEnvelope {
        RuleEnvelope {
            rule_id,
            version,
            event_type: event_type as u8,
            cf_x10k,
            evidence: EvidenceSummary {
                supporting_count: 100,
                contradicting_count: 5,
                distinct_regions: 4,
                recency_score_x10k: 8500,
            },
            conditions_count,
            payload: vec![],
        }
    }

    fn build_valid_wire_message(
        sk: &SigningKey,
        envelope: &RuleEnvelope,
        timestamp_us: u64,
    ) -> Vec<u8> {
        let event_type = RuleEventType::from_u8(envelope.event_type).unwrap();
        let payload = postcard::to_allocvec(envelope).unwrap();
        build_signed_wire_message(event_type, timestamp_us, 0x12345678, &payload, sk)
    }

    // ── Parse envelope tests ─────────────────────────────────────────────

    #[test]
    fn parse_envelope_valid_message() {
        let (sk, _vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 1, 1, 5000, 3);
        let payload = postcard::to_allocvec(&envelope).unwrap();
        let wire =
            build_signed_wire_message(RuleEventType::NewRule, 1000000, 0xAABBCCDD, &payload, &sk);

        let (header, parsed_payload, _sig) = parse_event_envelope(&wire).unwrap();
        assert_eq!(header.protocol_version, PROTOCOL_VERSION);
        assert_eq!(header.event_type, 0x01);
        assert_eq!(header.event_timestamp, 1000000);
        assert_eq!(header.shard_key_hash, 0xAABBCCDD);
        assert_eq!(parsed_payload, payload.as_slice());
    }

    #[test]
    fn parse_envelope_too_short() {
        let result = parse_event_envelope(&[0u8; 10]);
        assert_eq!(result.unwrap_err(), ValidationError::MalformedPayload);
    }

    #[test]
    fn parse_envelope_bad_protocol_version() {
        let mut wire = vec![0u8; 80];
        wire[0] = 0xFF; // bad version
        let result = parse_event_envelope(&wire);
        assert_eq!(result.unwrap_err(), ValidationError::MalformedPayload);
    }

    #[test]
    fn parse_envelope_unknown_event_type() {
        let mut wire = vec![0u8; 80];
        wire[0] = PROTOCOL_VERSION;
        wire[1] = 0xFF; // bad event type
        let result = parse_event_envelope(&wire);
        assert_eq!(result.unwrap_err(), ValidationError::UnknownEventType);
    }

    #[test]
    fn parse_envelope_truncated_payload() {
        let (sk, _) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 1, 1, 5000, 3);
        let payload = postcard::to_allocvec(&envelope).unwrap();
        let mut wire = build_signed_wire_message(RuleEventType::NewRule, 1000000, 0, &payload, &sk);
        // Truncate so declared payload_length exceeds actual data
        wire.truncate(82);
        let result = parse_event_envelope(&wire);
        assert_eq!(result.unwrap_err(), ValidationError::MalformedPayload);
    }

    // ── Signature verification tests ─────────────────────────────────────

    #[test]
    fn validate_valid_new_rule() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 42, 1, 5000, 3);
        let now = now_micros();
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        match result {
            IngestResult::Accepted(InboundRuleEvent::NewRule { envelope: e, .. }) => {
                assert_eq!(e.rule_id, 42);
                assert_eq!(e.version, 1);
                assert_eq!(e.cf_x10k, 5000);
            }
            other => panic!("Expected Accepted(NewRule), got {:?}", other),
        }
    }

    #[test]
    fn validate_invalid_signature() {
        let (sk, _vk) = test_keypair();
        // Use a different key for verification
        let mut rng2 = ChaCha20Rng::seed_from_u64(0xAAAA_BBBB);
        let other_sk = SigningKey::generate(&mut rng2);
        let other_vk = other_sk.verifying_key();

        let envelope = make_test_envelope(RuleEventType::NewRule, 1, 1, 5000, 3);
        let now = now_micros();
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &other_vk, &cache, &store, now);
        assert_eq!(
            result,
            IngestResult::Rejected(ValidationError::InvalidSignature)
        );
    }

    #[test]
    fn validate_tampered_payload_fails_signature() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 1, 1, 5000, 3);
        let now = now_micros();
        let mut wire = build_valid_wire_message(&sk, &envelope, now);

        // Tamper with payload (flip a bit in the last byte)
        let last = wire.len() - 1;
        wire[last] ^= 0xFF;

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        // Should fail at either signature or parse
        match result {
            IngestResult::Rejected(ValidationError::InvalidSignature)
            | IngestResult::Rejected(ValidationError::MalformedPayload) => {}
            other => panic!("Expected signature or parse failure, got {:?}", other),
        }
    }

    // ── Event age tests ──────────────────────────────────────────────────

    #[test]
    fn validate_stale_event_rejected() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 1, 1, 5000, 3);
        // Timestamp 8 days ago
        let now = now_micros();
        let old_ts = now - (8 * 24 * 3600 * 1_000_000);
        let wire = build_valid_wire_message(&sk, &envelope, old_ts);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        assert_eq!(result, IngestResult::Rejected(ValidationError::StaleEvent));
    }

    #[test]
    fn validate_event_at_boundary_accepted() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 1, 1, 5000, 3);
        // Exactly 7 days minus 1 second
        let now = 1_000_000_000_000_000u64; // fixed reference
        let ts = now - MAX_EVENT_AGE_MICROS + 1_000_000; // 1 second before cutoff
        let wire = build_valid_wire_message(&sk, &envelope, ts);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        match result {
            IngestResult::Accepted(_) => {}
            other => panic!("Expected Accepted, got {:?}", other),
        }
    }

    // ── Size check tests ─────────────────────────────────────────────────

    #[test]
    fn validate_oversized_payload_rejected() {
        let (sk, vk) = test_keypair();
        let mut envelope = make_test_envelope(RuleEventType::NewRule, 1, 1, 5000, 3);
        // Make payload large enough to exceed 512 bytes when serialized
        envelope.payload = vec![0xAB; 500];
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        assert_eq!(result, IngestResult::Rejected(ValidationError::TooLarge));
    }

    // ── Tombstone tests ──────────────────────────────────────────────────

    #[test]
    fn validate_tombstoned_rule_rejected() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 99, 1, 5000, 3);
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let mut cache = TombstoneCache::new();
        let now_s = now / 1_000_000;
        cache.insert(99, now_s + 86400); // tombstoned for 1 day from now

        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        assert_eq!(result, IngestResult::Rejected(ValidationError::Tombstoned));
    }

    #[test]
    fn validate_expired_tombstone_accepted() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 99, 1, 5000, 3);
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let mut cache = TombstoneCache::new();
        let now_s = now / 1_000_000;
        cache.insert(99, now_s - 1); // tombstone already expired

        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        match result {
            IngestResult::Accepted(_) => {}
            other => panic!("Expected Accepted, got {:?}", other),
        }
    }

    // ── Version check tests ──────────────────────────────────────────────

    #[test]
    fn validate_stale_version_rejected() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 10, 3, 5000, 3);
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let mut store = MockRuleVersionStore::new();
        store.set_version(10, 5); // local is version 5, incoming is 3

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        assert_eq!(
            result,
            IngestResult::Rejected(ValidationError::StaleVersion)
        );
    }

    #[test]
    fn validate_newer_version_accepted() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 10, 5, 5000, 3);
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let mut store = MockRuleVersionStore::new();
        store.set_version(10, 3); // local is version 3, incoming is 5

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        match result {
            IngestResult::Accepted(_) => {}
            other => panic!("Expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn validate_same_version_rejected_for_non_tombstone() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 10, 3, 5000, 3);
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let mut store = MockRuleVersionStore::new();
        store.set_version(10, 3); // same version

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        assert_eq!(
            result,
            IngestResult::Rejected(ValidationError::StaleVersion)
        );
    }

    #[test]
    fn validate_tombstone_same_version_accepted() {
        let (sk, vk) = test_keypair();
        let mut envelope = make_test_envelope(RuleEventType::Tombstone, 10, 3, 0, 0);
        // Set tombstone_until in payload
        let tombstone_until = 1_000_000u64 + TOMBSTONE_RETENTION_SECS;
        envelope.payload = tombstone_until.to_be_bytes().to_vec();

        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let mut store = MockRuleVersionStore::new();
        store.set_version(10, 3); // same version -- tombstones accept >=

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        match result {
            IngestResult::Accepted(InboundRuleEvent::Tombstone { rule_id, .. }) => {
                assert_eq!(rule_id, 10);
            }
            other => panic!("Expected Accepted(Tombstone), got {:?}", other),
        }
    }

    // ── Content validation tests ─────────────────────────────────────────

    #[test]
    fn validate_cf_too_high_rejected() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 1, 1, CF_CEILING_X10K + 1, 3);
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        assert_eq!(
            result,
            IngestResult::Rejected(ValidationError::InvalidContent)
        );
    }

    #[test]
    fn validate_too_many_conditions_rejected() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 1, 1, 5000, 11);
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        assert_eq!(
            result,
            IngestResult::Rejected(ValidationError::InvalidContent)
        );
    }

    #[test]
    fn validate_max_conditions_accepted() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 1, 1, 5000, MAX_CONDITIONS);
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        match result {
            IngestResult::Accepted(_) => {}
            other => panic!("Expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn validate_zero_cf_accepted() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 1, 1, 0, 3);
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        match result {
            IngestResult::Accepted(_) => {}
            other => panic!("Expected Accepted, got {:?}", other),
        }
    }

    // ── Event type routing tests ─────────────────────────────────────────

    #[test]
    fn validate_confidence_update_event() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::ConfidenceUpdate, 7, 2, 7500, 0);
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        match result {
            IngestResult::Accepted(InboundRuleEvent::ConfidenceUpdate {
                rule_id,
                new_cf_x10k,
                new_version,
                ..
            }) => {
                assert_eq!(rule_id, 7);
                assert_eq!(new_cf_x10k, 7500);
                assert_eq!(new_version, 2);
            }
            other => panic!("Expected ConfidenceUpdate, got {:?}", other),
        }
    }

    #[test]
    fn validate_merge_event() {
        let (sk, vk) = test_keypair();
        let mut envelope = make_test_envelope(RuleEventType::Merge, 10, 5, 8200, 0);
        envelope.payload = 20u32.to_be_bytes().to_vec(); // absorbed_id = 20
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        match result {
            IngestResult::Accepted(InboundRuleEvent::MergeEvent {
                primary_id,
                absorbed_id,
                merged_version,
                merged_cf_x10k,
            }) => {
                assert_eq!(primary_id, 10);
                assert_eq!(absorbed_id, 20);
                assert_eq!(merged_version, 5);
                assert_eq!(merged_cf_x10k, 8200);
            }
            other => panic!("Expected MergeEvent, got {:?}", other),
        }
    }

    #[test]
    fn validate_state_transition_event() {
        let (sk, vk) = test_keypair();
        let mut envelope = make_test_envelope(RuleEventType::StateTransition, 50, 3, 3000, 0);
        envelope.payload = vec![1, 3]; // old_status=1 (active), new_status=3 (dormant)
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        match result {
            IngestResult::Accepted(InboundRuleEvent::StateTransition {
                rule_id,
                old_status,
                new_status,
                version,
                ..
            }) => {
                assert_eq!(rule_id, 50);
                assert_eq!(old_status, 1);
                assert_eq!(new_status, 3);
                assert_eq!(version, 3);
            }
            other => panic!("Expected StateTransition, got {:?}", other),
        }
    }

    // ── TombstoneCache tests ─────────────────────────────────────────────

    #[test]
    fn tombstone_cache_insert_and_contains() {
        let mut cache = TombstoneCache::new();
        let future = now_secs() + 86400;
        cache.insert(1, future);
        assert!(cache.contains(1));
        assert!(!cache.contains(2));
    }

    #[test]
    fn tombstone_cache_expired_not_contained() {
        let mut cache = TombstoneCache::new();
        let past = now_secs().saturating_sub(1);
        cache.insert(1, past);
        assert!(!cache.contains(1));
    }

    #[test]
    fn tombstone_cache_gc_removes_expired() {
        let mut cache = TombstoneCache::new();
        let now = 1_000_000u64;
        cache.insert(1, now - 1); // expired
        cache.insert(2, now + 86400); // valid
        cache.insert(3, now - 100); // expired

        cache.gc_at(now);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_at(2, now));
    }

    #[test]
    fn tombstone_cache_default_is_empty() {
        let cache = TombstoneCache::default();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    // ── MockRuleVersionStore tests ───────────────────────────────────────

    #[test]
    fn mock_store_get_version() {
        let mut store = MockRuleVersionStore::new();
        assert_eq!(store.get_version(1), None);
        store.set_version(1, 5);
        assert_eq!(store.get_version(1), Some(5));
    }

    #[test]
    fn mock_store_get_cf() {
        let mut store = MockRuleVersionStore::new();
        assert_eq!(store.get_cf(1), None);
        store.set_cf(1, 7500);
        assert_eq!(store.get_cf(1), Some(7500));
    }

    // ── RuleEventType tests ──────────────────────────────────────────────

    #[test]
    fn rule_event_type_round_trip() {
        for byte in [0x01, 0x02, 0x03, 0x04, 0x05] {
            let et = RuleEventType::from_u8(byte).unwrap();
            assert_eq!(et as u8, byte);
        }
    }

    #[test]
    fn rule_event_type_unknown_returns_none() {
        assert!(RuleEventType::from_u8(0x00).is_none());
        assert!(RuleEventType::from_u8(0x06).is_none());
        assert!(RuleEventType::from_u8(0xFF).is_none());
    }

    // ── Unknown rule test ────────────────────────────────────────────────

    #[test]
    fn validate_unknown_rule_no_version_check() {
        let (sk, vk) = test_keypair();
        let envelope = make_test_envelope(RuleEventType::NewRule, 999, 1, 5000, 3);
        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new(); // empty -- rule 999 unknown

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        match result {
            IngestResult::Accepted(InboundRuleEvent::NewRule { envelope: e, .. }) => {
                assert_eq!(e.rule_id, 999);
            }
            other => panic!("Expected Accepted, got {:?}", other),
        }
    }

    // ── Scoring constant tests ───────────────────────────────────────────

    #[test]
    fn gossipsub_scoring_constants() {
        assert_eq!(P4_INVALID_MESSAGE_WEIGHT, -100.0);
        assert_eq!(P3_RATE_PENALTY_THRESHOLD, 20);
    }

    // ── build_signed_wire_message round-trip ─────────────────────────────

    #[test]
    fn build_signed_wire_message_produces_parseable_output() {
        let (sk, _) = test_keypair();
        let payload = vec![1, 2, 3, 4, 5];
        let wire =
            build_signed_wire_message(RuleEventType::NewRule, 42000000, 0xDEAD, &payload, &sk);

        let (header, parsed_payload, _sig) = parse_event_envelope(&wire).unwrap();
        assert_eq!(header.protocol_version, PROTOCOL_VERSION);
        assert_eq!(header.event_type, 0x01);
        assert_eq!(header.event_timestamp, 42000000);
        assert_eq!(header.shard_key_hash, 0xDEAD);
        assert_eq!(parsed_payload, &[1, 2, 3, 4, 5]);
    }

    // ── Tombstone payload validation tests ─────────────────────

    #[test]
    fn validate_tombstone_short_payload_rejected() {
        // A tombstone event with payload < 8 bytes must be rejected as
        // MalformedPayload.
        let (sk, vk) = test_keypair();
        let mut envelope = make_test_envelope(RuleEventType::Tombstone, 10, 3, 0, 0);
        // Payload with only 4 bytes -- too short for tombstone_until u64.
        envelope.payload = vec![0x00, 0x01, 0x02, 0x03];

        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        assert_eq!(
            result,
            IngestResult::Rejected(ValidationError::MalformedPayload),
            "Tombstone with payload < 8 bytes must be rejected as malformed"
        );
    }

    #[test]
    fn validate_tombstone_empty_payload_rejected() {
        // A tombstone event with zero-length payload must be rejected.
        let (sk, vk) = test_keypair();
        let mut envelope = make_test_envelope(RuleEventType::Tombstone, 10, 3, 0, 0);
        envelope.payload = vec![]; // empty payload

        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        assert_eq!(
            result,
            IngestResult::Rejected(ValidationError::MalformedPayload),
            "Tombstone with empty payload must be rejected as malformed"
        );
    }

    #[test]
    fn validate_tombstone_valid_8byte_payload_accepted() {
        // A tombstone with exactly 8 bytes (valid tombstone_until) must be accepted.
        let (sk, vk) = test_keypair();
        let mut envelope = make_test_envelope(RuleEventType::Tombstone, 10, 3, 0, 0);
        let tombstone_until = 1_000_000u64 + TOMBSTONE_RETENTION_SECS;
        envelope.payload = tombstone_until.to_be_bytes().to_vec();

        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        match result {
            IngestResult::Accepted(InboundRuleEvent::Tombstone {
                rule_id,
                tombstone_until: tu,
                version,
            }) => {
                assert_eq!(rule_id, 10);
                assert_eq!(tu, tombstone_until);
                assert_eq!(version, 3);
            }
            other => panic!(
                "Expected Accepted(Tombstone) for valid 8-byte payload, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn validate_tombstone_7byte_payload_rejected() {
        // Boundary case: exactly 7 bytes is still < 8, must be rejected.
        let (sk, vk) = test_keypair();
        let mut envelope = make_test_envelope(RuleEventType::Tombstone, 10, 3, 0, 0);
        envelope.payload = vec![0u8; 7]; // one byte short

        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        assert_eq!(
            result,
            IngestResult::Rejected(ValidationError::MalformedPayload),
            "Tombstone with 7-byte payload must be rejected"
        );
    }

    // ── MergeEvent short payload rejection tests ────────────────

    #[test]
    fn validate_merge_event_short_payload_rejected() {
        // MergeEvent with payload < 4 bytes must be rejected as
        // MalformedPayload, not silently default absorbed_id to 0.
        let (sk, vk) = test_keypair();
        let mut envelope = make_test_envelope(RuleEventType::Merge, 10, 2, 5000, 3);
        envelope.payload = vec![0u8; 3]; // 3 bytes, less than 4

        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        assert_eq!(
            result,
            IngestResult::Rejected(ValidationError::MalformedPayload),
            "MergeEvent with < 4 byte payload must be rejected"
        );
    }

    #[test]
    fn validate_merge_event_empty_payload_rejected() {
        // Empty payload edge case.
        let (sk, vk) = test_keypair();
        let mut envelope = make_test_envelope(RuleEventType::Merge, 10, 2, 5000, 3);
        envelope.payload = vec![];

        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        assert_eq!(
            result,
            IngestResult::Rejected(ValidationError::MalformedPayload),
            "MergeEvent with empty payload must be rejected"
        );
    }

    #[test]
    fn validate_merge_event_valid_4byte_payload_accepted() {
        // Exactly 4 bytes is valid.
        let (sk, vk) = test_keypair();
        let mut envelope = make_test_envelope(RuleEventType::Merge, 10, 2, 5000, 3);
        envelope.payload = 42u32.to_be_bytes().to_vec();

        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        match result {
            IngestResult::Accepted(InboundRuleEvent::MergeEvent {
                primary_id,
                absorbed_id,
                ..
            }) => {
                assert_eq!(primary_id, 10);
                assert_eq!(absorbed_id, 42);
            }
            other => panic!("Expected Accepted(MergeEvent), got {:?}", other),
        }
    }

    // ── Size check before parse test ────────────────────────────

    #[test]
    fn validate_oversized_payload_rejected_without_parse() {
        // Oversized payloads must be rejected at the size check step
        // BEFORE postcard parsing. We verify this by constructing a wire message
        // with a payload that exceeds MAX_RULE_WIRE_SIZE. The old ordering
        // would have attempted to parse it first.
        let (sk, vk) = test_keypair();
        let mut envelope = make_test_envelope(RuleEventType::NewRule, 1, 1, 5000, 3);
        // Use a payload that is > 512 bytes but is NOT valid postcard.
        // If size check runs first, we get TooLarge; if parse runs first, MalformedPayload.
        envelope.payload = vec![0xFF; 600];

        let now = 1_000_000_000_000_000u64;
        let wire = build_valid_wire_message(&sk, &envelope, now);

        let cache = TombstoneCache::new();
        let store = MockRuleVersionStore::new();

        let result = validate_rule_event_at(&wire, &vk, &cache, &store, now);
        assert_eq!(
            result,
            IngestResult::Rejected(ValidationError::TooLarge),
            "Oversized payload must hit size check BEFORE postcard parse"
        );
    }

    // ── PeerRateLimiter tests ──────────────────────────────────

    #[test]
    fn peer_rate_limiter_allows_up_to_limit() {
        let mut limiter = PeerRateLimiter::with_limit(3);
        let peer = b"peer-A";
        let now = 1_000_000u64;

        assert!(limiter.try_acquire_at(peer, now));
        assert!(limiter.try_acquire_at(peer, now + 1));
        assert!(limiter.try_acquire_at(peer, now + 2));
        // 4th event within 60s window should be rejected
        assert!(!limiter.try_acquire_at(peer, now + 3));
    }

    #[test]
    fn peer_rate_limiter_window_slides() {
        let mut limiter = PeerRateLimiter::with_limit(2);
        let peer = b"peer-B";
        let now = 1_000u64;

        assert!(limiter.try_acquire_at(peer, now));
        assert!(limiter.try_acquire_at(peer, now + 10));
        assert!(!limiter.try_acquire_at(peer, now + 20)); // at limit

        // After 60s from first event, it should expire
        assert!(limiter.try_acquire_at(peer, now + 61));
    }

    #[test]
    fn peer_rate_limiter_independent_peers() {
        let mut limiter = PeerRateLimiter::with_limit(2);
        let peer_a = b"peer-A";
        let peer_b = b"peer-B";
        let now = 1_000u64;

        // Fill peer A
        assert!(limiter.try_acquire_at(peer_a, now));
        assert!(limiter.try_acquire_at(peer_a, now + 1));
        assert!(!limiter.try_acquire_at(peer_a, now + 2));

        // Peer B is independent, should still be allowed
        assert!(limiter.try_acquire_at(peer_b, now + 2));
        assert!(limiter.try_acquire_at(peer_b, now + 3));
        assert!(!limiter.try_acquire_at(peer_b, now + 4));
    }

    #[test]
    fn peer_rate_limiter_gc_removes_expired_peers() {
        let mut limiter = PeerRateLimiter::with_limit(10);
        let peer = b"peer-C";
        let now = 1_000u64;

        limiter.try_acquire_at(peer, now);
        assert_eq!(limiter.tracked_peer_count(), 1);

        // After 60s, gc should remove this peer
        limiter.gc_at(now + 61);
        assert_eq!(limiter.tracked_peer_count(), 0);
    }

    #[test]
    fn peer_rate_limiter_default_limit_is_10() {
        let limiter = PeerRateLimiter::new();
        assert_eq!(
            limiter.max_per_minute,
            MAX_INBOUND_EVENTS_PER_PEER_PER_MINUTE
        );
        assert_eq!(limiter.max_per_minute, 10);
    }
}
