//! Cross-crate bridge types for the privacy pipeline <-> P2P integration.
//!
//! These types define the boundary between the rete-alpha privacy pipeline
//! and the hive-p2p-node crate. They are pure data types with no dependencies
//! on either crate's internal implementation.

pub mod rule_receiver;
pub mod tuple_sender;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

// ============================================================================
// Channel capacities
// ============================================================================

/// Channel capacity for outbound tuples (privacy pipeline -> Dandelion++).
pub const TUPLE_CHANNEL_CAPACITY: usize = 256;

/// Channel capacity for inbound rule events (P2P -> Rete engine).
pub const RULE_CHANNEL_CAPACITY: usize = 128;

// ============================================================================
// Channel type aliases
// ============================================================================

/// Sender half for outbound tuples.
pub type TupleSendChannel = mpsc::Sender<ShareablePayload>;

/// Receiver half for outbound tuples.
pub type TupleRecvChannel = mpsc::Receiver<ShareablePayload>;

/// Sender half for inbound rule events.
pub type RuleSendChannel = mpsc::Sender<InboundRuleEvent>;

/// Receiver half for inbound rule events.
pub type RuleRecvChannel = mpsc::Receiver<InboundRuleEvent>;

// ============================================================================
// ShareablePayload -- wire-ready tuple crossing from privacy pipeline to P2P
// ============================================================================

/// The wire-ready payload that crosses from privacy pipeline to P2P layer.
/// Produced by serializing a QueuedTuple when the jitter timer fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareablePayload {
    /// Postcard-serialized tuple bytes, <= 256 bytes.
    pub wire_bytes: Vec<u8>,

    /// Sensitivity tier (1-4, determines Dandelion++ stem length range).
    /// NOT transmitted on wire -- stem_hops is derived from tier
    /// locally before serialization. Skip both ser/de to prevent leaking
    /// the tier to relay peers. Deserialized value defaults to 0.
    #[serde(skip)]
    pub sensitivity_tier: u8,

    /// Stem hop count for this tuple (CSPRNG-selected, tier-variable).
    /// S1: 10-15, S2: 8-15, S3: 5-12, S4: 5-10.
    pub stem_hops: u8,

    /// Tuple ID for dedup/tracking (BLAKE3 of wire_bytes, first 20 bytes).
    pub tuple_id: [u8; 20],
}

impl ShareablePayload {
    /// Create a ShareablePayload from raw components.
    ///
    /// `wire_bytes` must be <= 256 bytes. `sensitivity_tier` must be 1-4.
    /// `stem_hops` is selected by the caller using a ChaCha20Rng with
    /// tier-variable ranges.
    /// `tuple_id` is the first 20 bytes of BLAKE3(wire_bytes).
    pub fn new(
        wire_bytes: Vec<u8>,
        sensitivity_tier: u8,
        stem_hops: u8,
        tuple_id: [u8; 20],
    ) -> Self {
        Self {
            wire_bytes,
            sensitivity_tier,
            stem_hops,
            tuple_id,
        }
    }

    /// Compute a tuple_id from wire_bytes using BLAKE3 (first 20 bytes).
    pub fn compute_tuple_id(wire_bytes: &[u8]) -> [u8; 20] {
        let hash = blake3::hash(wire_bytes);
        let mut tuple_id = [0u8; 20];
        tuple_id.copy_from_slice(&hash.as_bytes()[..20]);
        tuple_id
    }

    /// Select stem hop count for a given sensitivity tier using a CSPRNG.
    ///
    /// Tier-variable ranges:
    /// - S1 (Critical/Medical): 10-15
    /// - S2 (High/Financial):   8-15
    /// - S3 (Medium):           5-12
    /// - S4 (Low/Retail):       5-10
    pub fn select_stem_hops(sensitivity_tier: u8, rng: &mut rand_chacha::ChaCha20Rng) -> u8 {
        use rand::Rng;
        let (stem_min, stem_max) = match sensitivity_tier {
            1 => (10, 15), // S1Critical
            2 => (8, 15),  // S2High
            3 => (5, 12),  // S3Medium
            4 => (5, 10),  // S4Low
            _ => (8, 15),  // unknown -> conservative (S2)
        };
        rng.random_range(stem_min..=stem_max)
    }

    /// Build a ShareablePayload from wire bytes and a sensitivity tier.
    ///
    /// Computes tuple_id via BLAKE3 and selects stem_hops via ChaCha20Rng.
    pub fn from_wire_bytes(
        wire_bytes: Vec<u8>,
        sensitivity_tier: u8,
        rng: &mut rand_chacha::ChaCha20Rng,
    ) -> Self {
        let tuple_id = Self::compute_tuple_id(&wire_bytes);
        let stem_hops = Self::select_stem_hops(sensitivity_tier, rng);
        Self {
            wire_bytes,
            sensitivity_tier,
            stem_hops,
            tuple_id,
        }
    }
}

// ============================================================================
// InboundRuleEvent -- validated rule event from P2P network
// ============================================================================

/// An inbound rule event from the P2P network, after validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InboundRuleEvent {
    /// New rule crystallized elsewhere. Full wire format.
    NewRule {
        /// Serialized rule envelope bytes.
        envelope_bytes: Vec<u8>,
        /// Source peer identifier (serialized PeerId bytes).
        source_peer: Vec<u8>,
        /// Reception timestamp (unix seconds).
        received_at: u64,
    },

    /// Confidence update for an existing rule.
    ConfidenceUpdate {
        rule_id: u32,
        new_cf_x10k: u32,
        new_version: u32,
        evidence: EvidenceSummary,
    },

    /// Rule status changed (active -> weakened, etc.).
    StateTransition {
        rule_id: u32,
        old_status: u8,
        new_status: u8,
        version: u32,
        transition_time: u64,
    },

    /// Rule expired. Retract from engine immediately.
    Tombstone {
        rule_id: u32,
        tombstone_until: u64,
        version: u32,
    },

    /// Two rules merged. Retract absorbed, update primary.
    MergeEvent {
        primary_id: u32,
        absorbed_id: u32,
        merged_version: u32,
        merged_cf_x10k: u32,
    },
}

// ============================================================================
// EvidenceSummary -- confidence update evidence
// ============================================================================

/// Summary of evidence supporting a confidence update.
///
/// Transmitted with ConfidenceUpdate events so the receiver can
/// assess whether the update is well-supported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSummary {
    /// Number of supporting observations.
    pub supporting_count: u32,
    /// Number of contradicting observations.
    pub contradicting_count: u32,
    /// Number of distinct geographic regions observed.
    pub distinct_regions: u16,
    /// Recency score (0.0 - 1.0).
    pub recency_score_x10k: u16,
}

// ============================================================================
// OutboundRuleEvent -- local rule lifecycle events for P2P broadcast
// ============================================================================

/// An outbound rule event to broadcast via Gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundRuleEvent {
    /// Event type discriminator.
    pub event_type: RuleEventType,
    /// Event-type-specific payload, serialized.
    pub payload: Vec<u8>,
    /// First 4 bytes of BLAKE3(shard_key) for topic routing.
    pub shard_key_hash: u32,
}

/// Rule event type discriminator.
///
/// Maps to wire format event_type byte:
/// 0x01=NewRule, 0x02=ConfidenceUpdate, 0x03=StateTransition,
/// 0x04=Tombstone, 0x05=Merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RuleEventType {
    NewRule = 0x01,
    ConfidenceUpdate = 0x02,
    StateTransition = 0x03,
    Tombstone = 0x04,
    Merge = 0x05,
}

impl RuleEventType {
    /// Parse from wire byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(RuleEventType::NewRule),
            0x02 => Some(RuleEventType::ConfidenceUpdate),
            0x03 => Some(RuleEventType::StateTransition),
            0x04 => Some(RuleEventType::Tombstone),
            0x05 => Some(RuleEventType::Merge),
            _ => None,
        }
    }
}

// ============================================================================
// Helper: create channel pairs
// ============================================================================

/// Create a bounded tuple channel pair with the standard capacity (256).
pub fn tuple_channel() -> (TupleSendChannel, TupleRecvChannel) {
    mpsc::channel(TUPLE_CHANNEL_CAPACITY)
}

/// Create a bounded rule event channel pair with the standard capacity (128).
pub fn rule_channel() -> (RuleSendChannel, RuleRecvChannel) {
    mpsc::channel(RULE_CHANNEL_CAPACITY)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // ── ShareablePayload tests ──────────────────────────────────────────

    #[test]
    fn shareable_payload_new_stores_fields() {
        let payload = ShareablePayload::new(vec![1, 2, 3], 2, 10, [0u8; 20]);
        assert_eq!(payload.wire_bytes, vec![1, 2, 3]);
        assert_eq!(payload.sensitivity_tier, 2);
        assert_eq!(payload.stem_hops, 10);
        assert_eq!(payload.tuple_id, [0u8; 20]);
    }

    #[test]
    fn compute_tuple_id_is_blake3_first_20() {
        let data = b"test wire bytes for hashing";
        let id = ShareablePayload::compute_tuple_id(data);
        let expected = blake3::hash(data);
        assert_eq!(&id[..], &expected.as_bytes()[..20]);
    }

    #[test]
    fn compute_tuple_id_different_inputs_differ() {
        let id1 = ShareablePayload::compute_tuple_id(b"input A");
        let id2 = ShareablePayload::compute_tuple_id(b"input B");
        assert_ne!(id1, id2);
    }

    #[test]
    fn compute_tuple_id_deterministic() {
        let data = b"deterministic test";
        let id1 = ShareablePayload::compute_tuple_id(data);
        let id2 = ShareablePayload::compute_tuple_id(data);
        assert_eq!(id1, id2);
    }

    #[test]
    fn select_stem_hops_s1_range_10_to_15() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        for _ in 0..100 {
            let hops = ShareablePayload::select_stem_hops(1, &mut rng);
            assert!((10..=15).contains(&hops), "S1 hops {} out of range", hops);
        }
    }

    #[test]
    fn select_stem_hops_s2_range_8_to_15() {
        let mut rng = ChaCha20Rng::seed_from_u64(43);
        for _ in 0..100 {
            let hops = ShareablePayload::select_stem_hops(2, &mut rng);
            assert!((8..=15).contains(&hops), "S2 hops {} out of range", hops);
        }
    }

    #[test]
    fn select_stem_hops_s3_range_5_to_12() {
        let mut rng = ChaCha20Rng::seed_from_u64(44);
        for _ in 0..100 {
            let hops = ShareablePayload::select_stem_hops(3, &mut rng);
            assert!((5..=12).contains(&hops), "S3 hops {} out of range", hops);
        }
    }

    #[test]
    fn select_stem_hops_s4_range_5_to_10() {
        let mut rng = ChaCha20Rng::seed_from_u64(45);
        for _ in 0..100 {
            let hops = ShareablePayload::select_stem_hops(4, &mut rng);
            assert!((5..=10).contains(&hops), "S4 hops {} out of range", hops);
        }
    }

    #[test]
    fn select_stem_hops_unknown_tier_defaults_to_s2_range() {
        let mut rng = ChaCha20Rng::seed_from_u64(46);
        for _ in 0..100 {
            let hops = ShareablePayload::select_stem_hops(255, &mut rng);
            assert!(
                (8..=15).contains(&hops),
                "Unknown tier hops {} out of range",
                hops
            );
        }
    }

    #[test]
    fn from_wire_bytes_computes_id_and_hops() {
        let mut rng = ChaCha20Rng::seed_from_u64(47);
        let wire_bytes = vec![10, 20, 30, 40, 50];
        let payload = ShareablePayload::from_wire_bytes(wire_bytes.clone(), 3, &mut rng);

        // tuple_id should match BLAKE3
        let expected_id = ShareablePayload::compute_tuple_id(&wire_bytes);
        assert_eq!(payload.tuple_id, expected_id);

        // stem_hops should be in S3 range
        assert!((5..=12).contains(&payload.stem_hops));
        assert_eq!(payload.sensitivity_tier, 3);
    }

    #[test]
    fn shareable_payload_serde_roundtrip() {
        let payload = ShareablePayload::new(vec![0xDE, 0xAD, 0xBE, 0xEF], 1, 12, [0xAA; 20]);
        let bytes = postcard::to_allocvec(&payload).unwrap();
        let restored: ShareablePayload = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(payload.wire_bytes, restored.wire_bytes);
        // sensitivity_tier is NOT serialized on wire; deserialized
        // value defaults to 0. This is intentional -- stem_hops is already
        // derived from the tier locally before serialization.
        assert_eq!(restored.sensitivity_tier, 0);
        assert_eq!(payload.stem_hops, restored.stem_hops);
        assert_eq!(payload.tuple_id, restored.tuple_id);
    }

    #[test]
    fn shareable_payload_sensitivity_tier_not_on_wire() {
        // Verify that sensitivity_tier is excluded from wire bytes.
        // Serialize two payloads that differ ONLY in sensitivity_tier.
        let p1 = ShareablePayload::new(vec![0x01, 0x02], 1, 10, [0xBB; 20]);
        let p2 = ShareablePayload::new(vec![0x01, 0x02], 4, 10, [0xBB; 20]);
        let bytes1 = postcard::to_allocvec(&p1).unwrap();
        let bytes2 = postcard::to_allocvec(&p2).unwrap();
        // Wire bytes must be identical -- tier is not transmitted.
        assert_eq!(bytes1, bytes2, "sensitivity_tier must not appear on wire");
    }

    // ── InboundRuleEvent tests ──────────────────────────────────────────

    #[test]
    fn inbound_rule_event_new_rule_serde_roundtrip() {
        let event = InboundRuleEvent::NewRule {
            envelope_bytes: vec![1, 2, 3, 4, 5],
            source_peer: vec![0xAB; 32],
            received_at: 1700000000,
        };
        let bytes = postcard::to_allocvec(&event).unwrap();
        let restored: InboundRuleEvent = postcard::from_bytes(&bytes).unwrap();
        match restored {
            InboundRuleEvent::NewRule {
                envelope_bytes,
                source_peer,
                received_at,
            } => {
                assert_eq!(envelope_bytes, vec![1, 2, 3, 4, 5]);
                assert_eq!(source_peer, vec![0xAB; 32]);
                assert_eq!(received_at, 1700000000);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn inbound_rule_event_confidence_update_serde_roundtrip() {
        let event = InboundRuleEvent::ConfidenceUpdate {
            rule_id: 42,
            new_cf_x10k: 7500,
            new_version: 3,
            evidence: EvidenceSummary {
                supporting_count: 100,
                contradicting_count: 5,
                distinct_regions: 8,
                recency_score_x10k: 9200,
            },
        };
        let bytes = postcard::to_allocvec(&event).unwrap();
        let restored: InboundRuleEvent = postcard::from_bytes(&bytes).unwrap();
        match restored {
            InboundRuleEvent::ConfidenceUpdate {
                rule_id,
                new_cf_x10k,
                new_version,
                evidence,
            } => {
                assert_eq!(rule_id, 42);
                assert_eq!(new_cf_x10k, 7500);
                assert_eq!(new_version, 3);
                assert_eq!(evidence.supporting_count, 100);
                assert_eq!(evidence.contradicting_count, 5);
                assert_eq!(evidence.distinct_regions, 8);
                assert_eq!(evidence.recency_score_x10k, 9200);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn inbound_rule_event_state_transition_serde_roundtrip() {
        let event = InboundRuleEvent::StateTransition {
            rule_id: 99,
            old_status: 1,
            new_status: 3,
            version: 7,
            transition_time: 1700001000,
        };
        let bytes = postcard::to_allocvec(&event).unwrap();
        let restored: InboundRuleEvent = postcard::from_bytes(&bytes).unwrap();
        match restored {
            InboundRuleEvent::StateTransition {
                rule_id,
                old_status,
                new_status,
                version,
                transition_time,
            } => {
                assert_eq!(rule_id, 99);
                assert_eq!(old_status, 1);
                assert_eq!(new_status, 3);
                assert_eq!(version, 7);
                assert_eq!(transition_time, 1700001000);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn inbound_rule_event_tombstone_serde_roundtrip() {
        let event = InboundRuleEvent::Tombstone {
            rule_id: 200,
            tombstone_until: 1700086400,
            version: 15,
        };
        let bytes = postcard::to_allocvec(&event).unwrap();
        let restored: InboundRuleEvent = postcard::from_bytes(&bytes).unwrap();
        match restored {
            InboundRuleEvent::Tombstone {
                rule_id,
                tombstone_until,
                version,
            } => {
                assert_eq!(rule_id, 200);
                assert_eq!(tombstone_until, 1700086400);
                assert_eq!(version, 15);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn inbound_rule_event_merge_serde_roundtrip() {
        let event = InboundRuleEvent::MergeEvent {
            primary_id: 10,
            absorbed_id: 20,
            merged_version: 5,
            merged_cf_x10k: 8200,
        };
        let bytes = postcard::to_allocvec(&event).unwrap();
        let restored: InboundRuleEvent = postcard::from_bytes(&bytes).unwrap();
        match restored {
            InboundRuleEvent::MergeEvent {
                primary_id,
                absorbed_id,
                merged_version,
                merged_cf_x10k,
            } => {
                assert_eq!(primary_id, 10);
                assert_eq!(absorbed_id, 20);
                assert_eq!(merged_version, 5);
                assert_eq!(merged_cf_x10k, 8200);
            }
            _ => panic!("Wrong variant"),
        }
    }

    // ── OutboundRuleEvent tests ─────────────────────────────────────────

    #[test]
    fn outbound_rule_event_serde_roundtrip() {
        let event = OutboundRuleEvent {
            event_type: RuleEventType::NewRule,
            payload: vec![0xCA, 0xFE],
            shard_key_hash: 0xDEADBEEF,
        };
        let bytes = postcard::to_allocvec(&event).unwrap();
        let restored: OutboundRuleEvent = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.event_type, RuleEventType::NewRule);
        assert_eq!(restored.payload, vec![0xCA, 0xFE]);
        assert_eq!(restored.shard_key_hash, 0xDEADBEEF);
    }

    #[test]
    fn rule_event_type_all_variants_serde_roundtrip() {
        let variants = [
            RuleEventType::NewRule,
            RuleEventType::ConfidenceUpdate,
            RuleEventType::StateTransition,
            RuleEventType::Tombstone,
            RuleEventType::Merge,
        ];
        for variant in &variants {
            let bytes = postcard::to_allocvec(variant).unwrap();
            let restored: RuleEventType = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(*variant, restored);
        }
    }

    // ── Channel creation tests ──────────────────────────────────────────

    #[test]
    fn tuple_channel_capacity_is_256() {
        assert_eq!(TUPLE_CHANNEL_CAPACITY, 256);
    }

    #[test]
    fn rule_channel_capacity_is_128() {
        assert_eq!(RULE_CHANNEL_CAPACITY, 128);
    }

    // ── EvidenceSummary tests ───────────────────────────────────────────

    #[test]
    fn evidence_summary_serde_roundtrip() {
        let ev = EvidenceSummary {
            supporting_count: 500,
            contradicting_count: 10,
            distinct_regions: 12,
            recency_score_x10k: 8500,
        };
        let bytes = postcard::to_allocvec(&ev).unwrap();
        let restored: EvidenceSummary = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev.supporting_count, restored.supporting_count);
        assert_eq!(ev.contradicting_count, restored.contradicting_count);
        assert_eq!(ev.distinct_regions, restored.distinct_regions);
        assert_eq!(ev.recency_score_x10k, restored.recency_score_x10k);
    }

    // ── Integration test -- Rule events -> Channel 17 ──────────

    /// Test 3: InboundRuleEvent variants -> Channel 17 -> receive and verify.
    ///
    /// Validates that all 5 InboundRuleEvent variants can be sent through
    /// the bounded rule channel (cap 128), serialized via postcard for wire
    /// transport, and received with correct field values intact.
    #[test]
    fn test_gossipsub_rule_to_engine_channel() {
        let (tx, mut rx) = rule_channel();

        // Create and send all 5 event variants
        let events = vec![
            InboundRuleEvent::NewRule {
                envelope_bytes: vec![0x01, 0x02, 0x03, 0x04],
                source_peer: vec![0xAB; 32],
                received_at: 1700000000,
            },
            InboundRuleEvent::ConfidenceUpdate {
                rule_id: 42,
                new_cf_x10k: 8500,
                new_version: 3,
                evidence: EvidenceSummary {
                    supporting_count: 100,
                    contradicting_count: 5,
                    distinct_regions: 8,
                    recency_score_x10k: 9200,
                },
            },
            InboundRuleEvent::Tombstone {
                rule_id: 200,
                tombstone_until: 1700086400,
                version: 15,
            },
            InboundRuleEvent::StateTransition {
                rule_id: 99,
                old_status: 1,
                new_status: 3,
                version: 7,
                transition_time: 1700001000,
            },
            InboundRuleEvent::MergeEvent {
                primary_id: 10,
                absorbed_id: 20,
                merged_version: 5,
                merged_cf_x10k: 7000,
            },
        ];

        // Send all events through channel
        for event in &events {
            tx.try_send(event.clone())
                .expect("channel should not be full");
        }

        // Receive and verify each event
        let mut received = Vec::new();
        while let Ok(event) = rx.try_recv() {
            received.push(event);
        }

        assert_eq!(received.len(), 5, "All 5 events should be received");

        // Verify NewRule
        match &received[0] {
            InboundRuleEvent::NewRule {
                envelope_bytes,
                source_peer,
                received_at,
            } => {
                assert_eq!(*envelope_bytes, vec![0x01, 0x02, 0x03, 0x04]);
                assert_eq!(*source_peer, vec![0xAB; 32]);
                assert_eq!(*received_at, 1700000000);
            }
            _ => panic!("Expected NewRule, got {:?}", received[0]),
        }

        // Verify ConfidenceUpdate
        match &received[1] {
            InboundRuleEvent::ConfidenceUpdate {
                rule_id,
                new_cf_x10k,
                new_version,
                evidence,
            } => {
                assert_eq!(*rule_id, 42);
                assert_eq!(*new_cf_x10k, 8500);
                assert_eq!(*new_version, 3);
                assert_eq!(evidence.supporting_count, 100);
                assert_eq!(evidence.contradicting_count, 5);
            }
            _ => panic!("Expected ConfidenceUpdate, got {:?}", received[1]),
        }

        // Verify Tombstone
        match &received[2] {
            InboundRuleEvent::Tombstone {
                rule_id,
                tombstone_until,
                version,
            } => {
                assert_eq!(*rule_id, 200);
                assert_eq!(*tombstone_until, 1700086400);
                assert_eq!(*version, 15);
            }
            _ => panic!("Expected Tombstone, got {:?}", received[2]),
        }

        // Verify StateTransition
        match &received[3] {
            InboundRuleEvent::StateTransition {
                rule_id,
                old_status,
                new_status,
                ..
            } => {
                assert_eq!(*rule_id, 99);
                assert_eq!(*old_status, 1);
                assert_eq!(*new_status, 3);
            }
            _ => panic!("Expected StateTransition, got {:?}", received[3]),
        }

        // Verify MergeEvent
        match &received[4] {
            InboundRuleEvent::MergeEvent {
                primary_id,
                absorbed_id,
                merged_cf_x10k,
                ..
            } => {
                assert_eq!(*primary_id, 10);
                assert_eq!(*absorbed_id, 20);
                assert_eq!(*merged_cf_x10k, 7000);
            }
            _ => panic!("Expected MergeEvent, got {:?}", received[4]),
        }

        // Verify all events also survive postcard serialization roundtrip
        // (important for cross-crate wire transport)
        for event in &events {
            let bytes = postcard::to_allocvec(event).unwrap();
            let restored: InboundRuleEvent = postcard::from_bytes(&bytes).unwrap();
            // Serialize both to bytes and compare (since InboundRuleEvent doesn't impl PartialEq)
            let original_bytes = postcard::to_allocvec(event).unwrap();
            let restored_bytes = postcard::to_allocvec(&restored).unwrap();
            assert_eq!(
                original_bytes, restored_bytes,
                "Postcard roundtrip should preserve event data"
            );
        }
    }
}
