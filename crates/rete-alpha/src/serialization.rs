//! Binary serialization for rules and WMEs.
//!
//! Enables rules to be stored on disk and transmitted over the P2P network.
//! Uses `postcard` (COBS-free variant of serde for embedded/compact use) for
//! minimal wire size -- typically 2-5x smaller than bincode.
//!
//! Design decisions:
//! - **postcard** chosen over bincode/MessagePack because:
//!   - Variable-length integer encoding (varint) compresses small u32/u64 values
//!   - No framing overhead (unlike COBS mode)
//!   - ~100-200 bytes per rule (well under the 512-byte P2P cap)
//!   - Deterministic output (same input -> same bytes) for idempotent P2P sync
//! - Separate `RuleEnvelope` struct wraps version + payload for forward compatibility
//! - WME serialization included for snapshot/restore
//!
//! Wire format version: 1 (WIRE_VERSION constant).
//! Peers receiving a higher version should accept and skip unknown trailing fields
//! (postcard's varint + serde `#[serde(default)]` provide forward compat).

use crate::alpha_network::ConditionField;
use crate::lifecycle::EvolutionRecord;
use crate::wme::Wme;
use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Wire format version. Increment on breaking changes.
pub const WIRE_VERSION: u8 = 1;

/// Maximum serialized rule size for P2P transmission.
pub const MAX_RULE_WIRE_SIZE: usize = 512;

// ============================================================================
// Serializable condition (matches engine's CompactCondition)
// ============================================================================

/// A single alpha-network condition, serializable for wire transmission.
/// 3 bytes on wire: field (1 varint) + value_id (2 varint).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SerializableCondition {
    pub field: ConditionField,
    pub value_id: u16,
}

// ============================================================================
// Rule envelope -- the P2P wire unit
// ============================================================================

/// Complete serializable rule for P2P distribution.
///
/// Contains everything needed to reconstruct and evaluate a rule:
/// - Identity (rule_id, rule_tag)
/// - Conditions (alpha-network tests)
/// - Conclusion metadata
/// - Lifecycle state (EvolutionRecord)
/// - Wire format version for forward compatibility
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleEnvelope {
    /// Wire format version (currently 1).
    pub version: u8,

    // -- Identity --
    pub rule_id: u32,
    /// Rule tag string, e.g. "medical_bill:hospital:er_charge_range".
    pub rule_tag: String,

    // -- Conditions --
    pub conditions: Vec<SerializableCondition>,

    // -- Conclusion --
    /// Conclusion type index:
    /// 0=typical_range, 1=above_range, 2=below_range, 3=comparison, 4=warning, 5=informational.
    pub conclusion_type: u8,
    /// Comparison bucket (0-7) or 0xFF if not applicable.
    pub comparison_bucket: u8,
    /// Template arguments as key-value pairs.
    pub conclusion_args: Vec<(String, String)>,

    // -- Lifecycle --
    pub evolution: EvolutionRecord,
}

impl RuleEnvelope {
    /// Serialize this rule to a compact binary representation.
    ///
    /// Returns the serialized bytes, or an error if the result exceeds MAX_RULE_WIRE_SIZE.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let bytes =
            postcard::to_allocvec(self).map_err(|e| SerializationError::Encode(e.to_string()))?;
        if bytes.len() > MAX_RULE_WIRE_SIZE {
            return Err(SerializationError::TooLarge {
                actual: bytes.len(),
                max: MAX_RULE_WIRE_SIZE,
            });
        }
        Ok(bytes)
    }

    /// Deserialize a rule from binary bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let envelope: RuleEnvelope =
            postcard::from_bytes(bytes).map_err(|e| SerializationError::Decode(e.to_string()))?;
        Ok(envelope)
    }

    /// Serialize without the size check (for benchmarking / internal use).
    pub fn to_bytes_unchecked(&self) -> Result<Vec<u8>, SerializationError> {
        postcard::to_allocvec(self).map_err(|e| SerializationError::Encode(e.to_string()))
    }

    /// Wire size of this rule (serializes to compute).
    pub fn wire_size(&self) -> Result<usize, SerializationError> {
        let bytes =
            postcard::to_allocvec(self).map_err(|e| SerializationError::Encode(e.to_string()))?;
        Ok(bytes.len())
    }
}

// ============================================================================
// WME serialization (for snapshot/restore)
// ============================================================================

/// Batch of WMEs for snapshot/restore. Wraps a version + WME data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WmeSnapshot {
    /// Wire format version.
    pub version: u8,
    /// All WMEs in the snapshot.
    pub wmes: Vec<Wme>,
}

impl WmeSnapshot {
    /// Create a new snapshot from a set of WMEs.
    pub fn new(wmes: Vec<Wme>) -> Self {
        Self {
            version: WIRE_VERSION,
            wmes,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        postcard::to_allocvec(self).map_err(|e| SerializationError::Encode(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        postcard::from_bytes(bytes).map_err(|e| SerializationError::Decode(e.to_string()))
    }
}

/// Serialize a single WME to bytes.
pub fn serialize_wme(wme: &Wme) -> Result<Vec<u8>, SerializationError> {
    postcard::to_allocvec(wme).map_err(|e| SerializationError::Encode(e.to_string()))
}

/// Deserialize a single WME from bytes.
pub fn deserialize_wme(bytes: &[u8]) -> Result<Wme, SerializationError> {
    postcard::from_bytes(bytes).map_err(|e| SerializationError::Decode(e.to_string()))
}

// ============================================================================
// Error type
// ============================================================================

/// Errors during serialization/deserialization.
#[derive(Debug, Clone, PartialEq)]
pub enum SerializationError {
    /// Encoding failed.
    Encode(String),
    /// Decoding failed.
    Decode(String),
    /// Serialized size exceeds the wire cap.
    TooLarge { actual: usize, max: usize },
}

impl std::fmt::Display for SerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SerializationError::Encode(e) => write!(f, "serialization encode error: {}", e),
            SerializationError::Decode(e) => write!(f, "serialization decode error: {}", e),
            SerializationError::TooLarge { actual, max } => {
                write!(
                    f,
                    "serialized size {} exceeds maximum {} bytes",
                    actual, max
                )
            }
        }
    }
}

impl std::error::Error for SerializationError {}

// ============================================================================
// Helper: build a RuleEnvelope from engine types
// ============================================================================

/// Build a RuleEnvelope from the engine's internal representations.
pub fn build_rule_envelope(
    rule_id: u32,
    rule_tag: &str,
    conditions: &[(ConditionField, u16)],
    conclusion_type: u8,
    comparison_bucket: u8,
    conclusion_args: &[(&str, &str)],
    evolution: &EvolutionRecord,
) -> RuleEnvelope {
    RuleEnvelope {
        version: WIRE_VERSION,
        rule_id,
        rule_tag: rule_tag.to_string(),
        conditions: conditions
            .iter()
            .map(|(field, value_id)| SerializableCondition {
                field: *field,
                value_id: *value_id,
            })
            .collect(),
        conclusion_type,
        comparison_bucket,
        conclusion_args: conclusion_args
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        evolution: evolution.clone(),
    }
}

// ============================================================================
// Tests -- written first per TDD requirement
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alpha_network::ConditionField;
    use crate::lifecycle::{Domain, EvolutionRecord, SensitivityTier};
    use crate::production::RuleStatus;
    use crate::wme::Wme;
    use std::time::Instant;

    // ================================================================
    // Test helpers
    // ================================================================

    /// Build a typical rule envelope for testing (medical billing rule #127).
    fn make_test_rule(status: RuleStatus, cf: f64) -> RuleEnvelope {
        let now = 1_000_000u64;
        let tier = SensitivityTier::S3;
        let domain = Domain::Default;

        let mut evo = EvolutionRecord::new(now, cf, tier, domain, 5, 100);
        evo.status = status;
        evo.status_entered_at = now;
        evo.last_fired = now - 100;
        evo.strength_epoch = 42;
        evo.contradiction_streak = 0;
        evo.weakening_events = 2;
        evo.cumulative_delta_cf = 0.15;
        evo.context_divergence = 0.0;
        evo.tombstone_until = 0;
        evo.contradicting_count = 5;
        evo.distinct_regions = 5;
        evo.recency_score = 0.92;
        evo.last_seen = now - 10;
        evo.consistency_score = 0.95;

        build_rule_envelope(
            127,
            "medical_bill:hospital:er_charge_range",
            &[
                (ConditionField::EntityAType, 0),
                (ConditionField::EntityARole, 1),
                (ConditionField::EntityAGen, 2),
                (ConditionField::Relation, 3),
                (ConditionField::EntityBType, 4),
                (ConditionField::DocumentCategory, 5),
            ],
            0, // typical_range
            3, // bucket $1K-$5K
            &[
                ("entity_gen", "hospital"),
                ("relation", "er_charge"),
                ("amount_range", "$1K-$5K"),
                ("evidence_count", "1820"),
                ("region_count", "10"),
            ],
            &evo,
        )
    }

    /// Build a minimal rule (fewest fields) to test minimum wire size.
    fn make_minimal_rule() -> RuleEnvelope {
        let now = 1_000_000u64;
        let evo = EvolutionRecord::new(now, 0.3, SensitivityTier::S4, Domain::Default, 2, 8);

        build_rule_envelope(
            1,
            "r:s:d",
            &[(ConditionField::EntityAType, 0)],
            5,
            0xFF,
            &[],
            &evo,
        )
    }

    /// Build a maximal rule (many fields) to test size ceiling.
    fn make_maximal_rule() -> RuleEnvelope {
        let now = 1_000_000u64;
        let mut evo = EvolutionRecord::new(
            now,
            0.85,
            SensitivityTier::S1,
            Domain::MedicalReference,
            10,
            500,
        );
        evo.status = RuleStatus::Active;
        evo.strength_epoch = 999;
        evo.contradiction_streak = 5;
        evo.weakening_events = 20;
        evo.cumulative_delta_cf = 1.5;
        evo.contradicting_count = 50;
        evo.tombstone_until = now + 86400 * 365;

        build_rule_envelope(
            99999,
            "medical_bill:insurance_company:coverage_denial_rate_by_procedure_type",
            &[
                (ConditionField::EntityAType, 100),
                (ConditionField::EntityARole, 200),
                (ConditionField::EntityAGen, 300),
                (ConditionField::Relation, 400),
                (ConditionField::EntityBType, 500),
                (ConditionField::EntityBRole, 600),
                (ConditionField::EntityBGen, 700),
                (ConditionField::DocumentCategory, 800),
                (ConditionField::AmountBucket, 0b11110000),
                (ConditionField::EntityAType, 900),
            ],
            4, // warning
            7, // $100K+
            &[
                (
                    "entity_gen",
                    "insurance_company_with_very_long_name_for_testing",
                ),
                ("relation", "coverage_denial_rate"),
                ("detail", "High denial rate for this procedure category"),
                ("evidence_count", "50000"),
                ("confidence", "85"),
                ("region_count", "18"),
            ],
            &evo,
        )
    }

    fn make_test_wme() -> Wme {
        Wme::new(0, 1, 2, 3, 4, 5, 6, 3, 0, 0.91)
    }

    // ================================================================
    // Group 1: Round-trip fidelity for each lifecycle state
    // ================================================================

    #[test]
    fn test_roundtrip_candidate() {
        let rule = make_test_rule(RuleStatus::Candidate, 0.35);
        let bytes = rule.to_bytes().unwrap();
        let restored = RuleEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(rule, restored);
        assert_eq!(restored.evolution.status, RuleStatus::Candidate);
    }

    #[test]
    fn test_roundtrip_active() {
        let rule = make_test_rule(RuleStatus::Active, 0.72);
        let bytes = rule.to_bytes().unwrap();
        let restored = RuleEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(rule, restored);
        assert_eq!(restored.evolution.status, RuleStatus::Active);
    }

    #[test]
    fn test_roundtrip_weakened() {
        let rule = make_test_rule(RuleStatus::Weakened, 0.25);
        let bytes = rule.to_bytes().unwrap();
        let restored = RuleEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(rule, restored);
        assert_eq!(restored.evolution.status, RuleStatus::Weakened);
    }

    #[test]
    fn test_roundtrip_dormant() {
        let rule = make_test_rule(RuleStatus::Dormant, 0.15);
        let bytes = rule.to_bytes().unwrap();
        let restored = RuleEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(rule, restored);
        assert_eq!(restored.evolution.status, RuleStatus::Dormant);
    }

    #[test]
    fn test_roundtrip_expired() {
        let mut rule = make_test_rule(RuleStatus::Expired, 0.0);
        rule.evolution.tombstone_until = 2_000_000;
        let bytes = rule.to_bytes().unwrap();
        let restored = RuleEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(rule, restored);
        assert_eq!(restored.evolution.status, RuleStatus::Expired);
        assert_eq!(restored.evolution.tombstone_until, 2_000_000);
    }

    // ================================================================
    // Group 2: Wire size constraints
    // ================================================================

    #[test]
    fn test_typical_rule_under_512_bytes() {
        let rule = make_test_rule(RuleStatus::Active, 0.72);
        let size = rule.wire_size().unwrap();
        assert!(
            size <= MAX_RULE_WIRE_SIZE,
            "Typical rule {} bytes exceeds {} limit",
            size,
            MAX_RULE_WIRE_SIZE
        );
        // Expected ~114 bytes for a typical 6-condition rule
        eprintln!("Typical rule wire size: {} bytes", size);
    }

    #[test]
    fn test_minimal_rule_wire_size() {
        let rule = make_minimal_rule();
        let size = rule.wire_size().unwrap();
        assert!(
            size <= MAX_RULE_WIRE_SIZE,
            "Minimal rule {} bytes exceeds limit",
            size
        );
        eprintln!("Minimal rule wire size: {} bytes", size);
    }

    #[test]
    fn test_maximal_rule_under_512_bytes() {
        let rule = make_maximal_rule();
        let size = rule.wire_size().unwrap();
        assert!(
            size <= MAX_RULE_WIRE_SIZE,
            "Maximal rule {} bytes exceeds {} limit",
            size,
            MAX_RULE_WIRE_SIZE
        );
        eprintln!("Maximal rule wire size: {} bytes", size);
    }

    #[test]
    fn test_to_bytes_rejects_oversized() {
        // Construct an artificially enormous rule to trigger the size guard
        let now = 1_000_000u64;
        let evo = EvolutionRecord::new(now, 0.5, SensitivityTier::S3, Domain::Default, 3, 20);
        let mut rule = build_rule_envelope(
            1,
            &"x".repeat(400), // very long tag
            &[(ConditionField::EntityAType, 0)],
            0,
            0xFF,
            &[("k", &"v".repeat(200))], // large arg
            &evo,
        );
        // Ensure it is oversized
        let result = rule.to_bytes();
        if result.is_ok() {
            // If it still fits, push harder
            rule.conclusion_args
                .push(("extra".to_string(), "z".repeat(300)));
            let result = rule.to_bytes();
            assert!(
                matches!(result, Err(SerializationError::TooLarge { .. })),
                "Should reject oversized rule"
            );
        } else {
            assert!(matches!(result, Err(SerializationError::TooLarge { .. })));
        }
    }

    // ================================================================
    // Group 3: WME serialization
    // ================================================================

    #[test]
    fn test_wme_roundtrip() {
        let wme = make_test_wme();
        let bytes = serialize_wme(&wme).unwrap();
        let restored = deserialize_wme(&bytes).unwrap();

        assert_eq!(wme.entity_a_type, restored.entity_a_type);
        assert_eq!(wme.entity_a_role, restored.entity_a_role);
        assert_eq!(wme.entity_a_gen, restored.entity_a_gen);
        assert_eq!(wme.relation, restored.relation);
        assert_eq!(wme.entity_b_type, restored.entity_b_type);
        assert_eq!(wme.entity_b_role, restored.entity_b_role);
        assert_eq!(wme.entity_b_gen, restored.entity_b_gen);
        assert_eq!(wme.amount_bucket, restored.amount_bucket);
        assert_eq!(wme.document_category, restored.document_category);
        assert!((wme.extraction_cf - restored.extraction_cf).abs() < 1e-6);
    }

    #[test]
    fn test_wme_snapshot_roundtrip() {
        let wmes = vec![
            Wme::new(0, 1, 2, 3, 4, 5, 6, 3, 0, 0.91),
            Wme::new(10, 11, 12, 13, 14, 15, 16, 7, 1, 0.85),
            Wme::new(100, 101, 102, 103, 104, 105, 106, 255, 9, 0.77),
        ];
        let snapshot = WmeSnapshot::new(wmes.clone());
        let bytes = snapshot.to_bytes().unwrap();
        let restored = WmeSnapshot::from_bytes(&bytes).unwrap();

        assert_eq!(restored.version, WIRE_VERSION);
        assert_eq!(restored.wmes.len(), 3);
        for (orig, rest) in wmes.iter().zip(restored.wmes.iter()) {
            assert_eq!(orig.entity_a_type, rest.entity_a_type);
            assert_eq!(orig.amount_bucket, rest.amount_bucket);
            assert!((orig.extraction_cf - rest.extraction_cf).abs() < 1e-6);
        }
    }

    #[test]
    fn test_wme_wire_size() {
        let wme = make_test_wme();
        let bytes = serialize_wme(&wme).unwrap();
        // A single WME should be very compact (20 bytes struct, ~18-22 on wire)
        assert!(
            bytes.len() <= 32,
            "Single WME {} bytes exceeds 32",
            bytes.len()
        );
        eprintln!("Single WME wire size: {} bytes", bytes.len());
    }

    // ================================================================
    // Group 4: Deterministic serialization
    // ================================================================

    #[test]
    fn test_deterministic_serialization() {
        // Same rule serialized twice must produce identical bytes
        // (deterministic serialization)
        let rule = make_test_rule(RuleStatus::Active, 0.72);
        let bytes1 = rule.to_bytes().unwrap();
        let bytes2 = rule.to_bytes().unwrap();
        assert_eq!(bytes1, bytes2, "Serialization must be deterministic");
    }

    #[test]
    fn test_roundtrip_preserves_all_evolution_fields() {
        // Verify every single field of EvolutionRecord survives round-trip
        let now = 1_000_000u64;
        let mut evo = EvolutionRecord::new(
            now,
            0.85,
            SensitivityTier::S2,
            Domain::LegalRequirements,
            7,
            200,
        );
        evo.status = RuleStatus::Weakened;
        evo.status_entered_at = now + 5000;
        evo.created_at = now;
        evo.last_fired = now + 3000;
        evo.strength_epoch = 150;
        evo.contradiction_streak = 3;
        evo.weakening_events = 7;
        evo.confidence = 0.42;
        evo.cumulative_delta_cf = 0.73;
        evo.context_divergence = 0.15;
        evo.tombstone_until = now + 86400;
        evo.supporting_count = 200;
        evo.contradicting_count = 30;
        evo.distinct_regions = 7;
        evo.split_candidate = true;
        evo.recency_score = 0.65;
        evo.last_seen = now + 4000;
        evo.consistency_score = 0.85;

        let rule = build_rule_envelope(
            42,
            "legal:contract:term_frequency",
            &[(ConditionField::Relation, 10)],
            3,
            0xFF,
            &[("k", "v")],
            &evo,
        );

        let bytes = rule.to_bytes().unwrap();
        let restored = RuleEnvelope::from_bytes(&bytes).unwrap();
        let r = &restored.evolution;

        assert_eq!(r.status, RuleStatus::Weakened);
        assert_eq!(r.status_entered_at, now + 5000);
        assert_eq!(r.created_at, now);
        assert_eq!(r.last_fired, now + 3000);
        assert_eq!(r.strength_epoch, 150);
        assert_eq!(r.contradiction_streak, 3);
        assert_eq!(r.weakening_events, 7);
        assert!((r.confidence - 0.42).abs() < 1e-10);
        assert!((r.cumulative_delta_cf - 0.73).abs() < 1e-10);
        assert!((r.context_divergence - 0.15).abs() < 1e-10);
        assert_eq!(r.tombstone_until, now + 86400);
        assert_eq!(r.supporting_count, 200);
        assert_eq!(r.contradicting_count, 30);
        assert_eq!(r.distinct_regions, 7);
        assert!(r.split_candidate);
        assert_eq!(r.tier, SensitivityTier::S2);
        assert_eq!(r.domain, Domain::LegalRequirements);
        assert!((r.recency_score - 0.65).abs() < 1e-10);
        assert_eq!(r.last_seen, now + 4000);
        assert!((r.consistency_score - 0.85).abs() < 1e-10);
    }

    // ================================================================
    // Group 5: Version compatibility
    // ================================================================

    #[test]
    fn test_version_field_present() {
        let rule = make_test_rule(RuleStatus::Active, 0.72);
        let bytes = rule.to_bytes().unwrap();
        // First byte should be the version
        assert_eq!(bytes[0], WIRE_VERSION, "First byte should be wire version");

        let restored = RuleEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(restored.version, WIRE_VERSION);
    }

    #[test]
    fn test_corrupt_data_returns_error() {
        let result = RuleEnvelope::from_bytes(&[0xFF, 0x00, 0x01]);
        assert!(result.is_err(), "Corrupt data should return error");
    }

    #[test]
    fn test_empty_data_returns_error() {
        let result = RuleEnvelope::from_bytes(&[]);
        assert!(result.is_err(), "Empty data should return error");
    }

    // ================================================================
    // Group 6: Edge cases
    // ================================================================

    #[test]
    fn test_zero_conditions_rule() {
        let now = 1_000_000u64;
        let evo = EvolutionRecord::new(now, 0.5, SensitivityTier::S3, Domain::Default, 3, 20);
        let rule = build_rule_envelope(1, "test", &[], 0, 0xFF, &[], &evo);
        let bytes = rule.to_bytes().unwrap();
        let restored = RuleEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(restored.conditions.len(), 0);
    }

    #[test]
    fn test_empty_rule_tag() {
        let now = 1_000_000u64;
        let evo = EvolutionRecord::new(now, 0.5, SensitivityTier::S3, Domain::Default, 3, 20);
        let rule = build_rule_envelope(
            1,
            "",
            &[(ConditionField::EntityAType, 0)],
            0,
            0xFF,
            &[],
            &evo,
        );
        let bytes = rule.to_bytes().unwrap();
        let restored = RuleEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(restored.rule_tag, "");
    }

    #[test]
    fn test_all_condition_field_types() {
        // Verify every ConditionField variant survives serialization
        let fields = [
            ConditionField::EntityAType,
            ConditionField::EntityARole,
            ConditionField::EntityAGen,
            ConditionField::Relation,
            ConditionField::EntityBType,
            ConditionField::EntityBRole,
            ConditionField::EntityBGen,
            ConditionField::DocumentCategory,
            ConditionField::AmountBucket,
        ];
        let now = 1_000_000u64;
        let evo = EvolutionRecord::new(now, 0.5, SensitivityTier::S3, Domain::Default, 3, 20);

        let conditions: Vec<(ConditionField, u16)> = fields
            .iter()
            .enumerate()
            .map(|(i, f)| (*f, i as u16))
            .collect();
        let rule = build_rule_envelope(1, "test", &conditions, 0, 0xFF, &[], &evo);
        let bytes = rule.to_bytes().unwrap();
        let restored = RuleEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(restored.conditions.len(), fields.len());
        for (i, field) in fields.iter().enumerate() {
            assert_eq!(restored.conditions[i].field, *field);
            assert_eq!(restored.conditions[i].value_id, i as u16);
        }
    }

    #[test]
    fn test_all_sensitivity_tiers() {
        for tier in [
            SensitivityTier::S1,
            SensitivityTier::S2,
            SensitivityTier::S3,
            SensitivityTier::S4,
        ] {
            let now = 1_000_000u64;
            let evo = EvolutionRecord::new(now, 0.5, tier, Domain::Default, 3, 20);
            let rule = build_rule_envelope(1, "t", &[], 0, 0xFF, &[], &evo);
            let bytes = rule.to_bytes().unwrap();
            let restored = RuleEnvelope::from_bytes(&bytes).unwrap();
            assert_eq!(
                restored.evolution.tier, tier,
                "Tier {:?} failed roundtrip",
                tier
            );
        }
    }

    #[test]
    fn test_all_domains() {
        for domain in [
            Domain::CurrentPrices,
            Domain::Seasonal,
            Domain::ContractTerms,
            Domain::LegalRequirements,
            Domain::MedicalReference,
            Domain::Default,
        ] {
            let now = 1_000_000u64;
            let evo = EvolutionRecord::new(now, 0.5, SensitivityTier::S3, domain, 3, 20);
            let rule = build_rule_envelope(1, "t", &[], 0, 0xFF, &[], &evo);
            let bytes = rule.to_bytes().unwrap();
            let restored = RuleEnvelope::from_bytes(&bytes).unwrap();
            assert_eq!(
                restored.evolution.domain, domain,
                "Domain {:?} failed roundtrip",
                domain
            );
        }
    }

    #[test]
    fn test_wme_amount_bucket_255() {
        // N/A amount bucket special value
        let wme = Wme::new(0, 0, 0, 0, 0, 0, 0, 255, 0, 0.5);
        let bytes = serialize_wme(&wme).unwrap();
        let restored = deserialize_wme(&bytes).unwrap();
        assert_eq!(restored.amount_bucket, 255);
    }

    #[test]
    fn test_wme_extreme_extraction_cf() {
        // Edge values for extraction confidence
        for cf in [0.0f32, 1.0f32, 0.5f32, f32::MIN_POSITIVE] {
            let wme = Wme::new(0, 0, 0, 0, 0, 0, 0, 0, 0, cf);
            let bytes = serialize_wme(&wme).unwrap();
            let restored = deserialize_wme(&bytes).unwrap();
            assert!(
                (restored.extraction_cf - cf).abs() < 1e-7,
                "extraction_cf {} failed roundtrip: got {}",
                cf,
                restored.extraction_cf
            );
        }
    }

    // ================================================================
    // Group 7: Serialization overhead benchmarking
    // ================================================================

    #[test]
    fn test_serialization_performance() {
        // Requirement: serialization overhead < 1us per rule
        let rule = make_test_rule(RuleStatus::Active, 0.72);

        // Warm up
        for _ in 0..100 {
            let _ = rule.to_bytes_unchecked().unwrap();
        }

        // Measure serialize
        let iterations = 10_000;
        let start = Instant::now();
        for _ in 0..iterations {
            let bytes = rule.to_bytes_unchecked().unwrap();
            std::hint::black_box(&bytes);
        }
        let serialize_elapsed = start.elapsed();
        let serialize_ns = serialize_elapsed.as_nanos() / iterations as u128;

        // Measure deserialize
        let bytes = rule.to_bytes_unchecked().unwrap();
        let start = Instant::now();
        for _ in 0..iterations {
            let restored = RuleEnvelope::from_bytes(&bytes).unwrap();
            std::hint::black_box(&restored);
        }
        let deserialize_elapsed = start.elapsed();
        let deserialize_ns = deserialize_elapsed.as_nanos() / iterations as u128;

        let total_ns = serialize_ns + deserialize_ns;

        eprintln!("Serialization performance:");
        eprintln!("  Serialize:   {}ns/rule", serialize_ns);
        eprintln!("  Deserialize: {}ns/rule", deserialize_ns);
        eprintln!("  Round-trip:  {}ns/rule", total_ns);
        eprintln!("  Wire size:   {} bytes", bytes.len());

        // Target: < 1us (1000ns) per rule in release mode.
        // Debug mode is ~3-5x slower due to no inlining; use relaxed threshold.
        // Debug threshold widened from 10_000 → 20_000 to absorb shared-CI environment
        // noise (observed 10281ns on GitHub Actions ubuntu-latest; 20_000 gives ~2x
        // headroom over observed; release-mode 1000ns unchanged).
        let threshold = if cfg!(debug_assertions) {
            20_000
        } else {
            1_000
        };

        assert!(
            serialize_ns < threshold,
            "Serialize {}ns exceeds {}ns target",
            serialize_ns,
            threshold
        );

        assert!(
            deserialize_ns < threshold,
            "Deserialize {}ns exceeds {}ns target",
            deserialize_ns,
            threshold
        );

        // The combined overhead should be negligible vs the 49ns/WME engine time
        // (we target < 1us in release, which is ~20x the engine insert time --
        // acceptable since serialization happens once per rule, not per WME)
    }

    #[test]
    fn test_wme_serialization_performance() {
        let wme = make_test_wme();

        // Warm up
        for _ in 0..100 {
            let _ = serialize_wme(&wme).unwrap();
        }

        let iterations = 10_000;
        let start = Instant::now();
        for _ in 0..iterations {
            let bytes = serialize_wme(&wme).unwrap();
            std::hint::black_box(&bytes);
        }
        let serialize_elapsed = start.elapsed();
        let serialize_ns = serialize_elapsed.as_nanos() / iterations as u128;

        let bytes = serialize_wme(&wme).unwrap();
        let start = Instant::now();
        for _ in 0..iterations {
            let restored = deserialize_wme(&bytes).unwrap();
            std::hint::black_box(&restored);
        }
        let deserialize_elapsed = start.elapsed();
        let deserialize_ns = deserialize_elapsed.as_nanos() / iterations as u128;

        eprintln!("WME serialization performance:");
        eprintln!("  Serialize:   {}ns/wme", serialize_ns);
        eprintln!("  Deserialize: {}ns/wme", deserialize_ns);
        eprintln!("  Wire size:   {} bytes", bytes.len());

        // WME serialization should be even faster than rule serialization.
        // Debug mode uses relaxed threshold.
        let threshold = if cfg!(debug_assertions) { 5_000 } else { 500 };
        assert!(
            serialize_ns < threshold,
            "WME serialize {}ns exceeds {}ns target",
            serialize_ns,
            threshold
        );
    }

    // ================================================================
    // Group 8: Batch serialization
    // ================================================================

    #[test]
    fn test_batch_rule_serialization() {
        // Simulate serializing a set of rules across all states
        let states = [
            (RuleStatus::Candidate, 0.35),
            (RuleStatus::Active, 0.72),
            (RuleStatus::Weakened, 0.25),
            (RuleStatus::Dormant, 0.15),
            (RuleStatus::Expired, 0.0),
        ];

        let mut total_bytes = 0usize;
        for (i, (status, cf)) in states.iter().enumerate() {
            let mut rule = make_test_rule(*status, *cf);
            rule.rule_id = i as u32;
            let bytes = rule.to_bytes().unwrap();
            total_bytes += bytes.len();

            let restored = RuleEnvelope::from_bytes(&bytes).unwrap();
            assert_eq!(rule, restored, "Round-trip failed for state {:?}", status);
        }

        eprintln!(
            "Batch: 5 rules, total {} bytes, avg {} bytes/rule",
            total_bytes,
            total_bytes / states.len()
        );
    }

    #[test]
    fn test_large_wme_snapshot() {
        // 100 WMEs in a snapshot
        let wmes: Vec<Wme> = (0..100u16)
            .map(|i| {
                Wme::new(
                    i,
                    i + 1,
                    i + 2,
                    i + 3,
                    i + 4,
                    i + 5,
                    i + 6,
                    (i % 8) as u8,
                    (i % 10) as u8,
                    0.5 + (i as f32) * 0.001,
                )
            })
            .collect();
        let snapshot = WmeSnapshot::new(wmes.clone());
        let bytes = snapshot.to_bytes().unwrap();
        let restored = WmeSnapshot::from_bytes(&bytes).unwrap();

        assert_eq!(restored.wmes.len(), 100);
        for (orig, rest) in wmes.iter().zip(restored.wmes.iter()) {
            assert_eq!(orig.entity_a_type, rest.entity_a_type);
            assert_eq!(orig.entity_b_gen, rest.entity_b_gen);
        }

        eprintln!(
            "WME snapshot: 100 WMEs, {} bytes total, {} bytes/wme",
            bytes.len(),
            bytes.len() / 100
        );
    }

    // ================================================================
    // Group 9: EvolutionRecord direct serialization
    // ================================================================

    #[test]
    fn test_evolution_record_standalone_roundtrip() {
        let now = 1_000_000u64;
        let evo = EvolutionRecord::new(now, 0.72, SensitivityTier::S3, Domain::Default, 5, 100);
        let bytes = postcard::to_allocvec(&evo).unwrap();
        let restored: EvolutionRecord = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(evo.status, restored.status);
        assert_eq!(evo.created_at, restored.created_at);
        assert!((evo.confidence - restored.confidence).abs() < 1e-10);
        eprintln!("EvolutionRecord wire size: {} bytes", bytes.len());
    }
}
