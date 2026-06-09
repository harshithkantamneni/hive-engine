//! Type-state tuple types for the HIVE privacy pipeline.
//!
//! Each struct represents the output of one pipeline stage. The compiler
//! enforces stage ordering: a function that takes `PiiStrippedTuple` cannot
//! accept a `BucketedTuple`, so out-of-order execution is a compile error.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Stage 0 output ─────────────────────────────────────────────────────────

/// Raw tuple entering the privacy pipeline. This is a SEPARATE type from
/// `crate::tuple_adapter::RawTuple`; it contains only the fields needed
/// for the privacy path and strips file paths / document IDs that must
/// never leave the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawTuple {
    pub entity_a_type: String,
    pub entity_a_name: String,
    pub entity_a_role: String,
    pub entity_b_type: String,
    pub entity_b_name: String,
    pub entity_b_role: String,
    pub relation: String,
    pub amount: Option<f64>,
    pub context: Option<String>,
    pub document_category: String,
    pub source_region: String,
    pub time_period: String,
    pub extraction_timestamp: u64,
}

impl RawTuple {
    /// Convert from the existing `tuple_adapter::RawTuple` into the privacy
    /// pipeline's `RawTuple`. The adapter type carries fields (document_id,
    /// source_file_path) that must never enter the sharing path.
    ///
    /// `source_region` is provided by the caller because the adapter type
    /// does not carry geographic information.
    pub fn from_adapter_raw_tuple(
        adapter: &crate::tuple_adapter::RawTuple,
        source_region: &str,
    ) -> Self {
        // Try to parse entity_b value as an amount
        let amount = crate::tuple_adapter::parse_amount(&adapter.entity_b.value);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            entity_a_type: adapter.entity_a.entity_type.clone(),
            entity_a_name: adapter.entity_a.text.clone(),
            entity_a_role: adapter.entity_a.role.clone(),
            entity_b_type: adapter.entity_b.entity_type.clone(),
            entity_b_name: adapter.entity_b.text.clone(),
            entity_b_role: adapter.entity_b.role.clone(),
            relation: adapter.relationship.relation.clone(),
            amount,
            context: if adapter.relationship.context.is_empty() {
                None
            } else {
                Some(adapter.relationship.context.clone())
            },
            document_category: adapter.document_category.clone(),
            source_region: source_region.to_string(),
            time_period: String::new(), // populated downstream from extraction_ts
            extraction_timestamp: now,
        }
    }
}

// ─── Stage 1 output ─────────────────────────────────────────────────────────

/// Output of Stage 1 (PII stripping). Direct identifiers removed;
/// entity names replaced by type-only descriptors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiStrippedTuple {
    pub entity_a_type: String,
    pub entity_a_role: String,
    // entity_a_name: STRIPPED (not present)
    pub entity_b_type: String,
    pub entity_b_value: String, // generalized value, not raw name
    pub entity_b_role: String,
    pub relation: String,
    pub amount: Option<f64>,
    // context: STRIPPED (may contain PII)
    pub document_category: String,
    pub sensitivity_tier: SensitivityTier,
    pub source_region: String,
    pub time_period: String,
}

// ─── Stage 2 output ─────────────────────────────────────────────────────────

/// Output of Stage 2 (amount bucketing). Exact amounts replaced by a
/// logarithmic bucket index (0-7) or `0xFF` for N/A.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketedTuple {
    pub entity_a_type: String,
    pub entity_a_role: String,
    pub entity_b_type: String,
    pub entity_b_value: String,
    pub entity_b_role: String,
    pub relation: String,
    pub amount_bucket: u8, // 0-7 or 0xFF
    pub document_category: String,
    pub sensitivity_tier: SensitivityTier,
    pub source_region: String,
    pub time_period: String,
}

// ─── Stage 3 output ─────────────────────────────────────────────────────────

/// Output of Stage 3 (context generalization). Fields elevated in
/// generalization hierarchies until estimated k exceeds the tier threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralizedTuple {
    pub entity_a_type: String,
    pub entity_a_gen: String,   // generalized entity A value
    pub entity_a_gen_level: u8, // how many levels up
    pub entity_a_role: String,
    pub entity_b_type: String,
    pub entity_b_gen: String, // generalized entity B value
    pub entity_b_gen_level: u8,
    pub entity_b_role: String,
    pub relation: String,
    pub amount_bucket: u8,
    pub document_category: String,
    pub sensitivity_tier: SensitivityTier,
    pub source_region: String, // generalized region
    pub time_period: String,   // generalized time period
}

// ─── Stage 4 output ─────────────────────────────────────────────────────────

/// Output of Stage 4 (pattern hashing). HMAC-BLAKE3 hash computed
/// with device-local key; resolution levels selected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedTuple {
    pub inner: GeneralizedTuple,
    pub pattern_hash: [u8; 32],  // HMAC-BLAKE3 with device key
    pub pattern_key: PatternKey, // structured aggregation key
    pub resolution_level: u8,    // 0 = primary, 1 = coarse
}

// ─── Stage 5 output ─────────────────────────────────────────────────────────

/// Output of Stage 5 (k-anonymity check). Passed the full 12-field
/// multiplicative selectivity threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KCheckedTuple {
    pub inner: HashedTuple,
    pub estimated_k: f64,
}

// ─── Stage 6 output ─────────────────────────────────────────────────────────

/// Output of Stage 6 (l-diversity check). Passed entropy-based
/// l-diversity threshold on the sensitive attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LCheckedTuple {
    pub inner: KCheckedTuple,
    pub l_entropy: f64,
}

// ─── Stage 7 output ─────────────────────────────────────────────────────────

/// Output of Stage 7 (OUE encoding). Fields encoded with differential
/// privacy noise via Optimized Unary Encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedTuple {
    pub inner: LCheckedTuple,
    pub oue_vectors: Vec<OueFieldVector>,
    pub epsilon_consumed: f64,
}

// ─── Stage 8 output ─────────────────────────────────────────────────────────

/// Output of Stage 8 (budget check). Budget approved; encoding and
/// budget consumption are atomic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetApprovedTuple {
    pub inner: EncodedTuple,
    pub budget_snapshot: BudgetSnapshot,
}

// ─── Stage 9 output ─────────────────────────────────────────────────────────

/// Output of Stage 9 (jitter queue). Tuple placed in time-delayed
/// cross-document batch queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedTuple {
    pub inner: BudgetApprovedTuple,
    pub scheduled_send_time: u64, // unix timestamp
    pub batch_id: Option<u64>,
}

// ─── Supporting types ───────────────────────────────────────────────────────

/// Sensitivity tier for document categories. S1 = most sensitive (medical),
/// S4 = least (receipts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SensitivityTier {
    /// Critical: medical bills, EOBs, insurance, prescriptions
    S1Critical = 1,
    /// High: leases, contracts, bank statements, pay stubs, gov forms
    S2High = 2,
    /// Medium: utility bills, terms of service
    S3Medium = 3,
    /// Low: receipts, restaurant receipts
    S4Low = 4,
}

impl SensitivityTier {
    /// Convert a u8 tier value to a `SensitivityTier`, defaulting to S2
    /// for unknown values (conservative default).
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => SensitivityTier::S1Critical,
            2 => SensitivityTier::S2High,
            3 => SensitivityTier::S3Medium,
            4 => SensitivityTier::S4Low,
            _ => SensitivityTier::S2High, // unknown -> S2 (conservative)
        }
    }

    /// Return the numeric tier value (1-4).
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Index into arrays that are ordered [S1, S2, S3, S4] (0-based).
    pub fn index(self) -> usize {
        (self as u8 - 1) as usize
    }
}

/// Cross-device pattern aggregation key.
/// Used instead of pattern_hash for matching across devices -- the hash
/// is device-local and non-reversible.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PatternKey {
    pub entity_a_type: String,
    pub entity_a_gen: String,
    pub entity_a_gen_level: u8,
    pub relation: String,
    pub entity_b_type: String,
    pub entity_b_gen: String,
    pub entity_b_gen_level: u8,
    pub amount_bucket: u8,
    pub document_category: String,
}

/// One OUE-encoded field. Packed bit vector with per-field epsilon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OueFieldVector {
    pub field_name: String,
    pub domain_size: u16,
    pub epsilon: f64,
    pub bits: Vec<u8>, // packed bit vector
}

/// Snapshot of budget state at time of approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    pub tier: SensitivityTier,
    pub daily_remaining: f64,
    pub weekly_remaining: f64,
    pub lifetime_remaining: f64,
}

/// Result of attempting to process a tuple through the full privacy pipeline.
///
/// Note: `Queued(QueuedTuple)` is ~544 bytes, dwarfing the other variants
/// (~65 bytes). Boxing `QueuedTuple` would shrink the enum footprint but is
/// deferred: the public result is already propagated by move (not stored in
/// collections on the hot path) and introducing `Box<QueuedTuple>` would
/// change the wire shape observed by external consumers (integration tests,
/// P2P bridge, diagnostics Debug output). Revisit once a public API migration
/// is planned.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum PrivacyPipelineResult {
    /// Tuple approved and queued for sharing.
    Queued(QueuedTuple),
    /// Tuple suppressed at the named stage with reason.
    Suppressed {
        stage: &'static str,
        reason: String,
        document_category: String,
        sensitivity_tier: SensitivityTier,
    },
    /// Cold-start rules prevent sharing for this tier.
    ColdStartBlocked {
        tier: SensitivityTier,
        phase: NetworkPhase,
    },
}

/// Network maturity phase, determines cold-start gating and k-thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkPhase {
    /// < 10K users
    Bootstrap,
    /// 10K -- 100K users
    Growth,
    /// 100K -- 1M users
    Maturity,
    /// 1M+ users
    Scale,
}

impl NetworkPhase {
    /// 0-based index into k-threshold arrays ordered
    /// [Bootstrap, Growth, Maturity, Scale].
    pub fn index(self) -> usize {
        match self {
            NetworkPhase::Bootstrap => 0,
            NetworkPhase::Growth => 1,
            NetworkPhase::Maturity => 2,
            NetworkPhase::Scale => 3,
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- SensitivityTier tests ---

    #[test]
    fn sensitivity_tier_ordering_s1_less_than_s4() {
        assert!(SensitivityTier::S1Critical < SensitivityTier::S4Low);
    }

    #[test]
    fn sensitivity_tier_ordering_s2_less_than_s3() {
        assert!(SensitivityTier::S2High < SensitivityTier::S3Medium);
    }

    #[test]
    fn sensitivity_tier_ordering_all_tiers() {
        let tiers = [
            SensitivityTier::S1Critical,
            SensitivityTier::S2High,
            SensitivityTier::S3Medium,
            SensitivityTier::S4Low,
        ];
        for i in 0..tiers.len() - 1 {
            assert!(tiers[i] < tiers[i + 1], "S{} should be < S{}", i + 1, i + 2);
        }
    }

    #[test]
    fn sensitivity_tier_from_u8_valid() {
        assert_eq!(SensitivityTier::from_u8(1), SensitivityTier::S1Critical);
        assert_eq!(SensitivityTier::from_u8(2), SensitivityTier::S2High);
        assert_eq!(SensitivityTier::from_u8(3), SensitivityTier::S3Medium);
        assert_eq!(SensitivityTier::from_u8(4), SensitivityTier::S4Low);
    }

    #[test]
    fn sensitivity_tier_from_u8_unknown_defaults_to_s2() {
        assert_eq!(SensitivityTier::from_u8(0), SensitivityTier::S2High);
        assert_eq!(SensitivityTier::from_u8(5), SensitivityTier::S2High);
        assert_eq!(SensitivityTier::from_u8(255), SensitivityTier::S2High);
    }

    #[test]
    fn sensitivity_tier_as_u8_roundtrip() {
        for tier_val in 1..=4u8 {
            let tier = SensitivityTier::from_u8(tier_val);
            assert_eq!(tier.as_u8(), tier_val);
        }
    }

    #[test]
    fn sensitivity_tier_index() {
        assert_eq!(SensitivityTier::S1Critical.index(), 0);
        assert_eq!(SensitivityTier::S2High.index(), 1);
        assert_eq!(SensitivityTier::S3Medium.index(), 2);
        assert_eq!(SensitivityTier::S4Low.index(), 3);
    }

    #[test]
    fn sensitivity_tier_serde_roundtrip() {
        let tier = SensitivityTier::S3Medium;
        let json = serde_json::to_string(&tier).unwrap();
        let deserialized: SensitivityTier = serde_json::from_str(&json).unwrap();
        assert_eq!(tier, deserialized);
    }

    // --- PatternKey tests ---

    #[test]
    fn pattern_key_equality() {
        let pk1 = PatternKey {
            entity_a_type: "organization".into(),
            entity_a_gen: "medical_provider".into(),
            entity_a_gen_level: 2,
            relation: "charges".into(),
            entity_b_type: "procedure".into(),
            entity_b_gen: "surgical_procedure".into(),
            entity_b_gen_level: 3,
            amount_bucket: 4,
            document_category: "medical_bill".into(),
        };
        let pk2 = pk1.clone();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn pattern_key_inequality_on_gen_level() {
        let pk1 = PatternKey {
            entity_a_type: "organization".into(),
            entity_a_gen: "hospital".into(),
            entity_a_gen_level: 1,
            relation: "charges".into(),
            entity_b_type: "procedure".into(),
            entity_b_gen: "ear_surgery".into(),
            entity_b_gen_level: 2,
            amount_bucket: 3,
            document_category: "medical_bill".into(),
        };
        let mut pk2 = pk1.clone();
        pk2.entity_b_gen_level = 3;
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn pattern_key_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let pk = PatternKey {
            entity_a_type: "organization".into(),
            entity_a_gen: "hospital".into(),
            entity_a_gen_level: 1,
            relation: "charges".into(),
            entity_b_type: "procedure".into(),
            entity_b_gen: "ear_surgery".into(),
            entity_b_gen_level: 2,
            amount_bucket: 3,
            document_category: "medical_bill".into(),
        };
        let mut h1 = DefaultHasher::new();
        pk.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        pk.clone().hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn pattern_key_serde_roundtrip() {
        let pk = PatternKey {
            entity_a_type: "organization".into(),
            entity_a_gen: "hospital".into(),
            entity_a_gen_level: 1,
            relation: "charges".into(),
            entity_b_type: "procedure".into(),
            entity_b_gen: "ear_surgery".into(),
            entity_b_gen_level: 2,
            amount_bucket: 3,
            document_category: "medical_bill".into(),
        };
        let json = serde_json::to_string(&pk).unwrap();
        let deserialized: PatternKey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, deserialized);
    }

    // --- NetworkPhase tests ---

    #[test]
    fn network_phase_index() {
        assert_eq!(NetworkPhase::Bootstrap.index(), 0);
        assert_eq!(NetworkPhase::Growth.index(), 1);
        assert_eq!(NetworkPhase::Maturity.index(), 2);
        assert_eq!(NetworkPhase::Scale.index(), 3);
    }

    #[test]
    fn network_phase_serde_roundtrip() {
        let phase = NetworkPhase::Growth;
        let json = serde_json::to_string(&phase).unwrap();
        let deserialized: NetworkPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(phase, deserialized);
    }

    // --- OueFieldVector tests ---

    #[test]
    fn oue_field_vector_serde_roundtrip() {
        let v = OueFieldVector {
            field_name: "entity_b_value".into(),
            domain_size: 128,
            epsilon: 0.30,
            bits: vec![0xFF, 0x00, 0xAB],
        };
        let json = serde_json::to_string(&v).unwrap();
        let deserialized: OueFieldVector = serde_json::from_str(&json).unwrap();
        assert_eq!(v.field_name, deserialized.field_name);
        assert_eq!(v.domain_size, deserialized.domain_size);
        assert!((v.epsilon - deserialized.epsilon).abs() < 1e-10);
        assert_eq!(v.bits, deserialized.bits);
    }

    // --- BudgetSnapshot tests ---

    #[test]
    fn budget_snapshot_serde_roundtrip() {
        let snap = BudgetSnapshot {
            tier: SensitivityTier::S1Critical,
            daily_remaining: 1.5,
            weekly_remaining: 8.0,
            lifetime_remaining: 95.0,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let deserialized: BudgetSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap.tier, deserialized.tier);
        assert!((snap.daily_remaining - deserialized.daily_remaining).abs() < 1e-10);
    }

    // --- RawTuple conversion tests ---

    #[test]
    fn from_adapter_raw_tuple_basic_fields() {
        let adapter_tuple = crate::tuple_adapter::RawTuple {
            tuple_id: "test-id".into(),
            document_id: "doc-123".into(),
            extraction_ts: 1000,
            entity_a: crate::tuple_adapter::RawEntity {
                entity_type: "organization".into(),
                role: "provider".into(),
                text: "Riverside General Hospital".into(),
                value: "Riverside General Hospital".into(),
                privacy_class: crate::tuple_adapter::PrivacyClass::Public,
            },
            relationship: crate::tuple_adapter::RawRelationship {
                relation: "charges".into(),
                context: "ER visit on March 15".into(),
            },
            entity_b: crate::tuple_adapter::RawEntity {
                entity_type: "procedure".into(),
                role: "charge".into(),
                text: "bilateral cochlear implant".into(),
                value: "$8200".into(),
                privacy_class: crate::tuple_adapter::PrivacyClass::Sensitive,
            },
            document_category: "medical_bill".into(),
            sensitivity_tier: 1,
            extraction_confidence: 0.95,
            source_file_path: "/home/user/docs/bill.pdf".into(),
        };

        let privacy_raw = RawTuple::from_adapter_raw_tuple(&adapter_tuple, "US-Northeast");

        assert_eq!(privacy_raw.entity_a_type, "organization");
        assert_eq!(privacy_raw.entity_a_name, "Riverside General Hospital");
        assert_eq!(privacy_raw.entity_a_role, "provider");
        assert_eq!(privacy_raw.entity_b_type, "procedure");
        assert_eq!(privacy_raw.relation, "charges");
        assert_eq!(privacy_raw.document_category, "medical_bill");
        assert_eq!(privacy_raw.source_region, "US-Northeast");
        // Amount should be parsed from "$8200"
        assert!(privacy_raw.amount.is_some());
        assert!((privacy_raw.amount.unwrap() - 8200.0).abs() < 0.01);
    }

    #[test]
    fn from_adapter_raw_tuple_strips_context() {
        let adapter_tuple = crate::tuple_adapter::RawTuple {
            tuple_id: "t2".into(),
            document_id: "d2".into(),
            extraction_ts: 2000,
            entity_a: crate::tuple_adapter::RawEntity {
                entity_type: "person".into(),
                role: "patient".into(),
                text: "John Doe".into(),
                value: "John Doe".into(),
                privacy_class: crate::tuple_adapter::PrivacyClass::DirectId,
            },
            relationship: crate::tuple_adapter::RawRelationship {
                relation: "visited".into(),
                context: "Patient John visited ER".into(),
            },
            entity_b: crate::tuple_adapter::RawEntity {
                entity_type: "organization".into(),
                role: "provider".into(),
                text: "City Hospital".into(),
                value: "".into(),
                privacy_class: crate::tuple_adapter::PrivacyClass::Public,
            },
            document_category: "medical_bill".into(),
            sensitivity_tier: 1,
            extraction_confidence: 0.90,
            source_file_path: "/tmp/scan.pdf".into(),
        };

        let privacy_raw = RawTuple::from_adapter_raw_tuple(&adapter_tuple, "US-Midwest");
        // Context is preserved in RawTuple -- PII stripping happens in Stage 1
        assert!(privacy_raw.context.is_some());
        assert_eq!(privacy_raw.context.unwrap(), "Patient John visited ER");
    }

    #[test]
    fn from_adapter_raw_tuple_empty_context_becomes_none() {
        let adapter_tuple = crate::tuple_adapter::RawTuple {
            tuple_id: "t3".into(),
            document_id: "d3".into(),
            extraction_ts: 3000,
            entity_a: crate::tuple_adapter::RawEntity {
                entity_type: "amount".into(),
                role: "charge".into(),
                text: "$50".into(),
                value: "$50".into(),
                privacy_class: crate::tuple_adapter::PrivacyClass::Sensitive,
            },
            relationship: crate::tuple_adapter::RawRelationship {
                relation: "paid_for".into(),
                context: String::new(),
            },
            entity_b: crate::tuple_adapter::RawEntity {
                entity_type: "product".into(),
                role: "merchant".into(),
                text: "groceries".into(),
                value: "".into(),
                privacy_class: crate::tuple_adapter::PrivacyClass::Public,
            },
            document_category: "receipt".into(),
            sensitivity_tier: 4,
            extraction_confidence: 1.0,
            source_file_path: "/tmp/receipt.jpg".into(),
        };

        let privacy_raw = RawTuple::from_adapter_raw_tuple(&adapter_tuple, "US-South");
        assert!(privacy_raw.context.is_none());
    }

    #[test]
    fn from_adapter_raw_tuple_unparseable_amount() {
        let adapter_tuple = crate::tuple_adapter::RawTuple {
            tuple_id: "t4".into(),
            document_id: "d4".into(),
            extraction_ts: 4000,
            entity_a: crate::tuple_adapter::RawEntity {
                entity_type: "organization".into(),
                role: "employer".into(),
                text: "ACME Corp".into(),
                value: "N/A".into(),
                privacy_class: crate::tuple_adapter::PrivacyClass::Public,
            },
            relationship: crate::tuple_adapter::RawRelationship {
                relation: "employs".into(),
                context: String::new(),
            },
            entity_b: crate::tuple_adapter::RawEntity {
                entity_type: "term".into(),
                role: "category_code".into(),
                text: "full-time".into(),
                value: "N/A".into(),
                privacy_class: crate::tuple_adapter::PrivacyClass::Public,
            },
            document_category: "contract".into(),
            sensitivity_tier: 2,
            extraction_confidence: 0.8,
            source_file_path: "/docs/contract.pdf".into(),
        };

        let privacy_raw = RawTuple::from_adapter_raw_tuple(&adapter_tuple, "US-West");
        assert!(privacy_raw.amount.is_none());
    }
}
