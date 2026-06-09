//! QueuedTuple <-> wire bytes serialization for P2P transport.
//!
//! Serializes privacy-pipeline tuples to a compact binary wire format using
//! postcard (varint encoding). Dictionary-encodes all string fields as u16 IDs
//! for compactness. Target: <= 256 bytes.

use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Wire format version. Increment on breaking changes.
pub const WIRE_VERSION: u8 = 0x01;

/// Maximum wire size.
pub const MAX_TUPLE_WIRE_SIZE: usize = 256;

/// Sentinel dictionary ID for unknown/inline string values.
pub const DICT_ID_UNKNOWN: u16 = 0xFFFF;

// ============================================================================
// WireTuple -- the serializable wire format
// ============================================================================

/// Serializable tuple for P2P wire format.
///
/// Uses postcard for compact varint encoding.
/// All string fields are dictionary-encoded as u16 IDs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireTuple {
    /// Wire format version (0x01).
    pub version: u8,
    /// Sensitivity tier (1-4).
    pub sensitivity_tier: u8,
    /// Dictionary-encoded entity A type.
    pub entity_a_type_id: u16,
    /// Dictionary-encoded entity A generalized value.
    pub entity_a_gen_id: u16,
    /// Entity A generalization level.
    pub entity_a_gen_level: u8,
    /// Dictionary-encoded entity A role.
    pub entity_a_role_id: u16,
    /// Dictionary-encoded relation.
    pub relation_id: u16,
    /// Dictionary-encoded entity B type.
    pub entity_b_type_id: u16,
    /// Dictionary-encoded entity B generalized value.
    pub entity_b_gen_id: u16,
    /// Entity B generalization level.
    pub entity_b_gen_level: u8,
    /// Dictionary-encoded entity B role.
    pub entity_b_role_id: u16,
    /// Amount bucket (0-7 or 0xFF for N/A).
    pub amount_bucket: u8,
    /// Dictionary-encoded document category.
    pub document_category_id: u16,
    /// Dictionary-encoded source region.
    pub source_region_id: u16,
    /// Dictionary-encoded time period.
    pub time_period_id: u16,
    /// Number of OUE field vectors.
    pub oue_field_count: u8,
    /// OUE-encoded field vectors.
    pub oue_vectors: Vec<WireOueVector>,
    /// DP epsilon * 100 (integer representation).
    pub dp_epsilon_x100: u16,
}

/// One OUE-encoded field vector in wire format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireOueVector {
    /// Field identifier (which field this OUE vector encodes).
    pub field_id: u8,
    /// Domain size for this field.
    pub domain_size: u16,
    /// Packed bit vector (OUE-encoded).
    pub bits: Vec<u8>,
}

// ============================================================================
// Serialization error type
// ============================================================================

/// Errors during tuple wire serialization/deserialization.
#[derive(Debug, Clone, PartialEq)]
pub enum SerError {
    /// Encoding failed.
    Encode(String),
    /// Decoding failed.
    Decode(String),
    /// Serialized size exceeds the wire cap (256 bytes).
    TooLarge(usize),
}

impl std::fmt::Display for SerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SerError::Encode(e) => write!(f, "tuple wire encode error: {}", e),
            SerError::Decode(e) => write!(f, "tuple wire decode error: {}", e),
            SerError::TooLarge(size) => write!(
                f,
                "tuple wire size {} exceeds {} byte limit",
                size, MAX_TUPLE_WIRE_SIZE
            ),
        }
    }
}

impl std::error::Error for SerError {}

// ============================================================================
// Serialize / Deserialize functions
// ============================================================================

/// Serialize a WireTuple to compact binary wire format.
///
/// Uses postcard for varint encoding. Returns error if the result
/// exceeds MAX_TUPLE_WIRE_SIZE (256 bytes).
pub fn serialize(wire_tuple: &WireTuple) -> Result<Vec<u8>, SerError> {
    let bytes = postcard::to_allocvec(wire_tuple).map_err(|e| SerError::Encode(e.to_string()))?;
    if bytes.len() > MAX_TUPLE_WIRE_SIZE {
        return Err(SerError::TooLarge(bytes.len()));
    }
    Ok(bytes)
}

/// Serialize without the size check (for benchmarking / measuring).
pub fn serialize_unchecked(wire_tuple: &WireTuple) -> Result<Vec<u8>, SerError> {
    postcard::to_allocvec(wire_tuple).map_err(|e| SerError::Encode(e.to_string()))
}

/// Deserialize a WireTuple from binary bytes.
pub fn deserialize(bytes: &[u8]) -> Result<WireTuple, SerError> {
    postcard::from_bytes(bytes).map_err(|e| SerError::Decode(e.to_string()))
}

/// Compute the wire size of a WireTuple without the size check.
pub fn wire_size(wire_tuple: &WireTuple) -> Result<usize, SerError> {
    let bytes = postcard::to_allocvec(wire_tuple).map_err(|e| SerError::Encode(e.to_string()))?;
    Ok(bytes.len())
}

// ============================================================================
// Dictionary encoding helpers
// ============================================================================

/// A simple static dictionary for wire format encoding.
///
/// Maps well-known string values to u16 IDs for compact wire representation.
/// Unknown values use the sentinel DICT_ID_UNKNOWN (0xFFFF).
///
/// This mirrors the same scheme used in wme_factory.rs but for wire transport.
pub struct WireDictionary {
    entries: Vec<(&'static str, u16)>,
}

impl WireDictionary {
    /// Create the default wire dictionary with well-known HIVE field values.
    pub fn default_dictionary() -> Self {
        Self {
            entries: vec![
                // Entity types
                ("organization", 0),
                ("person", 1),
                ("amount", 2),
                ("diagnosis", 3),
                ("procedure", 4),
                ("medication", 5),
                ("state", 6),
                ("date", 7),
                ("salary", 8),
                ("term", 9),
                ("product", 10),
                // Relations
                ("charges", 100),
                ("billed_total", 101),
                ("patient_of", 102),
                ("diagnosed_with", 103),
                ("pays_salary", 104),
                ("employs", 105),
                ("located_in", 106),
                ("prescribed", 107),
                ("paid_for", 108),
                // Roles
                ("provider", 200),
                ("payer", 201),
                ("patient", 202),
                ("charge", 203),
                ("employer", 204),
                ("merchant", 205),
                // Generalized entity values
                ("healthcare_provider", 300),
                ("insurance_company", 301),
                ("hospital", 302),
                ("clinic", 303),
                ("surgery", 304),
                ("unknown", 305),
                ("large", 306),
                ("very_large", 307),
                ("small", 308),
                ("medium", 309),
                ("employer", 310),
                // Document categories
                ("medical_bill", 400),
                ("medical", 401),
                ("health", 402),
                ("legal", 403),
                ("financial", 404),
                ("tax", 405),
                ("general", 406),
                ("personal", 407),
                ("retail", 408),
                ("receipt", 409),
                // Source regions
                ("US-Northeast", 500),
                ("US-Southeast", 501),
                ("US-Midwest", 502),
                ("US-West", 503),
                ("US-Southwest", 504),
                ("US-Pacific", 505),
                ("US-Unknown", 506),
                // Time periods
                ("2024-Q1", 600),
                ("2024-Q2", 601),
                ("2024-Q3", 602),
                ("2024-Q4", 603),
                ("2025-Q1", 604),
                ("2025-Q2", 605),
                ("2025-Q3", 606),
                ("2025-Q4", 607),
                ("2026-Q1", 608),
                ("2026-Q2", 609),
            ],
        }
    }

    /// Lookup the u16 ID for a string value.
    /// Returns DICT_ID_UNKNOWN if not found.
    pub fn encode(&self, value: &str) -> u16 {
        self.entries
            .iter()
            .find(|(s, _)| *s == value)
            .map(|(_, id)| *id)
            .unwrap_or(DICT_ID_UNKNOWN)
    }

    /// Lookup the string for a u16 ID.
    /// Returns None if the ID is not in the dictionary.
    pub fn decode(&self, id: u16) -> Option<&'static str> {
        if id == DICT_ID_UNKNOWN {
            return None;
        }
        self.entries
            .iter()
            .find(|(_, eid)| *eid == id)
            .map(|(s, _)| *s)
    }
}

// ============================================================================
// Builder: construct WireTuple from field values
// ============================================================================

impl WireTuple {
    /// Create a minimal WireTuple with dictionary-encoded fields.
    ///
    /// NOTE: 16 arguments corresponds to the fixed wire-protocol schema; a builder
    /// struct would only wrap the same fields behind a setter API, so the direct
    /// constructor is retained.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sensitivity_tier: u8,
        entity_a_type_id: u16,
        entity_a_gen_id: u16,
        entity_a_gen_level: u8,
        entity_a_role_id: u16,
        relation_id: u16,
        entity_b_type_id: u16,
        entity_b_gen_id: u16,
        entity_b_gen_level: u8,
        entity_b_role_id: u16,
        amount_bucket: u8,
        document_category_id: u16,
        source_region_id: u16,
        time_period_id: u16,
        oue_vectors: Vec<WireOueVector>,
        dp_epsilon_x100: u16,
    ) -> Self {
        Self {
            version: WIRE_VERSION,
            sensitivity_tier,
            entity_a_type_id,
            entity_a_gen_id,
            entity_a_gen_level,
            entity_a_role_id,
            relation_id,
            entity_b_type_id,
            entity_b_gen_id,
            entity_b_gen_level,
            entity_b_role_id,
            amount_bucket,
            document_category_id,
            source_region_id,
            time_period_id,
            oue_field_count: oue_vectors.len() as u8,
            oue_vectors,
            dp_epsilon_x100,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test helpers ─────────────────────────────────────────────────────

    /// Build a typical medical bill tuple for testing.
    fn make_typical_medical_tuple() -> WireTuple {
        WireTuple::new(
            1,   // S1Critical
            0,   // organization
            300, // healthcare_provider
            2,
            200, // provider
            101, // billed_total
            2,   // amount
            306, // large
            0,
            203, // charge
            5,   // bucket $1K-$5K
            400, // medical_bill
            500, // US-Northeast
            608, // 2026-Q1
            vec![
                WireOueVector {
                    field_id: 0,
                    domain_size: 20,
                    bits: vec![0xFF, 0x0F, 0xAA],
                },
                WireOueVector {
                    field_id: 1,
                    domain_size: 15,
                    bits: vec![0xCC, 0xDD],
                },
                WireOueVector {
                    field_id: 2,
                    domain_size: 8,
                    bits: vec![0xEE],
                },
            ],
            30, // epsilon 0.30
        )
    }

    /// Build a minimal tuple (fewest fields, smallest OUE).
    fn make_minimal_tuple() -> WireTuple {
        WireTuple::new(
            4,   // S4Low
            1,   // person
            305, // unknown
            0,
            202, // patient
            102, // patient_of
            0,   // organization
            302, // hospital
            1,
            200,    // provider
            255,    // no amount
            406,    // general
            506,    // US-Unknown
            608,    // 2026-Q1
            vec![], // no OUE vectors
            50,     // epsilon 0.50
        )
    }

    /// Build a maximal tuple (many OUE vectors, larger domains).
    fn make_maximal_tuple() -> WireTuple {
        WireTuple::new(
            1,   // S1Critical
            0,   // organization
            301, // insurance_company
            3,
            201, // payer
            100, // charges
            4,   // procedure
            304, // surgery
            4,
            203, // charge
            7,   // bucket $50K+
            400, // medical_bill
            500, // US-Northeast
            608, // 2026-Q1
            vec![
                WireOueVector {
                    field_id: 0,
                    domain_size: 40,
                    bits: vec![0xFF; 5],
                },
                WireOueVector {
                    field_id: 1,
                    domain_size: 30,
                    bits: vec![0xAA; 4],
                },
                WireOueVector {
                    field_id: 2,
                    domain_size: 25,
                    bits: vec![0xBB; 4],
                },
                WireOueVector {
                    field_id: 3,
                    domain_size: 20,
                    bits: vec![0xCC; 3],
                },
                WireOueVector {
                    field_id: 4,
                    domain_size: 15,
                    bits: vec![0xDD; 2],
                },
                WireOueVector {
                    field_id: 5,
                    domain_size: 10,
                    bits: vec![0xEE; 2],
                },
                WireOueVector {
                    field_id: 6,
                    domain_size: 8,
                    bits: vec![0xFF],
                },
            ],
            15, // epsilon 0.15
        )
    }

    // ── Group 1: Round-trip fidelity tests ──────────────────────────────

    #[test]
    fn roundtrip_typical_medical_tuple() {
        let original = make_typical_medical_tuple();
        let bytes = serialize(&original).unwrap();
        let restored = deserialize(&bytes).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn roundtrip_minimal_tuple() {
        let original = make_minimal_tuple();
        let bytes = serialize(&original).unwrap();
        let restored = deserialize(&bytes).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn roundtrip_maximal_tuple() {
        let original = make_maximal_tuple();
        let bytes = serialize(&original).unwrap();
        let restored = deserialize(&bytes).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn roundtrip_preserves_version() {
        let original = make_typical_medical_tuple();
        let bytes = serialize(&original).unwrap();
        let restored = deserialize(&bytes).unwrap();
        assert_eq!(restored.version, WIRE_VERSION);
    }

    #[test]
    fn roundtrip_preserves_sensitivity_tier() {
        for tier in 1..=4u8 {
            let mut tuple = make_minimal_tuple();
            tuple.sensitivity_tier = tier;
            let bytes = serialize(&tuple).unwrap();
            let restored = deserialize(&bytes).unwrap();
            assert_eq!(restored.sensitivity_tier, tier);
        }
    }

    #[test]
    fn roundtrip_preserves_oue_vectors() {
        let original = make_typical_medical_tuple();
        let bytes = serialize(&original).unwrap();
        let restored = deserialize(&bytes).unwrap();

        assert_eq!(restored.oue_field_count, 3);
        assert_eq!(restored.oue_vectors.len(), 3);
        assert_eq!(restored.oue_vectors[0].field_id, 0);
        assert_eq!(restored.oue_vectors[0].domain_size, 20);
        assert_eq!(restored.oue_vectors[0].bits, vec![0xFF, 0x0F, 0xAA]);
        assert_eq!(restored.oue_vectors[1].domain_size, 15);
        assert_eq!(restored.oue_vectors[2].bits, vec![0xEE]);
    }

    #[test]
    fn roundtrip_preserves_all_dictionary_ids() {
        let original = make_typical_medical_tuple();
        let bytes = serialize(&original).unwrap();
        let restored = deserialize(&bytes).unwrap();

        assert_eq!(restored.entity_a_type_id, original.entity_a_type_id);
        assert_eq!(restored.entity_a_gen_id, original.entity_a_gen_id);
        assert_eq!(restored.entity_a_gen_level, original.entity_a_gen_level);
        assert_eq!(restored.entity_a_role_id, original.entity_a_role_id);
        assert_eq!(restored.relation_id, original.relation_id);
        assert_eq!(restored.entity_b_type_id, original.entity_b_type_id);
        assert_eq!(restored.entity_b_gen_id, original.entity_b_gen_id);
        assert_eq!(restored.entity_b_gen_level, original.entity_b_gen_level);
        assert_eq!(restored.entity_b_role_id, original.entity_b_role_id);
        assert_eq!(restored.amount_bucket, original.amount_bucket);
        assert_eq!(restored.document_category_id, original.document_category_id);
        assert_eq!(restored.source_region_id, original.source_region_id);
        assert_eq!(restored.time_period_id, original.time_period_id);
        assert_eq!(restored.dp_epsilon_x100, original.dp_epsilon_x100);
    }

    #[test]
    fn roundtrip_amount_bucket_na() {
        let mut tuple = make_minimal_tuple();
        tuple.amount_bucket = 0xFF;
        let bytes = serialize(&tuple).unwrap();
        let restored = deserialize(&bytes).unwrap();
        assert_eq!(restored.amount_bucket, 0xFF);
    }

    // ── Group 2: Size constraint tests ──────────────────────────────────

    #[test]
    fn typical_tuple_under_256_bytes() {
        let tuple = make_typical_medical_tuple();
        let size = wire_size(&tuple).unwrap();
        assert!(
            size <= MAX_TUPLE_WIRE_SIZE,
            "Typical tuple {} bytes exceeds {} limit",
            size,
            MAX_TUPLE_WIRE_SIZE
        );
        eprintln!("Typical medical tuple wire size: {} bytes", size);
    }

    #[test]
    fn minimal_tuple_wire_size() {
        let tuple = make_minimal_tuple();
        let size = wire_size(&tuple).unwrap();
        assert!(
            size <= MAX_TUPLE_WIRE_SIZE,
            "Minimal tuple {} bytes exceeds limit",
            size
        );
        eprintln!("Minimal tuple wire size: {} bytes", size);
    }

    #[test]
    fn maximal_tuple_under_256_bytes() {
        let tuple = make_maximal_tuple();
        let size = wire_size(&tuple).unwrap();
        assert!(
            size <= MAX_TUPLE_WIRE_SIZE,
            "Maximal tuple {} bytes exceeds {} limit",
            size,
            MAX_TUPLE_WIRE_SIZE
        );
        eprintln!("Maximal tuple wire size: {} bytes", size);
    }

    #[test]
    fn serialize_rejects_oversized() {
        // Construct an artificially huge tuple with enormous OUE vectors.
        // Need multiple large vectors to push past 256 bytes.
        let huge_oue: Vec<WireOueVector> = (0..10u8)
            .map(|i| WireOueVector {
                field_id: i,
                domain_size: 512,
                bits: vec![0xFF; 30], // 10 * 30 = 300+ bytes of OUE data
            })
            .collect();
        let mut tuple = make_minimal_tuple();
        tuple.oue_field_count = huge_oue.len() as u8;
        tuple.oue_vectors = huge_oue;

        let result = serialize(&tuple);
        assert!(
            matches!(result, Err(SerError::TooLarge(_))),
            "Should reject oversized tuple, got {:?}",
            result
        );
    }

    #[test]
    fn wire_size_report() {
        // Report wire sizes for various tuple configurations.
        let configs = [
            ("minimal (no OUE)", make_minimal_tuple()),
            ("typical (3 OUE)", make_typical_medical_tuple()),
            ("maximal (7 OUE)", make_maximal_tuple()),
        ];
        for (name, tuple) in &configs {
            let size = wire_size(tuple).unwrap();
            eprintln!("  {} -> {} bytes", name, size);
        }
    }

    // ── Group 3: Dictionary encoding tests ──────────────────────────────

    #[test]
    fn dictionary_encodes_known_values() {
        let dict = WireDictionary::default_dictionary();

        assert_eq!(dict.encode("organization"), 0);
        assert_eq!(dict.encode("person"), 1);
        assert_eq!(dict.encode("charges"), 100);
        assert_eq!(dict.encode("provider"), 200);
        assert_eq!(dict.encode("healthcare_provider"), 300);
        assert_eq!(dict.encode("medical_bill"), 400);
        assert_eq!(dict.encode("US-Northeast"), 500);
        assert_eq!(dict.encode("2026-Q1"), 608);
    }

    #[test]
    fn dictionary_unknown_returns_sentinel() {
        let dict = WireDictionary::default_dictionary();
        assert_eq!(dict.encode("totally_unknown_value"), DICT_ID_UNKNOWN);
        assert_eq!(dict.encode(""), DICT_ID_UNKNOWN);
    }

    #[test]
    fn dictionary_decode_known_id() {
        let dict = WireDictionary::default_dictionary();
        assert_eq!(dict.decode(0), Some("organization"));
        assert_eq!(dict.decode(100), Some("charges"));
        assert_eq!(dict.decode(400), Some("medical_bill"));
    }

    #[test]
    fn dictionary_decode_unknown_id() {
        let dict = WireDictionary::default_dictionary();
        assert_eq!(dict.decode(DICT_ID_UNKNOWN), None);
        assert_eq!(dict.decode(9999), None);
    }

    #[test]
    fn dictionary_encode_decode_roundtrip() {
        let dict = WireDictionary::default_dictionary();
        let test_values = [
            "organization",
            "person",
            "charges",
            "provider",
            "healthcare_provider",
            "medical_bill",
            "US-Northeast",
        ];
        for value in &test_values {
            let id = dict.encode(value);
            assert_ne!(id, DICT_ID_UNKNOWN, "Known value '{}' should encode", value);
            let decoded = dict.decode(id);
            assert_eq!(decoded, Some(*value), "Decode failed for '{}'", value);
        }
    }

    // ── Group 4: Deterministic serialization ────────────────────────────

    #[test]
    fn deterministic_serialization() {
        let tuple = make_typical_medical_tuple();
        let bytes1 = serialize(&tuple).unwrap();
        let bytes2 = serialize(&tuple).unwrap();
        assert_eq!(bytes1, bytes2, "Serialization must be deterministic");
    }

    // ── Group 5: Error handling ─────────────────────────────────────────

    #[test]
    fn deserialize_corrupt_data_returns_error() {
        let result = deserialize(&[0xFF, 0x00, 0x01, 0x02]);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_empty_data_returns_error() {
        let result = deserialize(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn ser_error_display() {
        assert!(format!("{}", SerError::Encode("test".into())).contains("encode"));
        assert!(format!("{}", SerError::Decode("test".into())).contains("decode"));
        assert!(format!("{}", SerError::TooLarge(300)).contains("300"));
    }

    // ── Group 6: Edge cases ─────────────────────────────────────────────

    #[test]
    fn zero_oue_vectors() {
        let tuple = make_minimal_tuple();
        assert_eq!(tuple.oue_field_count, 0);
        assert!(tuple.oue_vectors.is_empty());

        let bytes = serialize(&tuple).unwrap();
        let restored = deserialize(&bytes).unwrap();
        assert_eq!(restored.oue_field_count, 0);
        assert!(restored.oue_vectors.is_empty());
    }

    #[test]
    fn single_oue_vector_small_domain() {
        let tuple = WireTuple::new(
            3,
            0,
            300,
            1,
            200,
            101,
            2,
            306,
            0,
            203,
            5,
            400,
            500,
            608,
            vec![WireOueVector {
                field_id: 0,
                domain_size: 4,
                bits: vec![0x0F],
            }],
            30,
        );
        let bytes = serialize(&tuple).unwrap();
        let restored = deserialize(&bytes).unwrap();
        assert_eq!(restored.oue_vectors.len(), 1);
        assert_eq!(restored.oue_vectors[0].domain_size, 4);
    }

    #[test]
    fn all_dictionary_sentinel_ids() {
        // Tuple where all string fields are "unknown" (sentinel ID).
        let tuple = WireTuple::new(
            2,
            DICT_ID_UNKNOWN,
            DICT_ID_UNKNOWN,
            0,
            DICT_ID_UNKNOWN,
            DICT_ID_UNKNOWN,
            DICT_ID_UNKNOWN,
            DICT_ID_UNKNOWN,
            0,
            DICT_ID_UNKNOWN,
            255,
            DICT_ID_UNKNOWN,
            DICT_ID_UNKNOWN,
            DICT_ID_UNKNOWN,
            vec![],
            100,
        );
        let bytes = serialize(&tuple).unwrap();
        let restored = deserialize(&bytes).unwrap();
        assert_eq!(restored.entity_a_type_id, DICT_ID_UNKNOWN);
        assert_eq!(restored.relation_id, DICT_ID_UNKNOWN);
    }

    #[test]
    fn amount_bucket_all_values() {
        for bucket in 0..=7u8 {
            let mut tuple = make_minimal_tuple();
            tuple.amount_bucket = bucket;
            let bytes = serialize(&tuple).unwrap();
            let restored = deserialize(&bytes).unwrap();
            assert_eq!(restored.amount_bucket, bucket);
        }
    }

    #[test]
    fn dp_epsilon_extremes() {
        for epsilon_x100 in [0u16, 1, 50, 100, 200, 500, u16::MAX] {
            let mut tuple = make_minimal_tuple();
            tuple.dp_epsilon_x100 = epsilon_x100;
            let bytes = serialize(&tuple).unwrap();
            let restored = deserialize(&bytes).unwrap();
            assert_eq!(restored.dp_epsilon_x100, epsilon_x100);
        }
    }
}
