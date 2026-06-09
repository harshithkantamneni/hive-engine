//! WME Factory: converts RawTuple -> Wme using Dictionary encoding.
//!
//! This module bridges the Tuple Adapter output to the Rete-II engine
//! by converting string-based `RawTuple` fields into dictionary-encoded
//! `u16` fields in a compact `Wme` struct.
//!
//! Flow: ExtractionOutput -> Tuple Adapter -> RawTuple -> WME Factory -> Wme -> Engine

use crate::dictionary::Dictionary;
use crate::generalization;
use crate::tuple_adapter::{compute_bucket, parse_amount, RawTuple};
use crate::wme::Wme;

// ---------------------------------------------------------------------------
// Document category -> u8 index mapping (fixed, ~10 categories)
// ---------------------------------------------------------------------------

/// Map a document category string to a fixed u8 index.
///
/// 10 categories, aligned with the tuple_adapter sensitivity tiers.
/// Returns the u8 index (0-9). Unknown categories map to 9 ("other").
pub fn document_category_to_u8(category: &str) -> u8 {
    match category.to_lowercase().as_str() {
        "medical_bill" => 0,
        "medical" => 1,
        "health" => 2,
        "legal" => 3,
        "financial" => 4,
        "tax" => 5,
        "general" => 6,
        "personal" => 7,
        "retail" => 8,
        "receipt" => 8,        // same as retail
        "correspondence" => 7, // same as personal
        _ => 9,                // other / unknown
    }
}

/// Get the category string for a u8 index (inverse lookup for debugging).
pub fn u8_to_document_category(idx: u8) -> &'static str {
    match idx {
        0 => "medical_bill",
        1 => "medical",
        2 => "health",
        3 => "legal",
        4 => "financial",
        5 => "tax",
        6 => "general",
        7 => "personal",
        8 => "retail",
        _ => "other",
    }
}

// ---------------------------------------------------------------------------
// WME Factory: RawTuple -> Wme
// ---------------------------------------------------------------------------

/// Convert a RawTuple into a compact Wme.
///
/// Steps:
/// 1. Dictionary-encode string fields (entity types, roles, relation)
/// 2. Compute generalized values for entity_a and entity_b
/// 3. Dictionary-encode the generalized values
/// 4. Compute amount_bucket from entity_b value (if amount type)
/// 5. Map document_category to u8
/// 6. Cast extraction_confidence f64 -> f32
pub fn create_wme(raw: &RawTuple, dict: &mut Dictionary) -> Wme {
    // 1. Dictionary-encode primary string fields
    let entity_a_type = dict.get_or_insert(&raw.entity_a.entity_type);
    let entity_a_role = dict.get_or_insert(&raw.entity_a.role);
    let relation = dict.get_or_insert(&raw.relationship.relation);
    let entity_b_type = dict.get_or_insert(&raw.entity_b.entity_type);
    let entity_b_role = dict.get_or_insert(&raw.entity_b.role);

    // 2. Compute generalized values using the hierarchy tables
    let gen_a_str = generalization::generalize(&raw.entity_a.value, &raw.entity_a.entity_type);
    let gen_b_str = generalization::generalize(&raw.entity_b.value, &raw.entity_b.entity_type);

    // 3. Dictionary-encode generalized values
    let entity_a_gen = dict.get_or_insert(gen_a_str);
    let entity_b_gen = dict.get_or_insert(gen_b_str);

    // 4. Compute amount_bucket: parse entity_b value if it's an amount type
    let amount_bucket = compute_amount_bucket_for_tuple(raw);

    // 5. Document category -> u8
    let document_category = document_category_to_u8(&raw.document_category);

    // 6. Confidence: f64 -> f32
    let extraction_cf = raw.extraction_confidence as f32;

    Wme::new(
        entity_a_type,
        entity_a_role,
        entity_a_gen,
        relation,
        entity_b_type,
        entity_b_role,
        entity_b_gen,
        amount_bucket,
        document_category,
        extraction_cf,
    )
}

/// Compute the amount_bucket for a RawTuple.
///
/// Checks both entity_a and entity_b for amount-like types.
/// If entity_b is an amount type, parse its value and bucket it.
/// Otherwise check entity_a. If neither is an amount type, returns 255 (N/A).
fn compute_amount_bucket_for_tuple(raw: &RawTuple) -> u8 {
    // Check entity_b first (most common: e.g., "org billed_total amount")
    if is_amount_type(&raw.entity_b.entity_type) {
        let amount = parse_amount(&raw.entity_b.value);
        return compute_bucket(amount);
    }
    // Check entity_a as fallback
    if is_amount_type(&raw.entity_a.entity_type) {
        let amount = parse_amount(&raw.entity_a.value);
        return compute_bucket(amount);
    }
    // Neither entity is an amount type
    255
}

/// Check if an entity type represents a monetary/numeric value.
fn is_amount_type(entity_type: &str) -> bool {
    matches!(
        entity_type.to_lowercase().as_str(),
        "amount"
            | "total"
            | "balance"
            | "payment"
            | "charge"
            | "cost"
            | "fee"
            | "price"
            | "salary"
            | "income"
    )
}

/// Batch-convert multiple RawTuples into Wmes.
///
/// Shares a single Dictionary across all conversions for consistent encoding.
pub fn create_wmes(tuples: &[RawTuple], dict: &mut Dictionary) -> Vec<Wme> {
    tuples.iter().map(|raw| create_wme(raw, dict)).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dictionary::Dictionary;
    use crate::tuple_adapter::{
        convert, parse_extraction_json, ConversionContext, PrivacyClass, RawEntity,
        RawRelationship, RawTuple,
    };

    // -----------------------------------------------------------------------
    // Document category mapping tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_document_category_to_u8() {
        assert_eq!(document_category_to_u8("medical_bill"), 0);
        assert_eq!(document_category_to_u8("medical"), 1);
        assert_eq!(document_category_to_u8("health"), 2);
        assert_eq!(document_category_to_u8("legal"), 3);
        assert_eq!(document_category_to_u8("financial"), 4);
        assert_eq!(document_category_to_u8("tax"), 5);
        assert_eq!(document_category_to_u8("general"), 6);
        assert_eq!(document_category_to_u8("personal"), 7);
        assert_eq!(document_category_to_u8("retail"), 8);
        assert_eq!(document_category_to_u8("receipt"), 8);
        assert_eq!(document_category_to_u8("correspondence"), 7);
        assert_eq!(document_category_to_u8("unknown_category"), 9);
        assert_eq!(document_category_to_u8(""), 9);
    }

    #[test]
    fn test_document_category_case_insensitive() {
        assert_eq!(document_category_to_u8("Medical_Bill"), 0);
        assert_eq!(document_category_to_u8("FINANCIAL"), 4);
        assert_eq!(document_category_to_u8("Legal"), 3);
    }

    #[test]
    fn test_u8_to_document_category_roundtrip() {
        for idx in 0..=9u8 {
            let cat = u8_to_document_category(idx);
            // Verify the category maps back to the same or equivalent index
            let back = document_category_to_u8(cat);
            assert_eq!(
                back, idx,
                "Roundtrip failed for idx {}: cat='{}' -> {}",
                idx, cat, back
            );
        }
    }

    // -----------------------------------------------------------------------
    // Helper to build a RawTuple for testing
    // -----------------------------------------------------------------------

    // Test-only tuple builder; positional args mirror the tuple schema so each
    // call site reads top-to-bottom as A-side, relation, B-side, metadata.
    #[allow(clippy::too_many_arguments)]
    fn make_test_tuple(
        ea_type: &str,
        ea_role: &str,
        ea_value: &str,
        relation: &str,
        eb_type: &str,
        eb_role: &str,
        eb_value: &str,
        doc_category: &str,
        confidence: f64,
    ) -> RawTuple {
        RawTuple {
            tuple_id: "test-tuple-001".to_string(),
            document_id: "test-doc-hash".to_string(),
            extraction_ts: 1700000000,
            entity_a: RawEntity {
                entity_type: ea_type.to_string(),
                role: ea_role.to_string(),
                text: ea_role.to_string(),
                value: ea_value.to_string(),
                privacy_class: PrivacyClass::Public,
            },
            relationship: RawRelationship {
                relation: relation.to_string(),
                context: "test context".to_string(),
            },
            entity_b: RawEntity {
                entity_type: eb_type.to_string(),
                role: eb_role.to_string(),
                text: eb_role.to_string(),
                value: eb_value.to_string(),
                privacy_class: PrivacyClass::Public,
            },
            document_category: doc_category.to_string(),
            sensitivity_tier: 1,
            extraction_confidence: confidence,
            source_file_path: "/test/path".to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // WME creation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_wme_basic() {
        let mut dict = Dictionary::new();
        let raw = make_test_tuple(
            "organization",
            "Memorial Hospital",
            "hospital",
            "billed_total",
            "amount",
            "$1,234.56",
            "$1,234.56",
            "medical_bill",
            0.87,
        );

        let wme = create_wme(&raw, &mut dict);

        // Verify dictionary encoding works (lookup by string)
        assert_eq!(dict.get_str(wme.entity_a_type), Some("organization"));
        assert_eq!(dict.get_str(wme.entity_a_role), Some("Memorial Hospital"));
        assert_eq!(dict.get_str(wme.relation), Some("billed_total"));
        assert_eq!(dict.get_str(wme.entity_b_type), Some("amount"));
        assert_eq!(dict.get_str(wme.entity_b_role), Some("$1,234.56"));

        // Generalized values
        assert_eq!(dict.get_str(wme.entity_a_gen), Some("healthcare_provider"));
        assert_eq!(dict.get_str(wme.entity_b_gen), Some("large"));

        // Amount bucket: $1,234.56 -> bucket 5 (1K-5K)
        assert_eq!(wme.amount_bucket, 5);

        // Document category: medical_bill -> 0
        assert_eq!(wme.document_category, 0);

        // Confidence
        assert!((wme.extraction_cf - 0.87).abs() < 1e-6);
    }

    #[test]
    fn test_create_wme_person_to_organization() {
        let mut dict = Dictionary::new();
        let raw = make_test_tuple(
            "person",
            "John Smith",
            "John Smith",
            "patient_of",
            "organization",
            "Memorial Hospital",
            "hospital",
            "medical_bill",
            0.92,
        );

        let wme = create_wme(&raw, &mut dict);

        assert_eq!(dict.get_str(wme.entity_a_type), Some("person"));
        assert_eq!(dict.get_str(wme.entity_b_type), Some("organization"));
        assert_eq!(dict.get_str(wme.relation), Some("patient_of"));

        // Person -> generalize = "unknown" (no person hierarchy)
        assert_eq!(dict.get_str(wme.entity_a_gen), Some("unknown"));
        // Organization "hospital" -> "healthcare_provider"
        assert_eq!(dict.get_str(wme.entity_b_gen), Some("healthcare_provider"));

        // No amount entity -> 255
        assert_eq!(wme.amount_bucket, 255);
    }

    #[test]
    fn test_create_wme_diagnosis() {
        let mut dict = Dictionary::new();
        let raw = make_test_tuple(
            "person",
            "Jane Doe",
            "Jane Doe",
            "diagnosed_with",
            "diagnosis",
            "Appendectomy",
            "Appendectomy",
            "medical",
            0.75,
        );

        let wme = create_wme(&raw, &mut dict);

        // Diagnosis "Appendectomy" -> "surgery"
        assert_eq!(dict.get_str(wme.entity_b_gen), Some("surgery"));
        assert_eq!(wme.document_category, 1); // "medical" -> 1
        assert!((wme.extraction_cf - 0.75).abs() < 1e-6);
    }

    #[test]
    fn test_create_wme_financial() {
        let mut dict = Dictionary::new();
        let raw = make_test_tuple(
            "organization",
            "Acme Corp",
            "employer",
            "pays_salary",
            "salary",
            "$75,000",
            "$75,000",
            "financial",
            0.90,
        );

        let wme = create_wme(&raw, &mut dict);

        // Organization "employer" -> "employer"
        assert_eq!(dict.get_str(wme.entity_a_gen), Some("employer"));
        // Salary $75,000 -> bucket 7 (>= 50K) -> "very_large"
        assert_eq!(dict.get_str(wme.entity_b_gen), Some("very_large"));
        assert_eq!(wme.amount_bucket, 7);
        assert_eq!(wme.document_category, 4); // "financial" -> 4
    }

    #[test]
    fn test_create_wme_no_amount() {
        let mut dict = Dictionary::new();
        let raw = make_test_tuple(
            "person", "Alice", "Alice", "knows", "person", "Bob", "Bob", "general", 0.95,
        );

        let wme = create_wme(&raw, &mut dict);

        assert_eq!(wme.amount_bucket, 255);
        assert_eq!(wme.document_category, 6); // "general" -> 6
    }

    #[test]
    fn test_create_wme_entity_a_is_amount() {
        let mut dict = Dictionary::new();
        let raw = make_test_tuple(
            "amount",
            "$50.00",
            "$50.00",
            "charged_by",
            "organization",
            "Store",
            "store",
            "retail",
            0.80,
        );

        let wme = create_wme(&raw, &mut dict);

        // entity_a is the amount type, so bucket should come from it
        assert_eq!(wme.amount_bucket, 2); // $50 -> bucket 2 (50-100)
    }

    #[test]
    fn test_create_wme_geographic_generalization() {
        let mut dict = Dictionary::new();
        let raw = make_test_tuple(
            "organization",
            "Some Office",
            "clinic",
            "located_in",
            "state",
            "California Office",
            "CA",
            "general",
            0.88,
        );

        let wme = create_wme(&raw, &mut dict);

        // State "CA" -> "west"
        assert_eq!(dict.get_str(wme.entity_b_gen), Some("west"));
    }

    #[test]
    fn test_create_wme_dictionary_sharing() {
        let mut dict = Dictionary::new();

        let raw1 = make_test_tuple(
            "organization",
            "Hospital A",
            "hospital",
            "billed_total",
            "amount",
            "$100",
            "$100",
            "medical_bill",
            0.9,
        );
        let raw2 = make_test_tuple(
            "organization",
            "Hospital B",
            "clinic",
            "billed_total",
            "amount",
            "$200",
            "$200",
            "medical_bill",
            0.85,
        );

        let wme1 = create_wme(&raw1, &mut dict);
        let wme2 = create_wme(&raw2, &mut dict);

        // "organization" should have the same dict ID in both
        assert_eq!(wme1.entity_a_type, wme2.entity_a_type);
        // "billed_total" should be the same
        assert_eq!(wme1.relation, wme2.relation);
        // "amount" should be the same
        assert_eq!(wme1.entity_b_type, wme2.entity_b_type);
        // Roles are different
        assert_ne!(wme1.entity_a_role, wme2.entity_a_role);
    }

    // -----------------------------------------------------------------------
    // Batch conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_wmes_batch() {
        let mut dict = Dictionary::new();
        let tuples = vec![
            make_test_tuple(
                "person", "Alice", "Alice", "knows", "person", "Bob", "Bob", "general", 0.9,
            ),
            make_test_tuple(
                "organization",
                "Hospital",
                "hospital",
                "billed_total",
                "amount",
                "$500",
                "$500",
                "medical_bill",
                0.85,
            ),
        ];

        let wmes = create_wmes(&tuples, &mut dict);
        assert_eq!(wmes.len(), 2);
        assert_eq!(wmes[0].document_category, 6); // general
        assert_eq!(wmes[1].document_category, 0); // medical_bill
        assert_eq!(wmes[1].amount_bucket, 4); // $500 -> bucket 4 (500-1K)
    }

    // -----------------------------------------------------------------------
    // Integration: JSON -> parse -> convert -> create_wme -> verify
    // -----------------------------------------------------------------------

    #[test]
    fn test_end_to_end_json_to_wme() {
        let json = r#"{
            "document_category": "medical_bill",
            "entities": [
                {"id": "e1", "name": "John Smith", "type": "person", "value": "John Smith"},
                {"id": "e2", "name": "Memorial Hospital", "type": "organization", "value": "hospital"},
                {"id": "e3", "name": "$1,234.56", "type": "amount", "value": "$1,234.56"},
                {"id": "e4", "name": "Appendectomy", "type": "diagnosis", "value": "Appendectomy"}
            ],
            "relationships": [
                {"source": "e1", "target": "e2", "relationship": "patient_of", "context": "Patient treated"},
                {"source": "e2", "target": "e3", "relationship": "billed_total", "context": "Total charges"},
                {"source": "e1", "target": "e4", "relationship": "diagnosed_with", "context": "Diagnosis"}
            ]
        }"#;

        // Stage 1: JSON -> ExtractionOutput -> RawTuples
        let output = parse_extraction_json(json).unwrap();
        let ctx = ConversionContext {
            document_text: "Test medical bill".to_string(),
            source_file_path: "/test/bill.pdf".to_string(),
            extraction_confidence: 0.87,
        };
        let tuples = convert(&output, &ctx);
        assert_eq!(tuples.len(), 3);

        // Stage 2: RawTuples -> Wmes
        let mut dict = Dictionary::new();
        let wmes = create_wmes(&tuples, &mut dict);
        assert_eq!(wmes.len(), 3);

        // Verify WME 0: person patient_of organization
        let w0 = &wmes[0];
        assert_eq!(dict.get_str(w0.entity_a_type), Some("person"));
        assert_eq!(dict.get_str(w0.relation), Some("patient_of"));
        assert_eq!(dict.get_str(w0.entity_b_type), Some("organization"));
        assert_eq!(dict.get_str(w0.entity_b_gen), Some("healthcare_provider"));
        assert_eq!(w0.document_category, 0); // medical_bill
        assert_eq!(w0.amount_bucket, 255); // no amount entity
        assert!((w0.extraction_cf - 0.87).abs() < 1e-6);

        // Verify WME 1: organization billed_total amount
        let w1 = &wmes[1];
        assert_eq!(dict.get_str(w1.entity_a_type), Some("organization"));
        assert_eq!(dict.get_str(w1.relation), Some("billed_total"));
        assert_eq!(dict.get_str(w1.entity_b_type), Some("amount"));
        assert_eq!(dict.get_str(w1.entity_b_gen), Some("large")); // $1,234.56 -> large
        assert_eq!(w1.amount_bucket, 5); // $1,234.56 -> bucket 5 (1K-5K)

        // Verify WME 2: person diagnosed_with diagnosis
        let w2 = &wmes[2];
        assert_eq!(dict.get_str(w2.entity_a_type), Some("person"));
        assert_eq!(dict.get_str(w2.relation), Some("diagnosed_with"));
        assert_eq!(dict.get_str(w2.entity_b_type), Some("diagnosis"));
        assert_eq!(dict.get_str(w2.entity_b_gen), Some("surgery")); // Appendectomy -> surgery
        assert_eq!(w2.amount_bucket, 255); // no amount entity
    }

    #[test]
    fn test_end_to_end_financial_to_wme() {
        let json = r#"{
            "document_category": "financial",
            "entities": [
                {"id": "e1", "name": "Acme Corp", "type": "organization", "value": "employer"},
                {"id": "e2", "name": "Jane Doe", "type": "person", "value": "Jane Doe"},
                {"id": "e3", "name": "$75,000.00", "type": "salary", "value": "$75,000.00"}
            ],
            "relationships": [
                {"source": "e1", "target": "e2", "relationship": "employs", "context": "Employment"},
                {"source": "e2", "target": "e3", "relationship": "earns_salary", "context": "Salary"}
            ]
        }"#;

        let output = parse_extraction_json(json).unwrap();
        let ctx = ConversionContext {
            document_text: "Financial doc".to_string(),
            source_file_path: "/test/fin.pdf".to_string(),
            extraction_confidence: 0.92,
        };
        let tuples = convert(&output, &ctx);
        let mut dict = Dictionary::new();
        let wmes = create_wmes(&tuples, &mut dict);

        assert_eq!(wmes.len(), 2);

        // WME 0: org employs person
        assert_eq!(wmes[0].document_category, 4); // financial
        assert_eq!(wmes[0].amount_bucket, 255); // no amount entity

        // WME 1: person earns_salary salary
        assert_eq!(dict.get_str(wmes[1].entity_b_type), Some("salary"));
        assert_eq!(dict.get_str(wmes[1].entity_b_gen), Some("very_large")); // $75K
        assert_eq!(wmes[1].amount_bucket, 7); // >= 50K
        assert!((wmes[1].extraction_cf - 0.92).abs() < 1e-6);
    }

    #[test]
    fn test_end_to_end_wme_into_engine() {
        let json = r#"{
            "document_category": "medical_bill",
            "entities": [
                {"id": "e1", "name": "Memorial Hospital", "type": "organization", "value": "hospital"},
                {"id": "e2", "name": "$1,234.56", "type": "amount", "value": "$1,234.56"}
            ],
            "relationships": [
                {"source": "e1", "target": "e2", "relationship": "billed_total", "context": "Charges"}
            ]
        }"#;

        // Stage 1: parse + convert
        let output = parse_extraction_json(json).unwrap();
        let ctx = ConversionContext {
            document_text: "Medical bill test".to_string(),
            source_file_path: "/test/bill.pdf".to_string(),
            extraction_confidence: 0.87,
        };
        let tuples = convert(&output, &ctx);

        // Stage 2: create_wme using engine's dictionaries
        // We use a shared dictionary here, then register the rule using the same dict
        let mut dict = Dictionary::new();

        // Register a rule that matches: organization + billed_total + medical_bill
        let org_id = dict.get_or_insert("organization");
        let billed_id = dict.get_or_insert("billed_total");
        let amount_id = dict.get_or_insert("amount");
        let healthcare_id = dict.get_or_insert("healthcare_provider");

        // Create the WME
        let wme = create_wme(&tuples[0], &mut dict);

        // Verify the WME fields match the expected dictionary IDs
        assert_eq!(wme.entity_a_type, org_id);
        assert_eq!(wme.relation, billed_id);
        assert_eq!(wme.entity_b_type, amount_id);
        assert_eq!(dict.get_str(wme.entity_a_gen), Some("healthcare_provider"));
        assert_eq!(wme.entity_a_gen, healthcare_id);

        // Verify the WME is engine-compatible (correct field widths)
        assert!(wme.entity_a_type < u16::MAX);
        assert!(wme.amount_bucket == 5); // $1,234.56 -> bucket 5
        assert!(wme.document_category == 0); // medical_bill -> 0
    }

    // -----------------------------------------------------------------------
    // is_amount_type tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_amount_type() {
        assert!(is_amount_type("amount"));
        assert!(is_amount_type("Amount"));
        assert!(is_amount_type("total"));
        assert!(is_amount_type("balance"));
        assert!(is_amount_type("payment"));
        assert!(is_amount_type("salary"));
        assert!(is_amount_type("income"));
        assert!(is_amount_type("charge"));
        assert!(is_amount_type("cost"));
        assert!(is_amount_type("fee"));
        assert!(is_amount_type("price"));
        assert!(!is_amount_type("person"));
        assert!(!is_amount_type("organization"));
        assert!(!is_amount_type("date"));
        assert!(!is_amount_type(""));
    }
}
