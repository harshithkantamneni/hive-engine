//! Tuple Adapter: bridge between Python extraction model JSON output and
//! the Rust reasoning engine's internal types.
//!
//! Converts `ExtractionOutput` (deserialized from the extraction model's JSON)
//! into `Vec<RawTuple>` for downstream WME creation and Rete engine insertion.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Extraction types (Python -> Rust)
// ---------------------------------------------------------------------------

/// Deserialized from the JSON output of the Gemma 3n 2B extraction prompt.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtractionOutput {
    pub document_category: String,
    pub entities: Vec<ExtractedEntity>,
    pub relationships: Vec<ExtractedRelationship>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtractedEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub entity_type: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtractedRelationship {
    pub source: String,
    pub target: String,
    pub relationship: String,
    pub context: Option<String>,
}

/// Request sent from Rust orchestrator to Python extraction process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionRequest {
    pub request_id: String,
    pub text: String,
    pub max_tokens: u32,
}

impl ExtractionRequest {
    /// Create a new extraction request with the default max_tokens (2048).
    pub fn new(text: String) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            text,
            max_tokens: 2048,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Privacy classification for entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivacyClass {
    DirectId = 0,
    QuasiId = 1,
    Sensitive = 2,
    Public = 3,
}

/// Internal entity representation within a RawTuple.
#[derive(Debug, Clone)]
pub struct RawEntity {
    pub entity_type: String,
    pub role: String,
    pub text: String,
    pub value: String,
    pub privacy_class: PrivacyClass,
}

/// Internal relationship representation within a RawTuple.
#[derive(Debug, Clone)]
pub struct RawRelationship {
    pub relation: String,
    pub context: String,
}

/// The Rust-internal tuple representation, produced from each relationship
/// in an ExtractionOutput. One RawTuple per relationship.
#[derive(Debug, Clone)]
pub struct RawTuple {
    pub tuple_id: String,
    pub document_id: String,
    pub extraction_ts: u64,
    pub entity_a: RawEntity,
    pub relationship: RawRelationship,
    pub entity_b: RawEntity,
    pub document_category: String,
    pub sensitivity_tier: u8,
    pub extraction_confidence: f64,
    pub source_file_path: String,
}

// ---------------------------------------------------------------------------
// Conversion context
// ---------------------------------------------------------------------------

/// Parameters for converting an ExtractionOutput into RawTuples.
pub struct ConversionContext {
    /// The source document text (used for BLAKE3 hashing).
    pub document_text: String,
    /// Local file path of the source document. Never shared externally.
    pub source_file_path: String,
    /// Extraction confidence from the model. Defaults to 1.0 if not provided.
    pub extraction_confidence: f64,
}

// ---------------------------------------------------------------------------
// Core conversion logic
// ---------------------------------------------------------------------------

/// Convert an ExtractionOutput into a Vec<RawTuple>.
///
/// Each relationship in the extraction output produces one RawTuple.
/// Relationships referencing unknown entity IDs are skipped with an
/// eprintln warning (graceful degradation, no panics).
pub fn convert(output: &ExtractionOutput, ctx: &ConversionContext) -> Vec<RawTuple> {
    // Build entity lookup by ID
    let entity_map: HashMap<&str, &ExtractedEntity> =
        output.entities.iter().map(|e| (e.id.as_str(), e)).collect();

    let document_id = blake3::hash(ctx.document_text.as_bytes())
        .to_hex()
        .to_string();
    let extraction_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let sensitivity_tier = assign_tier(&output.document_category);

    let mut tuples = Vec::with_capacity(output.relationships.len());

    for rel in &output.relationships {
        let source_entity = match entity_map.get(rel.source.as_str()) {
            Some(e) => e,
            None => {
                eprintln!(
                    "[tuple_adapter] WARNING: relationship source '{}' not found in entities, skipping",
                    rel.source
                );
                continue;
            }
        };
        let target_entity = match entity_map.get(rel.target.as_str()) {
            Some(e) => e,
            None => {
                eprintln!(
                    "[tuple_adapter] WARNING: relationship target '{}' not found in entities, skipping",
                    rel.target
                );
                continue;
            }
        };

        let entity_a = make_raw_entity(source_entity);
        let entity_b = make_raw_entity(target_entity);

        tuples.push(RawTuple {
            tuple_id: uuid::Uuid::new_v4().to_string(),
            document_id: document_id.clone(),
            extraction_ts,
            entity_a,
            relationship: RawRelationship {
                relation: rel.relationship.clone(),
                context: rel.context.clone().unwrap_or_default(),
            },
            entity_b,
            document_category: output.document_category.clone(),
            sensitivity_tier,
            extraction_confidence: ctx.extraction_confidence,
            source_file_path: ctx.source_file_path.clone(),
        });
    }

    tuples
}

/// Build a RawEntity from an ExtractedEntity.
fn make_raw_entity(extracted: &ExtractedEntity) -> RawEntity {
    let privacy_class = classify_entity(&extracted.entity_type);
    RawEntity {
        entity_type: extracted.entity_type.clone(),
        role: extracted.name.clone(),
        text: extracted.name.clone(),
        value: extracted.value.clone().unwrap_or_default(),
        privacy_class,
    }
}

// ---------------------------------------------------------------------------
// Sensitivity tier assignment
// ---------------------------------------------------------------------------

/// Assign a sensitivity tier (1-4) based on document category.
///
/// - 1 (highest): medical_bill, medical, health
/// - 2: legal, financial, tax
/// - 3: general, personal, correspondence
/// - 4 (lowest): retail, receipt, other/unknown
pub fn assign_tier(document_category: &str) -> u8 {
    match document_category.to_lowercase().as_str() {
        "medical_bill" | "medical" | "health" => 1,
        "legal" | "financial" | "tax" => 2,
        "general" | "personal" | "correspondence" => 3,
        "retail" | "receipt" => 4,
        _ => 4,
    }
}

// ---------------------------------------------------------------------------
// Privacy classification
// ---------------------------------------------------------------------------

/// Classify an entity type into a PrivacyClass.
///
/// - DirectId: person, ssn, dob, name, social_security_number, date_of_birth
/// - QuasiId: address, phone, email, zip_code, phone_number
/// - Sensitive: diagnosis, salary, income, medical_condition, amount
/// - Public: everything else
pub fn classify_entity(entity_type: &str) -> PrivacyClass {
    match entity_type.to_lowercase().as_str() {
        "person"
        | "ssn"
        | "dob"
        | "name"
        | "social_security_number"
        | "date_of_birth"
        | "patient_name"
        | "full_name" => PrivacyClass::DirectId,

        "address" | "phone" | "email" | "zip_code" | "phone_number" | "mailing_address" => {
            PrivacyClass::QuasiId
        }

        "diagnosis" | "salary" | "income" | "medical_condition" | "amount" | "total"
        | "balance" | "payment" => PrivacyClass::Sensitive,

        _ => PrivacyClass::Public,
    }
}

// ---------------------------------------------------------------------------
// Amount parsing
// ---------------------------------------------------------------------------

/// Parse a monetary/numeric string into f64.
///
/// Handles formats: "$1,234.56", "12,500", "$-500.00", "1234", empty, "N/A".
/// Returns `None` for non-numeric values.
pub fn parse_amount(s: &str) -> Option<f64> {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("n/a") || trimmed == "-" {
        return None;
    }

    // Strip currency symbols and whitespace, keep minus sign and digits
    let cleaned: String = trimmed
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();

    if cleaned.is_empty() {
        return None;
    }

    cleaned.parse::<f64>().ok()
}

// ---------------------------------------------------------------------------
// Amount bucketing
// ---------------------------------------------------------------------------

/// Bucket an amount into one of 8 ranges (0-7), or 255 for N/A.
///
/// Buckets:
/// - 0: amount < 10
/// - 1: 10 <= amount < 50
/// - 2: 50 <= amount < 100
/// - 3: 100 <= amount < 500
/// - 4: 500 <= amount < 1,000
/// - 5: 1,000 <= amount < 5,000
/// - 6: 5,000 <= amount < 50,000
/// - 7: amount >= 50,000
/// - 255: N/A (None, NaN, or negative)
pub fn compute_bucket(amount: Option<f64>) -> u8 {
    match amount {
        None => 255,
        Some(v) if v.is_nan() || v < 0.0 => 255,
        Some(v) if v < 10.0 => 0,
        Some(v) if v < 50.0 => 1,
        Some(v) if v < 100.0 => 2,
        Some(v) if v < 500.0 => 3,
        Some(v) if v < 1_000.0 => 4,
        Some(v) if v < 5_000.0 => 5,
        Some(v) if v < 50_000.0 => 6,
        Some(_) => 7,
    }
}

// ---------------------------------------------------------------------------
// JSON deserialization helper
// ---------------------------------------------------------------------------

/// Deserialize an ExtractionOutput from a JSON string.
/// Returns a descriptive error on failure.
pub fn parse_extraction_json(json: &str) -> Result<ExtractionOutput, String> {
    serde_json::from_str(json).map_err(|e| format!("Failed to parse extraction JSON: {}", e))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Realistic extraction prompt output for a medical bill.
    fn sample_medical_json() -> &'static str {
        r#"{
            "document_category": "medical_bill",
            "entities": [
                {"id": "e1", "name": "John Smith", "type": "person", "value": "John Smith"},
                {"id": "e2", "name": "Memorial Hospital", "type": "organization", "value": null},
                {"id": "e3", "name": "$1,234.56", "type": "amount", "value": "$1,234.56"},
                {"id": "e4", "name": "Appendectomy", "type": "diagnosis", "value": "Appendectomy"},
                {"id": "e5", "name": "2024-03-15", "type": "date", "value": "2024-03-15"}
            ],
            "relationships": [
                {"source": "e1", "target": "e2", "relationship": "patient_of", "context": "John Smith was treated at Memorial Hospital"},
                {"source": "e2", "target": "e3", "relationship": "billed_total", "context": "Total charges: $1,234.56"},
                {"source": "e1", "target": "e4", "relationship": "diagnosed_with", "context": "Diagnosis: Appendectomy"},
                {"source": "e2", "target": "e5", "relationship": "service_date", "context": null}
            ]
        }"#
    }

    fn sample_ctx() -> ConversionContext {
        ConversionContext {
            document_text: "Sample medical bill document text".to_string(),
            source_file_path: "/home/user/documents/bill.pdf".to_string(),
            extraction_confidence: 0.87,
        }
    }

    // -----------------------------------------------------------------------
    // JSON deserialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_deserialize_medical_bill() {
        let output = parse_extraction_json(sample_medical_json()).unwrap();
        assert_eq!(output.document_category, "medical_bill");
        assert_eq!(output.entities.len(), 5);
        assert_eq!(output.relationships.len(), 4);

        // Verify entity fields
        let e1 = &output.entities[0];
        assert_eq!(e1.id, "e1");
        assert_eq!(e1.name, "John Smith");
        assert_eq!(e1.entity_type, "person");
        assert_eq!(e1.value, Some("John Smith".to_string()));

        // Verify null value becomes None
        let e2 = &output.entities[1];
        assert_eq!(e2.value, None);

        // Verify relationship fields
        let r1 = &output.relationships[0];
        assert_eq!(r1.source, "e1");
        assert_eq!(r1.target, "e2");
        assert_eq!(r1.relationship, "patient_of");
        assert!(r1.context.is_some());
    }

    #[test]
    fn test_deserialize_minimal_json() {
        let json = r#"{
            "document_category": "general",
            "entities": [],
            "relationships": []
        }"#;
        let output = parse_extraction_json(json).unwrap();
        assert_eq!(output.document_category, "general");
        assert!(output.entities.is_empty());
        assert!(output.relationships.is_empty());
    }

    #[test]
    fn test_deserialize_invalid_json() {
        let result = parse_extraction_json("not valid json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse"));
    }

    #[test]
    fn test_deserialize_missing_field() {
        let json = r#"{"document_category": "general"}"#;
        let result = parse_extraction_json(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_convert_medical_bill() {
        let output = parse_extraction_json(sample_medical_json()).unwrap();
        let ctx = sample_ctx();
        let tuples = convert(&output, &ctx);

        // 4 relationships -> 4 tuples
        assert_eq!(tuples.len(), 4);

        // Verify first tuple (e1 -> e2, patient_of)
        let t0 = &tuples[0];
        assert_eq!(t0.entity_a.entity_type, "person");
        assert_eq!(t0.entity_a.text, "John Smith");
        assert_eq!(t0.entity_b.entity_type, "organization");
        assert_eq!(t0.relationship.relation, "patient_of");
        assert_eq!(t0.document_category, "medical_bill");
        assert_eq!(t0.sensitivity_tier, 1);
        assert!((t0.extraction_confidence - 0.87).abs() < 1e-9);
        assert_eq!(t0.source_file_path, "/home/user/documents/bill.pdf");

        // Verify document_id is consistent (same document text -> same hash)
        let expected_hash = blake3::hash(b"Sample medical bill document text")
            .to_hex()
            .to_string();
        assert_eq!(t0.document_id, expected_hash);

        // All tuples share the same document_id
        for t in &tuples {
            assert_eq!(t.document_id, expected_hash);
        }

        // Each tuple has a unique tuple_id (UUID)
        let ids: Vec<&str> = tuples.iter().map(|t| t.tuple_id.as_str()).collect();
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "tuple_ids must be unique");
            }
        }
    }

    #[test]
    fn test_convert_entity_resolution() {
        let output = parse_extraction_json(sample_medical_json()).unwrap();
        let ctx = sample_ctx();
        let tuples = convert(&output, &ctx);

        // Second tuple: e2 (Memorial Hospital) -> e3 ($1,234.56)
        let t1 = &tuples[1];
        assert_eq!(t1.entity_a.entity_type, "organization");
        assert_eq!(t1.entity_a.text, "Memorial Hospital");
        assert_eq!(t1.entity_b.entity_type, "amount");
        assert_eq!(t1.entity_b.text, "$1,234.56");
        assert_eq!(t1.relationship.relation, "billed_total");
    }

    #[test]
    fn test_convert_privacy_classification() {
        let output = parse_extraction_json(sample_medical_json()).unwrap();
        let ctx = sample_ctx();
        let tuples = convert(&output, &ctx);

        // t0: person (DirectId) -> organization (Public)
        assert_eq!(tuples[0].entity_a.privacy_class, PrivacyClass::DirectId);
        assert_eq!(tuples[0].entity_b.privacy_class, PrivacyClass::Public);

        // t1: organization (Public) -> amount (Sensitive)
        assert_eq!(tuples[1].entity_a.privacy_class, PrivacyClass::Public);
        assert_eq!(tuples[1].entity_b.privacy_class, PrivacyClass::Sensitive);

        // t2: person (DirectId) -> diagnosis (Sensitive)
        assert_eq!(tuples[2].entity_a.privacy_class, PrivacyClass::DirectId);
        assert_eq!(tuples[2].entity_b.privacy_class, PrivacyClass::Sensitive);
    }

    #[test]
    fn test_convert_missing_entity_skips_gracefully() {
        let json = r#"{
            "document_category": "general",
            "entities": [
                {"id": "e1", "name": "Alice", "type": "person", "value": null}
            ],
            "relationships": [
                {"source": "e1", "target": "e_missing", "relationship": "knows", "context": null},
                {"source": "e_ghost", "target": "e1", "relationship": "owns", "context": null}
            ]
        }"#;
        let output = parse_extraction_json(json).unwrap();
        let ctx = sample_ctx();
        let tuples = convert(&output, &ctx);

        // Both relationships reference non-existent entities -> both skipped
        assert_eq!(tuples.len(), 0);
    }

    #[test]
    fn test_convert_empty_input() {
        let json = r#"{
            "document_category": "general",
            "entities": [],
            "relationships": []
        }"#;
        let output = parse_extraction_json(json).unwrap();
        let ctx = sample_ctx();
        let tuples = convert(&output, &ctx);
        assert!(tuples.is_empty());
    }

    #[test]
    fn test_convert_context_none_becomes_empty() {
        let json = r#"{
            "document_category": "retail",
            "entities": [
                {"id": "e1", "name": "Store", "type": "organization", "value": null},
                {"id": "e2", "name": "$50.00", "type": "amount", "value": "$50.00"}
            ],
            "relationships": [
                {"source": "e1", "target": "e2", "relationship": "charged", "context": null}
            ]
        }"#;
        let output = parse_extraction_json(json).unwrap();
        let ctx = sample_ctx();
        let tuples = convert(&output, &ctx);

        assert_eq!(tuples.len(), 1);
        assert_eq!(tuples[0].relationship.context, "");
    }

    // -----------------------------------------------------------------------
    // Sensitivity tier tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_assign_tier() {
        assert_eq!(assign_tier("medical_bill"), 1);
        assert_eq!(assign_tier("medical"), 1);
        assert_eq!(assign_tier("health"), 1);
        assert_eq!(assign_tier("Medical_Bill"), 1); // case insensitive
        assert_eq!(assign_tier("legal"), 2);
        assert_eq!(assign_tier("financial"), 2);
        assert_eq!(assign_tier("tax"), 2);
        assert_eq!(assign_tier("FINANCIAL"), 2);
        assert_eq!(assign_tier("general"), 3);
        assert_eq!(assign_tier("personal"), 3);
        assert_eq!(assign_tier("correspondence"), 3);
        assert_eq!(assign_tier("retail"), 4);
        assert_eq!(assign_tier("receipt"), 4);
        assert_eq!(assign_tier("unknown_category"), 4);
        assert_eq!(assign_tier(""), 4);
    }

    // -----------------------------------------------------------------------
    // Privacy classification tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_entity() {
        // DirectId
        assert_eq!(classify_entity("person"), PrivacyClass::DirectId);
        assert_eq!(classify_entity("ssn"), PrivacyClass::DirectId);
        assert_eq!(classify_entity("dob"), PrivacyClass::DirectId);
        assert_eq!(classify_entity("name"), PrivacyClass::DirectId);
        assert_eq!(classify_entity("Person"), PrivacyClass::DirectId); // case insensitive
        assert_eq!(classify_entity("SSN"), PrivacyClass::DirectId);

        // QuasiId
        assert_eq!(classify_entity("address"), PrivacyClass::QuasiId);
        assert_eq!(classify_entity("phone"), PrivacyClass::QuasiId);
        assert_eq!(classify_entity("email"), PrivacyClass::QuasiId);
        assert_eq!(classify_entity("zip_code"), PrivacyClass::QuasiId);

        // Sensitive
        assert_eq!(classify_entity("diagnosis"), PrivacyClass::Sensitive);
        assert_eq!(classify_entity("salary"), PrivacyClass::Sensitive);
        assert_eq!(classify_entity("income"), PrivacyClass::Sensitive);
        assert_eq!(classify_entity("amount"), PrivacyClass::Sensitive);

        // Public (unknown types)
        assert_eq!(classify_entity("organization"), PrivacyClass::Public);
        assert_eq!(classify_entity("date"), PrivacyClass::Public);
        assert_eq!(classify_entity("location"), PrivacyClass::Public);
        assert_eq!(classify_entity(""), PrivacyClass::Public);
    }

    // -----------------------------------------------------------------------
    // Amount parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_amount_standard() {
        assert!((parse_amount("$1,234.56").unwrap() - 1234.56).abs() < 1e-9);
    }

    #[test]
    fn test_parse_amount_no_dollar_sign() {
        assert!((parse_amount("12,500").unwrap() - 12500.0).abs() < 1e-9);
    }

    #[test]
    fn test_parse_amount_plain_number() {
        assert!((parse_amount("1234").unwrap() - 1234.0).abs() < 1e-9);
    }

    #[test]
    fn test_parse_amount_decimal_only() {
        assert!((parse_amount("99.99").unwrap() - 99.99).abs() < 1e-9);
    }

    #[test]
    fn test_parse_amount_negative() {
        assert!((parse_amount("$-500.00").unwrap() - (-500.0)).abs() < 1e-9);
    }

    #[test]
    fn test_parse_amount_negative_no_dollar() {
        assert!((parse_amount("-42.50").unwrap() - (-42.50)).abs() < 1e-9);
    }

    #[test]
    fn test_parse_amount_na() {
        assert_eq!(parse_amount("N/A"), None);
        assert_eq!(parse_amount("n/a"), None);
    }

    #[test]
    fn test_parse_amount_empty() {
        assert_eq!(parse_amount(""), None);
        assert_eq!(parse_amount("   "), None);
    }

    #[test]
    fn test_parse_amount_dash_only() {
        assert_eq!(parse_amount("-"), None);
    }

    #[test]
    fn test_parse_amount_non_numeric() {
        assert_eq!(parse_amount("abc"), None);
        assert_eq!(parse_amount("$"), None);
    }

    #[test]
    fn test_parse_amount_large() {
        assert!((parse_amount("$999,999.99").unwrap() - 999999.99).abs() < 1e-6);
    }

    #[test]
    fn test_parse_amount_zero() {
        assert!((parse_amount("$0.00").unwrap() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_parse_amount_whitespace() {
        assert!((parse_amount("  $1,234.56  ").unwrap() - 1234.56).abs() < 1e-9);
    }

    // -----------------------------------------------------------------------
    // Amount bucketing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_bucket_ranges() {
        // Bucket 0: < 10
        assert_eq!(compute_bucket(Some(0.0)), 0);
        assert_eq!(compute_bucket(Some(5.0)), 0);
        assert_eq!(compute_bucket(Some(9.99)), 0);

        // Bucket 1: 10-50
        assert_eq!(compute_bucket(Some(10.0)), 1);
        assert_eq!(compute_bucket(Some(49.99)), 1);

        // Bucket 2: 50-100
        assert_eq!(compute_bucket(Some(50.0)), 2);
        assert_eq!(compute_bucket(Some(99.99)), 2);

        // Bucket 3: 100-500
        assert_eq!(compute_bucket(Some(100.0)), 3);
        assert_eq!(compute_bucket(Some(499.99)), 3);

        // Bucket 4: 500-1K
        assert_eq!(compute_bucket(Some(500.0)), 4);
        assert_eq!(compute_bucket(Some(999.99)), 4);

        // Bucket 5: 1K-5K
        assert_eq!(compute_bucket(Some(1000.0)), 5);
        assert_eq!(compute_bucket(Some(4999.99)), 5);

        // Bucket 6: 5K-50K
        assert_eq!(compute_bucket(Some(5000.0)), 6);
        assert_eq!(compute_bucket(Some(49999.99)), 6);

        // Bucket 7: >= 50K
        assert_eq!(compute_bucket(Some(50000.0)), 7);
        assert_eq!(compute_bucket(Some(999999.0)), 7);
    }

    #[test]
    fn test_compute_bucket_na() {
        assert_eq!(compute_bucket(None), 255);
    }

    #[test]
    fn test_compute_bucket_negative() {
        assert_eq!(compute_bucket(Some(-1.0)), 255);
        assert_eq!(compute_bucket(Some(-500.0)), 255);
    }

    #[test]
    fn test_compute_bucket_nan() {
        assert_eq!(compute_bucket(Some(f64::NAN)), 255);
    }

    #[test]
    fn test_compute_bucket_boundary_values() {
        // Exact boundary values
        assert_eq!(compute_bucket(Some(10.0)), 1);
        assert_eq!(compute_bucket(Some(50.0)), 2);
        assert_eq!(compute_bucket(Some(100.0)), 3);
        assert_eq!(compute_bucket(Some(500.0)), 4);
        assert_eq!(compute_bucket(Some(1000.0)), 5);
        assert_eq!(compute_bucket(Some(5000.0)), 6);
        assert_eq!(compute_bucket(Some(50000.0)), 7);
    }

    // -----------------------------------------------------------------------
    // ExtractionRequest tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extraction_request_defaults() {
        let req = ExtractionRequest::new("Test document text".to_string());
        assert_eq!(req.text, "Test document text");
        assert_eq!(req.max_tokens, 2048);
        assert!(!req.request_id.is_empty());

        // Verify request_id is a valid UUID format (8-4-4-4-12 hex digits)
        assert_eq!(req.request_id.len(), 36);
        assert_eq!(req.request_id.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn test_extraction_request_serialization() {
        let req = ExtractionRequest {
            request_id: "test-uuid-123".to_string(),
            text: "Some OCR output".to_string(),
            max_tokens: 2048,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"request_id\":\"test-uuid-123\""));
        assert!(json.contains("\"max_tokens\":2048"));
    }

    // -----------------------------------------------------------------------
    // Integration: parse + convert end-to-end
    // -----------------------------------------------------------------------

    #[test]
    fn test_end_to_end_parse_and_convert() {
        let json = sample_medical_json();
        let output = parse_extraction_json(json).unwrap();
        let ctx = sample_ctx();
        let tuples = convert(&output, &ctx);

        assert_eq!(tuples.len(), 4);

        // Verify amount entity has the right value for bucketing downstream
        let billing_tuple = &tuples[1]; // e2 -> e3 (billed_total)
        let amount_str = &billing_tuple.entity_b.value;
        let parsed = parse_amount(amount_str).unwrap();
        assert!((parsed - 1234.56).abs() < 1e-9);
        assert_eq!(compute_bucket(Some(parsed)), 5); // 1K-5K bucket
    }

    #[test]
    fn test_end_to_end_financial_document() {
        let json = r#"{
            "document_category": "financial",
            "entities": [
                {"id": "e1", "name": "Acme Corp", "type": "organization", "value": null},
                {"id": "e2", "name": "Jane Doe", "type": "person", "value": "Jane Doe"},
                {"id": "e3", "name": "$75,000.00", "type": "amount", "value": "$75,000.00"},
                {"id": "e4", "name": "123-45-6789", "type": "ssn", "value": "123-45-6789"}
            ],
            "relationships": [
                {"source": "e1", "target": "e2", "relationship": "employs", "context": "Employment record"},
                {"source": "e2", "target": "e3", "relationship": "earns_salary", "context": "Annual salary: $75,000"},
                {"source": "e2", "target": "e4", "relationship": "identified_by", "context": "SSN on file"}
            ]
        }"#;
        let output = parse_extraction_json(json).unwrap();
        let ctx = ConversionContext {
            document_text: "Financial document content".to_string(),
            source_file_path: "/tmp/financial.pdf".to_string(),
            extraction_confidence: 0.92,
        };
        let tuples = convert(&output, &ctx);

        assert_eq!(tuples.len(), 3);

        // Financial -> tier 2
        assert_eq!(tuples[0].sensitivity_tier, 2);

        // SSN entity -> DirectId
        assert_eq!(tuples[2].entity_b.entity_type, "ssn");
        assert_eq!(tuples[2].entity_b.privacy_class, PrivacyClass::DirectId);

        // Amount: $75,000 -> bucket 7 (>= 50K)
        let salary_amount = parse_amount(&tuples[1].entity_b.value).unwrap();
        assert!((salary_amount - 75000.0).abs() < 1e-6);
        assert_eq!(compute_bucket(Some(salary_amount)), 7);
    }

    #[test]
    fn test_end_to_end_partial_entity_resolution() {
        // Mix of valid and invalid entity references
        let json = r#"{
            "document_category": "general",
            "entities": [
                {"id": "e1", "name": "Alice", "type": "person", "value": "Alice"},
                {"id": "e2", "name": "Bob", "type": "person", "value": "Bob"}
            ],
            "relationships": [
                {"source": "e1", "target": "e2", "relationship": "knows", "context": "Friends"},
                {"source": "e1", "target": "e99", "relationship": "lives_at", "context": null},
                {"source": "e98", "target": "e2", "relationship": "employs", "context": null}
            ]
        }"#;
        let output = parse_extraction_json(json).unwrap();
        let ctx = sample_ctx();
        let tuples = convert(&output, &ctx);

        // Only the first relationship resolves successfully
        assert_eq!(tuples.len(), 1);
        assert_eq!(tuples[0].entity_a.text, "Alice");
        assert_eq!(tuples[0].entity_b.text, "Bob");
    }
}
