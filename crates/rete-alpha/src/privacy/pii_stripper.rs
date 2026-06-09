//! PII Stripper -- Stage 1 of the HIVE Privacy Pipeline
//!
//! Implements deny-by-default PII removal.
//! Takes a `RawTuple` and produces a `PiiStrippedTuple` with all direct
//! identifiers removed and unknown entity types suppressed.
//!
//! Design principles:
//! - DENY-BY-DEFAULT: only explicitly allowed entity types pass through.
//! - Entity A name is ALWAYS stripped (person names, addresses, etc.).
//! - Context field is ALWAYS stripped (may contain PII in natural language).
//! - Direct ID types (person, SSN, email, etc.) are always REDACTED.
//! - Unknown entity types are SUPPRESSED.
//! - Unknown roles become "other".

use std::collections::{HashMap, HashSet};

use super::types::{PiiStrippedTuple, RawTuple, SensitivityTier};

// ---------------------------------------------------------------------------
// Configuration struct (standalone; will integrate with PrivacyConfig once
// config.rs is finalized)
// ---------------------------------------------------------------------------

/// Configuration for the PII Stripper stage.
///
/// Defines which entity types, roles, and direct-ID types are recognized,
/// plus the document-category-to-sensitivity-tier mapping.
#[derive(Debug, Clone)]
pub struct PiiStripperConfig {
    pub allowed_entity_types: Vec<String>,
    pub allowed_roles: Vec<String>,
    pub direct_id_types: Vec<String>,
    pub s1_categories: Vec<String>,
    pub s2_categories: Vec<String>,
    pub s3_categories: Vec<String>,
    pub s4_categories: Vec<String>,
    pub default_tier: u8,
}

// ---------------------------------------------------------------------------
// PiiStripper
// ---------------------------------------------------------------------------

/// Stage 1 processor: strips PII from raw tuples using a deny-by-default
/// allowlist approach.
///
/// # Invariants
///
/// - `strip()` always succeeds. Entities that cannot be safely shared are
///   suppressed or redacted, never errored.
/// - Entity A name is never present in the output.
/// - Context field is never present in the output.
/// - Unknown entity types produce "SUPPRESSED" in the output.
/// - Direct ID entity types produce "REDACTED" for entity B value.
pub struct PiiStripper {
    allowed_entity_types: HashSet<String>,
    allowed_roles: HashSet<String>,
    direct_id_types: HashSet<String>,
    tier_mapping: HashMap<String, SensitivityTier>,
    default_tier: SensitivityTier,
}

impl PiiStripper {
    /// Create a PiiStripper from external configuration.
    ///
    /// Accepts a `PiiStripperConfig` which can be populated from
    /// `privacy_config.toml` via the config module.
    pub fn new(config: &PiiStripperConfig) -> Self {
        let allowed_entity_types: HashSet<String> = config
            .allowed_entity_types
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        let allowed_roles: HashSet<String> = config
            .allowed_roles
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        let direct_id_types: HashSet<String> = config
            .direct_id_types
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        let mut tier_mapping = HashMap::new();
        for cat in &config.s1_categories {
            tier_mapping.insert(cat.to_lowercase(), SensitivityTier::S1Critical);
        }
        for cat in &config.s2_categories {
            tier_mapping.insert(cat.to_lowercase(), SensitivityTier::S2High);
        }
        for cat in &config.s3_categories {
            tier_mapping.insert(cat.to_lowercase(), SensitivityTier::S3Medium);
        }
        for cat in &config.s4_categories {
            tier_mapping.insert(cat.to_lowercase(), SensitivityTier::S4Low);
        }

        let default_tier = match config.default_tier {
            1 => SensitivityTier::S1Critical,
            3 => SensitivityTier::S3Medium,
            4 => SensitivityTier::S4Low,
            _ => SensitivityTier::S2High, // unknown defaults to S2
        };

        Self {
            allowed_entity_types,
            allowed_roles,
            direct_id_types,
            tier_mapping,
            default_tier,
        }
    }

    /// Create a PiiStripper with the standard hardcoded allowlists.
    pub fn with_defaults() -> Self {
        let config = PiiStripperConfig {
            allowed_entity_types: vec![
                "organization".into(),
                "procedure".into(),
                "diagnosis".into(),
                "product".into(),
                "vehicle".into(),
                "medication".into(),
                "amount".into(),
                "percentage".into(),
                "code".into(),
                "term".into(),
                "legal_mechanism".into(),
                "certification".into(),
            ],
            allowed_roles: vec![
                "provider".into(),
                "insurer".into(),
                "landlord".into(),
                "merchant".into(),
                "employer".into(),
                "charge".into(),
                "fee".into(),
                "payment".into(),
                "deductible".into(),
                "premium".into(),
                "billing_code".into(),
                "category_code".into(),
            ],
            direct_id_types: vec![
                "person".into(),
                "email".into(),
                "phone".into(),
                "address".into(),
                "ssn".into(),
                "account_number".into(),
                "policy_number".into(),
                "member_id".into(),
                "medical_record_number".into(),
                "npi_number".into(),
                "tax_id".into(),
                "date_of_birth".into(),
            ],
            s1_categories: vec![
                "medical_bill".into(),
                "medical_note".into(),
                "insurance_eob".into(),
                "prescription".into(),
            ],
            s2_categories: vec![
                "lease".into(),
                "contract".into(),
                "insurance_policy".into(),
                "government_form".into(),
                "bank_statement".into(),
                "pay_stub".into(),
            ],
            s3_categories: vec!["utility_bill".into(), "terms_of_service".into()],
            s4_categories: vec!["receipt".into(), "restaurant_receipt".into()],
            default_tier: 2,
        };
        Self::new(&config)
    }

    /// Strip PII from a raw tuple, producing a `PiiStrippedTuple`.
    ///
    /// This method always succeeds. Entities that cannot be safely shared
    /// are suppressed (type replaced with "SUPPRESSED") or redacted
    /// (value replaced with "REDACTED"). The method never panics or
    /// returns an error.
    ///
    /// # Processing steps
    ///
    /// 1. **Entity A name**: Always stripped. Only type and role survive.
    /// 2. **Context**: Always stripped. May contain PII in natural language.
    /// 3. **Entity type deny-by-default**: If entity_a_type or entity_b_type
    ///    is NOT in the allowed set, it is replaced with "SUPPRESSED".
    /// 4. **Direct ID suppression**: If entity_b_type is a known direct ID
    ///    type, entity_b_value is set to "REDACTED".
    /// 5. **Entity B value**: For allowed types, the raw name passes through
    ///    as entity_b_value. For suppressed types, value is "SUPPRESSED".
    /// 6. **Role filtering**: Unknown roles become "other".
    /// 7. **Sensitivity tier**: Mapped from document_category via tier_mapping.
    pub fn strip(&self, raw: RawTuple) -> PiiStrippedTuple {
        // Step 1 + 3: Process entity A type (name is always stripped)
        let entity_a_type = self.process_entity_type(&raw.entity_a_type);

        // Step 3: Process entity B type
        let entity_b_type = self.process_entity_type(&raw.entity_b_type);

        // Step 4 + 5: Process entity B value
        let entity_b_value =
            self.compute_entity_b_value(&raw.entity_b_type, &raw.entity_b_name, &entity_b_type);

        // Step 6: Process roles
        let entity_a_role = self.process_role(&raw.entity_a_role);
        let entity_b_role = self.process_role(&raw.entity_b_role);

        // Step 7: Assign sensitivity tier from document_category
        let sensitivity_tier = self.assign_sensitivity_tier(&raw.document_category);

        // Step 2: Context is always stripped -- not included in output struct

        PiiStrippedTuple {
            entity_a_type,
            entity_a_role,
            entity_b_type,
            entity_b_value,
            entity_b_role,
            relation: raw.relation,
            amount: raw.amount,
            document_category: raw.document_category,
            sensitivity_tier,
            source_region: raw.source_region,
            time_period: raw.time_period,
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Check if an entity type is in the allowed set (deny-by-default).
    /// Returns the original type if allowed, "SUPPRESSED" otherwise.
    fn process_entity_type(&self, entity_type: &str) -> String {
        let normalized = entity_type.to_lowercase();
        if self.allowed_entity_types.contains(&normalized) {
            normalized
        } else {
            "SUPPRESSED".to_string()
        }
    }

    /// Compute entity B value based on its type classification.
    ///
    /// - Direct ID types -> "REDACTED"
    /// - Allowed types -> raw name passes through (will be generalized in Stage 3)
    /// - Unknown/suppressed types -> "SUPPRESSED"
    fn compute_entity_b_value(
        &self,
        raw_type: &str,
        raw_name: &str,
        processed_type: &str,
    ) -> String {
        let normalized_type = raw_type.to_lowercase();

        // Direct ID types are always REDACTED regardless of other checks
        if self.direct_id_types.contains(&normalized_type) {
            return "REDACTED".to_string();
        }

        // If the type was suppressed (not in allowed list), suppress value too
        if processed_type == "SUPPRESSED" {
            return "SUPPRESSED".to_string();
        }

        // Allowed type: pass through the raw name for downstream generalization
        raw_name.to_string()
    }

    /// Filter a role: if not in the allowed roles set, return "other".
    fn process_role(&self, role: &str) -> String {
        let normalized = role.to_lowercase();
        if self.allowed_roles.contains(&normalized) {
            normalized
        } else {
            "other".to_string()
        }
    }

    /// Map document_category to SensitivityTier.
    /// Unknown categories default to the configured default tier (S2).
    fn assign_sensitivity_tier(&self, document_category: &str) -> SensitivityTier {
        let normalized = document_category.to_lowercase();
        self.tier_mapping
            .get(&normalized)
            .copied()
            .unwrap_or(self.default_tier)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Build a minimal RawTuple for testing.
    // Test helper mirrors RawTuple's A-side / B-side / metadata layout; a
    // struct wrapper would duplicate the schema without improving readability.
    #[allow(clippy::too_many_arguments)]
    fn make_raw(
        a_type: &str,
        a_name: &str,
        a_role: &str,
        b_type: &str,
        b_name: &str,
        b_role: &str,
        relation: &str,
        doc_cat: &str,
    ) -> RawTuple {
        RawTuple {
            entity_a_type: a_type.to_string(),
            entity_a_name: a_name.to_string(),
            entity_a_role: a_role.to_string(),
            entity_b_type: b_type.to_string(),
            entity_b_name: b_name.to_string(),
            entity_b_role: b_role.to_string(),
            relation: relation.to_string(),
            amount: None,
            context: Some("This context contains PII like John Smith".to_string()),
            document_category: doc_cat.to_string(),
            source_region: "US-Northeast".to_string(),
            time_period: "2026-Q1".to_string(),
            extraction_timestamp: 1713200000,
        }
    }

    fn stripper() -> PiiStripper {
        PiiStripper::with_defaults()
    }

    // -----------------------------------------------------------------------
    // 1. Entity A name is ALWAYS stripped
    // -----------------------------------------------------------------------

    #[test]
    fn test_entity_a_name_always_stripped() {
        let raw = make_raw(
            "organization",
            "Memorial Hospital",
            "provider",
            "procedure",
            "Appendectomy",
            "charge",
            "billed_for",
            "medical_bill",
        );
        let result = stripper().strip(raw);

        // PiiStrippedTuple has no entity_a_name field -- it is structurally
        // impossible for entity_a_name to leak. We verify the type and role
        // are present and correct instead.
        assert_eq!(result.entity_a_type, "organization");
        assert_eq!(result.entity_a_role, "provider");
    }

    #[test]
    fn test_entity_a_name_stripped_for_person() {
        let raw = make_raw(
            "person",
            "John Smith",
            "provider",
            "procedure",
            "Appendectomy",
            "charge",
            "treated_with",
            "medical_bill",
        );
        let result = stripper().strip(raw);

        // Person type is NOT in the allowed list -> SUPPRESSED
        assert_eq!(result.entity_a_type, "SUPPRESSED");
        // Name does not appear anywhere in the output
        assert_ne!(result.entity_a_role, "John Smith");
    }

    // -----------------------------------------------------------------------
    // 2. Context is ALWAYS stripped
    // -----------------------------------------------------------------------

    #[test]
    fn test_context_always_stripped() {
        let raw = make_raw(
            "organization",
            "Hospital",
            "provider",
            "procedure",
            "Surgery",
            "charge",
            "billed_for",
            "medical_bill",
        );
        let result = stripper().strip(raw);

        // PiiStrippedTuple has no context field -- structurally impossible
        // to leak. We verify the output struct does not expose context
        // by checking that all fields are populated from non-context sources.
        assert_eq!(result.relation, "billed_for");
        assert_eq!(result.document_category, "medical_bill");
    }

    #[test]
    fn test_context_stripped_even_when_none() {
        let mut raw = make_raw(
            "organization",
            "Hospital",
            "provider",
            "procedure",
            "Surgery",
            "charge",
            "billed_for",
            "medical_bill",
        );
        raw.context = None;
        let result = stripper().strip(raw);

        // Still produces a valid output
        assert_eq!(result.entity_a_type, "organization");
    }

    // -----------------------------------------------------------------------
    // 3. Direct ID types are always REDACTED
    // -----------------------------------------------------------------------

    #[test]
    fn test_direct_id_person_redacted() {
        let raw = make_raw(
            "organization",
            "Hospital",
            "provider",
            "person",
            "John Smith",
            "other",
            "patient_of",
            "medical_bill",
        );
        let result = stripper().strip(raw);

        assert_eq!(result.entity_b_type, "SUPPRESSED"); // person not in allowed types
        assert_eq!(result.entity_b_value, "REDACTED"); // direct ID -> REDACTED
    }

    #[test]
    fn test_direct_id_email_redacted() {
        let raw = make_raw(
            "organization",
            "Company",
            "employer",
            "email",
            "john@example.com",
            "other",
            "contact",
            "contract",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_b_value, "REDACTED");
    }

    #[test]
    fn test_direct_id_phone_redacted() {
        let raw = make_raw(
            "organization",
            "Office",
            "provider",
            "phone",
            "555-0123",
            "other",
            "contact",
            "contract",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_b_value, "REDACTED");
    }

    #[test]
    fn test_direct_id_address_redacted() {
        let raw = make_raw(
            "organization",
            "Hospital",
            "provider",
            "address",
            "123 Main St",
            "other",
            "located_at",
            "medical_bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_b_value, "REDACTED");
    }

    #[test]
    fn test_direct_id_ssn_redacted() {
        let raw = make_raw(
            "organization",
            "IRS",
            "provider",
            "ssn",
            "123-45-6789",
            "other",
            "identified_by",
            "government_form",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_b_value, "REDACTED");
    }

    #[test]
    fn test_direct_id_account_number_redacted() {
        let raw = make_raw(
            "organization",
            "Bank",
            "insurer",
            "account_number",
            "ACCT-98765",
            "other",
            "has_account",
            "bank_statement",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_b_value, "REDACTED");
    }

    #[test]
    fn test_direct_id_policy_number_redacted() {
        let raw = make_raw(
            "organization",
            "Insurer",
            "insurer",
            "policy_number",
            "POL-123456",
            "other",
            "covered_by",
            "insurance_eob",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_b_value, "REDACTED");
    }

    #[test]
    fn test_direct_id_member_id_redacted() {
        let raw = make_raw(
            "organization",
            "HMO",
            "insurer",
            "member_id",
            "MEM-999",
            "other",
            "member_of",
            "insurance_eob",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_b_value, "REDACTED");
    }

    #[test]
    fn test_direct_id_medical_record_number_redacted() {
        let raw = make_raw(
            "organization",
            "Clinic",
            "provider",
            "medical_record_number",
            "MRN-12345",
            "other",
            "record_for",
            "medical_note",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_b_value, "REDACTED");
    }

    #[test]
    fn test_direct_id_npi_number_redacted() {
        let raw = make_raw(
            "organization",
            "Dr. Office",
            "provider",
            "npi_number",
            "1234567890",
            "other",
            "provider_npi",
            "medical_bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_b_value, "REDACTED");
    }

    #[test]
    fn test_direct_id_tax_id_redacted() {
        let raw = make_raw(
            "organization",
            "Employer",
            "employer",
            "tax_id",
            "EIN-12-3456789",
            "other",
            "tax_filed_with",
            "government_form",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_b_value, "REDACTED");
    }

    #[test]
    fn test_direct_id_date_of_birth_redacted() {
        let raw = make_raw(
            "organization",
            "Hospital",
            "provider",
            "date_of_birth",
            "1990-05-15",
            "other",
            "born_on",
            "medical_bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_b_value, "REDACTED");
    }

    // -----------------------------------------------------------------------
    // 4. Unknown entity types are SUPPRESSED (deny-by-default)
    // -----------------------------------------------------------------------

    #[test]
    fn test_unknown_entity_a_type_suppressed() {
        let raw = make_raw(
            "alien_species",
            "Zorg",
            "provider",
            "procedure",
            "Checkup",
            "charge",
            "visited",
            "medical_bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_a_type, "SUPPRESSED");
    }

    #[test]
    fn test_unknown_entity_b_type_suppressed() {
        let raw = make_raw(
            "organization",
            "Hospital",
            "provider",
            "custom_field",
            "some_value",
            "charge",
            "has_custom",
            "medical_bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_b_type, "SUPPRESSED");
        assert_eq!(result.entity_b_value, "SUPPRESSED");
    }

    #[test]
    fn test_both_entity_types_unknown_suppressed() {
        let raw = make_raw(
            "unknown_a",
            "ValueA",
            "provider",
            "unknown_b",
            "ValueB",
            "charge",
            "related",
            "receipt",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_a_type, "SUPPRESSED");
        assert_eq!(result.entity_b_type, "SUPPRESSED");
        assert_eq!(result.entity_b_value, "SUPPRESSED");
    }

    // -----------------------------------------------------------------------
    // 5. Allowed entity types pass through
    // -----------------------------------------------------------------------

    #[test]
    fn test_allowed_entity_type_organization() {
        let raw = make_raw(
            "organization",
            "Acme Corp",
            "provider",
            "procedure",
            "Appendectomy",
            "charge",
            "billed_for",
            "medical_bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_a_type, "organization");
        assert_eq!(result.entity_b_type, "procedure");
        assert_eq!(result.entity_b_value, "Appendectomy");
    }

    #[test]
    fn test_allowed_entity_type_all_types() {
        let allowed = [
            "organization",
            "procedure",
            "diagnosis",
            "product",
            "vehicle",
            "medication",
            "amount",
            "percentage",
            "code",
            "term",
            "legal_mechanism",
            "certification",
        ];
        for entity_type in &allowed {
            let raw = make_raw(
                entity_type,
                "SomeName",
                "provider",
                entity_type,
                "SomeValue",
                "charge",
                "related",
                "receipt",
            );
            let result = stripper().strip(raw);
            assert_eq!(
                result.entity_a_type,
                entity_type.to_lowercase(),
                "entity_a_type '{}' should pass through",
                entity_type
            );
            assert_eq!(
                result.entity_b_type,
                entity_type.to_lowercase(),
                "entity_b_type '{}' should pass through",
                entity_type
            );
            assert_eq!(
                result.entity_b_value, "SomeValue",
                "entity_b_value should pass through for allowed type '{}'",
                entity_type
            );
        }
    }

    #[test]
    fn test_allowed_entity_type_case_insensitive() {
        let raw = make_raw(
            "Organization",
            "Hospital",
            "provider",
            "PROCEDURE",
            "Surgery",
            "charge",
            "billed_for",
            "medical_bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_a_type, "organization");
        assert_eq!(result.entity_b_type, "procedure");
    }

    // -----------------------------------------------------------------------
    // 6. Role filtering
    // -----------------------------------------------------------------------

    #[test]
    fn test_allowed_roles_pass_through() {
        let allowed_roles = [
            "provider",
            "insurer",
            "landlord",
            "merchant",
            "employer",
            "charge",
            "fee",
            "payment",
            "deductible",
            "premium",
            "billing_code",
            "category_code",
        ];
        for role in &allowed_roles {
            let raw = make_raw(
                "organization",
                "Name",
                role,
                "procedure",
                "Value",
                role,
                "related",
                "receipt",
            );
            let result = stripper().strip(raw);
            assert_eq!(
                result.entity_a_role,
                role.to_lowercase(),
                "entity_a_role '{}' should pass through",
                role
            );
            assert_eq!(
                result.entity_b_role,
                role.to_lowercase(),
                "entity_b_role '{}' should pass through",
                role
            );
        }
    }

    #[test]
    fn test_unknown_role_becomes_other() {
        let raw = make_raw(
            "organization",
            "Hospital",
            "receptionist",
            "procedure",
            "Checkup",
            "unknown_role",
            "billed_for",
            "medical_bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_a_role, "other");
        assert_eq!(result.entity_b_role, "other");
    }

    #[test]
    fn test_role_case_insensitive() {
        let raw = make_raw(
            "organization",
            "Hospital",
            "Provider",
            "procedure",
            "Surgery",
            "CHARGE",
            "billed_for",
            "medical_bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.entity_a_role, "provider");
        assert_eq!(result.entity_b_role, "charge");
    }

    // -----------------------------------------------------------------------
    // 7. Sensitivity tier assignment
    // -----------------------------------------------------------------------

    #[test]
    fn test_tier_s1_categories() {
        let s1 = [
            "medical_bill",
            "medical_note",
            "insurance_eob",
            "prescription",
        ];
        for cat in &s1 {
            let raw = make_raw(
                "organization",
                "H",
                "provider",
                "procedure",
                "P",
                "charge",
                "rel",
                cat,
            );
            let result = stripper().strip(raw);
            assert_eq!(
                result.sensitivity_tier,
                SensitivityTier::S1Critical,
                "category '{}' should map to S1Critical",
                cat
            );
        }
    }

    #[test]
    fn test_tier_s2_categories() {
        let s2 = [
            "lease",
            "contract",
            "insurance_policy",
            "government_form",
            "bank_statement",
            "pay_stub",
        ];
        for cat in &s2 {
            let raw = make_raw(
                "organization",
                "H",
                "provider",
                "procedure",
                "P",
                "charge",
                "rel",
                cat,
            );
            let result = stripper().strip(raw);
            assert_eq!(
                result.sensitivity_tier,
                SensitivityTier::S2High,
                "category '{}' should map to S2High",
                cat
            );
        }
    }

    #[test]
    fn test_tier_s3_categories() {
        let s3 = ["utility_bill", "terms_of_service"];
        for cat in &s3 {
            let raw = make_raw(
                "organization",
                "H",
                "provider",
                "procedure",
                "P",
                "charge",
                "rel",
                cat,
            );
            let result = stripper().strip(raw);
            assert_eq!(
                result.sensitivity_tier,
                SensitivityTier::S3Medium,
                "category '{}' should map to S3Medium",
                cat
            );
        }
    }

    #[test]
    fn test_tier_s4_categories() {
        let s4 = ["receipt", "restaurant_receipt"];
        for cat in &s4 {
            let raw = make_raw(
                "organization",
                "H",
                "provider",
                "procedure",
                "P",
                "charge",
                "rel",
                cat,
            );
            let result = stripper().strip(raw);
            assert_eq!(
                result.sensitivity_tier,
                SensitivityTier::S4Low,
                "category '{}' should map to S4Low",
                cat
            );
        }
    }

    #[test]
    fn test_tier_unknown_category_defaults_to_s2() {
        let raw = make_raw(
            "organization",
            "H",
            "provider",
            "procedure",
            "P",
            "charge",
            "rel",
            "alien_document_type",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.sensitivity_tier, SensitivityTier::S2High);
    }

    #[test]
    fn test_tier_case_insensitive() {
        let raw = make_raw(
            "organization",
            "H",
            "provider",
            "procedure",
            "P",
            "charge",
            "rel",
            "Medical_Bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.sensitivity_tier, SensitivityTier::S1Critical);
    }

    // -----------------------------------------------------------------------
    // 8. Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_strings_handled() {
        let raw = make_raw("", "", "", "", "", "", "", "");
        let result = stripper().strip(raw);

        // Empty entity type is not in allowed list -> SUPPRESSED
        assert_eq!(result.entity_a_type, "SUPPRESSED");
        assert_eq!(result.entity_b_type, "SUPPRESSED");
        assert_eq!(result.entity_b_value, "SUPPRESSED");
        // Empty role is not in allowed list -> "other"
        assert_eq!(result.entity_a_role, "other");
        assert_eq!(result.entity_b_role, "other");
        // Empty document category -> default tier S2
        assert_eq!(result.sensitivity_tier, SensitivityTier::S2High);
    }

    #[test]
    fn test_amount_passes_through() {
        let mut raw = make_raw(
            "organization",
            "Hospital",
            "provider",
            "procedure",
            "Surgery",
            "charge",
            "billed_for",
            "medical_bill",
        );
        raw.amount = Some(1234.56);
        let result = stripper().strip(raw);
        assert_eq!(result.amount, Some(1234.56));
    }

    #[test]
    fn test_amount_none_passes_through() {
        let raw = make_raw(
            "organization",
            "Hospital",
            "provider",
            "procedure",
            "Surgery",
            "charge",
            "billed_for",
            "medical_bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.amount, None);
    }

    #[test]
    fn test_relation_passes_through_unchanged() {
        let raw = make_raw(
            "organization",
            "Hospital",
            "provider",
            "procedure",
            "Surgery",
            "charge",
            "billed_for",
            "medical_bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.relation, "billed_for");
    }

    #[test]
    fn test_source_region_passes_through() {
        let raw = make_raw(
            "organization",
            "Hospital",
            "provider",
            "procedure",
            "Surgery",
            "charge",
            "billed_for",
            "medical_bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.source_region, "US-Northeast");
    }

    #[test]
    fn test_time_period_passes_through() {
        let raw = make_raw(
            "organization",
            "Hospital",
            "provider",
            "procedure",
            "Surgery",
            "charge",
            "billed_for",
            "medical_bill",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.time_period, "2026-Q1");
    }

    // -----------------------------------------------------------------------
    // 9. Custom config via new()
    // -----------------------------------------------------------------------

    #[test]
    fn test_custom_config() {
        let config = PiiStripperConfig {
            allowed_entity_types: vec!["custom_type".into()],
            allowed_roles: vec!["custom_role".into()],
            direct_id_types: vec!["secret_id".into()],
            s1_categories: vec!["ultra_secret".into()],
            s2_categories: vec![],
            s3_categories: vec![],
            s4_categories: vec!["mundane".into()],
            default_tier: 3,
        };
        let s = PiiStripper::new(&config);

        // custom_type allowed
        let raw = make_raw(
            "custom_type",
            "A",
            "custom_role",
            "custom_type",
            "B",
            "custom_role",
            "related",
            "ultra_secret",
        );
        let result = s.strip(raw);
        assert_eq!(result.entity_a_type, "custom_type");
        assert_eq!(result.entity_b_value, "B");
        assert_eq!(result.entity_a_role, "custom_role");
        assert_eq!(result.sensitivity_tier, SensitivityTier::S1Critical);

        // organization NOT in custom config -> suppressed
        let raw2 = make_raw(
            "organization",
            "Corp",
            "provider",
            "procedure",
            "X",
            "charge",
            "related",
            "mundane",
        );
        let result2 = s.strip(raw2);
        assert_eq!(result2.entity_a_type, "SUPPRESSED");
        assert_eq!(result2.sensitivity_tier, SensitivityTier::S4Low);

        // secret_id is direct ID -> REDACTED
        let raw3 = make_raw(
            "custom_type",
            "A",
            "custom_role",
            "secret_id",
            "TOP_SECRET_VALUE",
            "custom_role",
            "identified_by",
            "ultra_secret",
        );
        let result3 = s.strip(raw3);
        assert_eq!(result3.entity_b_value, "REDACTED");

        // Unknown category with default_tier=3 -> S3Medium
        let raw4 = make_raw(
            "custom_type",
            "A",
            "custom_role",
            "custom_type",
            "B",
            "custom_role",
            "related",
            "unknown_doc",
        );
        let result4 = s.strip(raw4);
        assert_eq!(result4.sensitivity_tier, SensitivityTier::S3Medium);
    }

    // -----------------------------------------------------------------------
    // 10. End-to-end realistic scenario
    // -----------------------------------------------------------------------

    #[test]
    fn test_realistic_medical_bill_scenario() {
        let s = stripper();

        // Tuple 1: organization -> procedure (both allowed)
        let raw1 = RawTuple {
            entity_a_type: "organization".to_string(),
            entity_a_name: "Riverside General Hospital".to_string(),
            entity_a_role: "provider".to_string(),
            entity_b_type: "procedure".to_string(),
            entity_b_name: "bilateral cochlear implant".to_string(),
            entity_b_role: "charge".to_string(),
            relation: "billed_for".to_string(),
            amount: Some(8200.0),
            context: Some("Patient John Smith received bilateral cochlear implant at Riverside General Hospital on March 15, 2026".to_string()),
            document_category: "medical_bill".to_string(),
            source_region: "US-Northeast".to_string(),
            time_period: "2026-Q1".to_string(),
            extraction_timestamp: 1713200000,
        };
        let result1 = s.strip(raw1);

        // Entity A: organization passes, name stripped (not in struct)
        assert_eq!(result1.entity_a_type, "organization");
        assert_eq!(result1.entity_a_role, "provider");

        // Entity B: procedure passes, value preserved for Stage 3
        assert_eq!(result1.entity_b_type, "procedure");
        assert_eq!(result1.entity_b_value, "bilateral cochlear implant");
        assert_eq!(result1.entity_b_role, "charge");

        // Amount preserved for Stage 2 bucketing
        assert_eq!(result1.amount, Some(8200.0));

        // Context stripped (not in struct)
        // Sensitivity tier: medical_bill -> S1Critical
        assert_eq!(result1.sensitivity_tier, SensitivityTier::S1Critical);

        // Tuple 2: person -> ssn (both direct IDs)
        let raw2 = RawTuple {
            entity_a_type: "person".to_string(),
            entity_a_name: "John Smith".to_string(),
            entity_a_role: "patient".to_string(),
            entity_b_type: "ssn".to_string(),
            entity_b_name: "123-45-6789".to_string(),
            entity_b_role: "identifier".to_string(),
            relation: "identified_by".to_string(),
            amount: None,
            context: Some("SSN: 123-45-6789".to_string()),
            document_category: "medical_bill".to_string(),
            source_region: "US-Northeast".to_string(),
            time_period: "2026-Q1".to_string(),
            extraction_timestamp: 1713200000,
        };
        let result2 = s.strip(raw2);

        // person not in allowed list -> SUPPRESSED
        assert_eq!(result2.entity_a_type, "SUPPRESSED");
        // patient not in allowed roles -> "other"
        assert_eq!(result2.entity_a_role, "other");
        // ssn is direct ID -> REDACTED, type SUPPRESSED
        assert_eq!(result2.entity_b_type, "SUPPRESSED");
        assert_eq!(result2.entity_b_value, "REDACTED");
        assert_eq!(result2.entity_b_role, "other");
    }

    #[test]
    fn test_realistic_lease_scenario() {
        let s = stripper();

        let raw = RawTuple {
            entity_a_type: "organization".to_string(),
            entity_a_name: "Sunset Properties LLC".to_string(),
            entity_a_role: "landlord".to_string(),
            entity_b_type: "amount".to_string(),
            entity_b_name: "$2,500".to_string(),
            entity_b_role: "payment".to_string(),
            relation: "monthly_rent".to_string(),
            amount: Some(2500.0),
            context: Some("Monthly rent for 123 Elm St, Apt 4B".to_string()),
            document_category: "lease".to_string(),
            source_region: "US-West".to_string(),
            time_period: "2026-Q2".to_string(),
            extraction_timestamp: 1713200000,
        };
        let result = s.strip(raw);

        assert_eq!(result.entity_a_type, "organization");
        assert_eq!(result.entity_a_role, "landlord");
        assert_eq!(result.entity_b_type, "amount");
        assert_eq!(result.entity_b_value, "$2,500");
        assert_eq!(result.entity_b_role, "payment");
        assert_eq!(result.sensitivity_tier, SensitivityTier::S2High);
        assert_eq!(result.amount, Some(2500.0));
    }

    // -----------------------------------------------------------------------
    // 11. Extraction timestamp is NOT in output (stripped by type system)
    // -----------------------------------------------------------------------

    #[test]
    fn test_extraction_timestamp_not_in_output() {
        let raw = make_raw(
            "organization",
            "H",
            "provider",
            "procedure",
            "P",
            "charge",
            "rel",
            "medical_bill",
        );
        let result = stripper().strip(raw);

        // PiiStrippedTuple has no extraction_timestamp field.
        // We verify this by confirming the struct compiles and all
        // fields are accounted for:
        let _ = result.entity_a_type;
        let _ = result.entity_a_role;
        let _ = result.entity_b_type;
        let _ = result.entity_b_value;
        let _ = result.entity_b_role;
        let _ = result.relation;
        let _ = result.amount;
        let _ = result.document_category;
        let _ = result.sensitivity_tier;
        let _ = result.source_region;
        let _ = result.time_period;
    }

    // -----------------------------------------------------------------------
    // 12. Document category passes through unchanged
    // -----------------------------------------------------------------------

    #[test]
    fn test_document_category_preserved() {
        let raw = make_raw(
            "organization",
            "H",
            "provider",
            "procedure",
            "P",
            "charge",
            "rel",
            "insurance_eob",
        );
        let result = stripper().strip(raw);
        assert_eq!(result.document_category, "insurance_eob");
    }
}
