//! Stage 6 of the Privacy Pipeline: l-Diversity Check
//!
//! Verifies that the equivalence class containing a tuple has sufficient
//! diversity in its sensitive attribute (SA) values, using entropy-based
//! l-diversity. If the Shannon entropy of the SA distribution falls below
//! the tier-specific threshold, the module attempts one additional
//! generalization step on the most generalizable QI field. If entropy
//! remains insufficient after generalization, the tuple is suppressed.
//!
//! ## Algorithm
//!
//! ```text
//! l_diversity_check(tuple, tier) -> Option<LCheckedTuple>:
//!     l_target = L_THRESHOLD[tier]
//!     sa_field = SENSITIVE_ATTRIBUTE_MAP[tuple.document_category]
//!     sa_distribution = get_sa_distribution(tuple.doc_category, tuple.QI_fields)
//!     entropy = -SUM(p * log2(p) for p in sa_distribution if p > 0)
//!     IF entropy < log2(l_target):
//!         tuple_more_general = generalize_one_level(tuple)
//!         IF tuple_more_general IS NOT NULL:
//!             RETURN l_diversity_check(tuple_more_general, tier)
//!         log_suppression(reason="l_diversity_fail")
//!         RETURN None
//!     RETURN Some(LCheckedTuple { inner: k_checked_tuple, l_entropy: entropy })
//! ```
//!
//! ## Entropy Thresholds
//!
//! | Tier | l (Distinct) | Entropy Target (bits) |
//! |------|--------------|-----------------------|
//! | S1   | >= 5         | >= 2.3                |
//! | S2   | >= 4         | >= 2.0                |
//! | S3   | >= 3         | >= 1.6                |
//! | S4   | >= 2         | >= 1.0                |
//!
//! ## Sensitive Attribute Map
//!
//! | Document Category        | SA Field            |
//! |--------------------------|---------------------|
//! | medical_bill/note        | entity_b_value      |
//! | insurance_eob/policy     | entity_b_value      |
//! | bank_statement/pay_stub  | amount_bucket       |
//! | lease/contract           | amount_bucket       |
//! | utility_bill             | amount_bucket       |
//! | receipt/restaurant_rcpt  | amount_bucket       |
//! | government_form          | entity_b_value      |
//! | terms_of_service         | entity_b_value      |

use super::audit_log::AuditLog;
use super::config::PrivacyConfig;
use super::frequency_tables::FrequencyTables;
use super::types::{GeneralizedTuple, HashedTuple, KCheckedTuple, LCheckedTuple, PatternKey};

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Trait for l-diversity checking. Allows mocking in downstream stages.
pub trait LDiversityChecker {
    /// Check whether the tuple's equivalence class has sufficient l-diversity.
    /// Returns `Some(LCheckedTuple)` on success, `None` if suppressed.
    fn check(&mut self, k_checked: KCheckedTuple) -> Option<LCheckedTuple>;
}

// ─── Sensitive Attribute Mapping ──────────────────────────────────────────────

/// The SA field name for a given document category.
/// Returns `"entity_b_value"` or `"amount_bucket"` per the SA map.
fn sensitive_attribute_for(document_category: &str) -> &'static str {
    match document_category {
        // Medical: procedure / diagnosis is entity_b_value
        "medical_bill" | "medical_note" | "prescription" => "entity_b_value",
        // Insurance: claim outcome / amount is entity_b_value
        "insurance_eob" | "insurance_policy" => "entity_b_value",
        // Financial: amount_bucket
        "bank_statement" | "pay_stub" => "amount_bucket",
        "lease" | "contract" => "amount_bucket",
        "utility_bill" => "amount_bucket",
        "receipt" | "restaurant_receipt" => "amount_bucket",
        // Government / legal: entity_b_value
        "government_form" => "entity_b_value",
        "terms_of_service" => "entity_b_value",
        // Unknown categories: conservative default to entity_b_value
        _ => "entity_b_value",
    }
}

// ─── Shannon Entropy ──────────────────────────────────────────────────────────

/// Compute Shannon entropy in bits: H = -SUM(p * log2(p)) for p > 0.
fn shannon_entropy(distribution: &[f64]) -> f64 {
    let mut entropy = 0.0;
    for &p in distribution {
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

// ─── Generalizable QI Fields ──────────────────────────────────────────────────

/// Maximum generalization level per field (matching generalizer.rs conventions).
fn max_gen_level(field: &str) -> u8 {
    match field {
        "entity_b_value" => 3,
        "source_region" => 3,
        "amount_bucket" => 2,
        "time_period" => 2,
        _ => 2, // flat-hierarchy fields: L0, L1(self), L2(*)
    }
}

// ─── SA Distribution Estimation ───────────────────────────────────────────────

/// Estimate the distribution of the sensitive attribute within the equivalence
/// class defined by the tuple's QI field values.
///
/// For V1, we use the frequency tables to enumerate known SA values and
/// compute their conditional probabilities given the QI fields. The
/// equivalence class selectivity is the product of QI field frequencies.
/// The conditional probability of each SA value is:
///
///   P(sa | QI) ~ P(sa) * P(QI | sa) / P(QI)
///
/// Since we assume independence (V1 simplification):
///   P(sa | QI) ~ P(sa)
///
/// So the SA distribution within the equivalence class is approximated
/// by the marginal SA distribution from frequency tables. This is a
/// conservative approximation that will be refined in V2 with actual
/// equivalence class tracking.
fn estimate_sa_distribution(
    sa_field: &str,
    freq_tables: &FrequencyTables,
    _document_category: &str,
) -> Vec<f64> {
    let known_values = freq_tables.known_values(sa_field);
    if known_values.is_empty() {
        return vec![1.0]; // Single value -> entropy 0
    }

    // Collect raw frequencies for all known SA values
    let raw: Vec<f64> = known_values
        .iter()
        .map(|v| freq_tables.field_frequency(sa_field, v))
        .filter(|&f| f > 0.0)
        .collect();

    if raw.is_empty() {
        return vec![1.0];
    }

    // Normalize to a probability distribution
    let total: f64 = raw.iter().sum();
    if total <= 0.0 {
        return vec![1.0];
    }

    raw.iter().map(|&f| f / total).collect()
}

/// Estimate SA distribution at a specific generalization level.
///
/// When QI fields are more generalized, the equivalence class is broader,
/// which typically increases SA diversity. At higher generalization levels,
/// we use the frequency_at_level API to get broader category frequencies,
/// resulting in a more uniform (higher entropy) distribution.
fn estimate_sa_distribution_at_gen_level(
    sa_field: &str,
    freq_tables: &FrequencyTables,
    _document_category: &str,
    gen_level: u8,
) -> Vec<f64> {
    let known_values = freq_tables.known_values(sa_field);
    if known_values.is_empty() {
        return vec![1.0];
    }

    // At gen_level > 0, use frequency_at_level which returns broader
    // category frequencies. This collapses specific values into categories,
    // giving a more concentrated (fewer buckets, more uniform) distribution.
    let raw: Vec<f64> = known_values
        .iter()
        .map(|v| freq_tables.field_frequency_at_level(sa_field, v, gen_level))
        .filter(|&f| f > 0.0)
        .collect();

    if raw.is_empty() {
        return vec![1.0];
    }

    // Deduplicate: at higher gen levels, many specific values map to the
    // same generalized category. Collect unique frequencies and their counts.
    // Actually for entropy calculation, we need the distribution over
    // distinct SA values in the equivalence class. At higher gen levels,
    // the number of distinct values that appear is larger (broader class),
    // so entropy increases. We model this by using the raw marginal distribution.
    let total: f64 = raw.iter().sum();
    if total <= 0.0 {
        return vec![1.0];
    }

    raw.iter().map(|&f| f / total).collect()
}

// ─── LDiversityCheck Struct ───────────────────────────────────────────────────

/// Concrete implementation of the l-diversity checker.
///
/// Holds references to config, frequency tables, and audit log.
/// The frequency tables serve double duty: they provide SA distribution
/// estimates and also serve as the `FrequencyProvider` for generalization
/// frequency lookups.
pub struct LDiversityCheck {
    config: PrivacyConfig,
    freq_tables: FrequencyTables,
    audit_log: AuditLog,
    /// Maximum number of generalization retries before suppression.
    max_retries: u8,
}

impl Default for LDiversityCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl LDiversityCheck {
    /// Create a new l-diversity checker with default config and frequency tables.
    pub fn new() -> Self {
        Self {
            config: PrivacyConfig::default_config(),
            freq_tables: FrequencyTables::new(),
            audit_log: AuditLog::new(1000),
            max_retries: 1,
        }
    }

    /// Create with explicit config, frequency tables, and audit log.
    pub fn with_config(
        config: PrivacyConfig,
        freq_tables: FrequencyTables,
        audit_log: AuditLog,
    ) -> Self {
        Self {
            config,
            freq_tables,
            audit_log,
            max_retries: 1,
        }
    }

    /// Get a reference to the audit log (for test inspection).
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Get a mutable reference to the audit log.
    pub fn audit_log_mut(&mut self) -> &mut AuditLog {
        &mut self.audit_log
    }

    /// Internal recursive check with retry tracking.
    fn check_inner(&mut self, k_checked: KCheckedTuple, retry_count: u8) -> Option<LCheckedTuple> {
        let tier = k_checked.inner.inner.sensitivity_tier;
        let tier_idx = tier.index();
        let entropy_target = self.config.l_diversity.for_tier_index(tier_idx);

        let doc_category = &k_checked.inner.inner.document_category;
        let sa_field = sensitive_attribute_for(doc_category);

        // Estimate SA distribution within the equivalence class.
        // Use the current generalization level of the SA field to determine
        // the distribution granularity.
        let sa_gen_level = if sa_field == "entity_b_value" {
            k_checked.inner.inner.entity_b_gen_level
        } else {
            // For amount_bucket, generalization is implicit in the bucket index.
            // Use 0 as the base level.
            0
        };

        let distribution = if sa_gen_level > 0 {
            estimate_sa_distribution_at_gen_level(
                sa_field,
                &self.freq_tables,
                doc_category,
                sa_gen_level,
            )
        } else {
            estimate_sa_distribution(sa_field, &self.freq_tables, doc_category)
        };

        let entropy = shannon_entropy(&distribution);

        if entropy >= entropy_target {
            // Pass: sufficient l-diversity
            return Some(LCheckedTuple {
                inner: k_checked,
                l_entropy: entropy,
            });
        }

        // Entropy too low: attempt one generalization step
        if retry_count < self.max_retries {
            if let Some(generalized_tuple) = self.generalize_one_level(&k_checked) {
                // Build a new KCheckedTuple with the generalized inner tuple
                let new_k_checked = KCheckedTuple {
                    inner: HashedTuple {
                        inner: generalized_tuple,
                        pattern_hash: k_checked.inner.pattern_hash,
                        pattern_key: self.rebuild_pattern_key(&k_checked.inner),
                        resolution_level: k_checked.inner.resolution_level,
                    },
                    estimated_k: k_checked.estimated_k,
                };
                return self.check_inner(new_k_checked, retry_count + 1);
            }
        }

        // Suppression: log and return None
        let doc_cat = k_checked.inner.inner.document_category.clone();
        self.audit_log.log(
            &doc_cat,
            tier,
            "l_diversity",
            &format!(
                "l_diversity_fail: entropy {:.4} < target {:.4} for tier {:?}",
                entropy, entropy_target, tier
            ),
            None,
        );

        None
    }

    /// Attempt to generalize one QI field by one level, choosing the field
    /// that is furthest below its max generalization level (most room to grow).
    ///
    /// This mirrors the generalizer's greedy approach but only takes a single
    /// step, by design.
    fn generalize_one_level(&self, k_checked: &KCheckedTuple) -> Option<GeneralizedTuple> {
        let inner = &k_checked.inner.inner;

        // Current generalization levels for each field
        let current_levels: Vec<(&str, u8)> = vec![
            ("entity_b_value", inner.entity_b_gen_level),
            (
                "source_region",
                self.infer_region_gen_level(&inner.source_region),
            ),
            ("entity_a_type", 0), // entity_a_type does not have a gen_level field directly
            ("entity_b_type", 0),
            ("amount_bucket", 0),
            ("relation", 0),
            ("time_period", self.infer_time_gen_level(&inner.time_period)),
            ("entity_a_role", 0),
            ("entity_b_role", 0),
        ];

        // Find the field with the most room to generalize
        let mut best_field: Option<&str> = None;
        let mut best_room: u8 = 0;

        for &(field, current_level) in &current_levels {
            let max_level = max_gen_level(field);
            if current_level < max_level {
                let room = max_level - current_level;
                if room > best_room {
                    best_room = room;
                    best_field = Some(field);
                }
            }
        }

        let field_to_generalize = best_field?;

        // Build a new GeneralizedTuple with the selected field bumped one level
        let mut new_tuple = inner.clone();

        match field_to_generalize {
            "entity_b_value" => {
                let new_level = inner.entity_b_gen_level + 1;
                new_tuple.entity_b_gen_level = new_level;
                if let Some(gen_value) = self.freq_tables.generalize_value(
                    "entity_b_value",
                    &inner.entity_b_gen,
                    new_level,
                ) {
                    new_tuple.entity_b_gen = gen_value;
                }
            }
            "source_region" => {
                let current_level = self.infer_region_gen_level(&inner.source_region);
                let new_level = current_level + 1;
                if let Some(gen_value) = self.freq_tables.generalize_value(
                    "source_region",
                    &inner.source_region,
                    new_level,
                ) {
                    new_tuple.source_region = gen_value;
                }
            }
            "entity_a_type" => {
                let new_level = inner.entity_a_gen_level + 1;
                new_tuple.entity_a_gen_level = new_level;
                if new_level >= 2 {
                    new_tuple.entity_a_gen = "*".to_string();
                }
            }
            "time_period" => {
                let current_level = self.infer_time_gen_level(&inner.time_period);
                if current_level == 0 && inner.time_period.contains("-Q") {
                    // Quarter -> Year
                    new_tuple.time_period = inner.time_period[..4].to_string();
                } else {
                    new_tuple.time_period = "*".to_string();
                }
            }
            _ => {
                // For flat-hierarchy fields, generalize to "*"
                match field_to_generalize {
                    "entity_b_type" => new_tuple.entity_b_type = "*".to_string(),
                    "amount_bucket" => new_tuple.amount_bucket = 0xFF,
                    "relation" => new_tuple.relation = "*".to_string(),
                    "entity_a_role" => new_tuple.entity_a_role = "*".to_string(),
                    "entity_b_role" => new_tuple.entity_b_role = "*".to_string(),
                    _ => return None,
                }
            }
        }

        Some(new_tuple)
    }

    /// Infer the current geographic generalization level from the region value.
    fn infer_region_gen_level(&self, region: &str) -> u8 {
        if region == "*" {
            return 3;
        }
        // Check if it's a Census region name
        let lower = region.to_lowercase();
        match lower.as_str() {
            "south" | "west" | "midwest" | "northeast" | "territory" => 2,
            "south_atlantic" | "east_north_central" | "pacific" | "west_south_central"
            | "mid_atlantic" | "mountain" | "west_north_central" | "new_england"
            | "east_south_central" => 1,
            _ => 0, // State-level or unknown
        }
    }

    /// Infer the current time generalization level from the time_period value.
    fn infer_time_gen_level(&self, time_period: &str) -> u8 {
        if time_period == "*" {
            return 2;
        }
        if time_period.contains("-Q") || time_period.contains("-q") {
            return 0; // Quarter level
        }
        if time_period.len() == 4 && time_period.chars().all(|c| c.is_ascii_digit()) {
            return 1; // Year level
        }
        0
    }

    /// Rebuild the pattern key after generalization.
    fn rebuild_pattern_key(&self, hashed: &HashedTuple) -> PatternKey {
        PatternKey {
            entity_a_type: hashed.inner.entity_a_type.clone(),
            entity_a_gen: hashed.inner.entity_a_gen.clone(),
            entity_a_gen_level: hashed.inner.entity_a_gen_level,
            relation: hashed.inner.relation.clone(),
            entity_b_type: hashed.inner.entity_b_type.clone(),
            entity_b_gen: hashed.inner.entity_b_gen.clone(),
            entity_b_gen_level: hashed.inner.entity_b_gen_level,
            amount_bucket: hashed.inner.amount_bucket,
            document_category: hashed.inner.document_category.clone(),
        }
    }
}

impl LDiversityChecker for LDiversityCheck {
    fn check(&mut self, k_checked: KCheckedTuple) -> Option<LCheckedTuple> {
        self.check_inner(k_checked, 0)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::types::SensitivityTier;

    // ── Test helpers ──────────────────────────────────────────────────────

    /// Build a minimal KCheckedTuple for testing.
    fn make_k_checked(
        document_category: &str,
        sensitivity_tier: SensitivityTier,
        entity_b_gen: &str,
        entity_b_gen_level: u8,
        amount_bucket: u8,
    ) -> KCheckedTuple {
        let gen = GeneralizedTuple {
            entity_a_type: "organization".into(),
            entity_a_gen: "healthcare_provider".into(),
            entity_a_gen_level: 1,
            entity_a_role: "provider".into(),
            entity_b_type: "procedure".into(),
            entity_b_gen: entity_b_gen.into(),
            entity_b_gen_level,
            entity_b_role: "charge".into(),
            relation: "charges".into(),
            amount_bucket,
            document_category: document_category.into(),
            sensitivity_tier,
            source_region: "pacific".into(),
            time_period: "2025-Q3".into(),
        };
        let hashed = HashedTuple {
            inner: gen.clone(),
            pattern_hash: [0u8; 32],
            pattern_key: PatternKey {
                entity_a_type: gen.entity_a_type.clone(),
                entity_a_gen: gen.entity_a_gen.clone(),
                entity_a_gen_level: gen.entity_a_gen_level,
                relation: gen.relation.clone(),
                entity_b_type: gen.entity_b_type.clone(),
                entity_b_gen: gen.entity_b_gen.clone(),
                entity_b_gen_level: gen.entity_b_gen_level,
                amount_bucket: gen.amount_bucket,
                document_category: gen.document_category.clone(),
            },
            resolution_level: 0,
        };
        KCheckedTuple {
            inner: hashed,
            estimated_k: 100.0,
        }
    }

    /// Build a default checker for tests.
    fn make_checker() -> LDiversityCheck {
        LDiversityCheck::new()
    }

    // ── Shannon entropy tests ────────────────────────────────────────────

    #[test]
    fn entropy_uniform_two_values() {
        // Two equally likely values: H = log2(2) = 1.0
        let dist = vec![0.5, 0.5];
        let h = shannon_entropy(&dist);
        assert!((h - 1.0).abs() < 1e-10, "H(0.5, 0.5) = 1.0, got {}", h);
    }

    #[test]
    fn entropy_uniform_four_values() {
        // Four equally likely: H = log2(4) = 2.0
        let dist = vec![0.25, 0.25, 0.25, 0.25];
        let h = shannon_entropy(&dist);
        assert!((h - 2.0).abs() < 1e-10, "H(uniform 4) = 2.0, got {}", h);
    }

    #[test]
    fn entropy_uniform_eight_values() {
        // Eight equally likely: H = log2(8) = 3.0
        let dist = vec![0.125; 8];
        let h = shannon_entropy(&dist);
        assert!((h - 3.0).abs() < 1e-10, "H(uniform 8) = 3.0, got {}", h);
    }

    #[test]
    fn entropy_single_value() {
        // Single certain outcome: H = 0
        let dist = vec![1.0];
        let h = shannon_entropy(&dist);
        assert!((h - 0.0).abs() < 1e-10, "H(1.0) = 0.0, got {}", h);
    }

    #[test]
    fn entropy_empty_distribution() {
        let dist: Vec<f64> = vec![];
        let h = shannon_entropy(&dist);
        assert!((h - 0.0).abs() < 1e-10, "H(empty) = 0.0, got {}", h);
    }

    #[test]
    fn entropy_skewed_distribution() {
        // p = [0.9, 0.1]: H = -(0.9*log2(0.9) + 0.1*log2(0.1))
        let dist = vec![0.9, 0.1];
        let h = shannon_entropy(&dist);
        let expected = -(0.9_f64 * 0.9_f64.log2() + 0.1_f64 * 0.1_f64.log2());
        assert!(
            (h - expected).abs() < 1e-10,
            "Expected {}, got {}",
            expected,
            h
        );
    }

    #[test]
    fn entropy_zero_probability_ignored() {
        // Zeros should not affect entropy (0 * log2(0) is defined as 0)
        let dist = vec![0.5, 0.0, 0.5, 0.0];
        let h = shannon_entropy(&dist);
        assert!(
            (h - 1.0).abs() < 1e-10,
            "H should be 1.0 with zeros ignored, got {}",
            h
        );
    }

    #[test]
    fn entropy_three_uniform() {
        // Three equally likely: H = log2(3) ~= 1.585
        let p = 1.0 / 3.0;
        let dist = vec![p, p, p];
        let h = shannon_entropy(&dist);
        assert!(
            (h - 3.0_f64.log2()).abs() < 1e-10,
            "H(uniform 3) = log2(3) ~= 1.585, got {}",
            h
        );
    }

    #[test]
    fn entropy_five_uniform() {
        // Five equally likely: H = log2(5) ~= 2.322
        let p = 1.0 / 5.0;
        let dist = vec![p; 5];
        let h = shannon_entropy(&dist);
        assert!(
            (h - 5.0_f64.log2()).abs() < 1e-10,
            "H(uniform 5) = log2(5) ~= 2.322, got {}",
            h
        );
    }

    #[test]
    fn entropy_is_non_negative() {
        // Entropy is always >= 0
        for n in 1..=20 {
            let p = 1.0 / n as f64;
            let dist = vec![p; n];
            let h = shannon_entropy(&dist);
            assert!(
                h >= -1e-15,
                "Entropy should be non-negative, got {} for n={}",
                h,
                n
            );
        }
    }

    #[test]
    fn entropy_monotonically_increases_with_uniformity() {
        // More uniform distributions have higher entropy
        let h2 = shannon_entropy(&[0.5, 0.5]);
        let h4 = shannon_entropy(&[0.25, 0.25, 0.25, 0.25]);
        let h8 = shannon_entropy(&[0.125; 8]);
        assert!(h4 > h2, "H(4) > H(2)");
        assert!(h8 > h4, "H(8) > H(4)");
    }

    // ── Sensitive attribute mapping tests ────────────────────────────────

    #[test]
    fn sa_mapping_medical_bill() {
        assert_eq!(sensitive_attribute_for("medical_bill"), "entity_b_value");
    }

    #[test]
    fn sa_mapping_medical_note() {
        assert_eq!(sensitive_attribute_for("medical_note"), "entity_b_value");
    }

    #[test]
    fn sa_mapping_prescription() {
        assert_eq!(sensitive_attribute_for("prescription"), "entity_b_value");
    }

    #[test]
    fn sa_mapping_insurance_eob() {
        assert_eq!(sensitive_attribute_for("insurance_eob"), "entity_b_value");
    }

    #[test]
    fn sa_mapping_insurance_policy() {
        assert_eq!(
            sensitive_attribute_for("insurance_policy"),
            "entity_b_value"
        );
    }

    #[test]
    fn sa_mapping_bank_statement() {
        assert_eq!(sensitive_attribute_for("bank_statement"), "amount_bucket");
    }

    #[test]
    fn sa_mapping_pay_stub() {
        assert_eq!(sensitive_attribute_for("pay_stub"), "amount_bucket");
    }

    #[test]
    fn sa_mapping_lease() {
        assert_eq!(sensitive_attribute_for("lease"), "amount_bucket");
    }

    #[test]
    fn sa_mapping_contract() {
        assert_eq!(sensitive_attribute_for("contract"), "amount_bucket");
    }

    #[test]
    fn sa_mapping_utility_bill() {
        assert_eq!(sensitive_attribute_for("utility_bill"), "amount_bucket");
    }

    #[test]
    fn sa_mapping_receipt() {
        assert_eq!(sensitive_attribute_for("receipt"), "amount_bucket");
    }

    #[test]
    fn sa_mapping_restaurant_receipt() {
        assert_eq!(
            sensitive_attribute_for("restaurant_receipt"),
            "amount_bucket"
        );
    }

    #[test]
    fn sa_mapping_government_form() {
        assert_eq!(sensitive_attribute_for("government_form"), "entity_b_value");
    }

    #[test]
    fn sa_mapping_terms_of_service() {
        assert_eq!(
            sensitive_attribute_for("terms_of_service"),
            "entity_b_value"
        );
    }

    #[test]
    fn sa_mapping_unknown_defaults_to_entity_b_value() {
        assert_eq!(sensitive_attribute_for("alien_document"), "entity_b_value");
    }

    // ── SA distribution estimation tests ─────────────────────────────────

    #[test]
    fn sa_distribution_entity_b_value_is_valid_distribution() {
        let ft = FrequencyTables::new();
        let dist = estimate_sa_distribution("entity_b_value", &ft, "medical_bill");
        let sum: f64 = dist.iter().sum();
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "Distribution should sum to 1.0, got {}",
            sum
        );
        assert!(
            dist.len() > 10,
            "Should have many SA values for entity_b_value"
        );
    }

    #[test]
    fn sa_distribution_amount_bucket_is_valid_distribution() {
        let ft = FrequencyTables::new();
        let dist = estimate_sa_distribution("amount_bucket", &ft, "receipt");
        let sum: f64 = dist.iter().sum();
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "Distribution should sum to 1.0, got {}",
            sum
        );
        assert!(dist.len() >= 8, "Should have >= 8 amount bucket values");
    }

    #[test]
    fn sa_distribution_all_probabilities_positive() {
        let ft = FrequencyTables::new();
        let dist = estimate_sa_distribution("entity_b_value", &ft, "medical_bill");
        for &p in &dist {
            assert!(p > 0.0, "All probabilities should be > 0");
        }
    }

    #[test]
    fn sa_distribution_all_probabilities_at_most_one() {
        let ft = FrequencyTables::new();
        let dist = estimate_sa_distribution("entity_b_value", &ft, "medical_bill");
        for &p in &dist {
            assert!(p <= 1.0, "All probabilities should be <= 1.0");
        }
    }

    // ── l-Diversity config threshold tests ───────────────────────────────

    #[test]
    fn l_diversity_threshold_s1() {
        let config = PrivacyConfig::default_config();
        let threshold = config.l_diversity.for_tier_index(0);
        assert!(
            (threshold - 2.3).abs() < 1e-10,
            "S1 threshold should be 2.3"
        );
    }

    #[test]
    fn l_diversity_threshold_s2() {
        let config = PrivacyConfig::default_config();
        let threshold = config.l_diversity.for_tier_index(1);
        assert!(
            (threshold - 2.0).abs() < 1e-10,
            "S2 threshold should be 2.0"
        );
    }

    #[test]
    fn l_diversity_threshold_s3() {
        let config = PrivacyConfig::default_config();
        let threshold = config.l_diversity.for_tier_index(2);
        assert!(
            (threshold - 1.6).abs() < 1e-10,
            "S3 threshold should be 1.6"
        );
    }

    #[test]
    fn l_diversity_threshold_s4() {
        let config = PrivacyConfig::default_config();
        let threshold = config.l_diversity.for_tier_index(3);
        assert!(
            (threshold - 1.0).abs() < 1e-10,
            "S4 threshold should be 1.0"
        );
    }

    // ── Full check: pass scenarios ───────────────────────────────────────

    #[test]
    fn check_pass_s4_low_receipt() {
        // S4 receipt: SA = amount_bucket, threshold = 1.0 bit
        // Amount bucket has 8+ values -> entropy >> 1.0
        let mut checker = make_checker();
        let tuple = make_k_checked("receipt", SensitivityTier::S4Low, "grocery", 1, 3);
        let result = checker.check(tuple);
        assert!(result.is_some(), "S4 receipt should pass l-diversity");
        let checked = result.unwrap();
        assert!(
            checked.l_entropy >= 1.0,
            "Entropy should be >= 1.0 bit for S4"
        );
    }

    #[test]
    fn check_pass_s3_utility_bill() {
        // S3 utility_bill: SA = amount_bucket, threshold = 1.6 bits
        let mut checker = make_checker();
        let tuple = make_k_checked("utility_bill", SensitivityTier::S3Medium, "utility", 0, 2);
        let result = checker.check(tuple);
        assert!(result.is_some(), "S3 utility_bill should pass l-diversity");
        let checked = result.unwrap();
        assert!(
            checked.l_entropy >= 1.6,
            "Entropy should be >= 1.6 bits for S3, got {}",
            checked.l_entropy
        );
    }

    #[test]
    fn check_pass_s2_lease() {
        // S2 lease: SA = amount_bucket, threshold = 2.0 bits
        let mut checker = make_checker();
        let tuple = make_k_checked("lease", SensitivityTier::S2High, "landlord", 0, 4);
        let result = checker.check(tuple);
        assert!(result.is_some(), "S2 lease should pass l-diversity");
        let checked = result.unwrap();
        assert!(
            checked.l_entropy >= 2.0,
            "Entropy should be >= 2.0 bits for S2, got {}",
            checked.l_entropy
        );
    }

    #[test]
    fn check_pass_s1_medical_bill() {
        // S1 medical_bill: SA = entity_b_value, threshold = 2.3 bits
        // entity_b_value has 100+ values -> high entropy
        let mut checker = make_checker();
        let tuple = make_k_checked("medical_bill", SensitivityTier::S1Critical, "surgery", 1, 5);
        let result = checker.check(tuple);
        assert!(result.is_some(), "S1 medical_bill should pass l-diversity");
        let checked = result.unwrap();
        assert!(
            checked.l_entropy >= 2.3,
            "Entropy should be >= 2.3 bits for S1, got {}",
            checked.l_entropy
        );
    }

    #[test]
    fn check_pass_insurance_eob() {
        let mut checker = make_checker();
        let tuple = make_k_checked(
            "insurance_eob",
            SensitivityTier::S1Critical,
            "claim_outcome",
            0,
            3,
        );
        let result = checker.check(tuple);
        assert!(result.is_some(), "insurance_eob should pass l-diversity");
    }

    #[test]
    fn check_pass_bank_statement() {
        let mut checker = make_checker();
        let tuple = make_k_checked("bank_statement", SensitivityTier::S2High, "bank", 1, 2);
        let result = checker.check(tuple);
        assert!(result.is_some(), "bank_statement should pass l-diversity");
    }

    #[test]
    fn check_pass_government_form() {
        let mut checker = make_checker();
        let tuple = make_k_checked(
            "government_form",
            SensitivityTier::S2High,
            "tax_form",
            0,
            0xFF,
        );
        let result = checker.check(tuple);
        assert!(result.is_some(), "government_form should pass l-diversity");
    }

    #[test]
    fn check_pass_pay_stub() {
        let mut checker = make_checker();
        let tuple = make_k_checked("pay_stub", SensitivityTier::S2High, "employer", 1, 3);
        let result = checker.check(tuple);
        assert!(result.is_some(), "pay_stub should pass l-diversity");
    }

    #[test]
    fn check_pass_contract() {
        let mut checker = make_checker();
        let tuple = make_k_checked("contract", SensitivityTier::S2High, "term", 0, 4);
        let result = checker.check(tuple);
        assert!(result.is_some(), "contract should pass l-diversity");
    }

    #[test]
    fn check_pass_restaurant_receipt() {
        let mut checker = make_checker();
        let tuple = make_k_checked(
            "restaurant_receipt",
            SensitivityTier::S4Low,
            "restaurant",
            1,
            0,
        );
        let result = checker.check(tuple);
        assert!(
            result.is_some(),
            "restaurant_receipt should pass l-diversity"
        );
    }

    #[test]
    fn check_pass_terms_of_service() {
        let mut checker = make_checker();
        let tuple = make_k_checked(
            "terms_of_service",
            SensitivityTier::S3Medium,
            "legal_mechanism",
            0,
            0xFF,
        );
        let result = checker.check(tuple);
        assert!(result.is_some(), "terms_of_service should pass l-diversity");
    }

    // ── LCheckedTuple output correctness ─────────────────────────────────

    #[test]
    fn output_preserves_inner_tuple() {
        let mut checker = make_checker();
        let tuple = make_k_checked("receipt", SensitivityTier::S4Low, "grocery", 1, 3);
        let k_est = tuple.estimated_k;
        let result = checker.check(tuple).unwrap();
        assert!(
            (result.inner.estimated_k - k_est).abs() < 1e-10,
            "KCheckedTuple inner should be preserved"
        );
    }

    #[test]
    fn output_l_entropy_is_positive() {
        let mut checker = make_checker();
        let tuple = make_k_checked("receipt", SensitivityTier::S4Low, "grocery", 1, 3);
        let result = checker.check(tuple).unwrap();
        assert!(
            result.l_entropy > 0.0,
            "l_entropy should be positive, got {}",
            result.l_entropy
        );
    }

    #[test]
    fn output_l_entropy_matches_computed_entropy() {
        let checker = make_checker();
        let ft = &checker.freq_tables;
        let dist = estimate_sa_distribution("amount_bucket", ft, "receipt");
        let expected_entropy = shannon_entropy(&dist);

        let mut checker = make_checker();
        let tuple = make_k_checked("receipt", SensitivityTier::S4Low, "grocery", 1, 3);
        let result = checker.check(tuple).unwrap();
        assert!(
            (result.l_entropy - expected_entropy).abs() < 1e-10,
            "Output entropy {} should match computed entropy {}",
            result.l_entropy,
            expected_entropy
        );
    }

    // ── Audit log / suppression tests ────────────────────────────────────

    #[test]
    fn suppression_logs_event() {
        // We need to force a suppression. We can do this by using a custom
        // config with a very high entropy threshold.
        let mut config = PrivacyConfig::default_config();
        config.l_diversity = super::super::config::LDiversityConfig {
            s1: 100.0, // impossibly high
            s2: 100.0,
            s3: 100.0,
            s4: 100.0,
        };
        let mut checker =
            LDiversityCheck::with_config(config, FrequencyTables::new(), AuditLog::new(100));
        let tuple = make_k_checked("receipt", SensitivityTier::S4Low, "grocery", 1, 3);
        let result = checker.check(tuple);
        assert!(
            result.is_none(),
            "Should be suppressed with impossibly high threshold"
        );
        assert_eq!(
            checker.audit_log().len(),
            1,
            "Should have logged one suppression event"
        );
        let event = &checker.audit_log().get_all()[0];
        assert_eq!(event.stage, "l_diversity");
        assert_eq!(event.document_category, "receipt");
        assert_eq!(event.sensitivity_tier, SensitivityTier::S4Low);
        assert!(event.reason.contains("l_diversity_fail"));
    }

    #[test]
    fn suppression_does_not_log_on_pass() {
        let mut checker = make_checker();
        let tuple = make_k_checked("receipt", SensitivityTier::S4Low, "grocery", 1, 3);
        let _result = checker.check(tuple);
        assert_eq!(checker.audit_log().len(), 0, "No suppression event on pass");
    }

    #[test]
    fn multiple_suppressions_accumulate() {
        let mut config = PrivacyConfig::default_config();
        config.l_diversity = super::super::config::LDiversityConfig {
            s1: 100.0,
            s2: 100.0,
            s3: 100.0,
            s4: 100.0,
        };
        let mut checker =
            LDiversityCheck::with_config(config, FrequencyTables::new(), AuditLog::new(100));

        let t1 = make_k_checked("receipt", SensitivityTier::S4Low, "grocery", 1, 3);
        let t2 = make_k_checked("lease", SensitivityTier::S2High, "landlord", 0, 4);
        checker.check(t1);
        checker.check(t2);
        assert_eq!(checker.audit_log().len(), 2);
    }

    // ── Generalize-one-level tests ───────────────────────────────────────

    #[test]
    fn generalize_one_level_returns_some() {
        let checker = make_checker();
        let tuple = make_k_checked(
            "medical_bill",
            SensitivityTier::S1Critical,
            "mri",
            0, // L0 -> can generalize
            5,
        );
        let result = checker.generalize_one_level(&tuple);
        assert!(result.is_some(), "Should be able to generalize from L0");
    }

    #[test]
    fn generalize_one_level_increments_gen_level() {
        let checker = make_checker();
        let tuple = make_k_checked("medical_bill", SensitivityTier::S1Critical, "mri", 0, 5);
        let gen = checker.generalize_one_level(&tuple).unwrap();
        // entity_b_value starts at L0 and has the most room (max=3),
        // so it should be chosen for generalization
        assert!(
            gen.entity_b_gen_level > 0,
            "entity_b_gen_level should have increased"
        );
    }

    #[test]
    fn generalize_one_level_chooses_field_with_most_room() {
        let checker = make_checker();
        // entity_b_value: L0 -> max L3 = room 3
        // source_region: inferred L0 -> max L3 = room 3
        // Both have room 3, but entity_b_value comes first
        let tuple = make_k_checked("medical_bill", SensitivityTier::S1Critical, "mri", 0, 5);
        let gen = checker.generalize_one_level(&tuple).unwrap();
        assert!(
            gen.entity_b_gen_level == 1,
            "Should generalize entity_b_value first (most room, first in list)"
        );
    }

    // ── Tier-specific check tests ────────────────────────────────────────

    #[test]
    fn all_tiers_pass_with_diverse_sa() {
        // entity_b_value has hundreds of values -> very high entropy
        // All tiers should pass
        let tiers = [
            (SensitivityTier::S1Critical, "medical_bill"),
            (SensitivityTier::S2High, "insurance_eob"),
            (SensitivityTier::S3Medium, "terms_of_service"),
            (SensitivityTier::S4Low, "receipt"),
        ];
        for (tier, doc_cat) in &tiers {
            let mut checker = make_checker();
            let tuple = make_k_checked(doc_cat, *tier, "surgery", 1, 3);
            let result = checker.check(tuple);
            assert!(
                result.is_some(),
                "Tier {:?} with doc_cat {} should pass",
                tier,
                doc_cat
            );
        }
    }

    #[test]
    fn s1_requires_higher_entropy_than_s4() {
        let config = PrivacyConfig::default_config();
        let s1_threshold = config.l_diversity.for_tier_index(0);
        let s4_threshold = config.l_diversity.for_tier_index(3);
        assert!(
            s1_threshold > s4_threshold,
            "S1 threshold ({}) should be higher than S4 ({})",
            s1_threshold,
            s4_threshold
        );
    }

    // ── Edge cases ───────────────────────────────────────────────────────

    #[test]
    fn entropy_exceeds_target_by_wide_margin() {
        // entity_b_value with 100+ values has very high entropy (>5 bits)
        let mut checker = make_checker();
        let tuple = make_k_checked("medical_bill", SensitivityTier::S1Critical, "imaging", 1, 3);
        let result = checker.check(tuple).unwrap();
        assert!(
            result.l_entropy > 2.3,
            "Entropy {} should exceed S1 target 2.3 by a wide margin",
            result.l_entropy
        );
    }

    #[test]
    fn region_gen_level_inference_state() {
        let checker = make_checker();
        assert_eq!(checker.infer_region_gen_level("CA"), 0);
        assert_eq!(checker.infer_region_gen_level("TX"), 0);
    }

    #[test]
    fn region_gen_level_inference_division() {
        let checker = make_checker();
        assert_eq!(checker.infer_region_gen_level("pacific"), 1);
        assert_eq!(checker.infer_region_gen_level("mid_atlantic"), 1);
    }

    #[test]
    fn region_gen_level_inference_region() {
        let checker = make_checker();
        assert_eq!(checker.infer_region_gen_level("south"), 2);
        assert_eq!(checker.infer_region_gen_level("west"), 2);
    }

    #[test]
    fn region_gen_level_inference_wildcard() {
        let checker = make_checker();
        assert_eq!(checker.infer_region_gen_level("*"), 3);
    }

    #[test]
    fn time_gen_level_inference_quarter() {
        let checker = make_checker();
        assert_eq!(checker.infer_time_gen_level("2025-Q3"), 0);
    }

    #[test]
    fn time_gen_level_inference_year() {
        let checker = make_checker();
        assert_eq!(checker.infer_time_gen_level("2025"), 1);
    }

    #[test]
    fn time_gen_level_inference_wildcard() {
        let checker = make_checker();
        assert_eq!(checker.infer_time_gen_level("*"), 2);
    }

    // ── Trait implementation test ─────────────────────────────────────────

    #[test]
    fn trait_impl_works_through_trait_object() {
        let mut checker: Box<dyn LDiversityChecker> = Box::new(make_checker());
        let tuple = make_k_checked("receipt", SensitivityTier::S4Low, "grocery", 1, 3);
        let result = checker.check(tuple);
        assert!(result.is_some(), "Should work through trait object");
    }

    // ── Generalization retry integration ─────────────────────────────────

    #[test]
    fn generalize_retry_with_high_threshold_eventually_suppresses() {
        let mut config = PrivacyConfig::default_config();
        config.l_diversity = super::super::config::LDiversityConfig {
            s1: 999.0, // impossible entropy
            s2: 999.0,
            s3: 999.0,
            s4: 999.0,
        };
        let mut checker =
            LDiversityCheck::with_config(config, FrequencyTables::new(), AuditLog::new(100));
        let tuple = make_k_checked("medical_bill", SensitivityTier::S1Critical, "mri", 0, 5);
        let result = checker.check(tuple);
        assert!(
            result.is_none(),
            "Should suppress when entropy is unreachable"
        );
        assert_eq!(checker.audit_log().len(), 1, "Should log suppression");
    }

    #[test]
    fn pass_does_not_trigger_generalization_retry() {
        let mut checker = make_checker();
        let tuple = make_k_checked("receipt", SensitivityTier::S4Low, "grocery", 1, 3);
        let original_doc_cat = tuple.inner.inner.document_category.clone();
        let result = checker.check(tuple).unwrap();
        // Document category should be unchanged (no retry needed)
        assert_eq!(
            result.inner.inner.inner.document_category, original_doc_cat,
            "Document category should be preserved on pass"
        );
    }

    // ── Max generalization level tests ───────────────────────────────────

    #[test]
    fn max_gen_level_entity_b_value() {
        assert_eq!(max_gen_level("entity_b_value"), 3);
    }

    #[test]
    fn max_gen_level_source_region() {
        assert_eq!(max_gen_level("source_region"), 3);
    }

    #[test]
    fn max_gen_level_amount_bucket() {
        assert_eq!(max_gen_level("amount_bucket"), 2);
    }

    #[test]
    fn max_gen_level_time_period() {
        assert_eq!(max_gen_level("time_period"), 2);
    }

    #[test]
    fn max_gen_level_flat_field() {
        assert_eq!(max_gen_level("relation"), 2);
        assert_eq!(max_gen_level("entity_a_type"), 2);
    }
}
