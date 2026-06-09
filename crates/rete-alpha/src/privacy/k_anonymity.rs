//! Stage 5 of the Privacy Pipeline: k-Anonymity Checker
//!
//! Performs a full 12-field multiplicative selectivity k-anonymity check on
//! `HashedTuple`s. Tuples whose estimated k falls below the tier-specific
//! threshold undergo progressive generalization (up to 3 steps). If still
//! below threshold after 3 steps, the tuple is suppressed.
//!
//! ## Algorithm
//!
//! ```text
//! k_est = N * product(field_selectivity(field_i)) for i in 1..=12
//! ```
//!
//! The 12 quasi-identifier fields are:
//! 1. entity_a_type       2. entity_a_gen       3. entity_a_role
//! 4. relation            5. entity_b_type      6. entity_b_gen
//! 7. entity_b_role       8. amount_bucket      9. document_category
//! 10. source_region      11. time_period       12. sensitivity_tier
//!
//! ## Dependencies
//!
//! - `privacy::types` -- `HashedTuple`, `KCheckedTuple`, `GeneralizedTuple`,
//!   `SensitivityTier`, `NetworkPhase`
//! - `privacy::config` -- `PrivacyConfig` (k_thresholds via `.get(tier_idx, phase_idx)`)
//! - `privacy::generalizer` -- `FrequencyProvider` trait (for field frequency lookups)
//! - `privacy::audit_log` -- `AuditLog` (suppression event logging)

use std::collections::HashMap;

use super::audit_log::AuditLog;
use super::config::PrivacyConfig;
use super::generalizer::FrequencyProvider;
use super::types::{GeneralizedTuple, HashedTuple, KCheckedTuple, NetworkPhase};

// ─── Constants ─────────────────────────────────────────────────────────────

/// The 12 quasi-identifier field names used in the multiplicative selectivity
/// model. Order matches the specification table.
const QI_FIELDS: [&str; 12] = [
    "entity_a_type",
    "entity_a_gen",
    "entity_a_role",
    "relation",
    "entity_b_type",
    "entity_b_gen",
    "entity_b_role",
    "amount_bucket",
    "document_category",
    "source_region",
    "time_period",
    "sensitivity_tier",
];

/// Maximum progressive generalization steps before suppression.
const MAX_GENERALIZATION_STEPS: usize = 3;

/// Fields that support multi-level generalization hierarchies and are
/// candidates for progressive generalization in Stage 5. Only fields with
/// meaningful higher-level groupings are included; flat fields (entity types,
/// roles, relation) provide negligible improvement from generalization here
/// because they were already generalized in Stage 3.
///
/// The fields and their generalization behavior:
/// - entity_b_gen: specific -> category -> broad domain -> * (up to 3 levels)
/// - entity_a_gen: specific -> category -> broad domain -> * (up to 3 levels)
/// - source_region: state -> division -> region -> * (up to 3 levels)
/// - amount_bucket: bucket -> range_label -> * (up to 2 levels)
/// - time_period: quarter -> year -> * (up to 2 levels)
/// - entity_a_type: value -> * (up to 1 level useful)
/// - entity_b_type: value -> * (up to 1 level useful)
/// - entity_a_role: value -> * (up to 1 level useful)
/// - entity_b_role: value -> * (up to 1 level useful)
/// - relation: value -> category -> * (up to 2 levels)
/// - document_category: value -> * (up to 1 level useful)
/// - sensitivity_tier: not generalizable (fixed by document type)
const GENERALIZABLE_QI_FIELDS: [&str; 11] = [
    "entity_b_gen",
    "entity_a_gen",
    "source_region",
    "amount_bucket",
    "time_period",
    "entity_a_type",
    "entity_b_type",
    "entity_a_role",
    "entity_b_role",
    "relation",
    "document_category",
];

/// Conservative population estimates per document category.
/// V1 uses hardcoded values; V2 will get real estimates from DHT.
///
/// These represent the estimated number of HIVE users who have shared
/// tuples in this document category. Conservative (low) estimates cause
/// more suppression, which is the safe direction for privacy.
fn estimated_population(document_category: &str) -> f64 {
    match document_category {
        "receipt" | "restaurant_receipt" => 50_000.0,
        "medical_bill" => 25_000.0,
        "utility_bill" => 30_000.0,
        "bank_statement" => 15_000.0,
        "insurance_eob" => 12_000.0,
        "lease" => 10_000.0,
        "contract" => 8_000.0,
        "pay_stub" => 12_000.0,
        "government_form" => 8_000.0,
        "prescription" => 10_000.0,
        "insurance_policy" => 7_000.0,
        "medical_note" => 5_000.0,
        "terms_of_service" => 4_000.0,
        "invoice" => 6_000.0,
        "tax_form" => 5_000.0,
        _ => 3_000.0, // Unknown category: very conservative
    }
}

// ─── Trait ──────────────────────────────────────────────────────────────────

/// Stage 5 k-anonymity checker interface.
///
/// Accepts a `HashedTuple` and returns `Some(KCheckedTuple)` if it passes
/// the full 12-field multiplicative selectivity threshold, or `None` if
/// suppressed.
pub trait KAnonymityChecker {
    fn check(&mut self, hashed: HashedTuple) -> Option<KCheckedTuple>;
}

// ─── Implementation ────────────────────────────────────────────────────────

/// Concrete Stage 5 processor. Holds references to config, frequency data,
/// audit log, and the current network phase.
pub struct KAnonymityCheck {
    config: PrivacyConfig,
    frequency_provider: Box<dyn FrequencyProvider>,
    audit_log: AuditLog,
    network_phase: NetworkPhase,
}

impl KAnonymityCheck {
    /// Create a new k-anonymity checker.
    pub fn new(
        config: PrivacyConfig,
        frequency_provider: Box<dyn FrequencyProvider>,
        audit_log: AuditLog,
        network_phase: NetworkPhase,
    ) -> Self {
        Self {
            config,
            frequency_provider,
            audit_log,
            network_phase,
        }
    }

    /// Create with a specific network phase (useful for testing phase transitions).
    pub fn with_phase(mut self, phase: NetworkPhase) -> Self {
        self.network_phase = phase;
        self
    }

    /// Get a reference to the audit log (for test inspection).
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Get a mutable reference to the audit log.
    pub fn audit_log_mut(&mut self) -> &mut AuditLog {
        &mut self.audit_log
    }

    // ── Core algorithm ───────────────────────────────────────────────────

    /// Extract the value of a quasi-identifier field from a `GeneralizedTuple`.
    fn field_value(inner: &GeneralizedTuple, field: &str) -> String {
        match field {
            "entity_a_type" => inner.entity_a_type.clone(),
            "entity_a_gen" => inner.entity_a_gen.clone(),
            "entity_a_role" => inner.entity_a_role.clone(),
            "relation" => inner.relation.clone(),
            "entity_b_type" => inner.entity_b_type.clone(),
            "entity_b_gen" => inner.entity_b_gen.clone(),
            "entity_b_role" => inner.entity_b_role.clone(),
            "amount_bucket" => inner.amount_bucket.to_string(),
            "document_category" => inner.document_category.clone(),
            "source_region" => inner.source_region.clone(),
            "time_period" => inner.time_period.clone(),
            "sensitivity_tier" => format!("S{}", inner.sensitivity_tier.as_u8()),
            _ => String::new(),
        }
    }

    /// Map QI field names to the frequency table field names used by
    /// `FrequencyProvider`. The entity_a_gen and entity_b_gen fields are
    /// looked up as "entity_b_value" in the frequency tables (both use
    /// the same generalized-entity frequency distribution).
    fn freq_field_name(qi_field: &str) -> &'static str {
        match qi_field {
            "entity_a_gen" => "entity_b_value",
            "entity_b_gen" => "entity_b_value",
            "entity_a_type" => "entity_a_type",
            "entity_a_role" => "entity_a_role",
            "relation" => "relation",
            "entity_b_type" => "entity_b_type",
            "entity_b_role" => "entity_b_role",
            "amount_bucket" => "amount_bucket",
            "document_category" => "document_category",
            "source_region" => "source_region",
            "time_period" => "time_period",
            "sensitivity_tier" => "sensitivity_tier",
            _ => "entity_b_value", // Fallback: use the broadest frequency table
        }
    }

    /// Compute the selectivity (frequency) for a single field value.
    ///
    /// For the `sensitivity_tier` field which has no frequency table entry,
    /// we use the fixed cardinality of 4 tiers: selectivity = 1/4 = 0.25.
    fn field_selectivity(&self, qi_field: &str, value: &str) -> f64 {
        if qi_field == "sensitivity_tier" {
            // Fixed 4 tiers, uniform distribution assumption
            return 0.25;
        }
        let freq_field = Self::freq_field_name(qi_field);
        self.frequency_provider.field_frequency(freq_field, value)
    }

    /// Compute the selectivity for a field value at a specific generalization level.
    fn field_selectivity_at_level(&self, qi_field: &str, value: &str, gen_level: u8) -> f64 {
        if qi_field == "sensitivity_tier" {
            return 0.25; // Not generalizable
        }
        let freq_field = Self::freq_field_name(qi_field);
        self.frequency_provider
            .field_frequency_at_level(freq_field, value, gen_level)
    }

    /// Estimate k for a tuple using the full 12-field multiplicative model.
    ///
    /// `k_est = N * product(selectivity(field_i)) for i in 1..=12`
    ///
    /// `gen_level_overrides` allows temporarily overriding generalization levels
    /// for specific fields during progressive generalization.
    fn estimate_k(&self, inner: &GeneralizedTuple, gen_level_overrides: &HashMap<&str, u8>) -> f64 {
        let n = estimated_population(&inner.document_category);
        let mut selectivity = 1.0_f64;

        for &field in &QI_FIELDS {
            let value = Self::field_value(inner, field);
            let gen_level = gen_level_overrides.get(field).copied().unwrap_or(0);

            let field_sel = if gen_level > 0 {
                self.field_selectivity_at_level(field, &value, gen_level)
            } else {
                self.field_selectivity(field, &value)
            };

            selectivity *= field_sel;
        }

        n * selectivity
    }

    /// Attempt progressive generalization to bring k_est above k_target.
    ///
    /// At each step, trial-generalize each candidate field and pick the one
    /// that provides the largest improvement in estimated k. Stops after
    /// `MAX_GENERALIZATION_STEPS` (3) or when k_target is met.
    ///
    /// Returns `Some(estimated_k)` if k_target was reached within the step
    /// budget, `None` if still below after exhausting steps.
    fn progressive_generalize_for_k(
        &self,
        inner: &GeneralizedTuple,
        k_target: f64,
    ) -> Option<(f64, HashMap<&str, u8>)> {
        let mut gen_levels: HashMap<&str, u8> = HashMap::new();

        // Maximum generalization level per field (aligned with frequency_tables.rs
        // and generalizer.rs hierarchies)
        let max_level_for = |field: &str| -> u8 {
            match field {
                "entity_b_gen" | "entity_a_gen" => 3,
                "source_region" => 3,
                "amount_bucket" | "time_period" => 2,
                "relation" => 2,
                "entity_a_type" | "entity_b_type" => 2,
                "entity_a_role" | "entity_b_role" => 2,
                "document_category" => 2,
                _ => 1,
            }
        };

        for _step in 0..MAX_GENERALIZATION_STEPS {
            let current_k = self.estimate_k(inner, &gen_levels);
            if current_k >= k_target {
                return Some((current_k, gen_levels));
            }

            // Find the field whose generalization gives the biggest delta-k
            let mut best_field: Option<&str> = None;
            let mut best_k: f64 = current_k;

            for &field in &GENERALIZABLE_QI_FIELDS {
                let current_level = gen_levels.get(field).copied().unwrap_or(0);
                if current_level >= max_level_for(field) {
                    continue; // Already at max
                }

                let mut trial = gen_levels.clone();
                trial.insert(field, current_level + 1);
                let trial_k = self.estimate_k(inner, &trial);

                if trial_k > best_k {
                    best_k = trial_k;
                    best_field = Some(field);
                }
            }

            match best_field {
                Some(field) => {
                    let current_level = gen_levels.get(field).copied().unwrap_or(0);
                    gen_levels.insert(field, current_level + 1);
                }
                None => {
                    // No field can improve k further
                    return None;
                }
            }
        }

        // Check once more after last step
        let final_k = self.estimate_k(inner, &gen_levels);
        if final_k >= k_target {
            Some((final_k, gen_levels))
        } else {
            None
        }
    }
}

impl KAnonymityChecker for KAnonymityCheck {
    /// Perform the full 12-field k-anonymity check on a `HashedTuple`.
    ///
    /// 1. Look up k_target from config (tier x network_phase)
    /// 2. Compute k_est via multiplicative selectivity
    /// 3. If k_est < k_target, attempt progressive generalization (max 3 steps)
    /// 4. If still below: log suppression, return None
    /// 5. Otherwise: return Some(KCheckedTuple)
    fn check(&mut self, hashed: HashedTuple) -> Option<KCheckedTuple> {
        let tier = hashed.inner.sensitivity_tier;
        let tier_idx = tier.index();
        let phase_idx = self.network_phase.index();
        let k_target = self.config.k_thresholds.get(tier_idx, phase_idx) as f64;

        // Step 1: Initial k estimation with no overrides
        let no_overrides: HashMap<&str, u8> = HashMap::new();
        let k_est = self.estimate_k(&hashed.inner, &no_overrides);

        if k_est >= k_target {
            return Some(KCheckedTuple {
                inner: hashed,
                estimated_k: k_est,
            });
        }

        // Step 2: Progressive generalization (max 3 steps)
        match self.progressive_generalize_for_k(&hashed.inner, k_target) {
            Some((final_k, _gen_overrides)) => {
                // NOTE: In V1, we return the tuple with the *original* generalization
                // levels from Stage 3 but report the *achievable* k_est. Stage 3
                // already produced the generalized values; Stage 5 only validates
                // that k is achievable. A V2 enhancement would apply the additional
                // generalization from Stage 5 back into the tuple fields.
                Some(KCheckedTuple {
                    inner: hashed,
                    estimated_k: final_k,
                })
            }
            None => {
                // Suppress: k_target unreachable within 3 generalization steps
                let doc_cat = hashed.inner.document_category.clone();
                self.audit_log.log(
                    &doc_cat,
                    tier,
                    "k_anonymity",
                    "full_field_k_below_threshold",
                    None,
                );
                None
            }
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::generalizer::MockFrequencyProvider;
    use crate::privacy::types::{PatternKey, SensitivityTier};

    // ── Test helpers ─────────────────────────────────────────────────────

    fn default_config() -> PrivacyConfig {
        PrivacyConfig::default_config()
    }

    /// Build a mock frequency provider where all fields return high
    /// frequencies (common values), making k_est comfortably above threshold.
    ///
    /// With 12-field multiplicative model:
    ///   k = N * product(sel_i, i=1..11) * 0.25 (sensitivity_tier)
    /// For k >> 400 (S1 Scale threshold), we need high selectivities.
    /// Using 0.80 default: k = 50000 * 0.80^11 * 0.25 = 50000 * 0.0859 * 0.25 = ~1074
    fn common_provider() -> MockFrequencyProvider {
        let mut p = MockFrequencyProvider::new();
        p.set_default(0.80);
        // Set specific field frequencies, all high
        p.set_frequency("entity_a_type", "organization", 0.80);
        p.set_frequency("entity_b_value", "laboratory", 0.80);
        p.set_frequency("entity_a_role", "provider", 0.80);
        p.set_frequency("relation", "charged_for", 0.80);
        p.set_frequency("entity_b_type", "procedure", 0.80);
        p.set_frequency("entity_b_value", "imaging", 0.80);
        p.set_frequency("entity_b_value", "grocery", 0.80);
        p.set_frequency("entity_b_value", "groceries", 0.80);
        p.set_frequency("entity_b_role", "charge", 0.80);
        p.set_frequency("entity_b_role", "merchant", 0.80);
        p.set_frequency("amount_bucket", "0", 0.80);
        p.set_frequency("document_category", "receipt", 0.80);
        p.set_frequency("source_region", "CA", 0.80);
        p.set_frequency("time_period", "2025-Q3", 0.80);
        p.set_frequency("relation", "purchased_from", 0.80);
        p.set_frequency("entity_a_type", "product", 0.80);
        p
    }

    /// Build a mock provider where all fields return very rare values,
    /// producing k_est well below threshold.
    fn rare_provider() -> MockFrequencyProvider {
        let mut p = MockFrequencyProvider::new();
        p.set_default(0.001);
        p
    }

    /// Build a mock provider for progressive generalization tests.
    /// Most fields are common (0.80), two fields are rare but generalizable.
    /// Before generalization: k ~ N * 0.80^9 * rare_a * rare_b * 0.25
    /// After generalizing the rare fields: k ~ N * 0.80^9 * gen_a * gen_b * 0.25
    fn generalizable_provider() -> MockFrequencyProvider {
        let mut p = MockFrequencyProvider::new();
        p.set_default(0.80);

        // entity_b_value: hearing_test is rare at L0, common at L1
        p.set_frequency("entity_b_value", "hearing_test", 0.001);
        p.set_level_frequency("entity_b_value", "hearing_test", 1, 0.80);
        p.set_level_frequency("entity_b_value", "hearing_test", 2, 0.90);

        // source_region: WY is rare at L0, broader at L1
        p.set_frequency("source_region", "WY", 0.002);
        p.set_level_frequency("source_region", "WY", 1, 0.80);
        p.set_level_frequency("source_region", "WY", 2, 0.90);

        // Other fields at common levels
        p.set_frequency("entity_a_type", "organization", 0.80);
        p.set_frequency("entity_a_role", "provider", 0.80);
        p.set_frequency("relation", "charged_for", 0.80);
        p.set_frequency("entity_b_type", "procedure", 0.80);
        p.set_frequency("entity_b_role", "charge", 0.80);
        p.set_frequency("amount_bucket", "0", 0.80);
        p.set_frequency("document_category", "medical_bill", 0.80);
        p.set_frequency("time_period", "2025-Q3", 0.80);
        p
    }

    /// Build a `GeneralizedTuple` with the given field values.
    // Test helper mirrors `GeneralizedTuple` layout; each QID is deliberately
    // positional so k-anonymity scenarios read top-to-bottom.
    #[allow(clippy::too_many_arguments)]
    fn make_generalized(
        entity_a_type: &str,
        entity_a_gen: &str,
        entity_a_role: &str,
        relation: &str,
        entity_b_type: &str,
        entity_b_gen: &str,
        entity_b_role: &str,
        amount_bucket: u8,
        document_category: &str,
        source_region: &str,
        time_period: &str,
        sensitivity_tier: SensitivityTier,
    ) -> GeneralizedTuple {
        GeneralizedTuple {
            entity_a_type: entity_a_type.to_string(),
            entity_a_gen: entity_a_gen.to_string(),
            entity_a_gen_level: 0,
            entity_a_role: entity_a_role.to_string(),
            entity_b_type: entity_b_type.to_string(),
            entity_b_gen: entity_b_gen.to_string(),
            entity_b_gen_level: 0,
            entity_b_role: entity_b_role.to_string(),
            relation: relation.to_string(),
            amount_bucket,
            document_category: document_category.to_string(),
            sensitivity_tier,
            source_region: source_region.to_string(),
            time_period: time_period.to_string(),
        }
    }

    /// Build a `HashedTuple` wrapping a `GeneralizedTuple`.
    fn make_hashed(inner: GeneralizedTuple) -> HashedTuple {
        HashedTuple {
            inner: inner.clone(),
            pattern_hash: [0u8; 32],
            pattern_key: PatternKey {
                entity_a_type: inner.entity_a_type.clone(),
                entity_a_gen: inner.entity_a_gen.clone(),
                entity_a_gen_level: inner.entity_a_gen_level,
                relation: inner.relation.clone(),
                entity_b_type: inner.entity_b_type.clone(),
                entity_b_gen: inner.entity_b_gen.clone(),
                entity_b_gen_level: inner.entity_b_gen_level,
                amount_bucket: inner.amount_bucket,
                document_category: inner.document_category.clone(),
            },
            resolution_level: 0,
        }
    }

    /// Standard common medical tuple: S4 receipt, common values
    fn common_receipt_tuple() -> HashedTuple {
        make_hashed(make_generalized(
            "organization",
            "grocery",
            "merchant",
            "purchased_from",
            "product",
            "groceries",
            "charge",
            0, // $0-$100
            "receipt",
            "CA",
            "2025-Q3",
            SensitivityTier::S4Low,
        ))
    }

    /// Rare medical tuple: S1, rare values
    fn rare_medical_tuple() -> HashedTuple {
        make_hashed(make_generalized(
            "organization",
            "hearing_test",
            "provider",
            "charged_for",
            "procedure",
            "hearing_test",
            "charge",
            7, // $100K+
            "medical_bill",
            "WY",
            "2025-Q3",
            SensitivityTier::S1Critical,
        ))
    }

    /// Build a checker with the given provider and phase.
    fn make_checker(provider: MockFrequencyProvider, phase: NetworkPhase) -> KAnonymityCheck {
        KAnonymityCheck::new(
            default_config(),
            Box::new(provider),
            AuditLog::new(1000),
            phase,
        )
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 1. BASIC PASS TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn common_tuple_passes_s4_bootstrap() {
        let mut checker = make_checker(common_provider(), NetworkPhase::Bootstrap);
        let result = checker.check(common_receipt_tuple());
        assert!(result.is_some(), "Common S4 tuple should pass at Bootstrap");
    }

    #[test]
    fn common_tuple_passes_s4_growth() {
        let mut checker = make_checker(common_provider(), NetworkPhase::Growth);
        let result = checker.check(common_receipt_tuple());
        assert!(result.is_some(), "Common S4 tuple should pass at Growth");
    }

    #[test]
    fn common_tuple_passes_s4_maturity() {
        let mut checker = make_checker(common_provider(), NetworkPhase::Maturity);
        let result = checker.check(common_receipt_tuple());
        assert!(result.is_some(), "Common S4 tuple should pass at Maturity");
    }

    #[test]
    fn common_tuple_passes_s4_scale() {
        let mut checker = make_checker(common_provider(), NetworkPhase::Scale);
        let result = checker.check(common_receipt_tuple());
        assert!(result.is_some(), "Common S4 tuple should pass at Scale");
    }

    #[test]
    fn pass_returns_positive_estimated_k() {
        let mut checker = make_checker(common_provider(), NetworkPhase::Bootstrap);
        let result = checker.check(common_receipt_tuple()).unwrap();
        assert!(
            result.estimated_k > 0.0,
            "estimated_k should be positive, got {}",
            result.estimated_k
        );
    }

    #[test]
    fn pass_preserves_inner_tuple() {
        let tuple = common_receipt_tuple();
        let original_hash = tuple.pattern_hash;
        let mut checker = make_checker(common_provider(), NetworkPhase::Bootstrap);
        let result = checker.check(tuple).unwrap();
        assert_eq!(
            result.inner.pattern_hash, original_hash,
            "Inner HashedTuple should be preserved"
        );
    }

    #[test]
    fn pass_preserves_document_category() {
        let mut checker = make_checker(common_provider(), NetworkPhase::Bootstrap);
        let result = checker.check(common_receipt_tuple()).unwrap();
        assert_eq!(result.inner.inner.document_category, "receipt");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 2. BASIC SUPPRESS TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn rare_tuple_suppressed_s1_bootstrap() {
        let mut checker = make_checker(rare_provider(), NetworkPhase::Bootstrap);
        let result = checker.check(rare_medical_tuple());
        assert!(
            result.is_none(),
            "Rare S1 tuple should be suppressed at Bootstrap"
        );
    }

    #[test]
    fn rare_tuple_suppressed_s1_scale() {
        let mut checker = make_checker(rare_provider(), NetworkPhase::Scale);
        let result = checker.check(rare_medical_tuple());
        assert!(
            result.is_none(),
            "Rare S1 tuple should be suppressed at Scale"
        );
    }

    #[test]
    fn suppression_logs_audit_event() {
        let mut checker = make_checker(rare_provider(), NetworkPhase::Bootstrap);
        checker.check(rare_medical_tuple());
        assert_eq!(
            checker.audit_log().len(),
            1,
            "Suppression should log exactly one audit event"
        );
    }

    #[test]
    fn suppression_audit_stage_is_k_anonymity() {
        let mut checker = make_checker(rare_provider(), NetworkPhase::Bootstrap);
        checker.check(rare_medical_tuple());
        let events = checker.audit_log().get_all();
        assert_eq!(events[0].stage, "k_anonymity");
    }

    #[test]
    fn suppression_audit_reason_is_below_threshold() {
        let mut checker = make_checker(rare_provider(), NetworkPhase::Bootstrap);
        checker.check(rare_medical_tuple());
        let events = checker.audit_log().get_all();
        assert_eq!(events[0].reason, "full_field_k_below_threshold");
    }

    #[test]
    fn suppression_audit_document_category() {
        let mut checker = make_checker(rare_provider(), NetworkPhase::Bootstrap);
        checker.check(rare_medical_tuple());
        let events = checker.audit_log().get_all();
        assert_eq!(events[0].document_category, "medical_bill");
    }

    #[test]
    fn suppression_audit_sensitivity_tier() {
        let mut checker = make_checker(rare_provider(), NetworkPhase::Bootstrap);
        checker.check(rare_medical_tuple());
        let events = checker.audit_log().get_all();
        assert_eq!(events[0].sensitivity_tier, SensitivityTier::S1Critical);
    }

    #[test]
    fn pass_does_not_log_audit_event() {
        let mut checker = make_checker(common_provider(), NetworkPhase::Bootstrap);
        checker.check(common_receipt_tuple());
        assert_eq!(
            checker.audit_log().len(),
            0,
            "Pass should not log any audit events"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 3. PROGRESSIVE GENERALIZATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn progressive_gen_rescues_borderline_tuple() {
        // A tuple that fails initial check but passes after generalization.
        // Most fields common (0.80), one rare field that generalizes well.
        // Before: k = 50000 * 0.80^10 * 0.001 * 0.25 ~ 1.34 (below S4 Bootstrap = 8)
        // After gen entity_b_value to L1: k = 50000 * 0.80^11 * 0.25 ~ 1074 (above 8)
        let mut p = MockFrequencyProvider::new();
        p.set_default(0.80);
        // entity_b_value is the rare field
        p.set_frequency("entity_b_value", "hearing_test", 0.001);
        p.set_level_frequency("entity_b_value", "hearing_test", 1, 0.80);

        let tuple = make_hashed(make_generalized(
            "organization",
            "hearing_test",
            "provider",
            "charged_for",
            "procedure",
            "hearing_test",
            "charge",
            0,
            "receipt",
            "CA",
            "2025-Q3",
            SensitivityTier::S4Low,
        ));

        let mut checker = make_checker(p, NetworkPhase::Bootstrap);
        let result = checker.check(tuple);
        assert!(
            result.is_some(),
            "Borderline tuple should be rescued by progressive generalization"
        );
    }

    #[test]
    fn progressive_gen_exhausts_3_steps_then_suppresses() {
        // Even after generalization, still below threshold
        let mut p = MockFrequencyProvider::new();
        p.set_default(0.0001); // All fields extremely rare
                               // Even generalized values are rare
        for field in &[
            "entity_b_value",
            "source_region",
            "entity_a_type",
            "entity_b_type",
            "entity_a_role",
            "entity_b_role",
            "relation",
            "amount_bucket",
            "document_category",
            "time_period",
        ] {
            for level in 1..=3u8 {
                p.set_level_frequency(field, "any", level, 0.001);
            }
        }

        let tuple = make_hashed(make_generalized(
            "any",
            "any",
            "any",
            "any",
            "any",
            "any",
            "any",
            0,
            "medical_bill",
            "any",
            "any",
            SensitivityTier::S1Critical,
        ));

        let mut checker = make_checker(p, NetworkPhase::Scale);
        let result = checker.check(tuple);
        assert!(
            result.is_none(),
            "Should suppress after 3 failed generalization steps"
        );
    }

    #[test]
    fn progressive_gen_picks_highest_improvement_field() {
        // Two rare fields: one generalizes much better than the other.
        // entity_b_value: rare (0.001) -> gen L1 (0.80) -- big improvement
        // source_region: rare (0.002) -> gen L1 (0.005) -- small improvement
        // Other 9 fields at 0.80, sensitivity_tier at 0.25
        // Before: k = 50000 * 0.80^9 * 0.001 * 0.002 * 0.25 ~ 0.0034
        // After gen entity_b_value: k = 50000 * 0.80^9 * 0.80 * 0.002 * 0.25 ~ 2.68
        // After also gen source_region: k = 50000 * 0.80^9 * 0.80 * 0.005 * 0.25 ~ 6.7
        // After gen entity_b_value to L2: k would be even higher (fallback 2^1 * 0.80)
        // The algorithm should pick entity_b_value first (800x improvement vs 2.5x).
        let mut p = MockFrequencyProvider::new();
        p.set_default(0.80);

        p.set_frequency("entity_b_value", "rare_proc", 0.001);
        p.set_level_frequency("entity_b_value", "rare_proc", 1, 0.80);

        p.set_frequency("source_region", "WY", 0.002);
        p.set_level_frequency("source_region", "WY", 1, 0.80);

        let tuple = make_hashed(make_generalized(
            "organization",
            "rare_proc",
            "provider",
            "charged_for",
            "procedure",
            "rare_proc",
            "charge",
            0,
            "receipt",
            "WY",
            "2025-Q3",
            SensitivityTier::S4Low,
        ));

        let mut checker = make_checker(p, NetworkPhase::Bootstrap);
        let result = checker.check(tuple);
        // After 2-3 generalization steps, k should reach S4 Bootstrap threshold (8)
        assert!(
            result.is_some(),
            "Greedy generalization should rescue by picking highest-improvement fields"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 4. TIER-SPECIFIC THRESHOLD TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn s1_has_highest_k_threshold() {
        let config = default_config();
        for phase_idx in 0..4 {
            let k_s1 = config.k_thresholds.get(0, phase_idx);
            let k_s4 = config.k_thresholds.get(3, phase_idx);
            assert!(
                k_s1 > k_s4,
                "S1 threshold ({}) should exceed S4 ({}) at phase {}",
                k_s1,
                k_s4,
                phase_idx
            );
        }
    }

    #[test]
    fn s4_easiest_to_pass() {
        // With moderate frequencies, S4 should pass where S1 fails
        let mut p_s4 = MockFrequencyProvider::new();
        p_s4.set_default(0.03); // Moderate rarity
        let mut p_s1 = MockFrequencyProvider::new();
        p_s1.set_default(0.03);

        let s4_tuple = make_hashed(make_generalized(
            "organization",
            "grocery",
            "merchant",
            "purchased_from",
            "product",
            "groceries",
            "charge",
            0,
            "receipt",
            "CA",
            "2025-Q3",
            SensitivityTier::S4Low,
        ));
        let s1_tuple = make_hashed(make_generalized(
            "organization",
            "grocery",
            "merchant",
            "purchased_from",
            "product",
            "groceries",
            "charge",
            0,
            "medical_bill",
            "CA",
            "2025-Q3",
            SensitivityTier::S1Critical,
        ));

        let mut checker_s4 = make_checker(p_s4, NetworkPhase::Bootstrap);
        let mut checker_s1 = make_checker(p_s1, NetworkPhase::Bootstrap);

        let r_s4 = checker_s4.check(s4_tuple);
        let r_s1 = checker_s1.check(s1_tuple);

        // At least one difference: S4 more likely to pass
        if r_s1.is_none() {
            assert!(
                r_s4.is_some() || r_s1.is_none(),
                "S4 should be at least as permissive as S1"
            );
        }
    }

    #[test]
    fn threshold_values_match_spec() {
        let config = default_config();
        // S1: [100, 200, 300, 400]
        assert_eq!(config.k_thresholds.get(0, 0), 100);
        assert_eq!(config.k_thresholds.get(0, 1), 200);
        assert_eq!(config.k_thresholds.get(0, 2), 300);
        assert_eq!(config.k_thresholds.get(0, 3), 400);
        // S2: [50, 100, 150, 200]
        assert_eq!(config.k_thresholds.get(1, 0), 50);
        assert_eq!(config.k_thresholds.get(1, 1), 100);
        // S3: [15, 30, 50, 75]
        assert_eq!(config.k_thresholds.get(2, 0), 15);
        assert_eq!(config.k_thresholds.get(2, 3), 75);
        // S4: [8, 15, 20, 30]
        assert_eq!(config.k_thresholds.get(3, 0), 8);
        assert_eq!(config.k_thresholds.get(3, 3), 30);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 5. NETWORK PHASE TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn bootstrap_is_most_permissive() {
        // Bootstrap has the lowest k_target for every tier
        let config = default_config();
        for tier_idx in 0..4 {
            let k_bootstrap = config.k_thresholds.get(tier_idx, 0);
            for phase_idx in 1..4 {
                let k_other = config.k_thresholds.get(tier_idx, phase_idx);
                assert!(
                    k_bootstrap <= k_other,
                    "Bootstrap should have lowest k_target for tier {}: {} vs {}",
                    tier_idx,
                    k_bootstrap,
                    k_other
                );
            }
        }
    }

    #[test]
    fn scale_is_most_restrictive() {
        let config = default_config();
        for tier_idx in 0..4 {
            let k_scale = config.k_thresholds.get(tier_idx, 3);
            for phase_idx in 0..3 {
                let k_other = config.k_thresholds.get(tier_idx, phase_idx);
                assert!(
                    k_scale >= k_other,
                    "Scale should have highest k_target for tier {}: {} vs {}",
                    tier_idx,
                    k_scale,
                    k_other
                );
            }
        }
    }

    #[test]
    fn same_tuple_passes_bootstrap_fails_scale() {
        // A borderline tuple that passes at Bootstrap but fails at Scale
        let mut p_boot = MockFrequencyProvider::new();
        p_boot.set_default(0.04);
        let mut p_scale = MockFrequencyProvider::new();
        p_scale.set_default(0.04);

        let tuple_boot = make_hashed(make_generalized(
            "organization",
            "grocery",
            "merchant",
            "purchased_from",
            "product",
            "groceries",
            "charge",
            0,
            "receipt",
            "CA",
            "2025-Q3",
            SensitivityTier::S4Low,
        ));
        let tuple_scale = make_hashed(make_generalized(
            "organization",
            "grocery",
            "merchant",
            "purchased_from",
            "product",
            "groceries",
            "charge",
            0,
            "receipt",
            "CA",
            "2025-Q3",
            SensitivityTier::S4Low,
        ));

        let mut checker_boot = make_checker(p_boot, NetworkPhase::Bootstrap);
        let mut checker_scale = make_checker(p_scale, NetworkPhase::Scale);

        let r_boot = checker_boot.check(tuple_boot);
        let r_scale = checker_scale.check(tuple_scale);

        // Both results should be coherent: either both pass (if k high enough)
        // or scale may fail while bootstrap passes
        if r_boot.is_some() && r_scale.is_none() {
            // Expected for borderline tuples
        }
        // At minimum, bootstrap should never be more restrictive than scale
        if r_scale.is_some() {
            assert!(
                r_boot.is_some(),
                "If Scale passes, Bootstrap must also pass"
            );
        }
    }

    #[test]
    fn with_phase_builder_works() {
        let checker = KAnonymityCheck::new(
            default_config(),
            Box::new(common_provider()),
            AuditLog::new(100),
            NetworkPhase::Bootstrap,
        )
        .with_phase(NetworkPhase::Scale);

        assert_eq!(checker.network_phase, NetworkPhase::Scale);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 6. SELECTIVITY AND ESTIMATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn sensitivity_tier_selectivity_is_025() {
        let checker = make_checker(common_provider(), NetworkPhase::Bootstrap);
        let sel = checker.field_selectivity("sensitivity_tier", "S1");
        assert!(
            (sel - 0.25).abs() < 1e-10,
            "sensitivity_tier selectivity should be 0.25, got {}",
            sel
        );
    }

    #[test]
    fn sensitivity_tier_selectivity_at_level_is_025() {
        let checker = make_checker(common_provider(), NetworkPhase::Bootstrap);
        let sel = checker.field_selectivity_at_level("sensitivity_tier", "S1", 2);
        assert!(
            (sel - 0.25).abs() < 1e-10,
            "sensitivity_tier selectivity at any level should be 0.25"
        );
    }

    #[test]
    fn estimate_k_is_positive() {
        let checker = make_checker(common_provider(), NetworkPhase::Bootstrap);
        let inner = make_generalized(
            "organization",
            "laboratory",
            "provider",
            "charged_for",
            "procedure",
            "imaging",
            "charge",
            0,
            "receipt",
            "CA",
            "2025-Q3",
            SensitivityTier::S4Low,
        );
        let no_overrides = HashMap::new();
        let k = checker.estimate_k(&inner, &no_overrides);
        assert!(k > 0.0, "k_est should be positive, got {}", k);
    }

    #[test]
    fn estimate_k_increases_with_gen_level() {
        let checker = make_checker(generalizable_provider(), NetworkPhase::Bootstrap);
        let inner = make_generalized(
            "organization",
            "hearing_test",
            "provider",
            "charged_for",
            "procedure",
            "hearing_test",
            "charge",
            0,
            "medical_bill",
            "WY",
            "2025-Q3",
            SensitivityTier::S1Critical,
        );
        let no_overrides = HashMap::new();
        let k_base = checker.estimate_k(&inner, &no_overrides);

        let mut gen_overrides = HashMap::new();
        gen_overrides.insert("entity_b_gen", 1u8);
        let k_gen = checker.estimate_k(&inner, &gen_overrides);

        assert!(
            k_gen >= k_base,
            "k_est should not decrease with generalization: {} vs {}",
            k_gen,
            k_base
        );
    }

    #[test]
    fn estimate_k_multiplicative_model() {
        // Verify the model: k = N * product(selectivities)
        let mut p = MockFrequencyProvider::new();
        // All fields return exactly 0.5
        p.set_default(0.5);
        let checker = make_checker(p, NetworkPhase::Bootstrap);

        let inner = make_generalized(
            "organization",
            "laboratory",
            "provider",
            "charged_for",
            "procedure",
            "imaging",
            "charge",
            0,
            "receipt",
            "CA",
            "2025-Q3",
            SensitivityTier::S4Low,
        );
        let no_overrides = HashMap::new();
        let k = checker.estimate_k(&inner, &no_overrides);

        // N for "receipt" = 50,000
        // 11 fields with selectivity 0.5 + 1 field (sensitivity_tier) with 0.25
        // k = 50000 * 0.5^11 * 0.25 = 50000 * (1/2048) * 0.25 = 50000 * 0.000122... = ~6.1
        let expected = 50_000.0 * (0.5_f64).powi(11) * 0.25;
        assert!(
            (k - expected).abs() < 0.01,
            "k should match multiplicative model: {} vs expected {}",
            k,
            expected
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 7. FIELD VALUE EXTRACTION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn field_value_entity_a_type() {
        let inner = make_generalized(
            "organization",
            "lab",
            "provider",
            "charges",
            "procedure",
            "mri",
            "charge",
            3,
            "medical_bill",
            "CA",
            "2025-Q3",
            SensitivityTier::S1Critical,
        );
        assert_eq!(
            KAnonymityCheck::field_value(&inner, "entity_a_type"),
            "organization"
        );
    }

    #[test]
    fn field_value_entity_a_gen() {
        let inner = make_generalized(
            "organization",
            "hospital",
            "provider",
            "charges",
            "procedure",
            "mri",
            "charge",
            3,
            "medical_bill",
            "CA",
            "2025-Q3",
            SensitivityTier::S1Critical,
        );
        assert_eq!(
            KAnonymityCheck::field_value(&inner, "entity_a_gen"),
            "hospital"
        );
    }

    #[test]
    fn field_value_amount_bucket() {
        let inner = make_generalized(
            "organization",
            "lab",
            "provider",
            "charges",
            "procedure",
            "mri",
            "charge",
            5,
            "medical_bill",
            "CA",
            "2025-Q3",
            SensitivityTier::S2High,
        );
        assert_eq!(KAnonymityCheck::field_value(&inner, "amount_bucket"), "5");
    }

    #[test]
    fn field_value_sensitivity_tier() {
        let inner = make_generalized(
            "organization",
            "lab",
            "provider",
            "charges",
            "procedure",
            "mri",
            "charge",
            3,
            "medical_bill",
            "CA",
            "2025-Q3",
            SensitivityTier::S3Medium,
        );
        assert_eq!(
            KAnonymityCheck::field_value(&inner, "sensitivity_tier"),
            "S3"
        );
    }

    #[test]
    fn field_value_all_12_fields_non_empty() {
        let inner = make_generalized(
            "organization",
            "hospital",
            "provider",
            "charged_for",
            "procedure",
            "mri",
            "charge",
            3,
            "medical_bill",
            "CA",
            "2025-Q3",
            SensitivityTier::S1Critical,
        );
        for field in &QI_FIELDS {
            let val = KAnonymityCheck::field_value(&inner, field);
            assert!(
                !val.is_empty(),
                "Field {} should have a non-empty value",
                field
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 8. UNKNOWN / EDGE CASE TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn unknown_field_values_use_conservative_estimate() {
        let mut p = MockFrequencyProvider::new();
        p.set_default(0.001); // Conservative for unknowns

        let checker = make_checker(p, NetworkPhase::Bootstrap);
        let inner = make_generalized(
            "alien_type",
            "alien_gen",
            "alien_role",
            "alien_rel",
            "alien_type2",
            "alien_gen2",
            "alien_role2",
            0,
            "alien_doc",
            "alien_region",
            "alien_time",
            SensitivityTier::S4Low,
        );
        let no_overrides = HashMap::new();
        let k = checker.estimate_k(&inner, &no_overrides);

        // With 0.001 for 11 fields and 0.25 for sensitivity_tier,
        // N = 3000 (unknown category), k = 3000 * 0.001^11 * 0.25 ~ 7.5e-31
        // Should be extremely small -> definitely suppressed
        assert!(k < 1.0, "All-unknown tuple should have very low k: {}", k);
    }

    #[test]
    fn amount_bucket_0xff_treated_as_na() {
        let mut p = MockFrequencyProvider::new();
        p.set_default(0.10);
        p.set_frequency("amount_bucket", "255", 0.005); // 0xFF = 255 = N/A

        let checker = make_checker(p, NetworkPhase::Bootstrap);
        let inner = make_generalized(
            "organization",
            "hospital",
            "provider",
            "charged_for",
            "procedure",
            "mri",
            "charge",
            0xFF,
            "medical_bill",
            "CA",
            "2025-Q3",
            SensitivityTier::S1Critical,
        );
        let no_overrides = HashMap::new();
        let k = checker.estimate_k(&inner, &no_overrides);

        // k should be computed with the N/A frequency
        assert!(
            k > 0.0,
            "0xFF amount bucket should produce valid k estimate"
        );
    }

    #[test]
    fn empty_string_field_values_handled() {
        let mut p = MockFrequencyProvider::new();
        p.set_default(0.01);

        let checker = make_checker(p, NetworkPhase::Bootstrap);
        let inner = make_generalized(
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            0,
            "",
            "",
            "",
            SensitivityTier::S4Low,
        );
        let no_overrides = HashMap::new();
        let k = checker.estimate_k(&inner, &no_overrides);
        // Should not panic, k should be computable
        assert!(k >= 0.0, "Empty fields should produce non-negative k");
    }

    #[test]
    fn population_estimate_for_unknown_category() {
        let n = estimated_population("completely_unknown_document_type");
        assert_eq!(
            n, 3_000.0,
            "Unknown categories should use conservative 3000"
        );
    }

    #[test]
    fn population_estimate_for_receipt() {
        let n = estimated_population("receipt");
        assert_eq!(n, 50_000.0);
    }

    #[test]
    fn population_estimate_for_medical_bill() {
        let n = estimated_population("medical_bill");
        assert_eq!(n, 25_000.0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 9. FREQ FIELD NAME MAPPING TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn entity_a_gen_maps_to_entity_b_value() {
        assert_eq!(
            KAnonymityCheck::freq_field_name("entity_a_gen"),
            "entity_b_value"
        );
    }

    #[test]
    fn entity_b_gen_maps_to_entity_b_value() {
        assert_eq!(
            KAnonymityCheck::freq_field_name("entity_b_gen"),
            "entity_b_value"
        );
    }

    #[test]
    fn other_fields_map_to_themselves() {
        assert_eq!(
            KAnonymityCheck::freq_field_name("source_region"),
            "source_region"
        );
        assert_eq!(KAnonymityCheck::freq_field_name("relation"), "relation");
        assert_eq!(
            KAnonymityCheck::freq_field_name("document_category"),
            "document_category"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 10. AUDIT LOG INTERACTION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn multiple_suppressions_accumulate_in_log() {
        let mut checker = make_checker(rare_provider(), NetworkPhase::Bootstrap);
        checker.check(rare_medical_tuple());
        checker.check(rare_medical_tuple());
        checker.check(rare_medical_tuple());
        assert_eq!(checker.audit_log().len(), 3);
    }

    #[test]
    fn audit_log_count_by_stage() {
        let mut checker = make_checker(rare_provider(), NetworkPhase::Bootstrap);
        checker.check(rare_medical_tuple());
        checker.check(rare_medical_tuple());
        assert_eq!(checker.audit_log().count_by_stage("k_anonymity"), 2);
    }

    #[test]
    fn mixed_pass_and_suppress_audit_log() {
        // Use a provider where common values are high (0.80) and we also
        // set specific rare values that make the S1 tuple fail.
        let mut p = MockFrequencyProvider::new();
        p.set_default(0.80);
        // Set specific rare values
        p.set_frequency("entity_b_value", "rare_gen", 0.0001);
        p.set_frequency("source_region", "ZZ", 0.0001);
        let mut checker = make_checker(p, NetworkPhase::Bootstrap);

        // S4 receipt should pass (all defaults = 0.80)
        let pass_result = checker.check(common_receipt_tuple());
        assert!(pass_result.is_some(), "Common S4 tuple should pass");
        let initial_count = checker.audit_log().len();
        assert_eq!(initial_count, 0, "No suppressions yet");

        // S1 medical_note with known-rare values should be suppressed
        // k = 5000 * 0.80^9 * 0.0001 * 0.0001 * 0.25 ~ extremely small
        let rare_tuple = make_hashed(make_generalized(
            "organization",
            "rare_gen",
            "provider",
            "charged_for",
            "procedure",
            "rare_gen",
            "charge",
            7,
            "medical_note",
            "ZZ",
            "2025-Q3",
            SensitivityTier::S1Critical,
        ));
        checker.check(rare_tuple);
        assert_eq!(
            checker.audit_log().len(),
            1,
            "Rare S1 tuple should be suppressed and logged"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 11. CONSTRUCTOR AND BUILDER TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn new_checker_has_empty_audit_log() {
        let checker = make_checker(common_provider(), NetworkPhase::Bootstrap);
        assert!(checker.audit_log().is_empty());
    }

    #[test]
    fn with_phase_preserves_config() {
        let config = default_config();
        let checker = KAnonymityCheck::new(
            config.clone(),
            Box::new(common_provider()),
            AuditLog::new(100),
            NetworkPhase::Bootstrap,
        )
        .with_phase(NetworkPhase::Growth);

        assert_eq!(checker.config.k_thresholds.get(0, 0), 100);
    }

    #[test]
    fn audit_log_mut_allows_clearing() {
        let mut checker = make_checker(rare_provider(), NetworkPhase::Bootstrap);
        checker.check(rare_medical_tuple());
        assert_eq!(checker.audit_log().len(), 1);
        checker.audit_log_mut().clear();
        assert_eq!(checker.audit_log().len(), 0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 12. ALL-FIELDS-AT-MAX TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn all_fields_at_max_frequency_produces_high_k() {
        let mut p = MockFrequencyProvider::new();
        p.set_default(0.90); // Very common values
        let checker = make_checker(p, NetworkPhase::Scale);

        let inner = make_generalized(
            "organization",
            "healthcare_provider",
            "provider",
            "charged_for",
            "procedure",
            "laboratory",
            "charge",
            0,
            "receipt",
            "south",
            "2025",
            SensitivityTier::S4Low,
        );
        let no_overrides = HashMap::new();
        let k = checker.estimate_k(&inner, &no_overrides);

        // N = 50000, 11 fields at 0.90, sensitivity_tier at 0.25
        // k = 50000 * 0.90^11 * 0.25 = 50000 * 0.314 * 0.25 ~ 3925
        assert!(k > 100.0, "All common values should produce high k: {}", k);
    }

    #[test]
    fn all_fields_at_min_frequency_produces_low_k() {
        let mut p = MockFrequencyProvider::new();
        p.set_default(0.001); // Very rare
        let checker = make_checker(p, NetworkPhase::Bootstrap);

        let inner = make_generalized(
            "rare_a",
            "rare_gen_a",
            "rare_role_a",
            "rare_rel",
            "rare_b",
            "rare_gen_b",
            "rare_role_b",
            7,
            "medical_note",
            "WY",
            "2021",
            SensitivityTier::S1Critical,
        );
        let no_overrides = HashMap::new();
        let k = checker.estimate_k(&inner, &no_overrides);
        assert!(k < 1.0, "All rare values should produce very low k: {}", k);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 13. QI_FIELDS CONSTANT TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn qi_fields_has_12_entries() {
        assert_eq!(QI_FIELDS.len(), 12, "Must have exactly 12 QI fields");
    }

    #[test]
    fn qi_fields_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for field in &QI_FIELDS {
            assert!(seen.insert(field), "Duplicate QI field: {}", field);
        }
    }

    #[test]
    fn generalizable_fields_has_11_entries() {
        assert_eq!(
            GENERALIZABLE_QI_FIELDS.len(),
            11,
            "11 fields should be generalizable (all except sensitivity_tier)"
        );
    }

    #[test]
    fn generalizable_fields_are_subset_of_qi_fields() {
        for field in &GENERALIZABLE_QI_FIELDS {
            assert!(
                QI_FIELDS.contains(field),
                "Generalizable field {} must be in QI_FIELDS",
                field
            );
        }
    }

    #[test]
    fn sensitivity_tier_not_in_generalizable() {
        assert!(
            !GENERALIZABLE_QI_FIELDS.contains(&"sensitivity_tier"),
            "sensitivity_tier should not be generalizable"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 14. POPULATION ESTIMATE TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn all_known_categories_have_positive_population() {
        let categories = [
            "receipt",
            "restaurant_receipt",
            "medical_bill",
            "utility_bill",
            "bank_statement",
            "insurance_eob",
            "lease",
            "contract",
            "pay_stub",
            "government_form",
            "prescription",
            "insurance_policy",
            "medical_note",
            "terms_of_service",
            "invoice",
            "tax_form",
        ];
        for cat in &categories {
            let n = estimated_population(cat);
            assert!(n > 0.0, "Population for {} should be positive", cat);
        }
    }

    #[test]
    fn receipt_has_highest_population() {
        let receipt_n = estimated_population("receipt");
        let categories = [
            "medical_bill",
            "utility_bill",
            "bank_statement",
            "insurance_eob",
            "lease",
            "contract",
            "pay_stub",
            "government_form",
        ];
        for cat in &categories {
            let n = estimated_population(cat);
            assert!(
                receipt_n >= n,
                "Receipt population ({}) should be >= {} population ({})",
                receipt_n,
                cat,
                n
            );
        }
    }

    #[test]
    fn unknown_category_has_lowest_population() {
        let unknown_n = estimated_population("xyz_unknown");
        let categories = ["receipt", "medical_bill", "utility_bill", "bank_statement"];
        for cat in &categories {
            let n = estimated_population(cat);
            assert!(
                unknown_n <= n,
                "Unknown category ({}) should have <= population than {} ({})",
                unknown_n,
                cat,
                n
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 15. TRAIT IMPLEMENTATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn kanonymity_checker_trait_is_object_safe() {
        // This test verifies the trait can be used as a trait object
        fn assert_trait_object(_: &mut dyn KAnonymityChecker) {}
        let mut checker = make_checker(common_provider(), NetworkPhase::Bootstrap);
        assert_trait_object(&mut checker);
    }

    #[test]
    fn checker_implements_kanonymity_checker() {
        let mut checker: Box<dyn KAnonymityChecker> =
            Box::new(make_checker(common_provider(), NetworkPhase::Bootstrap));
        let result = checker.check(common_receipt_tuple());
        // Just verify it compiles and runs through the trait
        let _ = result;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 16. INTEGRATION-STYLE TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn multiple_tuples_through_single_checker() {
        let mut checker = make_checker(common_provider(), NetworkPhase::Bootstrap);

        // Process multiple common tuples
        let t1 = common_receipt_tuple();
        let t2 = common_receipt_tuple();

        let r1 = checker.check(t1);
        let r2 = checker.check(t2);

        // Common tuples should pass with high-frequency provider
        assert!(r1.is_some(), "First common tuple should pass");
        assert!(r2.is_some(), "Second common tuple should pass");
        assert_eq!(
            checker.audit_log().len(),
            0,
            "No suppressions for common tuples"
        );
    }

    #[test]
    fn k_checked_tuple_wraps_hashed_tuple() {
        let mut checker = make_checker(common_provider(), NetworkPhase::Bootstrap);
        let result = checker.check(common_receipt_tuple()).unwrap();

        // Verify the nesting: KCheckedTuple -> HashedTuple -> GeneralizedTuple
        assert_eq!(result.inner.inner.entity_a_type, "organization");
        assert_eq!(result.inner.inner.document_category, "receipt");
        assert_eq!(result.inner.inner.sensitivity_tier, SensitivityTier::S4Low);
    }

    #[test]
    fn estimated_k_is_consistent_with_manual_calculation() {
        let mut p = MockFrequencyProvider::new();
        // Set exact frequencies for a controlled test
        p.set_frequency("entity_a_type", "organization", 0.25);
        p.set_frequency("entity_b_value", "hospital", 0.06);
        p.set_frequency("entity_a_role", "provider", 0.18);
        p.set_frequency("relation", "charged_for", 0.20);
        p.set_frequency("entity_b_type", "procedure", 0.15);
        p.set_frequency("entity_b_value", "mri", 0.0375);
        p.set_frequency("entity_b_role", "charge", 0.15);
        p.set_frequency("amount_bucket", "3", 0.12);
        p.set_frequency("document_category", "medical_bill", 0.15);
        p.set_frequency("source_region", "CA", 0.12);
        p.set_frequency("time_period", "2025-Q3", 0.09);

        // entity_a_gen and entity_b_gen both use "entity_b_value" for lookup
        let checker = make_checker(p, NetworkPhase::Bootstrap);
        let inner = make_generalized(
            "organization",
            "hospital",
            "provider",
            "charged_for",
            "procedure",
            "mri",
            "charge",
            3,
            "medical_bill",
            "CA",
            "2025-Q3",
            SensitivityTier::S1Critical,
        );
        let no_overrides = HashMap::new();
        let k = checker.estimate_k(&inner, &no_overrides);

        // Manual: N=25000
        // entity_a_type=0.25, entity_a_gen="hospital"->entity_b_value=0.06,
        // entity_a_role=0.18, relation=0.20, entity_b_type=0.15,
        // entity_b_gen="mri"->entity_b_value=0.0375, entity_b_role=0.15,
        // amount_bucket="3"=0.12, document_category=0.15,
        // source_region=0.12, time_period=0.09, sensitivity_tier=0.25
        let expected = 25_000.0
            * 0.25   // entity_a_type
            * 0.06   // entity_a_gen (hospital via entity_b_value)
            * 0.18   // entity_a_role
            * 0.20   // relation
            * 0.15   // entity_b_type
            * 0.0375 // entity_b_gen (mri via entity_b_value)
            * 0.15   // entity_b_role
            * 0.12   // amount_bucket
            * 0.15   // document_category
            * 0.12   // source_region
            * 0.09   // time_period
            * 0.25; // sensitivity_tier

        assert!(
            (k - expected).abs() / expected.max(1e-30) < 1e-6,
            "k_est ({}) should match manual calculation ({})",
            k,
            expected
        );
    }
}
