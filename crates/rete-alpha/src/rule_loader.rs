//! Rule Loader: loads seed rules into the Rete-II engine.
//!
//! Converts `SeedRule`s from `seed_rules.rs` into the engine's `Production`
//! type via `AlphaCondition` compilation and `Engine::add_production()`.
//!
//! The loader handles:
//! - Dictionary encoding of string values in seed conditions
//! - Amount bucket bitmask computation for gte/lte/range operators
//! - Document category u8 mapping via wme_factory
//! - Field-to-ConditionField mapping

use crate::alpha_network::{AlphaCondition, ConditionField};
use crate::engine::Engine;
use crate::production::RuleStatus;
use crate::seed_rules::{SeedCondition, SeedRule};
use crate::wme_factory::document_category_to_u8;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load all seed rules into the engine.
///
/// For each `SeedRule`, compiles it into `AlphaCondition`s using the engine's
/// dictionaries and registers it via `Engine::add_production()`.
///
/// Returns the number of rules successfully loaded.
pub fn load_seed_rules(engine: &mut Engine, rules: &[SeedRule]) -> usize {
    let mut loaded = 0;
    for rule in rules {
        let conditions = compile_seed_conditions(engine, &rule.conditions);
        if conditions.is_empty() {
            eprintln!(
                "[rule_loader] WARNING: Rule {} produced no valid conditions, skipping",
                rule.id
            );
            continue;
        }

        // Map seed confidence (f64) to engine confidence (f32)
        let confidence = rule.confidence as f32;

        // All seed rules start as Active since they come from vetted CMS/BLS data
        let status = RuleStatus::Active;

        engine.add_production(rule.id, &conditions, status, confidence);
        loaded += 1;
    }
    loaded
}

/// Convert a single `SeedRule` into a vector of `AlphaCondition`s
/// ready for `Engine::add_production()`.
///
/// This is the standalone conversion function that compiles seed conditions
/// using the engine's dictionaries. Useful for testing individual rule
/// compilation without loading into the engine.
pub fn seed_rule_to_conditions(engine: &mut Engine, rule: &SeedRule) -> Vec<AlphaCondition> {
    compile_seed_conditions(engine, &rule.conditions)
}

// ---------------------------------------------------------------------------
// Condition compilation internals
// ---------------------------------------------------------------------------

/// Compile a slice of `SeedCondition`s into `AlphaCondition`s.
///
/// Each seed condition is mapped to an engine `AlphaCondition` by:
/// 1. Parsing the `field` string into a `ConditionField` enum variant
/// 2. Encoding the `value` string into a `u16` via the appropriate dictionary
/// 3. For amount_bucket conditions, computing the bitmask from the operator
fn compile_seed_conditions(
    engine: &mut Engine,
    conditions: &[SeedCondition],
) -> Vec<AlphaCondition> {
    let mut compiled = Vec::with_capacity(conditions.len());

    for cond in conditions {
        if let Some(alpha_cond) = compile_one_condition(engine, cond) {
            compiled.push(alpha_cond);
        } else {
            eprintln!(
                "[rule_loader] WARNING: Could not compile condition field='{}' op='{}' value='{}'",
                cond.field, cond.operator, cond.value
            );
        }
    }

    compiled
}

/// Compile a single `SeedCondition` into an `AlphaCondition`.
///
/// Returns `None` if the field name is unrecognized.
fn compile_one_condition(engine: &mut Engine, cond: &SeedCondition) -> Option<AlphaCondition> {
    let field = parse_condition_field(&cond.field)?;

    let value_id = match field {
        // Amount bucket: compute bitmask from operator + value
        ConditionField::AmountBucket => {
            compute_bucket_mask(&cond.operator, &cond.value, cond.value_upper.as_deref())?
        }
        // Document category: use fixed u8 mapping, cast to u16
        ConditionField::DocumentCategory => document_category_to_u8(&cond.value) as u16,
        // All other fields: dictionary-encode the value string
        ConditionField::EntityAType => engine.entity_type_dict.get_or_insert(&cond.value),
        ConditionField::EntityARole => engine.entity_role_dict.get_or_insert(&cond.value),
        ConditionField::EntityAGen => engine.entity_gen_dict.get_or_insert(&cond.value),
        ConditionField::Relation => engine.relation_dict.get_or_insert(&cond.value),
        ConditionField::EntityBType => engine.entity_type_dict.get_or_insert(&cond.value),
        ConditionField::EntityBRole => engine.entity_role_dict.get_or_insert(&cond.value),
        ConditionField::EntityBGen => engine.entity_gen_dict.get_or_insert(&cond.value),
    };

    Some(AlphaCondition { field, value_id })
}

/// Parse a field name string into a `ConditionField` enum.
///
/// Returns `None` for unrecognized field names.
fn parse_condition_field(field: &str) -> Option<ConditionField> {
    match field {
        "entity_a_type" => Some(ConditionField::EntityAType),
        "entity_a_role" => Some(ConditionField::EntityARole),
        "entity_a_gen" => Some(ConditionField::EntityAGen),
        "relation" => Some(ConditionField::Relation),
        "entity_b_type" => Some(ConditionField::EntityBType),
        "entity_b_role" => Some(ConditionField::EntityBRole),
        "entity_b_gen" => Some(ConditionField::EntityBGen),
        "doc_category" => Some(ConditionField::DocumentCategory),
        "amount_bucket" => Some(ConditionField::AmountBucket),
        _ => None,
    }
}

/// Compute an amount bucket bitmask from an operator and value(s).
///
/// The engine's AmountBucketIndex uses an 8-bit bitmask where bit N = 1
/// means "matches bucket N". This function converts human-readable operators
/// into that bitmask format.
///
/// - "eq" with value "3" -> only bit 3 set -> 0b00001000
/// - "gte" with value "5" -> bits 5,6,7 set -> 0b11100000
/// - "lte" with value "2" -> bits 0,1,2 set -> 0b00000111
/// - "range" with value "3", upper "5" -> bits 3,4,5 -> 0b00111000
///
/// Returns the bitmask as u16 (only low byte used), or None on parse error.
fn compute_bucket_mask(operator: &str, value: &str, value_upper: Option<&str>) -> Option<u16> {
    let low: u8 = value.parse().ok()?;
    if low > 7 {
        return None;
    }

    let mask: u8 = match operator {
        "eq" => 1u8 << low,
        "gte" => {
            // Set bits low through 7
            let mut m = 0u8;
            for b in low..=7 {
                m |= 1u8 << b;
            }
            m
        }
        "lte" => {
            // Set bits 0 through low
            let mut m = 0u8;
            for b in 0..=low {
                m |= 1u8 << b;
            }
            m
        }
        "range" => {
            let high: u8 = value_upper?.parse().ok()?;
            if high > 7 || high < low {
                return None;
            }
            let mut m = 0u8;
            for b in low..=high {
                m |= 1u8 << b;
            }
            m
        }
        _ => return None,
    };

    Some(mask as u16)
}

// ---------------------------------------------------------------------------
// Summary / introspection helpers
// ---------------------------------------------------------------------------

/// Returns a summary of loaded rule counts by category.
///
/// Useful for logging at startup to verify all rule categories are represented.
pub fn summarize_seed_rules(rules: &[SeedRule]) -> String {
    let mut medical = 0u32;
    let mut lease = 0u32;
    let mut insurance = 0u32;
    let mut utility = 0u32;
    let mut retail = 0u32;
    let mut other = 0u32;

    for rule in rules {
        let cat = rule
            .conditions
            .iter()
            .find(|c| c.field == "doc_category")
            .map(|c| c.value.as_str());

        match cat {
            Some("medical_bill") => medical += 1,
            Some("legal") => lease += 1,
            Some("financial") => insurance += 1,
            Some("general") => utility += 1,
            Some("retail") => retail += 1,
            _ => other += 1,
        }
    }

    format!(
        "Seed rules: {} total (medical={}, lease={}, insurance={}, utility={}, retail={}, other={})",
        rules.len(),
        medical,
        lease,
        insurance,
        utility,
        retail,
        other
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use crate::seed_rules::get_seed_rules;
    use crate::wme::Wme;

    // -----------------------------------------------------------------------
    // Bitmask computation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bucket_mask_eq() {
        assert_eq!(compute_bucket_mask("eq", "0", None), Some(0b00000001));
        assert_eq!(compute_bucket_mask("eq", "3", None), Some(0b00001000));
        assert_eq!(compute_bucket_mask("eq", "7", None), Some(0b10000000));
    }

    #[test]
    fn test_bucket_mask_gte() {
        // gte 5 -> bits 5,6,7
        assert_eq!(compute_bucket_mask("gte", "5", None), Some(0b11100000));
        // gte 0 -> all bits
        assert_eq!(compute_bucket_mask("gte", "0", None), Some(0b11111111));
        // gte 7 -> only bit 7
        assert_eq!(compute_bucket_mask("gte", "7", None), Some(0b10000000));
    }

    #[test]
    fn test_bucket_mask_lte() {
        // lte 2 -> bits 0,1,2
        assert_eq!(compute_bucket_mask("lte", "2", None), Some(0b00000111));
        // lte 0 -> only bit 0
        assert_eq!(compute_bucket_mask("lte", "0", None), Some(0b00000001));
        // lte 7 -> all bits
        assert_eq!(compute_bucket_mask("lte", "7", None), Some(0b11111111));
    }

    #[test]
    fn test_bucket_mask_range() {
        // range 3-5 -> bits 3,4,5
        assert_eq!(
            compute_bucket_mask("range", "3", Some("5")),
            Some(0b00111000)
        );
        // range 0-0 -> just bit 0 (same as eq 0)
        assert_eq!(
            compute_bucket_mask("range", "0", Some("0")),
            Some(0b00000001)
        );
        // range 4-5 -> bits 4,5
        assert_eq!(
            compute_bucket_mask("range", "4", Some("5")),
            Some(0b00110000)
        );
    }

    #[test]
    fn test_bucket_mask_invalid() {
        assert_eq!(compute_bucket_mask("eq", "8", None), None); // bucket > 7
        assert_eq!(compute_bucket_mask("eq", "abc", None), None); // non-numeric
        assert_eq!(compute_bucket_mask("range", "5", Some("3")), None); // high < low
        assert_eq!(compute_bucket_mask("range", "3", None), None); // range without upper
        assert_eq!(compute_bucket_mask("bad_op", "3", None), None);
    }

    // -----------------------------------------------------------------------
    // Field parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_condition_field_valid() {
        assert_eq!(
            parse_condition_field("entity_a_type"),
            Some(ConditionField::EntityAType)
        );
        assert_eq!(
            parse_condition_field("entity_a_role"),
            Some(ConditionField::EntityARole)
        );
        assert_eq!(
            parse_condition_field("entity_a_gen"),
            Some(ConditionField::EntityAGen)
        );
        assert_eq!(
            parse_condition_field("relation"),
            Some(ConditionField::Relation)
        );
        assert_eq!(
            parse_condition_field("entity_b_type"),
            Some(ConditionField::EntityBType)
        );
        assert_eq!(
            parse_condition_field("entity_b_role"),
            Some(ConditionField::EntityBRole)
        );
        assert_eq!(
            parse_condition_field("entity_b_gen"),
            Some(ConditionField::EntityBGen)
        );
        assert_eq!(
            parse_condition_field("doc_category"),
            Some(ConditionField::DocumentCategory)
        );
        assert_eq!(
            parse_condition_field("amount_bucket"),
            Some(ConditionField::AmountBucket)
        );
    }

    #[test]
    fn test_parse_condition_field_invalid() {
        assert_eq!(parse_condition_field("unknown_field"), None);
        assert_eq!(parse_condition_field(""), None);
        assert_eq!(parse_condition_field("entity_c_type"), None);
    }

    // -----------------------------------------------------------------------
    // Full loading tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_all_seed_rules() {
        let mut engine = Engine::new();
        let rules = get_seed_rules();
        let loaded = load_seed_rules(&mut engine, &rules);

        assert_eq!(loaded, 40, "All 40 seed rules should load");
        assert_eq!(engine.production_count(), 40);
    }

    #[test]
    fn test_load_empty_rules() {
        let mut engine = Engine::new();
        let loaded = load_seed_rules(&mut engine, &[]);
        assert_eq!(loaded, 0);
        assert_eq!(engine.production_count(), 0);
    }

    #[test]
    fn test_seed_rule_to_conditions_basic() {
        let mut engine = Engine::new();
        let rule = crate::seed_rules::get_seed_rule_by_id(1).unwrap();
        let conditions = seed_rule_to_conditions(&mut engine, &rule);

        // Rule 1 has 6 conditions
        assert_eq!(conditions.len(), 6, "Rule 1 should have 6 conditions");

        // Verify the first condition is EntityAType with value "organization"
        assert_eq!(conditions[0].field, ConditionField::EntityAType);
        let org_str = engine.entity_type_dict.get_str(conditions[0].value_id);
        assert_eq!(org_str, Some("organization"));
    }

    // -----------------------------------------------------------------------
    // Rule firing tests: verify rules fire on matching WMEs
    // -----------------------------------------------------------------------

    #[test]
    fn test_medical_rule_fires_on_matching_wme() {
        let mut engine = Engine::new();
        let rules = get_seed_rules();
        load_seed_rules(&mut engine, &rules);

        // Construct a WME matching Rule 1: ER visit above range
        // Rule 1 conditions:
        //   entity_a_type = "organization"
        //   entity_a_gen = "healthcare_provider"
        //   relation = "billed_total"
        //   entity_b_type = "amount"
        //   doc_category = "medical_bill" (u8 = 0)
        //   amount_bucket >= 6
        let ea_type = engine.entity_type_dict.get_or_insert("organization");
        let ea_gen = engine.entity_gen_dict.get_or_insert("healthcare_provider");
        let rel = engine.relation_dict.get_or_insert("billed_total");
        let eb_type = engine.entity_type_dict.get_or_insert("amount");

        let wme = Wme::new(
            ea_type, // entity_a_type
            0,       // entity_a_role (any)
            ea_gen,  // entity_a_gen
            rel,     // relation
            eb_type, // entity_b_type
            0,       // entity_b_role (any)
            0,       // entity_b_gen (any)
            6,       // amount_bucket = 6 ($5K-$50K)
            0,       // doc_category = medical_bill
            0.90,    // extraction_cf
        );

        let fired = engine.insert_wme(wme);
        assert!(
            !fired.is_empty(),
            "At least one rule should fire for ER visit above range WME"
        );

        // Rule 1 should be among the fired rules
        let rule1_fired = fired.iter().any(|f| f.rule_id == 1);
        assert!(rule1_fired, "Rule 1 (ER above range) should fire");
    }

    #[test]
    fn test_medical_rule_does_not_fire_on_wrong_category() {
        let mut engine = Engine::new();
        let rules = get_seed_rules();
        load_seed_rules(&mut engine, &rules);

        // Construct a WME with retail category -- medical rules should not fire
        let ea_type = engine.entity_type_dict.get_or_insert("organization");
        let ea_gen = engine.entity_gen_dict.get_or_insert("healthcare_provider");
        let rel = engine.relation_dict.get_or_insert("billed_total");
        let eb_type = engine.entity_type_dict.get_or_insert("amount");

        let wme = Wme::new(
            ea_type, 0, ea_gen, rel, eb_type, 0, 0, 6, // amount_bucket
            8, // doc_category = retail (NOT medical_bill)
            0.90,
        );

        let fired = engine.insert_wme(wme);
        let medical_fired = fired.iter().any(|f| f.rule_id <= 15);
        assert!(
            !medical_fired,
            "No medical rules (1-15) should fire on retail doc_category"
        );
    }

    #[test]
    fn test_lease_rule_fires() {
        let mut engine = Engine::new();
        let rules = get_seed_rules();
        load_seed_rules(&mut engine, &rules);

        // Rule 16: rent above range (charges_rent, legal, amount >= bucket 6)
        let ea_type = engine.entity_type_dict.get_or_insert("organization");
        let rel = engine.relation_dict.get_or_insert("charges_rent");
        let eb_type = engine.entity_type_dict.get_or_insert("amount");

        let wme = Wme::new(
            ea_type, 0, 0, rel, eb_type, 0, 0, 6, // amount_bucket = 6 ($5K-$50K)
            3, // doc_category = legal
            0.85,
        );

        let fired = engine.insert_wme(wme);
        let rule16_fired = fired.iter().any(|f| f.rule_id == 16);
        assert!(rule16_fired, "Rule 16 (rent above range) should fire");
    }

    #[test]
    fn test_insurance_rule_fires() {
        let mut engine = Engine::new();
        let rules = get_seed_rules();
        load_seed_rules(&mut engine, &rules);

        // Rule 24: health insurance premium typical range
        // entity_a_type=organization, entity_a_gen=insurance,
        // relation=charges_premium, entity_b_type=amount,
        // doc_category=financial (4), amount_bucket range 4-5
        let ea_type = engine.entity_type_dict.get_or_insert("organization");
        let ea_gen = engine.entity_gen_dict.get_or_insert("insurance");
        let rel = engine.relation_dict.get_or_insert("charges_premium");
        let eb_type = engine.entity_type_dict.get_or_insert("amount");

        let wme = Wme::new(
            ea_type, 0, ea_gen, rel, eb_type, 0, 0, 5, // amount_bucket = 5 ($1K-$5K)
            4, // doc_category = financial
            0.88,
        );

        let fired = engine.insert_wme(wme);
        let rule24_fired = fired.iter().any(|f| f.rule_id == 24);
        assert!(
            rule24_fired,
            "Rule 24 (insurance premium typical) should fire"
        );
    }

    #[test]
    fn test_retail_rule_fires() {
        let mut engine = Engine::new();
        let rules = get_seed_rules();
        load_seed_rules(&mut engine, &rules);

        // Rule 37: retail purchase typical range
        // entity_a_type=organization, entity_a_gen=retail,
        // relation=charged_total, entity_b_type=amount,
        // doc_category=retail (8), amount_bucket range 1-3
        let ea_type = engine.entity_type_dict.get_or_insert("organization");
        let ea_gen = engine.entity_gen_dict.get_or_insert("retail");
        let rel = engine.relation_dict.get_or_insert("charged_total");
        let eb_type = engine.entity_type_dict.get_or_insert("amount");

        let wme = Wme::new(
            ea_type, 0, ea_gen, rel, eb_type, 0, 0, 2, // amount_bucket = 2 ($50-$100)
            8, // doc_category = retail
            0.80,
        );

        let fired = engine.insert_wme(wme);
        let rule37_fired = fired.iter().any(|f| f.rule_id == 37);
        assert!(rule37_fired, "Rule 37 (retail typical range) should fire");
    }

    #[test]
    fn test_utility_rule_fires() {
        let mut engine = Engine::new();
        let rules = get_seed_rules();
        load_seed_rules(&mut engine, &rules);

        // Rule 32: utility bill typical range
        // entity_a_type=organization, relation=billed_total,
        // entity_b_type=amount, doc_category=general (6), bucket 2-3
        let ea_type = engine.entity_type_dict.get_or_insert("organization");
        let rel = engine.relation_dict.get_or_insert("billed_total");
        let eb_type = engine.entity_type_dict.get_or_insert("amount");

        let wme = Wme::new(
            ea_type, 0, 0, rel, eb_type, 0, 0, 3, // amount_bucket = 3 ($100-$500)
            6, // doc_category = general
            0.85,
        );

        let fired = engine.insert_wme(wme);
        let rule32_fired = fired.iter().any(|f| f.rule_id == 32);
        assert!(rule32_fired, "Rule 32 (utility typical range) should fire");
    }

    #[test]
    fn test_no_false_positives_wrong_relation() {
        let mut engine = Engine::new();
        let rules = get_seed_rules();
        load_seed_rules(&mut engine, &rules);

        // WME with a relation that no rule uses
        let ea_type = engine.entity_type_dict.get_or_insert("organization");
        let rel = engine.relation_dict.get_or_insert("unknown_relation_xyz");
        let eb_type = engine.entity_type_dict.get_or_insert("amount");

        let wme = Wme::new(
            ea_type, 0, 0, rel, eb_type, 0, 0, 5, // amount_bucket
            0, // medical_bill doc_category
            0.90,
        );

        let fired = engine.insert_wme(wme);
        // Some rules may still fire if they don't require a specific relation
        // but rules that require specific relations should NOT fire
        let specific_relation_rules: Vec<u32> = fired
            .iter()
            .filter(|f| [1, 2, 8, 16, 17, 18, 19, 20, 21, 22, 24, 37, 38].contains(&f.rule_id))
            .map(|f| f.rule_id)
            .collect();
        assert!(
            specific_relation_rules.is_empty(),
            "Rules with specific relation conditions should not fire with unknown_relation: {:?}",
            specific_relation_rules
        );
    }

    #[test]
    fn test_no_false_positives_wrong_amount_bucket() {
        let mut engine = Engine::new();
        let rules = get_seed_rules();
        load_seed_rules(&mut engine, &rules);

        // Rule 1 requires amount_bucket >= 6
        // Send a WME with bucket 3 -- Rule 1 should NOT fire
        let ea_type = engine.entity_type_dict.get_or_insert("organization");
        let ea_gen = engine.entity_gen_dict.get_or_insert("healthcare_provider");
        let rel = engine.relation_dict.get_or_insert("billed_total");
        let eb_type = engine.entity_type_dict.get_or_insert("amount");

        let wme = Wme::new(
            ea_type, 0, ea_gen, rel, eb_type, 0, 0, 3, // amount_bucket = 3 (NOT >= 6)
            0, // medical_bill
            0.90,
        );

        let fired = engine.insert_wme(wme);
        let rule1_fired = fired.iter().any(|f| f.rule_id == 1);
        assert!(
            !rule1_fired,
            "Rule 1 (ER above range, bucket >= 6) should NOT fire for bucket 3"
        );
    }

    #[test]
    fn test_chained_cf_calculation() {
        let mut engine = Engine::new();
        let rules = get_seed_rules();
        load_seed_rules(&mut engine, &rules);

        let ea_type = engine.entity_type_dict.get_or_insert("organization");
        let ea_gen = engine.entity_gen_dict.get_or_insert("healthcare_provider");
        let rel = engine.relation_dict.get_or_insert("billed_total");
        let eb_type = engine.entity_type_dict.get_or_insert("amount");

        let extraction_cf = 0.90_f32;
        let wme = Wme::new(
            ea_type,
            0,
            ea_gen,
            rel,
            eb_type,
            0,
            0,
            6, // triggers Rule 1 (conf=0.87) and Rule 4 (conf=0.90)
            0, // medical_bill
            extraction_cf,
        );

        let fired = engine.insert_wme(wme);
        for fp in &fired {
            // Chained CF = rule confidence * extraction CF
            let expected = fp.confidence * extraction_cf;
            assert!(
                (fp.chained_cf - expected).abs() < 0.001,
                "Rule {} chained_cf: expected {}, got {}",
                fp.rule_id,
                expected,
                fp.chained_cf
            );
        }
    }

    #[test]
    fn test_multiple_rules_can_fire_on_same_wme() {
        let mut engine = Engine::new();
        let rules = get_seed_rules();
        load_seed_rules(&mut engine, &rules);

        // A medical bill from a healthcare_provider with large amount should
        // trigger multiple overlapping rules (1, 4, 12, 13, etc.)
        let ea_type = engine.entity_type_dict.get_or_insert("organization");
        let ea_gen = engine.entity_gen_dict.get_or_insert("healthcare_provider");
        let rel = engine.relation_dict.get_or_insert("billed_total");
        let eb_type = engine.entity_type_dict.get_or_insert("amount");
        let eb_gen = engine.entity_gen_dict.get_or_insert("very_large");

        let wme = Wme::new(
            ea_type, 0, ea_gen, rel, eb_type, 0, eb_gen, 6, // $5K-$50K
            0, // medical_bill
            0.90,
        );

        let fired = engine.insert_wme(wme);
        assert!(
            fired.len() >= 2,
            "Expected multiple rules to fire on a high-value medical bill, got {}",
            fired.len()
        );
    }

    // -----------------------------------------------------------------------
    // Summary tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_summarize_seed_rules() {
        let rules = get_seed_rules();
        let summary = summarize_seed_rules(&rules);
        assert!(summary.contains("40 total"));
        assert!(summary.contains("medical="));
        assert!(summary.contains("lease="));
        assert!(summary.contains("insurance="));
        assert!(summary.contains("utility="));
        assert!(summary.contains("retail="));
    }

    // -----------------------------------------------------------------------
    // JTMS integration test
    // -----------------------------------------------------------------------

    #[test]
    fn test_seed_rules_with_jtms() {
        use crate::jtms::BeliefState;

        let mut engine = Engine::new();
        let rules = get_seed_rules();
        load_seed_rules(&mut engine, &rules);

        let ea_type = engine.entity_type_dict.get_or_insert("organization");
        let ea_gen = engine.entity_gen_dict.get_or_insert("healthcare_provider");
        let rel = engine.relation_dict.get_or_insert("billed_total");
        let eb_type = engine.entity_type_dict.get_or_insert("amount");

        let wme = Wme::new(ea_type, 0, ea_gen, rel, eb_type, 0, 0, 6, 0, 0.90);

        let (wme_key, fired, conclusion_ids) = engine.insert_wme_with_jtms(wme, false);
        assert!(!fired.is_empty(), "Rules should fire");
        assert!(
            !conclusion_ids.is_empty(),
            "JTMS conclusions should be created"
        );

        // All conclusions should be IN
        for cid in &conclusion_ids {
            assert_eq!(engine.jtms.belief_state(*cid), Some(BeliefState::In));
        }

        // Retract the WME -> conclusions go OUT
        let retracted = engine.retract_wme(wme_key);
        assert!(!retracted.is_empty());
        for cid in &retracted {
            assert_eq!(engine.jtms.belief_state(*cid), Some(BeliefState::Out));
        }
    }
}
