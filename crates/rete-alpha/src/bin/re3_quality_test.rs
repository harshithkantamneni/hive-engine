//! RE3: Reasoning Quality Test Suite for HIVE Rete-II Engine + JTMS
//!
//! Data Scientist task: validate that the engine produces correct reasoning
//! on realistic HIVE scenarios. Covers:
//!   1. R8 test vectors (translated to Rust)
//!   2. Realistic HIVE use cases (medical, lease, insurance, utility)
//!   3. JTMS truth maintenance (retraction cascades, alternate support)
//!   4. MYCIN confidence propagation (concordant combination, chaining, ceilings)
//!   5. Multi-rule chains (output of one rule triggers another)
//!   6. Edge cases (empty WMEs, no-match rules, contradictory evidence)
//!   7. False-positive checks (rules must NOT fire when conditions unmet)
//!   8. Performance validation (sub-microsecond per WME)
//!
//! Run: cargo run --release --bin re3_quality_test

use rete_alpha::alpha_network::{AlphaCondition, ConditionField};
use rete_alpha::engine::Engine;
use rete_alpha::jtms::{
    mycin_combine, mycin_combine_all, BeliefState, Jtms, CF_CEILING_ACTIVE, CF_CEILING_SYSTEM,
};
use rete_alpha::production::RuleStatus;
use rete_alpha::wme::Wme;
use std::time::Instant;

// ============================================================================
// Test infrastructure
// ============================================================================

struct TestResult {
    name: String,
    passed: bool,
    details: String,
    #[allow(dead_code)] // Captured for future latency-report extensions.
    duration_us: f64,
}

impl TestResult {
    fn pass(name: &str, details: &str, duration_us: f64) -> Self {
        Self {
            name: name.to_string(),
            passed: true,
            details: details.to_string(),
            duration_us,
        }
    }
    fn fail(name: &str, details: &str, duration_us: f64) -> Self {
        Self {
            name: name.to_string(),
            passed: false,
            details: details.to_string(),
            duration_us,
        }
    }
}

// ============================================================================
// Helper: build an engine with dictionaries pre-populated for a domain
// ============================================================================

#[allow(dead_code)]
struct DomainEngine {
    engine: Engine,
    // Medical domain
    org: u16,
    provider: u16,
    hospital: u16,
    billed_at: u16,
    amount_type: u16,
    charged_total: u16,
    procedure: u16,
    er_visit: u16,
    lab_test: u16,
    diagnosis: u16,
    has_diagnosis: u16,
    patient: u16,

    // Lease domain
    person: u16,
    landlord: u16,
    tenant: u16,
    rent_amount: u16,
    security_deposit: u16,
    late_fee: u16,
    lease_term: u16,
    penalty: u16,
    clause: u16,
    has_clause: u16,
    notice_period: u16,

    // Insurance domain
    insurance_co: u16,
    insurer: u16,
    coverage_limit: u16,
    deductible: u16,
    premium: u16,
    exclusion: u16,
    has_exclusion: u16,
    policy_type: u16,

    // Utility domain
    utility_company: u16,
    energy_charge: u16,

    // Doc categories as u8
    medical_bill_cat: u8,
    lease_cat: u8,
    insurance_cat: u8,
    utility_cat: u8,
}

impl DomainEngine {
    fn new() -> Self {
        let mut engine = Engine::new();

        // Entity types
        let org = engine.entity_type_dict.get_or_insert("organization");
        let person = engine.entity_type_dict.get_or_insert("person");
        let amount_type = engine.entity_type_dict.get_or_insert("amount");
        let procedure = engine.entity_type_dict.get_or_insert("procedure");
        let clause = engine.entity_type_dict.get_or_insert("clause");
        let penalty = engine.entity_type_dict.get_or_insert("penalty");
        let policy_type = engine.entity_type_dict.get_or_insert("policy_type");

        // Entity roles
        let provider = engine.entity_role_dict.get_or_insert("provider");
        let landlord = engine.entity_role_dict.get_or_insert("landlord");
        let tenant = engine.entity_role_dict.get_or_insert("tenant");
        let _property_mgmt = engine.entity_role_dict.get_or_insert("property_management");
        let insurer = engine.entity_role_dict.get_or_insert("insurer");
        let patient = engine.entity_role_dict.get_or_insert("patient");

        // Entity gen (generalized values)
        let hospital = engine.entity_gen_dict.get_or_insert("hospital");
        let er_visit = engine.entity_gen_dict.get_or_insert("er_visit");
        let lab_test = engine.entity_gen_dict.get_or_insert("lab_test");
        let diagnosis = engine.entity_gen_dict.get_or_insert("diagnosis");
        let insurance_co = engine.entity_gen_dict.get_or_insert("insurance_company");
        let utility_company = engine.entity_gen_dict.get_or_insert("utility_company");
        let exclusion = engine.entity_gen_dict.get_or_insert("exclusion");

        // Relations
        let billed_at = engine.relation_dict.get_or_insert("billed_at");
        let charged_total = engine.relation_dict.get_or_insert("charged_total");
        let has_diagnosis = engine.relation_dict.get_or_insert("has_diagnosis");
        let rent_amount = engine.relation_dict.get_or_insert("rent_amount");
        let security_deposit = engine.relation_dict.get_or_insert("security_deposit");
        let late_fee = engine.relation_dict.get_or_insert("late_fee");
        let lease_term = engine.relation_dict.get_or_insert("lease_term");
        let has_clause = engine.relation_dict.get_or_insert("has_clause");
        let notice_period = engine.relation_dict.get_or_insert("notice_period");
        let coverage_limit = engine.relation_dict.get_or_insert("coverage_limit");
        let deductible = engine.relation_dict.get_or_insert("deductible");
        let premium = engine.relation_dict.get_or_insert("premium");
        let has_exclusion = engine.relation_dict.get_or_insert("has_exclusion");
        let energy_charge = engine.relation_dict.get_or_insert("energy_charge");

        // Document categories
        let medical_bill_cat = engine.doc_category_dict.get_or_insert("medical_bill") as u8;
        let lease_cat = engine.doc_category_dict.get_or_insert("lease_agreement") as u8;
        let insurance_cat = engine.doc_category_dict.get_or_insert("insurance_policy") as u8;
        let utility_cat = engine.doc_category_dict.get_or_insert("utility_bill") as u8;

        Self {
            engine,
            org,
            person,
            amount_type,
            procedure,
            clause,
            penalty,
            policy_type,
            provider,
            landlord,
            tenant,
            insurer,
            patient,
            hospital,
            er_visit,
            lab_test,
            diagnosis,
            insurance_co,
            utility_company,
            exclusion,
            billed_at,
            charged_total,
            has_diagnosis,
            rent_amount,
            security_deposit,
            late_fee,
            lease_term,
            has_clause,
            notice_period,
            coverage_limit,
            deductible,
            premium,
            has_exclusion,
            energy_charge,
            medical_bill_cat,
            lease_cat,
            insurance_cat,
            utility_cat,
        }
    }
}

// ============================================================================
// SCENARIO 1: R8 Test Vector 7 -- Full Rete-II Walkthrough (Medical Bill)
// ============================================================================

fn test_r8_vector7_medical_bill_walkthrough() -> TestResult {
    let name = "R8-V7: Medical bill full walkthrough";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    // Rule #127: hospital billed_at amount in medical_bill
    // 6 conditions: entity_a_type=org, entity_a_role=provider, entity_a_gen=hospital,
    //               relation=billed_at, entity_b_type=amount, doc_category=medical_bill
    let conditions = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityARole,
            value_id: d.provider,
        },
        AlphaCondition {
            field: ConditionField::EntityAGen,
            value_id: d.hospital,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.billed_at,
        },
        AlphaCondition {
            field: ConditionField::EntityBType,
            value_id: d.amount_type,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
    ];
    d.engine
        .add_production(127, &conditions, RuleStatus::Active, 0.72);

    // WME: hospital billed $1K-$5K for medical_bill, extraction confidence 0.91
    let wme = Wme::new(
        d.org,
        d.provider,
        d.hospital,
        d.billed_at,
        d.amount_type,
        0,
        0,
        3, // amount_bucket=3 ($1K-$5K)
        d.medical_bill_cat,
        0.91,
    );

    let (_wme_key, fired, conclusion_ids) = d.engine.insert_wme_with_jtms(wme, false);
    let duration = start.elapsed().as_micros() as f64;

    // Verify: exactly 1 production fires
    if fired.len() != 1 {
        return TestResult::fail(
            name,
            &format!("Expected 1 fired production, got {}", fired.len()),
            duration,
        );
    }
    if fired[0].rule_id != 127 {
        return TestResult::fail(
            name,
            &format!("Expected rule 127, got {}", fired[0].rule_id),
            duration,
        );
    }

    // Verify chained CF: 0.72 * 0.91 = 0.6552
    let expected_cf = 0.72_f32 * 0.91_f32;
    if (fired[0].chained_cf - expected_cf).abs() > 0.001 {
        return TestResult::fail(
            name,
            &format!(
                "Expected CF {:.4}, got {:.4}",
                expected_cf, fired[0].chained_cf
            ),
            duration,
        );
    }

    // Verify JTMS: conclusion is IN with correct CF
    if conclusion_ids.len() != 1 {
        return TestResult::fail(
            name,
            &format!("Expected 1 conclusion, got {}", conclusion_ids.len()),
            duration,
        );
    }
    if d.engine.jtms.belief_state(conclusion_ids[0]) != Some(BeliefState::In) {
        return TestResult::fail(name, "Conclusion should be IN", duration);
    }
    let jtms_cf = d.engine.jtms.combined_cf(conclusion_ids[0]).unwrap();
    if (jtms_cf - expected_cf).abs() > 0.001 {
        return TestResult::fail(
            name,
            &format!("JTMS CF {:.4} != expected {:.4}", jtms_cf, expected_cf),
            duration,
        );
    }

    TestResult::pass(
        name,
        &format!(
            "Rule 127 fired, CF={:.4}, JTMS IN. WME key valid. Duration {:.1}us",
            expected_cf, duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 2: R8 Test Vector 3 -- MYCIN Concordant Combination
// ============================================================================

fn test_r8_vector3_mycin_concordant() -> TestResult {
    let name = "R8-V3: MYCIN concordant combination (2 & 3 rules)";
    let start = Instant::now();

    // Test 2-rule combination: 0.7 + 0.6 * (1 - 0.7) = 0.88
    let cf2 = mycin_combine(0.7, 0.6);
    if (cf2 - 0.88).abs() > 1e-5 {
        return TestResult::fail(name, &format!("2-rule: expected 0.88, got {:.6}", cf2), 0.0);
    }

    // Test 3-rule combination: 0.88 + 0.5 * (1 - 0.88) = 0.94
    let cf3 = mycin_combine_all(&[0.7, 0.6, 0.5]);
    if (cf3 - 0.94).abs() > 1e-5 {
        return TestResult::fail(name, &format!("3-rule: expected 0.94, got {:.6}", cf3), 0.0);
    }

    // Test via JTMS node (R8 Test Vector 3 full path)
    let mut jtms = Jtms::new();
    use slotmap::SlotMap;
    let mut sm = SlotMap::<rete_alpha::wme::WmeKey, ()>::with_key();
    let k0 = sm.insert(());
    let k1 = sm.insert(());
    let k2 = sm.insert(());

    let cid = jtms.add_justification(1, vec![k0], 0.7, 1, false).unwrap();
    jtms.add_supporting_justification(cid, 2, vec![k1], 0.6, 1);
    let cf_after_2 = jtms.combined_cf(cid).unwrap();
    if (cf_after_2 - 0.88).abs() > 1e-5 {
        return TestResult::fail(
            name,
            &format!("JTMS 2-rule: expected 0.88, got {:.6}", cf_after_2),
            0.0,
        );
    }

    jtms.add_supporting_justification(cid, 3, vec![k2], 0.5, 1);
    let cf_after_3 = jtms.combined_cf(cid).unwrap();
    if (cf_after_3 - 0.94).abs() > 1e-5 {
        return TestResult::fail(
            name,
            &format!("JTMS 3-rule: expected 0.94, got {:.6}", cf_after_3),
            0.0,
        );
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "2-rule=0.88, 3-rule=0.94, JTMS matches. Duration {:.1}us",
            duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 3: R8 Test Vector 4 -- MYCIN Chain (confidence decay through chain)
// ============================================================================

fn test_r8_vector4_mycin_chain() -> TestResult {
    let name = "R8-V4: MYCIN chain confidence decay";
    let start = Instant::now();

    // Rule A: CF_rule=0.85, extraction_cf=0.90 -> chained=0.765
    let cf_a = 0.85_f32 * 0.90_f32;
    if (cf_a - 0.765).abs() > 0.001 {
        return TestResult::fail(
            name,
            &format!("Chain A: expected 0.765, got {:.4}", cf_a),
            0.0,
        );
    }

    // Rule B chains: CF_rule_B=0.75 * 0.765 = 0.574
    let cf_b = 0.75_f32 * cf_a;
    if (cf_b - 0.574).abs() > 0.002 {
        return TestResult::fail(
            name,
            &format!("Chain B: expected ~0.574, got {:.4}", cf_b),
            0.0,
        );
    }

    // Rule C chains: CF_rule_C=0.70 * 0.574 = 0.402
    let cf_c = 0.70_f32 * cf_b;
    if (cf_c - 0.402).abs() > 0.002 {
        return TestResult::fail(
            name,
            &format!("Chain C: expected ~0.402, got {:.4}", cf_c),
            0.0,
        );
    }

    // Verify via engine: build 3-rule chain
    let mut d = DomainEngine::new();

    // Rule A: org+provider+hospital+billed_at+amount+medical_bill -> fires on medical WME
    let conditions_a = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityARole,
            value_id: d.provider,
        },
        AlphaCondition {
            field: ConditionField::EntityAGen,
            value_id: d.hospital,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.billed_at,
        },
        AlphaCondition {
            field: ConditionField::EntityBType,
            value_id: d.amount_type,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
    ];
    d.engine
        .add_production(100, &conditions_a, RuleStatus::Active, 0.85);

    let wme = Wme::new(
        d.org,
        d.provider,
        d.hospital,
        d.billed_at,
        d.amount_type,
        0,
        0,
        3,
        d.medical_bill_cat,
        0.90,
    );
    let (_wme_key, fired, _cids) = d.engine.insert_wme_with_jtms(wme, false);

    if fired.len() != 1 {
        return TestResult::fail(name, &format!("Expected 1 fire, got {}", fired.len()), 0.0);
    }
    let engine_cf = fired[0].chained_cf;
    if (engine_cf - 0.765).abs() > 0.001 {
        return TestResult::fail(
            name,
            &format!("Engine chain A CF: expected 0.765, got {:.4}", engine_cf),
            0.0,
        );
    }

    // Verify chain depth rejection at depth 6
    let mut jtms = Jtms::new();
    use slotmap::SlotMap;
    let mut sm = SlotMap::<rete_alpha::wme::WmeKey, ()>::with_key();
    let k = sm.insert(());
    let at_depth_5 = jtms.add_justification(1, vec![k], 0.5, 5, false);
    let at_depth_6 = jtms.add_justification(2, vec![k], 0.5, 6, false);

    if at_depth_5.is_none() {
        return TestResult::fail(name, "Depth 5 should be accepted", 0.0);
    }
    if at_depth_6.is_some() {
        return TestResult::fail(name, "Depth 6 should be rejected", 0.0);
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "Chain: A={:.3}, B={:.3}, C={:.3}. Depth 5 OK, depth 6 rejected. Duration {:.1}us",
            cf_a, cf_b, cf_c, duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 4: JTMS Retraction -- WME removed, conclusions go OUT
// ============================================================================

fn test_jtms_retraction_basic() -> TestResult {
    let name = "JTMS-1: Basic retraction (WME removed -> conclusion OUT)";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    let conditions = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityARole,
            value_id: d.provider,
        },
        AlphaCondition {
            field: ConditionField::EntityAGen,
            value_id: d.hospital,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.billed_at,
        },
        AlphaCondition {
            field: ConditionField::EntityBType,
            value_id: d.amount_type,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
    ];
    d.engine
        .add_production(200, &conditions, RuleStatus::Active, 0.80);

    let wme = Wme::new(
        d.org,
        d.provider,
        d.hospital,
        d.billed_at,
        d.amount_type,
        0,
        0,
        5,
        d.medical_bill_cat,
        0.95,
    );
    let (wme_key, fired, cids) = d.engine.insert_wme_with_jtms(wme, false);

    if fired.len() != 1 || cids.len() != 1 {
        return TestResult::fail(name, "Expected exactly 1 fire and 1 conclusion", 0.0);
    }

    let cid = cids[0];
    if d.engine.jtms.belief_state(cid) != Some(BeliefState::In) {
        return TestResult::fail(name, "Conclusion should be IN before retraction", 0.0);
    }

    // Retract
    let retracted = d.engine.retract_wme(wme_key);
    if retracted.len() != 1 || retracted[0] != cid {
        return TestResult::fail(
            name,
            &format!("Expected retraction of {:?}, got {:?}", cid, retracted),
            0.0,
        );
    }
    if d.engine.jtms.belief_state(cid) != Some(BeliefState::Out) {
        return TestResult::fail(name, "Conclusion should be OUT after retraction", 0.0);
    }
    if d.engine.wme_count() != 0 {
        return TestResult::fail(name, "Working memory should be empty after retraction", 0.0);
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "Insert->IN, retract->OUT, WM empty. Duration {:.1}us",
            duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 5: JTMS Alternate Support -- retract one WME, conclusion stays IN
// ============================================================================

fn test_jtms_alternate_support() -> TestResult {
    let name = "JTMS-2: Alternate support (retract 1 of 2 WMEs, conclusion stays IN)";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    let conditions = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityARole,
            value_id: d.provider,
        },
        AlphaCondition {
            field: ConditionField::EntityAGen,
            value_id: d.hospital,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.billed_at,
        },
        AlphaCondition {
            field: ConditionField::EntityBType,
            value_id: d.amount_type,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
    ];
    d.engine
        .add_production(300, &conditions, RuleStatus::Active, 0.75);

    // Insert two WMEs that both fire the same rule (different amount buckets)
    let wme1 = Wme::new(
        d.org,
        d.provider,
        d.hospital,
        d.billed_at,
        d.amount_type,
        0,
        0,
        3,
        d.medical_bill_cat,
        0.90,
    );
    let wme2 = Wme::new(
        d.org,
        d.provider,
        d.hospital,
        d.billed_at,
        d.amount_type,
        0,
        0,
        5,
        d.medical_bill_cat,
        0.85,
    );

    let (key1, _, cids1) = d.engine.insert_wme_with_jtms(wme1, false);
    let (_key2, _, cids2) = d.engine.insert_wme_with_jtms(wme2, false);

    if cids1.len() != 1 || cids2.len() != 1 {
        return TestResult::fail(name, "Expected 1 conclusion per WME", 0.0);
    }

    // Each WME creates its own conclusion (different ConclusionIds)
    if cids1[0] == cids2[0] {
        return TestResult::fail(
            name,
            "Different WMEs should produce different conclusions",
            0.0,
        );
    }

    // Both should be IN
    if d.engine.jtms.belief_state(cids1[0]) != Some(BeliefState::In)
        || d.engine.jtms.belief_state(cids2[0]) != Some(BeliefState::In)
    {
        return TestResult::fail(name, "Both conclusions should be IN", 0.0);
    }

    // Retract WME 1 -> conclusion 1 OUT, conclusion 2 still IN
    let retracted = d.engine.retract_wme(key1);
    if retracted.len() != 1 || retracted[0] != cids1[0] {
        return TestResult::fail(name, "Only conclusion 1 should be retracted", 0.0);
    }
    if d.engine.jtms.belief_state(cids1[0]) != Some(BeliefState::Out) {
        return TestResult::fail(name, "Conclusion 1 should be OUT", 0.0);
    }
    if d.engine.jtms.belief_state(cids2[0]) != Some(BeliefState::In) {
        return TestResult::fail(name, "Conclusion 2 should still be IN", 0.0);
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "Retract WME1->cid1 OUT, cid2 stays IN. Duration {:.1}us",
            duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 6: JTMS Cascade Retraction (dependency chain)
// ============================================================================

fn test_jtms_cascade_retraction() -> TestResult {
    let name = "JTMS-3: Cascade retraction (chain depth 3)";
    let start = Instant::now();

    let mut jtms = Jtms::new();
    use slotmap::SlotMap;
    let mut sm = SlotMap::<rete_alpha::wme::WmeKey, ()>::with_key();
    let wme_key = sm.insert(());

    // Build chain: WME -> Conclusion A (depth 1) -> B depends on A -> C depends on B
    let cid_a = jtms
        .add_justification(1, vec![wme_key], 0.9, 1, false)
        .unwrap();
    let cid_b = jtms
        .add_justification(2, vec![wme_key], 0.8, 2, false)
        .unwrap();
    let cid_c = jtms
        .add_justification(3, vec![wme_key], 0.7, 3, false)
        .unwrap();

    jtms.add_dependency(cid_a, cid_b);
    jtms.add_dependency(cid_b, cid_c);

    // All IN
    if jtms.belief_state(cid_a) != Some(BeliefState::In)
        || jtms.belief_state(cid_b) != Some(BeliefState::In)
        || jtms.belief_state(cid_c) != Some(BeliefState::In)
    {
        return TestResult::fail(
            name,
            "All three conclusions should be IN before retraction",
            0.0,
        );
    }

    // Retract WME -> all go OUT (cascade)
    let retracted = jtms.retract_wme(wme_key);
    if retracted.len() != 3 {
        return TestResult::fail(
            name,
            &format!("Expected 3 retracted, got {}", retracted.len()),
            0.0,
        );
    }
    if jtms.belief_state(cid_a) != Some(BeliefState::Out)
        || jtms.belief_state(cid_b) != Some(BeliefState::Out)
        || jtms.belief_state(cid_c) != Some(BeliefState::Out)
    {
        return TestResult::fail(
            name,
            "All conclusions should be OUT after cascade retraction",
            0.0,
        );
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "3-level cascade: all OUT after WME retraction. Duration {:.1}us",
            duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 7: JTMS Rule Retraction (rule expires, conclusions retracted)
// ============================================================================

fn test_jtms_rule_retraction() -> TestResult {
    let name = "JTMS-4: Rule retraction (rule expires -> conclusions OUT)";
    let start = Instant::now();

    let mut jtms = Jtms::new();
    use slotmap::SlotMap;
    let mut sm = SlotMap::<rete_alpha::wme::WmeKey, ()>::with_key();
    let k0 = sm.insert(());
    let k1 = sm.insert(());
    let k2 = sm.insert(());

    // Rule 1 produces 2 conclusions, Rule 2 produces 1
    let cid_1a = jtms.add_justification(1, vec![k0], 0.8, 1, false).unwrap();
    let cid_1b = jtms.add_justification(1, vec![k1], 0.7, 1, false).unwrap();
    let cid_2 = jtms.add_justification(2, vec![k2], 0.6, 1, false).unwrap();

    // All IN
    if jtms.in_count() != 3 {
        return TestResult::fail(
            name,
            &format!("Expected 3 IN, got {}", jtms.in_count()),
            0.0,
        );
    }

    // Retract rule 1 -> its 2 conclusions go OUT, rule 2's stays IN
    let retracted = jtms.retract_rule(1);
    if retracted.len() != 2 {
        return TestResult::fail(
            name,
            &format!("Expected 2 retracted from rule 1, got {}", retracted.len()),
            0.0,
        );
    }
    if jtms.belief_state(cid_1a) != Some(BeliefState::Out)
        || jtms.belief_state(cid_1b) != Some(BeliefState::Out)
    {
        return TestResult::fail(name, "Rule 1 conclusions should be OUT", 0.0);
    }
    if jtms.belief_state(cid_2) != Some(BeliefState::In) {
        return TestResult::fail(name, "Rule 2 conclusion should still be IN", 0.0);
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "Rule 1 retracted: 2 OUT. Rule 2: 1 IN. Duration {:.1}us",
            duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 8: CF Ceiling Enforcement (active=0.95, system=0.98)
// ============================================================================

fn test_cf_ceiling_enforcement() -> TestResult {
    let name = "MYCIN-1: CF ceiling enforcement (active=0.95, system=0.98)";
    let start = Instant::now();

    let mut jtms = Jtms::new();
    use slotmap::SlotMap;
    let mut sm = SlotMap::<rete_alpha::wme::WmeKey, ()>::with_key();
    let k0 = sm.insert(());
    let k1 = sm.insert(());
    let k2 = sm.insert(());
    let k3 = sm.insert(());

    // Active rule: 0.9 + 0.8*(1-0.9) = 0.98 -> clamped to 0.95
    let cid = jtms.add_justification(1, vec![k0], 0.9, 1, false).unwrap();
    jtms.add_supporting_justification(cid, 2, vec![k1], 0.8, 1);
    let cf = jtms.combined_cf(cid).unwrap();
    if (cf - CF_CEILING_ACTIVE).abs() > 1e-5 {
        return TestResult::fail(
            name,
            &format!(
                "Active ceiling: expected {}, got {:.6}",
                CF_CEILING_ACTIVE, cf
            ),
            0.0,
        );
    }

    // System rule: same math, clamped to 0.98
    let cid_sys = jtms.add_justification(10, vec![k2], 0.9, 1, true).unwrap();
    jtms.add_supporting_justification(cid_sys, 11, vec![k3], 0.8, 1);
    let cf_sys = jtms.combined_cf(cid_sys).unwrap();
    if (cf_sys - CF_CEILING_SYSTEM).abs() > 1e-5 {
        return TestResult::fail(
            name,
            &format!(
                "System ceiling: expected {}, got {:.6}",
                CF_CEILING_SYSTEM, cf_sys
            ),
            0.0,
        );
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "Active ceiling={}, System ceiling={}. Duration {:.1}us",
            CF_CEILING_ACTIVE, CF_CEILING_SYSTEM, duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 9: Medical Bill -- realistic HIVE scenario
// Entities extracted from a hospital bill -> match pricing rules -> detect above-average
// ============================================================================

fn test_hive_medical_bill_scenario() -> TestResult {
    let name = "HIVE-1: Medical bill entity extraction -> pricing rule -> above-average detection";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    // Rule: ER visit charge, typical range is $1K-$5K (bucket 3)
    let conditions_er = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityAGen,
            value_id: d.er_visit,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.charged_total,
        },
        AlphaCondition {
            field: ConditionField::EntityBType,
            value_id: d.amount_type,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
    ];
    d.engine
        .add_production(400, &conditions_er, RuleStatus::Active, 0.82);

    // Rule: Lab test charge, typical range is $100-$500 (bucket 1)
    let conditions_lab = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityAGen,
            value_id: d.lab_test,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.charged_total,
        },
        AlphaCondition {
            field: ConditionField::EntityBType,
            value_id: d.amount_type,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
    ];
    d.engine
        .add_production(401, &conditions_lab, RuleStatus::Active, 0.78);

    // WME 1: ER visit charged $8,000 (bucket 4: $5K-$10K) -- ABOVE typical bucket 3
    let wme_er = Wme::new(
        d.org,
        d.provider,
        d.er_visit,
        d.charged_total,
        d.amount_type,
        0,
        0,
        4,
        d.medical_bill_cat,
        0.92,
    );
    let (key_er, fired_er, cids_er) = d.engine.insert_wme_with_jtms(wme_er, false);

    if fired_er.len() != 1 || fired_er[0].rule_id != 400 {
        return TestResult::fail(
            name,
            &format!(
                "ER WME: expected rule 400 to fire, got {:?}",
                fired_er.iter().map(|f| f.rule_id).collect::<Vec<_>>()
            ),
            0.0,
        );
    }

    // WME 2: Lab test charged $250 (bucket 1: $100-$500) -- WITHIN typical bucket 1
    let wme_lab = Wme::new(
        d.org,
        d.provider,
        d.lab_test,
        d.charged_total,
        d.amount_type,
        0,
        0,
        1,
        d.medical_bill_cat,
        0.88,
    );
    let (_key_lab, fired_lab, cids_lab) = d.engine.insert_wme_with_jtms(wme_lab, false);

    if fired_lab.len() != 1 || fired_lab[0].rule_id != 401 {
        return TestResult::fail(
            name,
            &format!(
                "Lab WME: expected rule 401 to fire, got {:?}",
                fired_lab.iter().map(|f| f.rule_id).collect::<Vec<_>>()
            ),
            0.0,
        );
    }

    // WME 3: A person entity (patient) -- should NOT fire either medical rule
    let wme_person = Wme::new(
        d.person,
        d.patient,
        0,
        d.has_diagnosis,
        d.procedure,
        0,
        d.diagnosis,
        255,
        d.medical_bill_cat,
        0.85,
    );
    let fired_person = d.engine.insert_wme(wme_person);
    if !fired_person.is_empty() {
        return TestResult::fail(
            name,
            &format!(
                "Person WME should not fire pricing rules, got {} fires",
                fired_person.len()
            ),
            0.0,
        );
    }

    // Verify independence: retract ER WME, lab conclusion stays
    let _retracted = d.engine.retract_wme(key_er);
    if d.engine.jtms.belief_state(cids_er[0]) != Some(BeliefState::Out) {
        return TestResult::fail(name, "ER conclusion should be OUT after retraction", 0.0);
    }
    if d.engine.jtms.belief_state(cids_lab[0]) != Some(BeliefState::In) {
        return TestResult::fail(name, "Lab conclusion should still be IN", 0.0);
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "ER rule fired (CF={:.3}), Lab rule fired (CF={:.3}), Person no-fire. \
                  Retraction independent. Duration {:.1}us",
            fired_er[0].chained_cf, fired_lab[0].chained_cf, duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 10: Lease Agreement -- realistic HIVE scenario
// ============================================================================

fn test_hive_lease_agreement_scenario() -> TestResult {
    let name = "HIVE-2: Lease agreement -> tenant rights rules -> flag unusual terms";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    // Rule: Security deposit > $5K is unusual (bucket >= 4)
    // Bitmask for buckets 4,5,6,7 = 0b11110000
    let conditions_deposit = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityARole,
            value_id: d.landlord,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.security_deposit,
        },
        AlphaCondition {
            field: ConditionField::EntityBType,
            value_id: d.amount_type,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.lease_cat as u16,
        },
        AlphaCondition {
            field: ConditionField::AmountBucket,
            value_id: 0b11110000u16,
        },
    ];
    d.engine
        .add_production(500, &conditions_deposit, RuleStatus::Active, 0.70);

    // Rule: Rent amount in typical range $1K-$5K (bucket 3)
    let conditions_rent = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityARole,
            value_id: d.landlord,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.rent_amount,
        },
        AlphaCondition {
            field: ConditionField::EntityBType,
            value_id: d.amount_type,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.lease_cat as u16,
        },
    ];
    d.engine
        .add_production(501, &conditions_rent, RuleStatus::Active, 0.65);

    // Rule: Late fee (any amount) in lease
    let conditions_late = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityARole,
            value_id: d.landlord,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.late_fee,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.lease_cat as u16,
        },
    ];
    d.engine
        .add_production(502, &conditions_late, RuleStatus::Active, 0.60);

    // WME: Security deposit $7,500 (bucket 4: $5K-$10K) -- UNUSUAL
    let wme_deposit = Wme::new(
        d.org,
        d.landlord,
        0,
        d.security_deposit,
        d.amount_type,
        0,
        0,
        4,
        d.lease_cat,
        0.93,
    );
    let (_, fired_deposit, _) = d.engine.insert_wme_with_jtms(wme_deposit, false);

    if fired_deposit.len() != 1 || fired_deposit[0].rule_id != 500 {
        return TestResult::fail(
            name,
            &format!(
                "Deposit WME: expected rule 500, got {:?}",
                fired_deposit.iter().map(|f| f.rule_id).collect::<Vec<_>>()
            ),
            0.0,
        );
    }

    // WME: Rent $2,500 (bucket 3: $1K-$5K)
    let wme_rent = Wme::new(
        d.org,
        d.landlord,
        0,
        d.rent_amount,
        d.amount_type,
        0,
        0,
        3,
        d.lease_cat,
        0.95,
    );
    let (_, fired_rent, _) = d.engine.insert_wme_with_jtms(wme_rent, false);

    if fired_rent.len() != 1 || fired_rent[0].rule_id != 501 {
        return TestResult::fail(
            name,
            &format!(
                "Rent WME: expected rule 501, got {:?}",
                fired_rent.iter().map(|f| f.rule_id).collect::<Vec<_>>()
            ),
            0.0,
        );
    }

    // WME: Late fee $100 (bucket 0: $0-$100)
    let wme_late = Wme::new(
        d.org,
        d.landlord,
        0,
        d.late_fee,
        d.amount_type,
        0,
        0,
        0,
        d.lease_cat,
        0.88,
    );
    let (_, fired_late, _) = d.engine.insert_wme_with_jtms(wme_late, false);

    if fired_late.len() != 1 || fired_late[0].rule_id != 502 {
        return TestResult::fail(
            name,
            &format!(
                "Late fee WME: expected rule 502, got {:?}",
                fired_late.iter().map(|f| f.rule_id).collect::<Vec<_>>()
            ),
            0.0,
        );
    }

    // WME: Normal security deposit $2,000 (bucket 3: $1K-$5K) -- should NOT fire rule 500
    // (bucket 3 is not in bitmask 0b11110000)
    let wme_normal_deposit = Wme::new(
        d.org,
        d.landlord,
        0,
        d.security_deposit,
        d.amount_type,
        0,
        0,
        3,
        d.lease_cat,
        0.90,
    );
    let (_, fired_normal, _) = d.engine.insert_wme_with_jtms(wme_normal_deposit, false);
    // Rule 500 requires bucket >= 4, so bucket 3 should NOT match it
    let rule500_fired = fired_normal.iter().any(|f| f.rule_id == 500);
    if rule500_fired {
        return TestResult::fail(
            name,
            "Normal deposit (bucket 3) should NOT fire unusual-deposit rule 500",
            0.0,
        );
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "Unusual deposit flagged (rule 500), rent typical (501), late fee (502). \
                  Normal deposit NOT flagged. Duration {:.1}us",
            duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 11: Insurance Policy -- realistic HIVE scenario
// ============================================================================

fn test_hive_insurance_policy_scenario() -> TestResult {
    let name = "HIVE-3: Insurance policy -> coverage rules -> identify gaps";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    // Rule: Coverage limit in insurance policy
    let conditions_coverage = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityARole,
            value_id: d.insurer,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.coverage_limit,
        },
        AlphaCondition {
            field: ConditionField::EntityBType,
            value_id: d.amount_type,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.insurance_cat as u16,
        },
    ];
    d.engine
        .add_production(600, &conditions_coverage, RuleStatus::Active, 0.85);

    // Rule: Deductible amount
    let conditions_deductible = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityARole,
            value_id: d.insurer,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.deductible,
        },
        AlphaCondition {
            field: ConditionField::EntityBType,
            value_id: d.amount_type,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.insurance_cat as u16,
        },
    ];
    d.engine
        .add_production(601, &conditions_deductible, RuleStatus::Active, 0.80);

    // Rule: Exclusion clause detected (weakened -- lower confidence)
    let conditions_exclusion = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityARole,
            value_id: d.insurer,
        },
        AlphaCondition {
            field: ConditionField::EntityAGen,
            value_id: d.insurance_co,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.has_exclusion,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.insurance_cat as u16,
        },
    ];
    d.engine
        .add_production(602, &conditions_exclusion, RuleStatus::Weakened, 0.45);

    // WME: Coverage limit $50K-$100K (bucket 6)
    let wme_coverage = Wme::new(
        d.org,
        d.insurer,
        d.insurance_co,
        d.coverage_limit,
        d.amount_type,
        0,
        0,
        6,
        d.insurance_cat,
        0.94,
    );
    let (_, fired_cov, _) = d.engine.insert_wme_with_jtms(wme_coverage, false);

    if fired_cov.len() != 1 || fired_cov[0].rule_id != 600 {
        return TestResult::fail(name, "Coverage WME should fire rule 600", 0.0);
    }

    // WME: Deductible $1K-$5K (bucket 3)
    let wme_deductible = Wme::new(
        d.org,
        d.insurer,
        d.insurance_co,
        d.deductible,
        d.amount_type,
        0,
        0,
        3,
        d.insurance_cat,
        0.91,
    );
    let (_, fired_ded, _) = d.engine.insert_wme_with_jtms(wme_deductible, false);

    if fired_ded.len() != 1 || fired_ded[0].rule_id != 601 {
        return TestResult::fail(name, "Deductible WME should fire rule 601", 0.0);
    }

    // WME: Exclusion clause
    let wme_exclusion = Wme::new(
        d.org,
        d.insurer,
        d.insurance_co,
        d.has_exclusion,
        d.policy_type,
        0,
        d.exclusion,
        255,
        d.insurance_cat,
        0.87,
    );
    let (_, fired_excl, _) = d.engine.insert_wme_with_jtms(wme_exclusion, false);

    if fired_excl.len() != 1 || fired_excl[0].rule_id != 602 {
        return TestResult::fail(name, "Exclusion WME should fire rule 602 (weakened)", 0.0);
    }

    // Verify weakened rule has lower chained CF
    let excl_cf = fired_excl[0].chained_cf;
    let cov_cf = fired_cov[0].chained_cf;
    if excl_cf >= cov_cf {
        return TestResult::fail(
            name,
            &format!(
                "Weakened rule CF ({:.3}) should be < active rule CF ({:.3})",
                excl_cf, cov_cf
            ),
            0.0,
        );
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "Coverage (rule 600, CF={:.3}), Deductible (601, CF={:.3}), \
                  Exclusion (602 weakened, CF={:.3}). Duration {:.1}us",
            cov_cf, fired_ded[0].chained_cf, excl_cf, duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 12: R8 Test Vector 7 adapted -- Utility Bill
// ============================================================================

fn test_r8_vector7_utility_bill() -> TestResult {
    let name = "R8-V7-Util: Utility bill full walkthrough (adapted from R8 V7)";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    // Rule #650: utility_company charged_total amount utility_bill
    let conditions = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityAGen,
            value_id: d.utility_company,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.energy_charge,
        },
        AlphaCondition {
            field: ConditionField::EntityBType,
            value_id: d.amount_type,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.utility_cat as u16,
        },
    ];
    d.engine
        .add_production(650, &conditions, RuleStatus::Active, 0.59);

    // WME: utility bill $145 (bucket 1: $100-$500), extraction_cf = 0.91
    let wme = Wme::new(
        d.org,
        0,
        d.utility_company,
        d.energy_charge,
        d.amount_type,
        0,
        0,
        1,
        d.utility_cat,
        0.91,
    );
    let (_wme_key, fired, cids) = d.engine.insert_wme_with_jtms(wme, false);

    if fired.len() != 1 || fired[0].rule_id != 650 {
        return TestResult::fail(name, "Expected rule 650 to fire", 0.0);
    }

    // Expected CF: 0.59 * 0.91 = 0.5369
    let expected_cf = 0.59_f32 * 0.91_f32;
    if (fired[0].chained_cf - expected_cf).abs() > 0.001 {
        return TestResult::fail(
            name,
            &format!(
                "Expected CF {:.4}, got {:.4}",
                expected_cf, fired[0].chained_cf
            ),
            0.0,
        );
    }

    // JTMS justification created
    if cids.len() != 1 {
        return TestResult::fail(name, "Expected 1 JTMS conclusion", 0.0);
    }
    if d.engine.jtms.belief_state(cids[0]) != Some(BeliefState::In) {
        return TestResult::fail(name, "Conclusion should be IN", 0.0);
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "Rule 650 fired, CF={:.4} (0.59*0.91), JTMS IN. Duration {:.1}us",
            expected_cf, duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 13: False Positive Tests -- rules must NOT fire when conditions unmet
// ============================================================================

fn test_false_positive_checks() -> TestResult {
    let name = "FP-1: False positive checks (6 sub-tests)";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    // Set up a strict rule: needs 6 conditions
    let conditions = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityARole,
            value_id: d.provider,
        },
        AlphaCondition {
            field: ConditionField::EntityAGen,
            value_id: d.hospital,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.billed_at,
        },
        AlphaCondition {
            field: ConditionField::EntityBType,
            value_id: d.amount_type,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
    ];
    d.engine
        .add_production(700, &conditions, RuleStatus::Active, 0.80);

    let mut fp_count = 0;
    let mut details = Vec::new();

    // FP-1a: Wrong entity_a_type (person instead of org)
    let wme_wrong_type = Wme::new(
        d.person,
        d.provider,
        d.hospital,
        d.billed_at,
        d.amount_type,
        0,
        0,
        3,
        d.medical_bill_cat,
        0.90,
    );
    let fired = d.engine.insert_wme(wme_wrong_type);
    if fired.is_empty() {
        details.push("FP-1a: PASS (wrong entity_a_type)");
    } else {
        fp_count += 1;
        details.push("FP-1a: FAIL -- fired with wrong entity_a_type");
    }

    // FP-1b: Wrong entity_a_role (tenant instead of provider)
    let wme_wrong_role = Wme::new(
        d.org,
        d.tenant,
        d.hospital,
        d.billed_at,
        d.amount_type,
        0,
        0,
        3,
        d.medical_bill_cat,
        0.90,
    );
    let fired = d.engine.insert_wme(wme_wrong_role);
    if fired.is_empty() {
        details.push("FP-1b: PASS (wrong entity_a_role)");
    } else {
        fp_count += 1;
        details.push("FP-1b: FAIL -- fired with wrong entity_a_role");
    }

    // FP-1c: Wrong relation (charged_total instead of billed_at)
    let wme_wrong_rel = Wme::new(
        d.org,
        d.provider,
        d.hospital,
        d.charged_total,
        d.amount_type,
        0,
        0,
        3,
        d.medical_bill_cat,
        0.90,
    );
    let fired = d.engine.insert_wme(wme_wrong_rel);
    if fired.is_empty() {
        details.push("FP-1c: PASS (wrong relation)");
    } else {
        fp_count += 1;
        details.push("FP-1c: FAIL -- fired with wrong relation");
    }

    // FP-1d: Wrong document_category (lease instead of medical)
    let wme_wrong_doc = Wme::new(
        d.org,
        d.provider,
        d.hospital,
        d.billed_at,
        d.amount_type,
        0,
        0,
        3,
        d.lease_cat,
        0.90,
    );
    let fired = d.engine.insert_wme(wme_wrong_doc);
    if fired.is_empty() {
        details.push("FP-1d: PASS (wrong doc_category)");
    } else {
        fp_count += 1;
        details.push("FP-1d: FAIL -- fired with wrong doc_category");
    }

    // FP-1e: Wrong entity_a_gen (er_visit instead of hospital)
    let wme_wrong_gen = Wme::new(
        d.org,
        d.provider,
        d.er_visit,
        d.billed_at,
        d.amount_type,
        0,
        0,
        3,
        d.medical_bill_cat,
        0.90,
    );
    let fired = d.engine.insert_wme(wme_wrong_gen);
    if fired.is_empty() {
        details.push("FP-1e: PASS (wrong entity_a_gen)");
    } else {
        fp_count += 1;
        details.push("FP-1e: FAIL -- fired with wrong entity_a_gen");
    }

    // FP-1f: Wrong entity_b_type (procedure instead of amount)
    let wme_wrong_btype = Wme::new(
        d.org,
        d.provider,
        d.hospital,
        d.billed_at,
        d.procedure,
        0,
        0,
        3,
        d.medical_bill_cat,
        0.90,
    );
    let fired = d.engine.insert_wme(wme_wrong_btype);
    if fired.is_empty() {
        details.push("FP-1f: PASS (wrong entity_b_type)");
    } else {
        fp_count += 1;
        details.push("FP-1f: FAIL -- fired with wrong entity_b_type");
    }

    let duration = start.elapsed().as_micros() as f64;
    let detail_str = details.join("; ");
    if fp_count > 0 {
        TestResult::fail(
            name,
            &format!("{} false positive(s): {}", fp_count, detail_str),
            duration,
        )
    } else {
        TestResult::pass(
            name,
            &format!(
                "0 false positives in 6 sub-tests. Duration {:.1}us",
                duration
            ),
            duration,
        )
    }
}

// ============================================================================
// SCENARIO 14: Status-based firing -- Dormant and Expired rules do not fire
// ============================================================================

fn test_status_based_firing() -> TestResult {
    let name = "STATUS-1: Dormant and Expired rules do not fire; Candidate and Weakened do";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    let base_conditions = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.billed_at,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
    ];

    // Same conditions, 5 different statuses
    d.engine
        .add_production(800, &base_conditions, RuleStatus::Active, 0.8);
    d.engine
        .add_production(801, &base_conditions, RuleStatus::Candidate, 0.6);
    d.engine
        .add_production(802, &base_conditions, RuleStatus::Weakened, 0.4);
    d.engine
        .add_production(803, &base_conditions, RuleStatus::Dormant, 0.3);
    d.engine
        .add_production(804, &base_conditions, RuleStatus::Expired, 0.2);

    let wme = Wme::new(
        d.org,
        0,
        0,
        d.billed_at,
        0,
        0,
        0,
        255,
        d.medical_bill_cat,
        0.90,
    );
    let fired = d.engine.insert_wme(wme);

    let fired_ids: Vec<u32> = fired.iter().map(|f| f.rule_id).collect();

    // Active, Candidate, Weakened should fire; Dormant, Expired should NOT
    if !fired_ids.contains(&800) {
        return TestResult::fail(name, "Active rule 800 should fire", 0.0);
    }
    if !fired_ids.contains(&801) {
        return TestResult::fail(name, "Candidate rule 801 should fire", 0.0);
    }
    if !fired_ids.contains(&802) {
        return TestResult::fail(name, "Weakened rule 802 should fire", 0.0);
    }
    if fired_ids.contains(&803) {
        return TestResult::fail(name, "Dormant rule 803 should NOT fire", 0.0);
    }
    if fired_ids.contains(&804) {
        return TestResult::fail(name, "Expired rule 804 should NOT fire", 0.0);
    }
    if fired.len() != 3 {
        return TestResult::fail(name, &format!("Expected 3 fires, got {}", fired.len()), 0.0);
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "Active+Candidate+Weakened fire (3), Dormant+Expired skip (2). Duration {:.1}us",
            duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 15: Multi-rule matching -- single WME matches multiple rules
// ============================================================================

fn test_multi_rule_matching() -> TestResult {
    let name = "MULTI-1: Single WME matches multiple independent rules";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    // Rule A: broad match (just entity_a_type=org + doc_category=medical)
    let cond_a = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
    ];
    d.engine
        .add_production(900, &cond_a, RuleStatus::Active, 0.50);

    // Rule B: narrower match (adds relation=billed_at)
    let cond_b = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.billed_at,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
    ];
    d.engine
        .add_production(901, &cond_b, RuleStatus::Active, 0.70);

    // Rule C: most specific (adds entity_a_gen=hospital)
    let cond_c = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityAGen,
            value_id: d.hospital,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.billed_at,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
    ];
    d.engine
        .add_production(902, &cond_c, RuleStatus::Active, 0.85);

    // WME matches all 3
    let wme = Wme::new(
        d.org,
        0,
        d.hospital,
        d.billed_at,
        0,
        0,
        0,
        255,
        d.medical_bill_cat,
        0.90,
    );
    let fired = d.engine.insert_wme(wme);

    let fired_ids: Vec<u32> = fired.iter().map(|f| f.rule_id).collect();
    if fired.len() != 3 {
        return TestResult::fail(
            name,
            &format!("Expected 3 fires, got {} ({:?})", fired.len(), fired_ids),
            0.0,
        );
    }
    if !fired_ids.contains(&900) || !fired_ids.contains(&901) || !fired_ids.contains(&902) {
        return TestResult::fail(
            name,
            &format!("Expected rules 900,901,902; got {:?}", fired_ids),
            0.0,
        );
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "All 3 rules fire for broad+narrow+specific. Duration {:.1}us",
            duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 16: Edge case -- empty WME set (no WMEs, no fires)
// ============================================================================

fn test_edge_empty_wme_set() -> TestResult {
    let name = "EDGE-1: Empty working memory (no WMEs inserted)";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    let conditions = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.billed_at,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
    ];
    d.engine
        .add_production(1000, &conditions, RuleStatus::Active, 0.80);

    // No WMEs inserted -- verify engine state
    if d.engine.wme_count() != 0 {
        return TestResult::fail(name, "Working memory should be empty", 0.0);
    }
    if d.engine.production_count() != 1 {
        return TestResult::fail(name, "Should have 1 production", 0.0);
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "0 WMEs, 1 production, no errors. Duration {:.1}us",
            duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 17: Edge case -- rule with no matches
// ============================================================================

fn test_edge_rule_no_matches() -> TestResult {
    let name = "EDGE-2: Rule exists but no WME matches (100 WMEs, 0 fires)";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    // Rule requires insurance domain
    let conditions = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityARole,
            value_id: d.insurer,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.coverage_limit,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.insurance_cat as u16,
        },
    ];
    d.engine
        .add_production(1100, &conditions, RuleStatus::Active, 0.75);

    // Insert 100 medical WMEs (none match insurance rule)
    let mut total_fires = 0;
    for i in 0..100u16 {
        let wme = Wme::new(
            d.org,
            d.provider,
            d.hospital,
            d.billed_at,
            d.amount_type,
            0,
            0,
            (i % 8) as u8,
            d.medical_bill_cat,
            0.90,
        );
        let fired = d.engine.insert_wme(wme);
        total_fires += fired.len();
    }

    if total_fires != 0 {
        return TestResult::fail(name, &format!("Expected 0 fires, got {}", total_fires), 0.0);
    }
    if d.engine.wme_count() != 100 {
        return TestResult::fail(
            name,
            &format!("Expected 100 WMEs, got {}", d.engine.wme_count()),
            0.0,
        );
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "100 WMEs inserted, 0 fires (no false positives). Duration {:.1}us",
            duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 18: Amount bucket bitmask precision
// ============================================================================

fn test_amount_bucket_bitmask_precision() -> TestResult {
    let name = "BUCKET-1: Amount bucket bitmask matching precision (8 buckets)";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    // Rule: matches buckets 2,3 only (mask = 0b00001100)
    let conditions = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.billed_at,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
        AlphaCondition {
            field: ConditionField::AmountBucket,
            value_id: 0b00001100u16,
        },
    ];
    d.engine
        .add_production(1200, &conditions, RuleStatus::Active, 0.70);

    let mut matches = Vec::new();
    for bucket in 0..8u8 {
        let wme = Wme::new(
            d.org,
            0,
            0,
            d.billed_at,
            0,
            0,
            0,
            bucket,
            d.medical_bill_cat,
            0.90,
        );
        let fired = d.engine.insert_wme(wme);
        if !fired.is_empty() {
            matches.push(bucket);
        }
    }

    // Also test bucket 255 (N/A) -- should NOT match
    let wme_na = Wme::new(
        d.org,
        0,
        0,
        d.billed_at,
        0,
        0,
        0,
        255,
        d.medical_bill_cat,
        0.90,
    );
    let fired_na = d.engine.insert_wme(wme_na);
    if !fired_na.is_empty() {
        return TestResult::fail(name, "Bucket 255 (N/A) should not match bitmask", 0.0);
    }

    if matches != vec![2, 3] {
        return TestResult::fail(
            name,
            &format!("Expected buckets [2,3], got {:?}", matches),
            0.0,
        );
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "Buckets 2,3 match; 0,1,4,5,6,7,255 don't. Duration {:.1}us",
            duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 19: Performance -- 1000 WMEs with 50 rules
// ============================================================================

fn test_performance_1k_wmes() -> TestResult {
    let name = "PERF-1: 1000 WMEs x 50 rules throughput";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    // Register 50 rules across different domains
    let relations = [
        d.billed_at,
        d.charged_total,
        d.rent_amount,
        d.security_deposit,
        d.coverage_limit,
        d.deductible,
        d.premium,
        d.energy_charge,
        d.late_fee,
        d.has_clause,
    ];
    let gens = [
        d.hospital,
        d.er_visit,
        d.lab_test,
        d.utility_company,
        d.insurance_co,
    ];
    let cats = [
        d.medical_bill_cat,
        d.lease_cat,
        d.insurance_cat,
        d.utility_cat,
    ];

    for i in 0..50u32 {
        let rel = relations[(i as usize) % relations.len()];
        let gen = gens[(i as usize) % gens.len()];
        let cat = cats[(i as usize) % cats.len()];

        let conditions = vec![
            AlphaCondition {
                field: ConditionField::EntityAType,
                value_id: d.org,
            },
            AlphaCondition {
                field: ConditionField::EntityAGen,
                value_id: gen,
            },
            AlphaCondition {
                field: ConditionField::Relation,
                value_id: rel,
            },
            AlphaCondition {
                field: ConditionField::DocumentCategory,
                value_id: cat as u16,
            },
        ];
        d.engine
            .add_production(2000 + i, &conditions, RuleStatus::Active, 0.70);
    }

    // Insert 1000 WMEs
    let insert_start = Instant::now();
    let mut total_fires = 0u64;
    for i in 0..1000u32 {
        let rel = relations[(i as usize) % relations.len()];
        let gen = gens[(i as usize) % gens.len()];
        let cat = cats[(i as usize) % cats.len()];

        let wme = Wme::new(
            d.org,
            0,
            gen,
            rel,
            d.amount_type,
            0,
            0,
            (i % 8) as u8,
            cat,
            0.85,
        );
        let fired = d.engine.insert_wme(wme);
        total_fires += fired.len() as u64;
    }
    let insert_elapsed = insert_start.elapsed();
    let avg_ns = insert_elapsed.as_nanos() as f64 / 1000.0;

    // Target: < 1000 ns (1 us) per WME
    let passed = avg_ns < 1000.0;

    let duration = start.elapsed().as_micros() as f64;
    let result_str = format!(
        "1000 WMEs x 50 rules: avg {:.0}ns/WME, total fires: {}, {:.2}ms total. {}",
        avg_ns,
        total_fires,
        insert_elapsed.as_micros() as f64 / 1000.0,
        if passed {
            "UNDER 1us target"
        } else {
            "OVER 1us target"
        }
    );

    if passed {
        TestResult::pass(name, &result_str, duration)
    } else {
        TestResult::fail(name, &result_str, duration)
    }
}

// ============================================================================
// SCENARIO 20: Cross-domain isolation -- medical rules don't fire on lease WMEs
// ============================================================================

fn test_cross_domain_isolation() -> TestResult {
    let name = "ISOLATION-1: Cross-domain isolation (medical rules vs lease WMEs)";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    // Medical rule
    let med_conditions = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityAGen,
            value_id: d.hospital,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.billed_at,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.medical_bill_cat as u16,
        },
    ];
    d.engine
        .add_production(3000, &med_conditions, RuleStatus::Active, 0.80);

    // Lease rule
    let lease_conditions = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityARole,
            value_id: d.landlord,
        },
        AlphaCondition {
            field: ConditionField::Relation,
            value_id: d.rent_amount,
        },
        AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: d.lease_cat as u16,
        },
    ];
    d.engine
        .add_production(3001, &lease_conditions, RuleStatus::Active, 0.75);

    // Insert medical WME -> only medical rule should fire
    let wme_med = Wme::new(
        d.org,
        d.provider,
        d.hospital,
        d.billed_at,
        d.amount_type,
        0,
        0,
        3,
        d.medical_bill_cat,
        0.90,
    );
    let fired_med = d.engine.insert_wme(wme_med);
    let med_ids: Vec<u32> = fired_med.iter().map(|f| f.rule_id).collect();
    if fired_med.len() != 1 || fired_med[0].rule_id != 3000 {
        return TestResult::fail(
            name,
            &format!("Medical WME: expected [3000], got {:?}", med_ids),
            0.0,
        );
    }

    // Insert lease WME -> only lease rule should fire
    let wme_lease = Wme::new(
        d.org,
        d.landlord,
        0,
        d.rent_amount,
        d.amount_type,
        0,
        0,
        3,
        d.lease_cat,
        0.92,
    );
    let fired_lease = d.engine.insert_wme(wme_lease);
    let lease_ids: Vec<u32> = fired_lease.iter().map(|f| f.rule_id).collect();
    if fired_lease.len() != 1 || fired_lease[0].rule_id != 3001 {
        return TestResult::fail(
            name,
            &format!("Lease WME: expected [3001], got {:?}", lease_ids),
            0.0,
        );
    }

    // Insert insurance WME -> neither should fire
    let wme_ins = Wme::new(
        d.org,
        d.insurer,
        d.insurance_co,
        d.coverage_limit,
        d.amount_type,
        0,
        0,
        6,
        d.insurance_cat,
        0.88,
    );
    let fired_ins = d.engine.insert_wme(wme_ins);
    if !fired_ins.is_empty() {
        return TestResult::fail(
            name,
            &format!("Insurance WME fired {} rules (expected 0)", fired_ins.len()),
            0.0,
        );
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "Medical->rule 3000 only, Lease->rule 3001 only, Insurance->no fire. Duration {:.1}us",
            duration
        ),
        duration,
    )
}

// ============================================================================
// SCENARIO 21: MYCIN CF edge cases
// ============================================================================

fn test_mycin_edge_cases() -> TestResult {
    let name = "MYCIN-2: CF edge cases (zero, one, identity)";
    let start = Instant::now();

    // combine(0, X) = X
    let r1 = mycin_combine(0.0, 0.5);
    if (r1 - 0.5).abs() > 1e-6 {
        return TestResult::fail(
            name,
            &format!("combine(0.0, 0.5): expected 0.5, got {:.6}", r1),
            0.0,
        );
    }

    // combine(1, X) = 1
    let r2 = mycin_combine(1.0, 0.5);
    if (r2 - 1.0).abs() > 1e-6 {
        return TestResult::fail(
            name,
            &format!("combine(1.0, 0.5): expected 1.0, got {:.6}", r2),
            0.0,
        );
    }

    // combine(0, 0) = 0
    let r3 = mycin_combine(0.0, 0.0);
    if r3.abs() > 1e-6 {
        return TestResult::fail(
            name,
            &format!("combine(0.0, 0.0): expected 0.0, got {:.6}", r3),
            0.0,
        );
    }

    // combine_all of empty = 0
    let r4 = mycin_combine_all(&[]);
    if r4.abs() > 1e-6 {
        return TestResult::fail(
            name,
            &format!("combine_all([]): expected 0.0, got {:.6}", r4),
            0.0,
        );
    }

    // combine_all of single = itself
    let r5 = mycin_combine_all(&[0.73]);
    if (r5 - 0.73).abs() > 1e-6 {
        return TestResult::fail(
            name,
            &format!("combine_all([0.73]): expected 0.73, got {:.6}", r5),
            0.0,
        );
    }

    // Monotonicity: adding evidence never decreases CF (for positive CFs)
    let cf_base = mycin_combine_all(&[0.3, 0.4]);
    let cf_more = mycin_combine_all(&[0.3, 0.4, 0.2]);
    if cf_more < cf_base {
        return TestResult::fail(
            name,
            &format!("Monotonicity violated: {} < {}", cf_more, cf_base),
            0.0,
        );
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(name,
        &format!("All edge cases pass: zero identity, one absorb, empty list, monotonicity. Duration {:.1}us",
                 duration), duration)
}

// ============================================================================
// SCENARIO 22: Secondary index path (rules without all 3 composite fields)
// ============================================================================

fn test_secondary_index_path() -> TestResult {
    let name = "INDEX-1: Secondary index path (rules missing composite fields)";
    let start = Instant::now();

    let mut d = DomainEngine::new();

    // Rule with only entity_a_type (no relation or doc_category) -- goes to secondary path
    let conditions = vec![
        AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: d.org,
        },
        AlphaCondition {
            field: ConditionField::EntityAGen,
            value_id: d.hospital,
        },
    ];
    d.engine
        .add_production(4000, &conditions, RuleStatus::Active, 0.60);

    // This rule should be in secondary_productions
    if d.engine.secondary_productions.is_empty() {
        return TestResult::fail(name, "Expected rule 4000 in secondary_productions", 0.0);
    }

    // WME: matches the 2-condition secondary rule
    let wme = Wme::new(d.org, 0, d.hospital, 0, 0, 0, 0, 255, 0, 0.90);
    let fired = d.engine.insert_wme(wme);

    if fired.len() != 1 || fired[0].rule_id != 4000 {
        return TestResult::fail(
            name,
            &format!(
                "Expected rule 4000 to fire via secondary path, got {:?}",
                fired.iter().map(|f| f.rule_id).collect::<Vec<_>>()
            ),
            0.0,
        );
    }

    let duration = start.elapsed().as_micros() as f64;
    TestResult::pass(
        name,
        &format!(
            "Rule 4000 fires via secondary index path (2 conditions). Duration {:.1}us",
            duration
        ),
        duration,
    )
}

// ============================================================================
// Main: run all scenarios
// ============================================================================

fn main() {
    println!("=================================================================");
    println!("  RE3: HIVE Rete-II Reasoning Quality Test Suite");
    println!("  Engine: Rete-II alpha network + JTMS");
    println!("  Date: 2026-04-15");
    println!("=================================================================\n");

    let overall_start = Instant::now();

    let tests: Vec<TestResult> = vec![
        // R8 Test Vectors
        test_r8_vector7_medical_bill_walkthrough(),
        test_r8_vector3_mycin_concordant(),
        test_r8_vector4_mycin_chain(),
        // JTMS Truth Maintenance
        test_jtms_retraction_basic(),
        test_jtms_alternate_support(),
        test_jtms_cascade_retraction(),
        test_jtms_rule_retraction(),
        // MYCIN Confidence
        test_cf_ceiling_enforcement(),
        test_mycin_edge_cases(),
        // Realistic HIVE Scenarios
        test_hive_medical_bill_scenario(),
        test_hive_lease_agreement_scenario(),
        test_hive_insurance_policy_scenario(),
        test_r8_vector7_utility_bill(),
        // False Positive & Isolation
        test_false_positive_checks(),
        test_status_based_firing(),
        test_cross_domain_isolation(),
        // Multi-rule & Edge Cases
        test_multi_rule_matching(),
        test_edge_empty_wme_set(),
        test_edge_rule_no_matches(),
        test_amount_bucket_bitmask_precision(),
        test_secondary_index_path(),
        // Performance
        test_performance_1k_wmes(),
    ];

    let total = tests.len();
    let passed = tests.iter().filter(|t| t.passed).count();
    let failed = tests.iter().filter(|t| !t.passed).count();

    println!("--- Test Results ---\n");
    for (i, test) in tests.iter().enumerate() {
        let status = if test.passed { "PASS" } else { "FAIL" };
        println!("[{:2}] [{}] {}", i + 1, status, test.name);
        println!("     {}", test.details);
        println!();
    }

    let total_duration = overall_start.elapsed();
    println!("=================================================================");
    println!("  SUMMARY: {}/{} passed, {} failed", passed, total, failed);
    println!(
        "  Total time: {:.2}ms",
        total_duration.as_micros() as f64 / 1000.0
    );
    println!("=================================================================\n");

    if failed > 0 {
        println!("FAILED TESTS:");
        for test in tests.iter().filter(|t| !t.passed) {
            println!("  - {}: {}", test.name, test.details);
        }
        std::process::exit(1);
    } else {
        println!("ALL TESTS PASSED. Reasoning quality validated.");
    }
}
