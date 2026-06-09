//! Pipeline Integration Test: Full end-to-end pipeline validation.
//!
//! Exercises: ExtractionOutput JSON -> Tuple Adapter -> WME Factory -> Rete-II Engine -> FiredProductions
//!
//! Test scenarios:
//!   1. Medical Bill ($8,200 ER visit charge)
//!   2. Lease Agreement ($2,500 rent + $150 late fee)
//!
//! Run: cargo run --bin a3_pipeline_test

use rete_alpha::pipeline::{
    all_test_rules, lease_agreement_rules, medical_bill_rules, LocalPipeline,
};
use std::time::Instant;

// ============================================================================
// Test data
// ============================================================================

fn medical_bill_json() -> &'static str {
    r#"{
        "document_category": "medical_bill",
        "entities": [
            {"id": "e1", "name": "Memorial Hospital", "type": "organization", "value": "Memorial Hospital"},
            {"id": "e2", "name": "ER Visit Charge", "type": "amount", "value": "$8,200.00"},
            {"id": "e3", "name": "John Patient", "type": "person", "value": null}
        ],
        "relationships": [
            {"source": "e1", "target": "e2", "relationship": "charged_total", "context": "Emergency room visit"},
            {"source": "e3", "target": "e1", "relationship": "patient_at", "context": null}
        ]
    }"#
}

fn lease_agreement_json() -> &'static str {
    r#"{
        "document_category": "lease_agreement",
        "entities": [
            {"id": "e1", "name": "Property Management LLC", "type": "organization", "value": "Property Management LLC"},
            {"id": "e2", "name": "Monthly Rent", "type": "amount", "value": "$2,500.00"},
            {"id": "e3", "name": "Late Fee", "type": "amount", "value": "$150.00"}
        ],
        "relationships": [
            {"source": "e1", "target": "e2", "relationship": "charges_rent", "context": "Monthly rental payment"},
            {"source": "e1", "target": "e3", "relationship": "charges_late_fee", "context": "After 5 day grace period"}
        ]
    }"#
}

// ============================================================================
// Test runner
// ============================================================================

fn main() {
    println!("==========================================================");
    println!("  HIVE A3: Full Pipeline Integration Test");
    println!("  ExtractionOutput -> Tuple Adapter -> WME Factory -> Engine");
    println!("==========================================================");
    println!();

    let total_start = Instant::now();
    let mut pass_count = 0u32;
    let mut fail_count = 0u32;

    // ------------------------------------------------------------------
    // Scenario 1: Medical Bill
    // ------------------------------------------------------------------
    println!("--- Scenario 1: Medical Bill ---");
    println!();

    let t0 = Instant::now();
    let mut pipeline = LocalPipeline::new();
    pipeline.load_rules(medical_bill_rules());
    let setup_time = t0.elapsed();
    println!(
        "  Rules loaded: {} productions in {:?}",
        pipeline.production_count(),
        setup_time
    );

    let t1 = Instant::now();
    let result = pipeline
        .process_extraction(medical_bill_json(), "/documents/medical_bill_2024.pdf")
        .expect("Medical bill processing should succeed");
    let process_time = t1.elapsed();

    println!("  Tuples created:     {}", result.tuples_created);
    println!("  WMEs inserted:      {}", result.wmes_inserted);
    println!("  Productions fired:  {}", result.fired_productions.len());
    println!("  Processing time:    {:?}", process_time);
    println!();

    // Verify tuple count
    if result.tuples_created == 2 {
        println!("  [PASS] Correct tuple count (2 relationships -> 2 tuples)");
        pass_count += 1;
    } else {
        println!("  [FAIL] Expected 2 tuples, got {}", result.tuples_created);
        fail_count += 1;
    }

    // Verify WME count
    if result.wmes_inserted == 2 {
        println!("  [PASS] All tuples converted to WMEs (2/2)");
        pass_count += 1;
    } else {
        println!("  [FAIL] Expected 2 WMEs, got {}", result.wmes_inserted);
        fail_count += 1;
    }

    // Verify productions fired
    let med_rule_ids: Vec<u32> = result
        .fired_productions
        .iter()
        .map(|fp| fp.rule_id)
        .collect();
    if result.fired_productions.len() == 2
        && med_rule_ids.contains(&1001)
        && med_rule_ids.contains(&1002)
    {
        println!("  [PASS] Both medical rules fired (1001: charged_total, 1002: patient_at)");
        pass_count += 1;
    } else {
        println!(
            "  [FAIL] Expected rules [1001, 1002], got {:?}",
            med_rule_ids
        );
        fail_count += 1;
    }

    // Verify confidence
    for fp in &result.fired_productions {
        let expected = fp.confidence * fp.extraction_cf;
        if (fp.chained_cf - expected).abs() < 1e-6 {
            println!(
                "  [PASS] Rule {} chained_cf = {:.4} (rule_cf={:.2} * ext_cf={:.2})",
                fp.rule_id, fp.chained_cf, fp.confidence, fp.extraction_cf
            );
            pass_count += 1;
        } else {
            println!(
                "  [FAIL] Rule {} chained_cf = {:.4}, expected {:.4}",
                fp.rule_id, fp.chained_cf, expected
            );
            fail_count += 1;
        }
    }

    // Verify working memory
    if pipeline.wme_count() == 2 {
        println!("  [PASS] Working memory has 2 WMEs");
        pass_count += 1;
    } else {
        println!(
            "  [FAIL] Working memory has {} WMEs, expected 2",
            pipeline.wme_count()
        );
        fail_count += 1;
    }

    println!();

    // ------------------------------------------------------------------
    // Scenario 2: Lease Agreement
    // ------------------------------------------------------------------
    println!("--- Scenario 2: Lease Agreement ---");
    println!();

    let t2 = Instant::now();
    let mut pipeline2 = LocalPipeline::new();
    pipeline2.load_rules(lease_agreement_rules());
    let setup_time2 = t2.elapsed();
    println!(
        "  Rules loaded: {} productions in {:?}",
        pipeline2.production_count(),
        setup_time2
    );

    let t3 = Instant::now();
    let result2 = pipeline2
        .process_extraction(lease_agreement_json(), "/documents/lease_2024.pdf")
        .expect("Lease processing should succeed");
    let process_time2 = t3.elapsed();

    println!("  Tuples created:     {}", result2.tuples_created);
    println!("  WMEs inserted:      {}", result2.wmes_inserted);
    println!("  Productions fired:  {}", result2.fired_productions.len());
    println!("  Processing time:    {:?}", process_time2);
    println!();

    // Verify tuple count
    if result2.tuples_created == 2 {
        println!("  [PASS] Correct tuple count (2 relationships -> 2 tuples)");
        pass_count += 1;
    } else {
        println!("  [FAIL] Expected 2 tuples, got {}", result2.tuples_created);
        fail_count += 1;
    }

    // Verify WME count
    if result2.wmes_inserted == 2 {
        println!("  [PASS] All tuples converted to WMEs (2/2)");
        pass_count += 1;
    } else {
        println!("  [FAIL] Expected 2 WMEs, got {}", result2.wmes_inserted);
        fail_count += 1;
    }

    // Verify productions fired
    let lease_rule_ids: Vec<u32> = result2
        .fired_productions
        .iter()
        .map(|fp| fp.rule_id)
        .collect();
    if result2.fired_productions.len() == 2
        && lease_rule_ids.contains(&2001)
        && lease_rule_ids.contains(&2002)
    {
        println!("  [PASS] Both lease rules fired (2001: charges_rent, 2002: charges_late_fee)");
        pass_count += 1;
    } else {
        println!(
            "  [FAIL] Expected rules [2001, 2002], got {:?}",
            lease_rule_ids
        );
        fail_count += 1;
    }

    // Verify confidence
    for fp in &result2.fired_productions {
        let expected = fp.confidence * fp.extraction_cf;
        if (fp.chained_cf - expected).abs() < 1e-6 {
            println!(
                "  [PASS] Rule {} chained_cf = {:.4} (rule_cf={:.2} * ext_cf={:.2})",
                fp.rule_id, fp.chained_cf, fp.confidence, fp.extraction_cf
            );
            pass_count += 1;
        } else {
            println!(
                "  [FAIL] Rule {} chained_cf = {:.4}, expected {:.4}",
                fp.rule_id, fp.chained_cf, expected
            );
            fail_count += 1;
        }
    }

    println!();

    // ------------------------------------------------------------------
    // Scenario 3: Cross-domain isolation
    // ------------------------------------------------------------------
    println!("--- Scenario 3: Cross-Domain Isolation ---");
    println!();

    let mut pipeline3 = LocalPipeline::new();
    pipeline3.load_rules(all_test_rules());
    println!(
        "  Rules loaded: {} productions (both domains)",
        pipeline3.production_count()
    );

    // Medical rules should not fire on lease data
    let r_cross1 = pipeline3
        .process_extraction(lease_agreement_json(), "/test/lease.pdf")
        .unwrap();

    let lease_fired_ids: Vec<u32> = r_cross1
        .fired_productions
        .iter()
        .map(|fp| fp.rule_id)
        .collect();
    let only_lease_rules = lease_fired_ids.iter().all(|id| *id >= 2001 && *id <= 2002);
    if only_lease_rules && r_cross1.fired_productions.len() == 2 {
        println!("  [PASS] Lease data fires only lease rules (no medical cross-fire)");
        pass_count += 1;
    } else {
        println!(
            "  [FAIL] Lease data fired unexpected rules: {:?}",
            lease_fired_ids
        );
        fail_count += 1;
    }

    // Lease rules should not fire on medical data
    let r_cross2 = pipeline3
        .process_extraction(medical_bill_json(), "/test/bill.pdf")
        .unwrap();

    let med_fired_ids: Vec<u32> = r_cross2
        .fired_productions
        .iter()
        .map(|fp| fp.rule_id)
        .collect();
    let only_med_rules = med_fired_ids.iter().all(|id| *id >= 1001 && *id <= 1002);
    if only_med_rules && r_cross2.fired_productions.len() == 2 {
        println!("  [PASS] Medical data fires only medical rules (no lease cross-fire)");
        pass_count += 1;
    } else {
        println!(
            "  [FAIL] Medical data fired unexpected rules: {:?}",
            med_fired_ids
        );
        fail_count += 1;
    }

    println!();

    // ------------------------------------------------------------------
    // Scenario 4: Error handling
    // ------------------------------------------------------------------
    println!("--- Scenario 4: Error Handling ---");
    println!();

    let mut pipeline4 = LocalPipeline::new();
    pipeline4.load_rules(all_test_rules());

    // Malformed JSON
    let bad_result = pipeline4.process_extraction("not json", "/test/bad.pdf");
    if bad_result.is_err() {
        println!("  [PASS] Malformed JSON returns Err");
        pass_count += 1;
    } else {
        println!("  [FAIL] Malformed JSON should return Err");
        fail_count += 1;
    }

    // Missing entity references
    let missing_ref_json = r#"{
        "document_category": "medical_bill",
        "entities": [{"id": "e1", "name": "X", "type": "organization", "value": "X"}],
        "relationships": [{"source": "e1", "target": "e_missing", "relationship": "r", "context": null}]
    }"#;
    let missing_result = pipeline4
        .process_extraction(missing_ref_json, "/test/missing.pdf")
        .unwrap();
    if missing_result.tuples_created == 0 {
        println!("  [PASS] Missing entity references gracefully skipped (0 tuples)");
        pass_count += 1;
    } else {
        println!(
            "  [FAIL] Expected 0 tuples for missing refs, got {}",
            missing_result.tuples_created
        );
        fail_count += 1;
    }

    // Empty extraction
    let empty_json = r#"{"document_category": "general", "entities": [], "relationships": []}"#;
    let empty_result = pipeline4
        .process_extraction(empty_json, "/test/empty.pdf")
        .unwrap();
    if empty_result.tuples_created == 0 && empty_result.fired_productions.is_empty() {
        println!("  [PASS] Empty extraction processes cleanly (0 tuples, 0 firings)");
        pass_count += 1;
    } else {
        println!("  [FAIL] Empty extraction should produce 0 tuples/firings");
        fail_count += 1;
    }

    println!();

    // ------------------------------------------------------------------
    // Scenario 5: Sequential multi-document processing
    // ------------------------------------------------------------------
    println!("--- Scenario 5: Sequential Multi-Document Processing ---");
    println!();

    let mut pipeline5 = LocalPipeline::new();
    pipeline5.load_rules(all_test_rules());

    let t5 = Instant::now();
    let mut total_tuples = 0;
    let mut total_firings = 0;
    let iterations = 100;

    for i in 0..iterations {
        let json = if i % 2 == 0 {
            medical_bill_json()
        } else {
            lease_agreement_json()
        };
        let r = pipeline5
            .process_extraction(json, &format!("/test/batch/doc_{}.pdf", i))
            .unwrap();
        total_tuples += r.tuples_created;
        total_firings += r.fired_productions.len();
    }
    let batch_time = t5.elapsed();

    println!("  Documents processed: {}", iterations);
    println!("  Total tuples:        {}", total_tuples);
    println!("  Total firings:       {}", total_firings);
    println!("  Total WMEs:          {}", pipeline5.wme_count());
    println!("  Dict size:           {} entries", pipeline5.dict_size());
    println!("  Batch time:          {:?}", batch_time);
    println!("  Per-document avg:    {:?}", batch_time / iterations);
    println!();

    if total_tuples == iterations as usize * 2 {
        println!(
            "  [PASS] All {} documents produced 2 tuples each (total: {})",
            iterations, total_tuples
        );
        pass_count += 1;
    } else {
        println!(
            "  [FAIL] Expected {} tuples, got {}",
            iterations * 2,
            total_tuples
        );
        fail_count += 1;
    }

    if total_firings == iterations as usize * 2 {
        println!(
            "  [PASS] All {} documents produced 2 firings each (total: {})",
            iterations, total_firings
        );
        pass_count += 1;
    } else {
        println!(
            "  [FAIL] Expected {} firings, got {}",
            iterations * 2,
            total_firings
        );
        fail_count += 1;
    }

    if pipeline5.wme_count() == iterations as usize * 2 {
        println!("  [PASS] Working memory has {} WMEs", pipeline5.wme_count());
        pass_count += 1;
    } else {
        println!(
            "  [FAIL] Expected {} WMEs, got {}",
            iterations * 2,
            pipeline5.wme_count()
        );
        fail_count += 1;
    }

    println!();

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------
    let total_time = total_start.elapsed();
    println!("==========================================================");
    println!("  RESULTS: {} passed, {} failed", pass_count, fail_count);
    println!("  Total time: {:?}", total_time);
    println!("==========================================================");

    if fail_count > 0 {
        std::process::exit(1);
    }
}
