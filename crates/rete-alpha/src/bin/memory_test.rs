//! Memory measurement: create 10K rules + 100K WMEs and report RSS.
//! Success criteria: < 10MB for 10K rules + 100K WMEs.

use rand::prelude::*;
use rete_alpha::alpha_network::{AlphaCondition, ConditionField};
use rete_alpha::engine::Engine;
use rete_alpha::production::RuleStatus;
use rete_alpha::wme::Wme;
use std::time::Instant;

const NUM_RULES: usize = 10_000;
const NUM_WMES: usize = 100_000;

/// Get RSS in bytes via sysctl on macOS
fn get_rss_bytes() -> usize {
    use std::process::Command;
    let pid = std::process::id();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .expect("failed to run ps");
    let rss_kb: usize = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or(0);
    rss_kb * 1024
}

/// Generate realistic rule conditions per E8/R5/R8 patterns.
/// Realistic field cardinalities:
/// - entity_a_type: ~34 types (E8)
/// - entity_a_role: ~50 roles
/// - entity_a_gen: ~100 generalizations (hierarchy levels)
/// - relation: ~50 relations
/// - entity_b_type: ~34 types
/// - entity_b_role: ~50 roles
/// - entity_b_gen: ~100 generalizations
/// - document_category: 10 categories
fn populate_dictionaries(engine: &mut Engine, _rng: &mut StdRng) -> DictInfo {
    // Entity types (34 per E8)
    let entity_types: Vec<String> = (0..34).map(|i| format!("entity_type_{}", i)).collect();
    let type_ids: Vec<u16> = entity_types
        .iter()
        .map(|s| engine.entity_type_dict.get_or_insert(s))
        .collect();

    // Entity roles (~50)
    let entity_roles: Vec<String> = (0..50).map(|i| format!("role_{}", i)).collect();
    let role_ids: Vec<u16> = entity_roles
        .iter()
        .map(|s| engine.entity_role_dict.get_or_insert(s))
        .collect();

    // Generalizations (~100 -- reflects hierarchy levels)
    let entity_gens: Vec<String> = (0..100).map(|i| format!("gen_{}", i)).collect();
    let gen_ids: Vec<u16> = entity_gens
        .iter()
        .map(|s| engine.entity_gen_dict.get_or_insert(s))
        .collect();

    // Relations (~50)
    let relations: Vec<String> = (0..50).map(|i| format!("relation_{}", i)).collect();
    let relation_ids: Vec<u16> = relations
        .iter()
        .map(|s| engine.relation_dict.get_or_insert(s))
        .collect();

    // Document categories (10)
    let doc_categories = [
        "medical_bill",
        "insurance_eob",
        "lease",
        "receipt",
        "bank_statement",
        "pay_stub",
        "utility_bill",
        "prescription",
        "government_form",
        "credit_card",
    ];
    let _cat_ids: Vec<u16> = doc_categories
        .iter()
        .map(|s| engine.doc_category_dict.get_or_insert(s))
        .collect();

    DictInfo {
        type_ids,
        role_ids,
        gen_ids,
        relation_ids,
        category_count: doc_categories.len() as u8,
    }
}

struct DictInfo {
    type_ids: Vec<u16>,
    role_ids: Vec<u16>,
    gen_ids: Vec<u16>,
    relation_ids: Vec<u16>,
    category_count: u8,
}

fn main() {
    println!("=== HIVE Rete-II Alpha Network Memory Test ===");
    println!("Rules: {}, WMEs: {}", NUM_RULES, NUM_WMES);
    println!();

    let rss_before = get_rss_bytes();
    println!(
        "RSS before engine creation: {:.2} MB",
        rss_before as f64 / 1_048_576.0
    );

    let mut engine = Engine::new();
    let mut rng = StdRng::seed_from_u64(42);

    let dict = populate_dictionaries(&mut engine, &mut rng);

    let hash_fields = [
        ConditionField::EntityAType,
        ConditionField::EntityARole,
        ConditionField::EntityAGen,
        ConditionField::Relation,
        ConditionField::EntityBType,
        ConditionField::EntityBRole,
        ConditionField::EntityBGen,
        ConditionField::DocumentCategory,
    ];

    // Phase 1: Add 10K rules
    // Realistic: rules cluster by document_category (each category has ~1000 rules)
    // Each rule has 3-6 conditions, always including entity_a_type, relation, doc_category
    let t_rules = Instant::now();
    for rule_idx in 0..NUM_RULES {
        let num_conditions = rng.random_range(3..=6usize);
        let mut conditions = Vec::with_capacity(num_conditions);
        let mut used_fields = Vec::new();

        // Always: entity_a_type, relation, document_category
        conditions.push(AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: dict.type_ids[rng.random_range(0..dict.type_ids.len())],
        });
        used_fields.push(ConditionField::EntityAType);

        conditions.push(AlphaCondition {
            field: ConditionField::Relation,
            value_id: dict.relation_ids[rng.random_range(0..dict.relation_ids.len())],
        });
        used_fields.push(ConditionField::Relation);

        conditions.push(AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: rng.random_range(0..dict.category_count) as u16,
        });
        used_fields.push(ConditionField::DocumentCategory);

        let remaining = num_conditions - 3;
        let mut available: Vec<ConditionField> = hash_fields
            .iter()
            .filter(|f| !used_fields.contains(f))
            .copied()
            .collect();
        available.push(ConditionField::AmountBucket);

        for _ in 0..remaining {
            if available.is_empty() {
                break;
            }
            let fi = rng.random_range(0..available.len());
            let field = available.remove(fi);
            let value_id = match field {
                ConditionField::EntityARole | ConditionField::EntityBRole => {
                    dict.role_ids[rng.random_range(0..dict.role_ids.len())]
                }
                ConditionField::EntityAGen | ConditionField::EntityBGen => {
                    dict.gen_ids[rng.random_range(0..dict.gen_ids.len())]
                }
                ConditionField::EntityBType => {
                    dict.type_ids[rng.random_range(0..dict.type_ids.len())]
                }
                ConditionField::AmountBucket => {
                    let t = rng.random_range(0..8u8);
                    (t..8).fold(0u8, |m, b| m | (1 << b)) as u16
                }
                _ => rng.random_range(0..10) as u16,
            };
            conditions.push(AlphaCondition { field, value_id });
        }

        let status = match rng.random_range(0..10u32) {
            0..=6 => RuleStatus::Active,
            7..=8 => RuleStatus::Candidate,
            _ => RuleStatus::Weakened,
        };
        let confidence = rng.random_range(30..95) as f32 / 100.0;
        engine.add_production(rule_idx as u32, &conditions, status, confidence);
    }
    let t_rules_elapsed = t_rules.elapsed();

    let rss_after_rules = get_rss_bytes();
    println!(
        "Rules compiled in {:.2} ms",
        t_rules_elapsed.as_secs_f64() * 1000.0
    );
    println!(
        "RSS after {} rules: {:.2} MB",
        NUM_RULES,
        rss_after_rules as f64 / 1_048_576.0
    );
    println!(
        "Rule compilation memory: {:.2} MB",
        (rss_after_rules - rss_before) as f64 / 1_048_576.0
    );
    println!("Productions registered: {}", engine.production_count());
    println!();

    // Phase 2: Insert 100K WMEs
    let t_wmes = Instant::now();
    let mut total_fired: u64 = 0;
    let mut max_fired_per_wme: usize = 0;
    let mut fire_counts = Vec::with_capacity(NUM_WMES);
    let mut output = Vec::new();

    for _ in 0..NUM_WMES {
        let wme = Wme::new(
            dict.type_ids[rng.random_range(0..dict.type_ids.len())],
            dict.role_ids[rng.random_range(0..dict.role_ids.len())],
            dict.gen_ids[rng.random_range(0..dict.gen_ids.len())],
            dict.relation_ids[rng.random_range(0..dict.relation_ids.len())],
            dict.type_ids[rng.random_range(0..dict.type_ids.len())],
            dict.role_ids[rng.random_range(0..dict.role_ids.len())],
            dict.gen_ids[rng.random_range(0..dict.gen_ids.len())],
            rng.random_range(0..8),
            rng.random_range(0..dict.category_count),
            rng.random_range(50..99) as f32 / 100.0,
        );

        output.clear();
        engine.insert_wme_into(&wme, &mut output);

        let fired = output.len();
        total_fired += fired as u64;
        if fired > max_fired_per_wme {
            max_fired_per_wme = fired;
        }
        fire_counts.push(fired);

        // Store in working memory
        engine.working_memory.insert(wme);
    }
    let t_wmes_elapsed = t_wmes.elapsed();

    let rss_final = get_rss_bytes();

    // Compute fire count statistics
    fire_counts.sort();
    let median_fires = fire_counts[fire_counts.len() / 2];
    let p95_fires = fire_counts[(fire_counts.len() as f64 * 0.95) as usize];
    let p99_fires = fire_counts[(fire_counts.len() as f64 * 0.99) as usize];
    let avg_fires = total_fired as f64 / NUM_WMES as f64;

    // Compute latency from total time (per-WME Instant::now() has ~20ns overhead that skews results)
    let avg_ns = t_wmes_elapsed.as_nanos() as f64 / NUM_WMES as f64;

    // For percentile measurements, do a separate pass with batched timing
    // Sample 10K WMEs with individual timing
    let mut latencies_ns = Vec::with_capacity(10_000);
    let mut rng2 = StdRng::seed_from_u64(99);
    for _ in 0..10_000 {
        let wme = Wme::new(
            dict.type_ids[rng2.random_range(0..dict.type_ids.len())],
            dict.role_ids[rng2.random_range(0..dict.role_ids.len())],
            dict.gen_ids[rng2.random_range(0..dict.gen_ids.len())],
            dict.relation_ids[rng2.random_range(0..dict.relation_ids.len())],
            dict.type_ids[rng2.random_range(0..dict.type_ids.len())],
            dict.role_ids[rng2.random_range(0..dict.role_ids.len())],
            dict.gen_ids[rng2.random_range(0..dict.gen_ids.len())],
            rng2.random_range(0..8),
            rng2.random_range(0..dict.category_count),
            rng2.random_range(50..99) as f32 / 100.0,
        );
        let t0 = Instant::now();
        output.clear();
        engine.insert_wme_into(&wme, &mut output);
        let elapsed = t0.elapsed().as_nanos() as u64;
        latencies_ns.push(elapsed);
    }
    latencies_ns.sort();
    let median_ns = latencies_ns[latencies_ns.len() / 2];
    let p95_ns = latencies_ns[(latencies_ns.len() as f64 * 0.95) as usize];
    let p99_ns = latencies_ns[(latencies_ns.len() as f64 * 0.99) as usize];
    let max_ns = *latencies_ns.last().unwrap();

    println!("--- WME Insertion Latency ---");
    println!(
        "Total time: {:.2} ms",
        t_wmes_elapsed.as_secs_f64() * 1000.0
    );
    println!(
        "Avg latency:    {:>8.0} ns ({:.3} us)",
        avg_ns,
        avg_ns / 1000.0
    );
    println!(
        "Median latency: {:>8} ns ({:.3} us)",
        median_ns,
        median_ns as f64 / 1000.0
    );
    println!(
        "P95 latency:    {:>8} ns ({:.3} us)",
        p95_ns,
        p95_ns as f64 / 1000.0
    );
    println!(
        "P99 latency:    {:>8} ns ({:.3} us)",
        p99_ns,
        p99_ns as f64 / 1000.0
    );
    println!(
        "Max latency:    {:>8} ns ({:.3} us)",
        max_ns,
        max_ns as f64 / 1000.0
    );
    println!();
    println!("--- Rule Firing Stats ---");
    println!("Total productions fired: {}", total_fired);
    println!("Avg fires per WME: {:.2}", avg_fires);
    println!("Median fires per WME: {}", median_fires);
    println!("P95 fires per WME: {}", p95_fires);
    println!("P99 fires per WME: {}", p99_fires);
    println!("Max fires per WME: {}", max_fired_per_wme);
    println!(
        "Rules fired per second: {:.0}",
        total_fired as f64 / t_wmes_elapsed.as_secs_f64()
    );
    println!();
    println!("--- Memory ---");
    println!("RSS final: {:.2} MB", rss_final as f64 / 1_048_576.0);
    println!(
        "Total engine memory (RSS delta): {:.2} MB",
        (rss_final - rss_before) as f64 / 1_048_576.0
    );
    println!("WMEs in working memory: {}", engine.wme_count());
    println!();

    // Size analysis
    let wme_size = std::mem::size_of::<Wme>();
    let prod_size = std::mem::size_of::<rete_alpha::production::Production>();
    println!("--- Struct Sizes ---");
    println!("Wme: {} bytes", wme_size);
    println!("Production: {} bytes", prod_size);
    println!(
        "Estimated WME storage ({}): {:.2} KB",
        NUM_WMES,
        (wme_size * NUM_WMES) as f64 / 1024.0
    );
    println!(
        "Estimated Production storage ({}): {:.2} KB",
        NUM_RULES,
        (prod_size * NUM_RULES) as f64 / 1024.0
    );

    // Pass/fail check
    println!();
    println!("=== SUCCESS CRITERIA ===");
    let mem_mb = (rss_final - rss_before) as f64 / 1_048_576.0;

    let median_pass = median_ns < 1000;
    let p99_pass = p99_ns < 5000;
    let mem_pass = mem_mb < 10.0;

    println!(
        "Median WME insertion: {} ns  [target < 1000 ns]  {}",
        median_ns,
        if median_pass { "PASS" } else { "FAIL" }
    );
    println!(
        "P99 WME insertion:    {} ns  [target < 5000 ns]  {}",
        p99_ns,
        if p99_pass { "PASS" } else { "FAIL" }
    );
    println!(
        "Memory usage:         {:.2} MB  [target < 10 MB]    {}",
        mem_mb,
        if mem_pass { "PASS" } else { "FAIL" }
    );
}
