//! JTMS Memory + Latency Benchmark
//! Success criteria:
//! - Memory for 10K rules + 100K WMEs + JTMS < 12 MB
//! - WME insertion with JTMS overhead < 1 us median

use rand::prelude::*;
use rete_alpha::alpha_network::{AlphaCondition, ConditionField};
use rete_alpha::engine::Engine;
use rete_alpha::jtms::JtmsNode;
use rete_alpha::production::RuleStatus;
use rete_alpha::wme::Wme;
use std::time::Instant;

const NUM_RULES: usize = 10_000;
const NUM_WMES: usize = 100_000;

const HASH_FIELDS: &[ConditionField] = &[
    ConditionField::EntityAType,
    ConditionField::EntityARole,
    ConditionField::EntityAGen,
    ConditionField::Relation,
    ConditionField::EntityBType,
    ConditionField::EntityBRole,
    ConditionField::EntityBGen,
    ConditionField::DocumentCategory,
];

/// Get RSS in bytes via ps on macOS
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

struct DictInfo {
    type_ids: Vec<u16>,
    role_ids: Vec<u16>,
    gen_ids: Vec<u16>,
    relation_ids: Vec<u16>,
    category_count: u8,
}

fn populate_dictionaries(engine: &mut Engine) -> DictInfo {
    let type_ids: Vec<u16> = (0..34)
        .map(|i| {
            engine
                .entity_type_dict
                .get_or_insert(&format!("entity_type_{}", i))
        })
        .collect();
    let role_ids: Vec<u16> = (0..50)
        .map(|i| {
            engine
                .entity_role_dict
                .get_or_insert(&format!("role_{}", i))
        })
        .collect();
    let gen_ids: Vec<u16> = (0..100)
        .map(|i| engine.entity_gen_dict.get_or_insert(&format!("gen_{}", i)))
        .collect();
    let relation_ids: Vec<u16> = (0..50)
        .map(|i| {
            engine
                .relation_dict
                .get_or_insert(&format!("relation_{}", i))
        })
        .collect();
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
    for cat in &doc_categories {
        engine.doc_category_dict.get_or_insert(cat);
    }

    DictInfo {
        type_ids,
        role_ids,
        gen_ids,
        relation_ids,
        category_count: doc_categories.len() as u8,
    }
}

fn main() {
    println!("=== HIVE Rete-II JTMS Benchmark ===");
    println!("Rules: {}, WMEs: {}", NUM_RULES, NUM_WMES);
    println!();

    let rss_before = get_rss_bytes();
    println!(
        "RSS before engine creation: {:.2} MB",
        rss_before as f64 / 1_048_576.0
    );

    let mut engine = Engine::new();
    let mut rng = StdRng::seed_from_u64(42);
    let dict = populate_dictionaries(&mut engine);

    // Phase 1: Add 10K rules
    let t_rules = Instant::now();
    for rule_idx in 0..NUM_RULES {
        let num_conds = rng.random_range(3..=6usize);
        let mut conditions = Vec::with_capacity(num_conds);
        let mut used = Vec::new();

        conditions.push(AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: dict.type_ids[rng.random_range(0..dict.type_ids.len())],
        });
        used.push(ConditionField::EntityAType);

        conditions.push(AlphaCondition {
            field: ConditionField::Relation,
            value_id: dict.relation_ids[rng.random_range(0..dict.relation_ids.len())],
        });
        used.push(ConditionField::Relation);

        conditions.push(AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: rng.random_range(0..dict.category_count) as u16,
        });
        used.push(ConditionField::DocumentCategory);

        let remaining = num_conds - 3;
        let mut avail: Vec<ConditionField> = HASH_FIELDS
            .iter()
            .filter(|f| !used.contains(f))
            .copied()
            .collect();
        avail.push(ConditionField::AmountBucket);

        for _ in 0..remaining {
            if avail.is_empty() {
                break;
            }
            let fi = rng.random_range(0..avail.len());
            let field = avail.remove(fi);
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
    println!();

    // Phase 2: Insert 100K WMEs WITH JTMS tracking
    let t_wmes = Instant::now();
    let mut total_fired: u64 = 0;
    let mut total_conclusions: u64 = 0;
    let mut max_fired_per_wme: usize = 0;

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

        let (_wme_key, fired, conclusions) = engine.insert_wme_with_jtms(wme, false);
        let n_fired = fired.len();
        total_fired += n_fired as u64;
        total_conclusions += conclusions.len() as u64;
        if n_fired > max_fired_per_wme {
            max_fired_per_wme = n_fired;
        }
    }
    let t_wmes_elapsed = t_wmes.elapsed();
    let rss_after_wmes = get_rss_bytes();

    // Compute latency
    let avg_ns = t_wmes_elapsed.as_nanos() as f64 / NUM_WMES as f64;

    // Separate latency measurement pass (10K samples)
    // Measure RSS BEFORE the latency pass (latency pass adds extra WMEs)
    let rss_final = get_rss_bytes();

    // Separate latency measurement pass: use insert_wme_with_jtms for realistic overhead
    // These WMEs are additional (will inflate memory) so we measure RSS before this pass
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
        // Measure insert_wme_with_jtms latency
        let (_key, _fired, _concl) = engine.insert_wme_with_jtms(wme, false);
        let elapsed = t0.elapsed().as_nanos() as u64;
        latencies_ns.push(elapsed);
    }
    latencies_ns.sort();
    let median_ns = latencies_ns[latencies_ns.len() / 2];
    let p95_ns = latencies_ns[(latencies_ns.len() as f64 * 0.95) as usize];
    let p99_ns = latencies_ns[(latencies_ns.len() as f64 * 0.99) as usize];
    let max_ns = *latencies_ns.last().unwrap();

    println!("--- WME Insertion WITH JTMS Latency ---");
    println!(
        "Total time: {:.2} ms (100K WMEs)",
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

    println!("--- JTMS Stats ---");
    println!("Total productions fired: {}", total_fired);
    println!("Total JTMS conclusions: {}", total_conclusions);
    println!("JTMS nodes: {}", engine.jtms.conclusion_count());
    println!("JTMS IN nodes: {}", engine.jtms.in_count());
    println!(
        "JTMS total justifications created: {}",
        engine.jtms.total_justifications_created
    );
    println!(
        "JTMS max cascade depth reached: {}",
        engine.jtms.max_cascade_depth_reached
    );
    println!(
        "Avg fires per WME: {:.2}",
        total_fired as f64 / NUM_WMES as f64
    );
    println!("Max fires per WME: {}", max_fired_per_wme);
    println!();

    println!("--- Memory ---");
    println!(
        "RSS before:       {:.2} MB",
        rss_before as f64 / 1_048_576.0
    );
    println!(
        "RSS after rules:  {:.2} MB",
        rss_after_rules as f64 / 1_048_576.0
    );
    println!(
        "RSS after WMEs:   {:.2} MB",
        rss_after_wmes as f64 / 1_048_576.0
    );
    println!("RSS final:        {:.2} MB", rss_final as f64 / 1_048_576.0);
    let mem_delta = (rss_final - rss_before) as f64 / 1_048_576.0;
    println!("Total engine memory (RSS delta): {:.2} MB", mem_delta);
    println!("WMEs in working memory: {}", engine.wme_count());
    println!();

    // Struct sizes
    let jtms_node_size = std::mem::size_of::<JtmsNode>();
    let justification_size = std::mem::size_of::<rete_alpha::jtms::Justification>();
    let conclusion_id_size = std::mem::size_of::<rete_alpha::jtms::ConclusionId>();
    println!("--- JTMS Struct Sizes ---");
    println!("JtmsNode: {} bytes", jtms_node_size);
    println!("Justification: {} bytes", justification_size);
    println!("ConclusionId: {} bytes", conclusion_id_size);
    println!();

    // Success criteria
    println!("=== SUCCESS CRITERIA ===");
    let median_pass = median_ns < 1000;
    let mem_pass = mem_delta < 12.0;

    println!(
        "Median insertion+JTMS: {} ns  [target < 1000 ns]  {}",
        median_ns,
        if median_pass { "PASS" } else { "FAIL" }
    );
    println!(
        "Memory (total):        {:.2} MB [target < 12 MB]    {}",
        mem_delta,
        if mem_pass { "PASS" } else { "FAIL" }
    );
}
