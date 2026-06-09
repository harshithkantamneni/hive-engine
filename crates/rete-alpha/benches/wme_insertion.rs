//! Criterion benchmark: WME insertion throughput.
//! Benchmark protocol:
//! - 10K synthetic rules with 3-6 conditions each
//! - 100K synthetic WMEs with realistic field distributions
//! - Measure: insertion latency (median, p95, p99, max)

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::prelude::*;
use rete_alpha::alpha_network::{AlphaCondition, ConditionField};
use rete_alpha::engine::Engine;
use rete_alpha::production::RuleStatus;
use rete_alpha::wme::Wme;

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

#[allow(dead_code)] // dictionary id vectors are retained so benchmark setup can grow
                    // additional WME variants without re-plumbing the harness.
struct BenchSetup {
    wmes: Vec<Wme>,
    type_ids: Vec<u16>,
    role_ids: Vec<u16>,
    gen_ids: Vec<u16>,
    relation_ids: Vec<u16>,
    category_count: u8,
}

fn setup_engine(num_rules: usize, num_wmes: usize) -> (Engine, BenchSetup) {
    let mut engine = Engine::new();
    let mut rng = StdRng::seed_from_u64(42);

    // Realistic cardinalities per E8
    let type_ids: Vec<u16> = (0..34)
        .map(|i| {
            engine
                .entity_type_dict
                .get_or_insert(&format!("type_{}", i))
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
        .map(|i| engine.relation_dict.get_or_insert(&format!("rel_{}", i)))
        .collect();
    let _: Vec<u16> = (0..10)
        .map(|i| {
            engine
                .doc_category_dict
                .get_or_insert(&format!("cat_{}", i))
        })
        .collect();
    let category_count = 10u8;

    // Generate rules
    for rule_idx in 0..num_rules {
        let num_conds = rng.random_range(3..=6usize);
        let mut conditions = Vec::with_capacity(num_conds);
        let mut used = Vec::new();

        conditions.push(AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: type_ids[rng.random_range(0..type_ids.len())],
        });
        used.push(ConditionField::EntityAType);

        conditions.push(AlphaCondition {
            field: ConditionField::Relation,
            value_id: relation_ids[rng.random_range(0..relation_ids.len())],
        });
        used.push(ConditionField::Relation);

        conditions.push(AlphaCondition {
            field: ConditionField::DocumentCategory,
            value_id: rng.random_range(0..category_count) as u16,
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
                    role_ids[rng.random_range(0..role_ids.len())]
                }
                ConditionField::EntityAGen | ConditionField::EntityBGen => {
                    gen_ids[rng.random_range(0..gen_ids.len())]
                }
                ConditionField::EntityBType => type_ids[rng.random_range(0..type_ids.len())],
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

    // Generate WMEs
    let wmes: Vec<Wme> = (0..num_wmes)
        .map(|_| {
            Wme::new(
                type_ids[rng.random_range(0..type_ids.len())],
                role_ids[rng.random_range(0..role_ids.len())],
                gen_ids[rng.random_range(0..gen_ids.len())],
                relation_ids[rng.random_range(0..relation_ids.len())],
                type_ids[rng.random_range(0..type_ids.len())],
                role_ids[rng.random_range(0..role_ids.len())],
                gen_ids[rng.random_range(0..gen_ids.len())],
                rng.random_range(0..8),
                rng.random_range(0..category_count),
                rng.random_range(50..99) as f32 / 100.0,
            )
        })
        .collect();

    let setup = BenchSetup {
        wmes,
        type_ids,
        role_ids,
        gen_ids,
        relation_ids,
        category_count,
    };

    (engine, setup)
}

fn bench_wme_insertion(c: &mut Criterion) {
    let mut group = c.benchmark_group("wme_insertion");

    // Primary benchmark: 10K rules, single WME insertion
    let (mut engine, setup) = setup_engine(10_000, 100_000);
    let wmes = &setup.wmes;

    group.bench_function("10k_rules_single_wme", |b| {
        let mut idx = 0;
        let mut output = Vec::new();
        b.iter(|| {
            let wme = &wmes[idx % wmes.len()];
            output.clear();
            engine.insert_wme_into(black_box(wme), &mut output);
            idx += 1;
            black_box(&output);
        });
    });

    group.finish();
}

fn bench_bulk_insertion(c: &mut Criterion) {
    let mut group = c.benchmark_group("bulk_insertion");
    group.sample_size(20);

    let (mut engine, setup) = setup_engine(10_000, 100_000);

    group.bench_function("100k_wmes_bulk", |b| {
        b.iter(|| {
            let mut output = Vec::new();
            let mut total_fired = 0u64;
            for wme in &setup.wmes {
                output.clear();
                engine.insert_wme_into(black_box(wme), &mut output);
                total_fired += output.len() as u64;
            }
            black_box(total_fired)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_wme_insertion, bench_bulk_insertion);
criterion_main!(benches);
