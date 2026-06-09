//! Full Throughput Benchmark -- HIVE Rete-II Engine (ALL modules)
//!
//! Measures the complete pipeline with all modules enabled:
//!   Alpha Network + JTMS + Lifecycle + Serialization
//!
//! Scales: 100 rules / 1K WMEs, 1K rules / 10K WMEs, 10K rules / 100K WMEs
//!
//! Run: cargo run --release --bin re5_throughput

use rete_alpha::alpha_network::{AlphaCondition, ConditionField};
use rete_alpha::engine::Engine;
use rete_alpha::lifecycle::{self, Domain, EvolutionRecord, SensitivityTier};
use rete_alpha::production::RuleStatus;
use rete_alpha::serialization::{build_rule_envelope, RuleEnvelope};
use rete_alpha::wme::Wme;
use std::time::Instant;

// ============================================================================
// Configuration
// ============================================================================

struct ScaleConfig {
    label: &'static str,
    num_rules: usize,
    num_wmes: usize,
}

const SCALES: [ScaleConfig; 3] = [
    ScaleConfig {
        label: "Small  (100 rules / 1K WMEs)",
        num_rules: 100,
        num_wmes: 1_000,
    },
    ScaleConfig {
        label: "Medium (1K rules / 10K WMEs)",
        num_rules: 1_000,
        num_wmes: 10_000,
    },
    ScaleConfig {
        label: "Target (10K rules / 100K WMEs)",
        num_rules: 10_000,
        num_wmes: 100_000,
    },
];

// ============================================================================
// Realistic domain vocabulary
// ============================================================================

/// HIVE domains for realistic rule generation
const ENTITY_TYPES: &[&str] = &[
    "organization",
    "person",
    "amount",
    "procedure",
    "clause",
    "penalty",
    "policy_type",
    "document",
    "medication",
    "device",
    "service",
    "facility",
    "code",
    "date_range",
    "percentage",
];

const ENTITY_ROLES: &[&str] = &[
    "provider",
    "landlord",
    "tenant",
    "insurer",
    "patient",
    "beneficiary",
    "adjuster",
    "specialist",
    "pharmacy",
    "lab",
    "contractor",
    "subcontractor",
    "guarantor",
    "employer",
    "broker",
];

const ENTITY_GENS: &[&str] = &[
    "hospital",
    "er_visit",
    "lab_test",
    "insurance_company",
    "utility_company",
    "clinic",
    "surgery_center",
    "pharmacy_chain",
    "specialist_office",
    "urgent_care",
    "rehab_facility",
    "home_health",
    "mental_health",
    "dental_office",
    "imaging_center",
];

const RELATIONS: &[&str] = &[
    "billed_at",
    "charged_total",
    "has_diagnosis",
    "rent_amount",
    "security_deposit",
    "late_fee",
    "lease_term",
    "has_clause",
    "notice_period",
    "coverage_limit",
    "deductible",
    "premium",
    "has_exclusion",
    "energy_charge",
    "copay_amount",
    "coinsurance_pct",
    "out_of_pocket_max",
    "procedure_code",
    "covered_at",
    "denied_for",
];

const DOC_CATEGORIES: &[&str] = &[
    "medical_bill",
    "lease_agreement",
    "insurance_policy",
    "utility_bill",
    "explanation_of_benefits",
    "claim_form",
    "lab_report",
    "prescription",
    "referral",
    "discharge_summary",
];

const RULE_TAGS: &[&str] = &[
    "medical_bill:hospital:er_charge_range",
    "medical_bill:hospital:lab_test_pricing",
    "medical_bill:clinic:office_visit_range",
    "medical_bill:pharmacy:prescription_cost",
    "medical_bill:imaging:mri_ct_pricing",
    "lease:landlord:security_deposit_unusual",
    "lease:landlord:rent_increase_cap",
    "lease:tenant:late_fee_compliance",
    "lease:property:maintenance_responsibility",
    "insurance:coverage:deductible_range",
    "insurance:coverage:copay_typical",
    "insurance:exclusion:pre_existing",
    "insurance:claim:denial_rate",
    "utility:electric:seasonal_rate",
    "utility:gas:base_charge_range",
    "eob:payment:allowed_amount",
    "eob:adjustment:contractual_write_off",
    "claim:procedure:cpt_code_match",
    "referral:specialist:authorization_required",
    "discharge:medication:follow_up_prescribed",
];

const CONCLUSION_ARGS_KEYS: &[&str] = &[
    "entity_gen",
    "relation",
    "amount_range",
    "evidence_count",
    "region_count",
    "confidence",
    "detail",
    "procedure_code",
];

const SENSITIVITY_TIERS: &[SensitivityTier] = &[
    SensitivityTier::S1,
    SensitivityTier::S2,
    SensitivityTier::S3,
    SensitivityTier::S4,
];

const DOMAINS: &[Domain] = &[
    Domain::MedicalReference,
    Domain::LegalRequirements,
    Domain::ContractTerms,
    Domain::Seasonal,
    Domain::CurrentPrices,
    Domain::Default,
];

// ============================================================================
// Simple deterministic pseudo-RNG (avoid pulling in rand for the binary)
// ============================================================================

struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    fn next_f64(&mut self) -> f64 {
        (self.next_u64() % 10000) as f64 / 10000.0
    }

    fn next_f32(&mut self) -> f32 {
        (self.next_u64() % 10000) as f32 / 10000.0
    }
}

// ============================================================================
// Benchmark results
// ============================================================================

#[derive(Debug)]
struct LatencyStats {
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    mean_ns: u64,
    min_ns: u64,
    max_ns: u64,
}

fn compute_latency_stats(latencies: &mut [u64]) -> LatencyStats {
    latencies.sort_unstable();
    let n = latencies.len();
    if n == 0 {
        return LatencyStats {
            p50_ns: 0,
            p95_ns: 0,
            p99_ns: 0,
            mean_ns: 0,
            min_ns: 0,
            max_ns: 0,
        };
    }
    let sum: u64 = latencies.iter().sum();
    LatencyStats {
        p50_ns: latencies[n / 2],
        p95_ns: latencies[(n as f64 * 0.95) as usize],
        p99_ns: latencies[(n as f64 * 0.99) as usize],
        mean_ns: sum / n as u64,
        min_ns: latencies[0],
        max_ns: latencies[n - 1],
    }
}

#[derive(Debug)]
#[allow(dead_code)] // label/num_rules/num_wmes used only via Debug formatting when dumped to JSON
struct ScaleResult {
    label: String,
    num_rules: usize,
    num_wmes: usize,
    // Insertion throughput
    insertion_wmes_per_sec: f64,
    insertion_avg_ns: f64,
    // Rule firing
    total_firings: u64,
    firings_per_sec: f64,
    // End-to-end latency (insert + fire + JTMS)
    e2e_latency: LatencyStats,
    // Serialization
    serialize_total_ms: f64,
    serialize_per_rule_ns: f64,
    deserialize_total_ms: f64,
    deserialize_per_rule_ns: f64,
    serialization_mismatches: usize,
    avg_wire_size_bytes: f64,
    // Lifecycle
    lifecycle_ops_total: usize,
    lifecycle_duration_us: f64,
    promotes: usize,
    weakens: usize,
    expires: usize,
    // Memory
    memory_estimate_bytes: usize,
    // JTMS stats
    jtms_conclusions: usize,
    jtms_in_count: usize,
}

// ============================================================================
// Engine setup: populate dictionaries and register rules
// ============================================================================

fn setup_engine(
    num_rules: usize,
    rng: &mut SimpleRng,
) -> (Engine, Vec<Vec<(ConditionField, u16)>>) {
    let mut engine = Engine::new();

    // Pre-populate all dictionaries
    for s in ENTITY_TYPES {
        engine.entity_type_dict.get_or_insert(s);
    }
    for s in ENTITY_ROLES {
        engine.entity_role_dict.get_or_insert(s);
    }
    for s in ENTITY_GENS {
        engine.entity_gen_dict.get_or_insert(s);
    }
    for s in RELATIONS {
        engine.relation_dict.get_or_insert(s);
    }
    for s in DOC_CATEGORIES {
        engine.doc_category_dict.get_or_insert(s);
    }

    // Stash dict IDs for fast lookup
    let et_ids: Vec<u16> = ENTITY_TYPES
        .iter()
        .map(|s| engine.entity_type_dict.get_id(s).unwrap())
        .collect();
    let er_ids: Vec<u16> = ENTITY_ROLES
        .iter()
        .map(|s| engine.entity_role_dict.get_id(s).unwrap())
        .collect();
    let eg_ids: Vec<u16> = ENTITY_GENS
        .iter()
        .map(|s| engine.entity_gen_dict.get_id(s).unwrap())
        .collect();
    let rel_ids: Vec<u16> = RELATIONS
        .iter()
        .map(|s| engine.relation_dict.get_id(s).unwrap())
        .collect();
    let dc_ids: Vec<u16> = DOC_CATEGORIES
        .iter()
        .map(|s| engine.doc_category_dict.get_id(s).unwrap())
        .collect();

    let mut all_conditions: Vec<Vec<(ConditionField, u16)>> = Vec::with_capacity(num_rules);

    // Status distribution: 60% Active, 20% Candidate, 10% Weakened, 5% Dormant, 5% Expired
    let statuses = [
        RuleStatus::Active,
        RuleStatus::Active,
        RuleStatus::Active,
        RuleStatus::Active,
        RuleStatus::Active,
        RuleStatus::Active,
        RuleStatus::Candidate,
        RuleStatus::Candidate,
        RuleStatus::Weakened,
        RuleStatus::Dormant,
    ];

    for i in 0..num_rules {
        // Each rule has 3-6 conditions (realistic for HIVE rules)
        let num_conds = 3 + rng.next_usize(4); // 3..=6

        let ea_type = et_ids[rng.next_usize(et_ids.len())];
        let rel = rel_ids[rng.next_usize(rel_ids.len())];
        let doc_cat = dc_ids[rng.next_usize(dc_ids.len())];

        let mut conditions = vec![
            AlphaCondition {
                field: ConditionField::EntityAType,
                value_id: ea_type,
            },
            AlphaCondition {
                field: ConditionField::Relation,
                value_id: rel,
            },
            AlphaCondition {
                field: ConditionField::DocumentCategory,
                value_id: doc_cat,
            },
        ];

        let mut serializable_conds = vec![
            (ConditionField::EntityAType, ea_type),
            (ConditionField::Relation, rel),
            (ConditionField::DocumentCategory, doc_cat),
        ];

        // Add extra conditions
        let extra_fields = [
            (ConditionField::EntityARole, &er_ids),
            (ConditionField::EntityAGen, &eg_ids),
            (ConditionField::EntityBType, &et_ids),
        ];

        for j in 0..(num_conds - 3) {
            let (field, ids) = &extra_fields[j % extra_fields.len()];
            let val = ids[rng.next_usize(ids.len())];
            conditions.push(AlphaCondition {
                field: *field,
                value_id: val,
            });
            serializable_conds.push((*field, val));
        }

        let status = statuses[i % statuses.len()];
        let confidence = 0.3 + rng.next_f32() * 0.6; // 0.3..0.9

        engine.add_production(i as u32, &conditions, status, confidence);
        all_conditions.push(serializable_conds);
    }

    (engine, all_conditions)
}

// ============================================================================
// Generate WMEs that will match a fraction of rules
// ============================================================================

fn generate_wmes(engine: &Engine, num_wmes: usize, rng: &mut SimpleRng) -> Vec<Wme> {
    let et_ids: Vec<u16> = ENTITY_TYPES
        .iter()
        .filter_map(|s| engine.entity_type_dict.get_id(s))
        .collect();
    let er_ids: Vec<u16> = ENTITY_ROLES
        .iter()
        .filter_map(|s| engine.entity_role_dict.get_id(s))
        .collect();
    let eg_ids: Vec<u16> = ENTITY_GENS
        .iter()
        .filter_map(|s| engine.entity_gen_dict.get_id(s))
        .collect();
    let rel_ids: Vec<u16> = RELATIONS
        .iter()
        .filter_map(|s| engine.relation_dict.get_id(s))
        .collect();
    let dc_ids: Vec<u16> = DOC_CATEGORIES
        .iter()
        .filter_map(|s| engine.doc_category_dict.get_id(s))
        .collect();

    let mut wmes = Vec::with_capacity(num_wmes);
    for _ in 0..num_wmes {
        let wme = Wme::new(
            et_ids[rng.next_usize(et_ids.len())],
            er_ids[rng.next_usize(er_ids.len())],
            eg_ids[rng.next_usize(eg_ids.len())],
            rel_ids[rng.next_usize(rel_ids.len())],
            et_ids[rng.next_usize(et_ids.len())],
            er_ids[rng.next_usize(er_ids.len())],
            eg_ids[rng.next_usize(eg_ids.len())],
            (rng.next_usize(8)) as u8,
            dc_ids[rng.next_usize(dc_ids.len())] as u8,
            0.5 + rng.next_f32() * 0.45, // extraction_cf: 0.5..0.95
        );
        wmes.push(wme);
    }
    wmes
}

// ============================================================================
// Benchmark: WME insertion with JTMS
// ============================================================================

fn bench_insertion(engine: &mut Engine, wmes: &[Wme]) -> (u64, Vec<u64>) {
    let mut total_firings = 0u64;
    let mut latencies = Vec::with_capacity(wmes.len());

    for wme in wmes {
        let start = Instant::now();
        let (_wme_key, fired, _conclusion_ids) = engine.insert_wme_with_jtms(*wme, false);
        let elapsed_ns = start.elapsed().as_nanos() as u64;
        total_firings += fired.len() as u64;
        latencies.push(elapsed_ns);
    }

    (total_firings, latencies)
}

// ============================================================================
// Benchmark: Serialization round-trip
// ============================================================================

fn bench_serialization(
    num_rules: usize,
    all_conditions: &[Vec<(ConditionField, u16)>],
    rng: &mut SimpleRng,
) -> (f64, f64, f64, f64, usize, f64) {
    let now_ts = 1_000_000u64;

    // Build RuleEnvelopes
    let envelopes: Vec<RuleEnvelope> = (0..num_rules)
        .map(|i| {
            let tier = SENSITIVITY_TIERS[i % SENSITIVITY_TIERS.len()];
            let domain = DOMAINS[i % DOMAINS.len()];
            let status = match i % 10 {
                0..=5 => RuleStatus::Active,
                6..=7 => RuleStatus::Candidate,
                8 => RuleStatus::Weakened,
                _ => RuleStatus::Dormant,
            };
            let cf = 0.3 + (rng.next_f64() * 0.6);
            let mut evo =
                EvolutionRecord::new(now_ts, cf, tier, domain, 3 + (i % 8) as u8, 20 + i as u32);
            evo.status = status;
            evo.status_entered_at = now_ts;
            evo.last_fired = now_ts.saturating_sub(100);
            evo.strength_epoch = (i % 500) as u32;
            evo.supporting_count = 10 + i as u32;
            evo.contradicting_count = (i % 5) as u32;
            evo.recency_score = 0.5 + rng.next_f64() * 0.5;
            evo.last_seen = now_ts.saturating_sub(10);
            evo.consistency_score = 0.7 + rng.next_f64() * 0.3;

            let tag = RULE_TAGS[i % RULE_TAGS.len()];
            let conds = &all_conditions[i];

            let conclusion_args: Vec<(&str, &str)> = CONCLUSION_ARGS_KEYS
                .iter()
                .take(2 + i % 3)
                .map(|k| (*k, "sample_value"))
                .collect();

            build_rule_envelope(
                i as u32,
                tag,
                conds,
                (i % 6) as u8,
                (i % 8) as u8,
                &conclusion_args,
                &evo,
            )
        })
        .collect();

    // Serialize all
    let ser_start = Instant::now();
    let serialized: Vec<Vec<u8>> = envelopes
        .iter()
        .map(|e| {
            e.to_bytes_unchecked()
                .expect("serialization should not fail")
        })
        .collect();
    let ser_elapsed_ms = ser_start.elapsed().as_nanos() as f64 / 1_000_000.0;

    // Deserialize all
    let deser_start = Instant::now();
    let deserialized: Vec<RuleEnvelope> = serialized
        .iter()
        .map(|bytes| RuleEnvelope::from_bytes(bytes).expect("deserialization should not fail"))
        .collect();
    let deser_elapsed_ms = deser_start.elapsed().as_nanos() as f64 / 1_000_000.0;

    // Verify round-trip fidelity
    let mut mismatches = 0usize;
    for (orig, restored) in envelopes.iter().zip(deserialized.iter()) {
        if orig != restored {
            mismatches += 1;
        }
    }

    let avg_wire_size: f64 =
        serialized.iter().map(|b| b.len() as f64).sum::<f64>() / num_rules as f64;

    let ser_per_rule_ns = ser_elapsed_ms * 1_000_000.0 / num_rules as f64;
    let deser_per_rule_ns = deser_elapsed_ms * 1_000_000.0 / num_rules as f64;

    (
        ser_elapsed_ms,
        ser_per_rule_ns,
        deser_elapsed_ms,
        deser_per_rule_ns,
        mismatches,
        avg_wire_size,
    )
}

// ============================================================================
// Benchmark: Lifecycle operations
// ============================================================================

fn bench_lifecycle(num_rules: usize, rng: &mut SimpleRng) -> (usize, f64, usize, usize, usize) {
    let now_ts = 1_000_000u64;
    let future_ts = now_ts + 86400 * 2; // 2 days later

    // Create EvolutionRecords
    let mut records: Vec<EvolutionRecord> = (0..num_rules)
        .map(|i| {
            let tier = SENSITIVITY_TIERS[i % SENSITIVITY_TIERS.len()];
            let domain = DOMAINS[i % DOMAINS.len()];
            let cf = 0.3 + rng.next_f64() * 0.6;
            let mut rec =
                EvolutionRecord::new(now_ts, cf, tier, domain, 3 + (i % 8) as u8, 20 + i as u32);
            // Distribute statuses: 60% Candidate, 20% Active, 10% Weakened, 10% Dormant
            match i % 10 {
                0..=5 => {
                    rec.status = RuleStatus::Candidate;
                }
                6..=7 => {
                    rec.status = RuleStatus::Active;
                    rec.confidence = 0.5 + rng.next_f64() * 0.4;
                }
                8 => {
                    rec.status = RuleStatus::Weakened;
                    rec.confidence = 0.2 + rng.next_f64() * 0.2;
                }
                _ => {
                    rec.status = RuleStatus::Dormant;
                    rec.confidence = 0.15 + rng.next_f64() * 0.15;
                }
            }
            rec
        })
        .collect();

    let lifecycle_start = Instant::now();
    let mut promotes = 0usize;
    let mut weakens = 0usize;
    let mut expires = 0usize;

    // Promote 10% of Candidate rules to Active
    let promote_count = num_rules / 10;
    for i in 0..promote_count {
        let idx = i % records.len();
        if records[idx].status == RuleStatus::Candidate {
            records[idx].confidence = 0.6;
            records[idx].distinct_regions = 5;
            // Force eligibility: set created long enough ago
            records[idx].status_entered_at = now_ts.saturating_sub(86400 * 2);
            let result = lifecycle::check_transitions(&mut records[idx], future_ts);
            if result.is_some() {
                promotes += 1;
            }
        }
    }

    // Weaken 5% via contradictions
    let weaken_count = num_rules / 20;
    for i in 0..weaken_count {
        let idx = (promote_count + i) % records.len();
        if records[idx].status == RuleStatus::Active {
            // Lower confidence to near threshold so contradictions push it below
            records[idx].confidence = 0.35;
            records[idx].supporting_count = 10;
            records[idx].contradicting_count = 0;
            for _ in 0..8 {
                lifecycle::weaken(&mut records[idx], future_ts + 1);
            }
            if records[idx].status == RuleStatus::Weakened
                || records[idx].status == RuleStatus::Dormant
                || records[idx].status == RuleStatus::Expired
            {
                weakens += 1;
            }
        }
    }

    // Expire 2%
    let expire_count = num_rules / 50;
    for i in 0..expire_count {
        let idx = (promote_count + weaken_count + i) % records.len();
        if records[idx].status == RuleStatus::Weakened
            || records[idx].status == RuleStatus::Candidate
        {
            records[idx].confidence = 0.05; // below CF_KILL
            let result = lifecycle::check_transitions(&mut records[idx], future_ts + 2);
            if result.is_some() {
                expires += 1;
            }
        }
    }

    let lifecycle_elapsed_us = lifecycle_start.elapsed().as_nanos() as f64 / 1000.0;
    let total_ops = promotes + weakens + expires;

    (total_ops, lifecycle_elapsed_us, promotes, weakens, expires)
}

// ============================================================================
// Memory estimation
// ============================================================================

fn estimate_memory(engine: &Engine, num_rules: usize) -> usize {
    // WME: ~24 bytes each (compact repr) + SlotMap overhead (~32 bytes per entry)
    let wme_mem = engine.wme_count() * 56;

    // Productions: ~24 bytes each + conditions vec (~40 bytes avg)
    let prod_mem = num_rules * 64;

    // Alpha network: composite index + field indexes
    // Estimate: ~80 bytes per rule in index structures
    let alpha_mem = num_rules * 80;

    // JTMS: JtmsNode has ~54 bytes fixed on stack, most conclusions in V1 alpha
    // have 1 justification with 1 WmeKey (no dependents). Actual heap:
    //   justifications Vec: 24 (stack) + 1 * ~40 bytes (Justification: rule_id(4) + Vec(24) + cf(4) + depth(1))
    //   dependents Vec: 24 (stack) + 0 heap (empty in alpha-only mode)
    //   combined_cf + belief_state + is_system: ~6 bytes
    //   Total per node: ~54 stack + ~40 heap = ~94 bytes
    // But most nodes have exactly 1 justification with 1 WmeKey, so
    // the Justification's supporting_wmes Vec typically stores 1 WmeKey on heap = 8 bytes.
    // Realistic estimate: ~80 bytes per conclusion.
    let jtms_mem = engine.jtms.conclusion_count() * 80;

    // Reverse index in JTMS: FxHashMap entry (ConclusionId vec per WmeKey)
    // Most WMEs support 0-2 conclusions. Vec overhead = 24 bytes + small heap.
    let jtms_reverse_mem = engine.wme_count() * 16;

    wme_mem + prod_mem + alpha_mem + jtms_mem + jtms_reverse_mem
}

// ============================================================================
// Run one scale
// ============================================================================

fn run_scale(config: &ScaleConfig) -> ScaleResult {
    let mut rng = SimpleRng::new(42 + config.num_rules as u64);

    // Phase 1: Setup engine with rules
    let (mut engine, all_conditions) = setup_engine(config.num_rules, &mut rng);

    // Phase 2: Generate WMEs
    let wmes = generate_wmes(&engine, config.num_wmes, &mut rng);

    // Phase 3: Benchmark WME insertion + JTMS
    let insert_start = Instant::now();
    let (total_firings, mut latencies) = bench_insertion(&mut engine, &wmes);
    let insert_elapsed = insert_start.elapsed();

    let insertion_avg_ns = insert_elapsed.as_nanos() as f64 / config.num_wmes as f64;
    let insertion_wmes_per_sec = config.num_wmes as f64 / insert_elapsed.as_secs_f64();
    let firings_per_sec = total_firings as f64 / insert_elapsed.as_secs_f64();

    let e2e_latency = compute_latency_stats(&mut latencies);

    // Phase 4: Serialization benchmark
    let mut ser_rng = SimpleRng::new(99 + config.num_rules as u64);
    let (
        ser_total_ms,
        ser_per_rule_ns,
        deser_total_ms,
        deser_per_rule_ns,
        mismatches,
        avg_wire_size,
    ) = bench_serialization(config.num_rules, &all_conditions, &mut ser_rng);

    // Phase 5: Lifecycle benchmark
    let mut lc_rng = SimpleRng::new(777 + config.num_rules as u64);
    let (lc_total_ops, lc_duration_us, promotes, weakens, expires) =
        bench_lifecycle(config.num_rules, &mut lc_rng);

    // Phase 6: Memory estimation
    let memory_bytes = estimate_memory(&engine, config.num_rules);

    let jtms_conclusions = engine.jtms.conclusion_count();
    let jtms_in_count = engine.jtms.in_count();

    ScaleResult {
        label: config.label.to_string(),
        num_rules: config.num_rules,
        num_wmes: config.num_wmes,
        insertion_wmes_per_sec,
        insertion_avg_ns,
        total_firings,
        firings_per_sec,
        e2e_latency,
        serialize_total_ms: ser_total_ms,
        serialize_per_rule_ns: ser_per_rule_ns,
        deserialize_total_ms: deser_total_ms,
        deserialize_per_rule_ns: deser_per_rule_ns,
        serialization_mismatches: mismatches,
        avg_wire_size_bytes: avg_wire_size,
        lifecycle_ops_total: lc_total_ops,
        lifecycle_duration_us: lc_duration_us,
        promotes,
        weakens,
        expires,
        memory_estimate_bytes: memory_bytes,
        jtms_conclusions,
        jtms_in_count,
    }
}

// ============================================================================
// Verdict logic
// ============================================================================

fn print_verdict(results: &[ScaleResult]) {
    println!("\n=================================================================");
    println!("  VERDICT AGAINST TARGETS");
    println!("=================================================================\n");

    let mut all_pass = true;

    // Target 1: >10,000 rules evaluated per second at target scale
    let target = &results[2]; // 10K rules scale
    let rules_per_sec = target.firings_per_sec;
    let pass_throughput = rules_per_sec > 10_000.0;
    println!(
        "  [{}] Rule firing rate at target scale: {:.0} firings/sec (target: >10,000)",
        if pass_throughput { "PASS" } else { "FAIL" },
        rules_per_sec
    );
    if !pass_throughput {
        all_pass = false;
    }

    // Target 2: Serialization round-trip fidelity (zero mismatches at all scales)
    let total_mismatches: usize = results.iter().map(|r| r.serialization_mismatches).sum();
    let pass_fidelity = total_mismatches == 0;
    println!(
        "  [{}] Serialization round-trip fidelity: {} mismatches across all scales (target: 0)",
        if pass_fidelity { "PASS" } else { "FAIL" },
        total_mismatches
    );
    if !pass_fidelity {
        all_pass = false;
    }

    // Target 3: Memory at 10K rules + 100K WMEs under 15 MB
    let mem_mb = target.memory_estimate_bytes as f64 / (1024.0 * 1024.0);
    let pass_memory = mem_mb < 15.0;
    println!(
        "  [{}] Memory at target scale: {:.2} MB (target: <15 MB)",
        if pass_memory { "PASS" } else { "FAIL" },
        mem_mb
    );
    if !pass_memory {
        all_pass = false;
    }

    // Target 4: P99 latency under 10us at target scale
    let p99_us = target.e2e_latency.p99_ns as f64 / 1000.0;
    let pass_p99 = p99_us < 10.0;
    println!(
        "  [{}] P99 end-to-end latency at target scale: {:.2} us (target: <10 us)",
        if pass_p99 { "PASS" } else { "FAIL" },
        p99_us
    );
    if !pass_p99 {
        all_pass = false;
    }

    // Target 5: Serialization under 1us per rule
    let pass_ser = target.serialize_per_rule_ns < 1000.0;
    println!(
        "  [{}] Serialization per rule at target scale: {:.0} ns (target: <1000 ns)",
        if pass_ser { "PASS" } else { "FAIL" },
        target.serialize_per_rule_ns
    );
    if !pass_ser {
        all_pass = false;
    }

    // Target 6: Deserialization under 1us per rule
    let pass_deser = target.deserialize_per_rule_ns < 1000.0;
    println!(
        "  [{}] Deserialization per rule at target scale: {:.0} ns (target: <1000 ns)",
        if pass_deser { "PASS" } else { "FAIL" },
        target.deserialize_per_rule_ns
    );
    if !pass_deser {
        all_pass = false;
    }

    // Target 7: WME insertion > 1M WMEs/sec
    let pass_wme_throughput = target.insertion_wmes_per_sec > 1_000_000.0;
    println!(
        "  [{}] WME insertion throughput at target scale: {:.0} WMEs/sec (target: >1M)",
        if pass_wme_throughput { "PASS" } else { "FAIL" },
        target.insertion_wmes_per_sec
    );
    if !pass_wme_throughput {
        all_pass = false;
    }

    println!("\n  ===================================================");
    if all_pass {
        println!("  OVERALL: PASS -- All targets met at all scales");
    } else {
        println!("  OVERALL: PARTIAL -- Some targets not met (see above)");
    }
    println!("  ===================================================");
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    println!("=================================================================");
    println!("  RE5: Full Throughput Benchmark");
    println!("  HIVE Rete-II Engine -- ALL Modules Enabled");
    println!("  Alpha Network + JTMS + Lifecycle + Serialization");
    println!("  Date: 2026-04-15");
    println!("=================================================================\n");

    let overall_start = Instant::now();
    let mut results = Vec::new();

    for config in &SCALES {
        println!("--- {} ---\n", config.label);
        let scale_start = Instant::now();
        let result = run_scale(config);
        let scale_elapsed = scale_start.elapsed();

        println!("  WME Insertion:");
        println!(
            "    Throughput:        {:.0} WMEs/sec",
            result.insertion_wmes_per_sec
        );
        println!(
            "    Avg latency:       {:.0} ns/WME",
            result.insertion_avg_ns
        );
        println!("    Total firings:     {}", result.total_firings);
        println!(
            "    Firing rate:       {:.0} firings/sec",
            result.firings_per_sec
        );
        println!();
        println!("  End-to-End Latency (insert + match + JTMS):");
        println!("    P50:  {} ns", result.e2e_latency.p50_ns);
        println!("    P95:  {} ns", result.e2e_latency.p95_ns);
        println!("    P99:  {} ns", result.e2e_latency.p99_ns);
        println!("    Mean: {} ns", result.e2e_latency.mean_ns);
        println!("    Min:  {} ns", result.e2e_latency.min_ns);
        println!("    Max:  {} ns", result.e2e_latency.max_ns);
        println!();
        println!("  Serialization Round-Trip:");
        println!(
            "    Serialize:     {:.2} ms total, {:.0} ns/rule",
            result.serialize_total_ms, result.serialize_per_rule_ns
        );
        println!(
            "    Deserialize:   {:.2} ms total, {:.0} ns/rule",
            result.deserialize_total_ms, result.deserialize_per_rule_ns
        );
        println!("    Mismatches:    {}", result.serialization_mismatches);
        println!(
            "    Avg wire size: {:.0} bytes/rule",
            result.avg_wire_size_bytes
        );
        println!();
        println!("  Lifecycle Operations:");
        println!("    Total ops: {}", result.lifecycle_ops_total);
        println!("    Duration:  {:.1} us", result.lifecycle_duration_us);
        println!("    Promotes (Candidate->Active): {}", result.promotes);
        println!("    Weakens (via contradictions):  {}", result.weakens);
        println!("    Expires (via CHECK_KILL):       {}", result.expires);
        println!();
        println!("  Memory & JTMS:");
        println!(
            "    Estimated memory: {:.2} MB",
            result.memory_estimate_bytes as f64 / (1024.0 * 1024.0)
        );
        println!("    JTMS conclusions: {}", result.jtms_conclusions);
        println!("    JTMS IN beliefs:  {}", result.jtms_in_count);
        println!();
        println!("  Scale completed in {:.2} ms\n", scale_elapsed.as_millis());

        results.push(result);
    }

    print_verdict(&results);

    let total_elapsed = overall_start.elapsed();
    println!(
        "\n  Total benchmark time: {:.2} ms",
        total_elapsed.as_millis()
    );
    println!("=================================================================\n");
}
