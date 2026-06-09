//! Local Processing Pipeline: ExtractionOutput JSON -> insights.
//!
//! Wires together the full local pipeline:
//!   ExtractionOutput JSON -> Tuple Adapter -> WME Factory -> Rete-II Engine -> FiredProductions
//!
//! The `LocalPipeline` struct owns the shared Dictionary and Engine, providing
//! a single `process_extraction()` entry point for document processing.

use crate::alpha_network::{AlphaCondition, ConditionField};
use crate::dictionary::Dictionary;
use crate::engine::Engine;
use crate::production::{FiredProduction, RuleStatus};
use crate::tuple_adapter::{self, ConversionContext, ExtractionOutput};
use crate::wme_factory;

// ---------------------------------------------------------------------------
// ProductionSpec: declarative rule definition for seeding
// ---------------------------------------------------------------------------

/// Declarative specification for a production rule.
///
/// Users specify conditions as (field, string_value) pairs.
/// The pipeline handles dictionary encoding internally.
#[derive(Debug, Clone)]
pub struct ProductionSpec {
    pub rule_id: u32,
    pub conditions: Vec<(ConditionField, String)>,
    pub confidence: f32,
}

// ---------------------------------------------------------------------------
// ProcessingResult: output of a single document processing pass
// ---------------------------------------------------------------------------

/// Result of processing a single extraction through the pipeline.
#[derive(Debug)]
pub struct ProcessingResult {
    /// Number of RawTuples produced by the tuple adapter (A1).
    pub tuples_created: usize,
    /// Number of WMEs successfully inserted into the engine.
    pub wmes_inserted: usize,
    /// All productions that fired during WME insertion.
    pub fired_productions: Vec<FiredProduction>,
}

// ---------------------------------------------------------------------------
// LocalPipeline
// ---------------------------------------------------------------------------

/// The local processing pipeline: ExtractionOutput -> insights.
///
/// Owns a shared Dictionary (for WME field encoding) and a Rete-II Engine.
/// Thread-local, no P2P -- rules are pre-seeded.
pub struct LocalPipeline {
    /// Shared dictionary for string -> u16 encoding across all WMEs.
    pub dict: Dictionary,
    /// The Rete-II alpha engine.
    pub engine: Engine,
}

impl LocalPipeline {
    /// Create a new pipeline instance with empty dictionary and engine.
    pub fn new() -> Self {
        Self {
            dict: Dictionary::new(),
            engine: Engine::new(),
        }
    }

    /// Load pre-seeded rules into the engine.
    ///
    /// Each `ProductionSpec` is compiled into engine conditions using the
    /// shared dictionary. DocumentCategory conditions are handled specially
    /// (mapped to u8 via wme_factory::document_category_to_u8, then stored as u16).
    pub fn load_rules(&mut self, rules: Vec<ProductionSpec>) {
        for spec in &rules {
            let conditions: Vec<AlphaCondition> = spec
                .conditions
                .iter()
                .map(|(field, value)| {
                    let value_id = match field {
                        ConditionField::DocumentCategory => {
                            wme_factory::document_category_to_u8(value) as u16
                        }
                        ConditionField::AmountBucket => {
                            // value is a decimal bitmask string, e.g. "240" for buckets 4-7
                            value.parse::<u16>().unwrap_or(0)
                        }
                        _ => self.dict.get_or_insert(value),
                    };
                    AlphaCondition {
                        field: *field,
                        value_id,
                    }
                })
                .collect();

            self.engine.add_production(
                spec.rule_id,
                &conditions,
                RuleStatus::Active,
                spec.confidence,
            );
        }
    }

    /// Process a complete extraction output through the pipeline.
    ///
    /// Steps:
    /// 1. Deserialize JSON -> ExtractionOutput (serde_json)
    /// 2. Convert via tuple_adapter::convert() -> Vec<RawTuple>
    /// 3. For each RawTuple, call wme_factory::create_wme() -> Wme
    /// 4. Insert each Wme into the Rete-II engine via engine.insert_wme()
    /// 5. Collect and return all fired productions
    ///
    /// Returns Err if JSON deserialization fails. Malformed entity references
    /// are skipped gracefully (per A1 design).
    pub fn process_extraction(
        &mut self,
        json: &str,
        source_file: &str,
    ) -> Result<ProcessingResult, String> {
        // Step 1: Deserialize JSON -> ExtractionOutput
        let extraction_output = tuple_adapter::parse_extraction_json(json)?;

        self.process_extraction_output(&extraction_output, source_file)
    }

    /// Process a pre-parsed ExtractionOutput (avoids double deserialization).
    pub fn process_extraction_output(
        &mut self,
        output: &ExtractionOutput,
        source_file: &str,
    ) -> Result<ProcessingResult, String> {
        // Step 2: Convert ExtractionOutput -> Vec<RawTuple>
        let ctx = ConversionContext {
            document_text: format!("source:{}", source_file),
            source_file_path: source_file.to_string(),
            extraction_confidence: 1.0,
        };
        let tuples = tuple_adapter::convert(output, &ctx);
        let tuples_created = tuples.len();

        // Steps 3-5: RawTuple -> Wme -> Engine insertion -> collect firings
        let mut all_fired = Vec::new();
        let mut wmes_inserted = 0;

        for raw_tuple in &tuples {
            // Step 3: Create WME using shared dictionary
            let wme = wme_factory::create_wme(raw_tuple, &mut self.dict);

            // Step 4: Insert into engine, collect firings
            let fired = self.engine.insert_wme(wme);

            // Step 5: Accumulate results
            wmes_inserted += 1;
            all_fired.extend(fired);
        }

        Ok(ProcessingResult {
            tuples_created,
            wmes_inserted,
            fired_productions: all_fired,
        })
    }

    /// Convenience: number of productions loaded in the engine.
    pub fn production_count(&self) -> usize {
        self.engine.production_count()
    }

    /// Convenience: number of WMEs currently in working memory.
    pub fn wme_count(&self) -> usize {
        self.engine.wme_count()
    }

    /// Convenience: dictionary size (number of unique strings encoded).
    pub fn dict_size(&self) -> usize {
        self.dict.len()
    }
}

impl Default for LocalPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Pre-seeded rule helpers
// ---------------------------------------------------------------------------

/// Create sample productions for testing the medical bill scenario.
///
/// Rules:
/// 1. If entity_a_type=organization AND relation=charged_total AND document_category=medical_bill -> fire
/// 2. If entity_a_type=person AND relation=patient_at AND document_category=medical_bill -> fire
pub fn medical_bill_rules() -> Vec<ProductionSpec> {
    vec![
        ProductionSpec {
            rule_id: 1001,
            conditions: vec![
                (ConditionField::EntityAType, "organization".to_string()),
                (ConditionField::Relation, "charged_total".to_string()),
                (ConditionField::DocumentCategory, "medical_bill".to_string()),
            ],
            confidence: 0.85,
        },
        ProductionSpec {
            rule_id: 1002,
            conditions: vec![
                (ConditionField::EntityAType, "person".to_string()),
                (ConditionField::Relation, "patient_at".to_string()),
                (ConditionField::DocumentCategory, "medical_bill".to_string()),
            ],
            confidence: 0.80,
        },
    ]
}

/// Create sample productions for testing the lease agreement scenario.
///
/// Rules:
/// 1. If entity_a_type=organization AND relation=charges_rent AND document_category=lease_agreement -> fire
/// 2. If entity_a_type=organization AND relation=charges_late_fee AND document_category=lease_agreement -> fire
pub fn lease_agreement_rules() -> Vec<ProductionSpec> {
    vec![
        ProductionSpec {
            rule_id: 2001,
            conditions: vec![
                (ConditionField::EntityAType, "organization".to_string()),
                (ConditionField::Relation, "charges_rent".to_string()),
                (
                    ConditionField::DocumentCategory,
                    "lease_agreement".to_string(),
                ),
            ],
            confidence: 0.90,
        },
        ProductionSpec {
            rule_id: 2002,
            conditions: vec![
                (ConditionField::EntityAType, "organization".to_string()),
                (ConditionField::Relation, "charges_late_fee".to_string()),
                (
                    ConditionField::DocumentCategory,
                    "lease_agreement".to_string(),
                ),
            ],
            confidence: 0.88,
        },
    ]
}

/// Create a combined set of rules for both test scenarios.
pub fn all_test_rules() -> Vec<ProductionSpec> {
    let mut rules = medical_bill_rules();
    rules.extend(lease_agreement_rules());
    rules
}

// ---------------------------------------------------------------------------
// D5 Step 5: Tuple drain task + helpers for privacy pipeline -> P2P bridge
// ---------------------------------------------------------------------------

use crate::bridge::tuple_sender::{SendError, TupleSender};
use crate::bridge::ShareablePayload;
use crate::privacy::jitter_queue::JitterQueueOps;
use crate::privacy::types::QueuedTuple;

/// Extract the sensitivity tier from a QueuedTuple as a u8 value.
///
/// Navigates the type-state wrapper chain:
///   QueuedTuple -> BudgetApprovedTuple -> EncodedTuple -> LCheckedTuple
///   -> KCheckedTuple -> HashedTuple -> GeneralizedTuple.sensitivity_tier
pub fn sensitivity_tier_u8(queued: &QueuedTuple) -> u8 {
    queued
        .inner // BudgetApprovedTuple
        .inner // EncodedTuple
        .inner // LCheckedTuple
        .inner // KCheckedTuple
        .inner // HashedTuple
        .inner // GeneralizedTuple
        .sensitivity_tier
        .as_u8()
}

/// Serialize a QueuedTuple to wire bytes using postcard.
///
/// The QueuedTuple is serialized in its entirety (all wrapper layers).
/// The resulting bytes must be <= 256 bytes per E8 v1.1 constraint;
/// the OUE encoding and generalization stages upstream ensure this.
pub fn serialize_queued_tuple(queued: &QueuedTuple) -> Vec<u8> {
    postcard::to_allocvec(queued).expect("QueuedTuple serialization should not fail")
}

/// Async drain task that periodically drains the jitter queue and sends
/// tuples through the TupleSender (Channel 16) as ShareablePayloads.
///
/// This function is spawned as a tokio task when both `enable_privacy_pipeline`
/// and `enable_p2p` are true. It runs until the TupleSender signals channel
/// closure or the supplied shutdown_notify is triggered.
///
/// Privacy-first: if the channel is full, tuples are dropped (not buffered).
/// This prevents timing information leakage from backpressure.
pub async fn tuple_drain_task<JQ: JitterQueueOps + Send + 'static>(
    pipeline: std::sync::Arc<tokio::sync::Mutex<crate::privacy::pipeline::PrivacyPipeline<JQ>>>,
    tuple_sender: Box<dyn TupleSender>,
    shutdown_notify: tokio::sync::watch::Receiver<bool>,
) {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::time::{SystemTime, UNIX_EPOCH};

    let drain_interval = std::time::Duration::from_secs(900); // 15 minutes
    let mut timer = tokio::time::interval(drain_interval);
    timer.tick().await; // skip first immediate tick

    let mut rng = ChaCha20Rng::from_os_rng();
    let mut total_drained: u64 = 0;
    let mut total_dropped: u64 = 0;

    let mut shutdown = shutdown_notify;

    loop {
        tokio::select! {
            _ = timer.tick() => {
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let batches = {
                    let mut pipeline = pipeline.lock().await;
                    pipeline.drain_ready_batches(now_secs)
                };

                for batch in batches {
                    for queued_tuple in batch {
                        let wire_bytes = serialize_queued_tuple(&queued_tuple);
                        let tier = sensitivity_tier_u8(&queued_tuple);
                        let payload = ShareablePayload::from_wire_bytes(
                            wire_bytes,
                            tier,
                            &mut rng,
                        );

                        match tuple_sender.try_send(payload) {
                            Ok(()) => {
                                total_drained += 1;
                            }
                            Err(SendError::ChannelFull) => {
                                total_dropped += 1;
                                // Privacy > delivery: drop rather than buffer.
                            }
                            Err(SendError::ChannelClosed) => {
                                // Channel closed; stop draining.
                                return;
                            }
                        }
                    }
                }
            }

            _ = shutdown.changed() => {
                // Shutdown signal received.
                let _ = total_drained;
                let _ = total_dropped;
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // D5 Step 6: Integration tests for privacy pipeline -> P2P bridge
    // -----------------------------------------------------------------------

    /// Test 1: Privacy pipeline drain -> ShareablePayload -> Channel 16.
    ///
    /// Verifies the outbound tuple path from jitter queue to P2P channel:
    ///   JitterQueue.enqueue(BudgetApprovedTuple) -> QueuedTuple
    ///   -> drain_ready_batches() -> serialize_queued_tuple()
    ///   -> ShareablePayload::from_wire_bytes() -> MpscTupleSender.try_send()
    ///   -> channel receiver receives ShareablePayload.
    ///
    /// Uses make_test_approved() (from privacy::pipeline tests) to bypass
    /// upstream privacy stages and focus on the D5 drain-to-channel path.
    ///
    /// Spec: D5 Section 6 Test 1.
    #[test]
    fn test_privacy_drain_to_tuple_channel() {
        use crate::bridge::tuple_sender::MpscTupleSender;
        use crate::privacy::config::PrivacyConfig;
        use crate::privacy::types::*;
        use crate::privacy::{PrivacyPipeline, SimpleJitterQueue};
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        /// Build a BudgetApprovedTuple for S4 tier (receipt).
        fn make_s4_approved() -> BudgetApprovedTuple {
            let gen = GeneralizedTuple {
                entity_a_type: "org".into(),
                entity_a_gen: "store".into(),
                entity_a_gen_level: 1,
                entity_a_role: "m".into(),
                entity_b_type: "prod".into(),
                entity_b_gen: "groc".into(),
                entity_b_gen_level: 1,
                entity_b_role: "c".into(),
                relation: "sold".into(),
                amount_bucket: 2,
                document_category: "receipt".into(),
                sensitivity_tier: SensitivityTier::S4Low,
                source_region: "MW".into(),
                time_period: "Q1".into(),
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
            let k_checked = KCheckedTuple {
                inner: hashed,
                estimated_k: 100.0,
            };
            let l_checked = LCheckedTuple {
                inner: k_checked,
                l_entropy: 2.5,
            };
            let encoded = EncodedTuple {
                inner: l_checked,
                oue_vectors: vec![OueFieldVector {
                    field_name: "v".into(),
                    domain_size: 8,
                    epsilon: 0.3,
                    bits: vec![0xFF; 1],
                }],
                epsilon_consumed: 8.0,
            };
            BudgetApprovedTuple {
                inner: encoded,
                budget_snapshot: BudgetSnapshot {
                    tier: SensitivityTier::S4Low,
                    daily_remaining: 30.0,
                    weekly_remaining: 150.0,
                    lifetime_remaining: 4500.0,
                },
            }
        }

        // 1. Create pipeline and directly enqueue via jitter queue
        let config = PrivacyConfig::default_config();
        let mut pipeline = PrivacyPipeline::<SimpleJitterQueue>::new_deterministic(config, 42);
        pipeline.update_network_size(2_000_000);

        // 2. Build 5 S4-tier BudgetApprovedTuples and enqueue directly
        //    into the jitter queue (bypasses upstream stages that may suppress).
        for _ in 0..5 {
            pipeline.enqueue_approved(make_s4_approved());
        }

        // 3. Create channel and sender
        let (tx, mut rx) = crate::bridge::tuple_channel();
        let sender = MpscTupleSender::new(tx);

        // 4. Drain with future timestamp (past max hold for S4)
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 7200;
        let batches = pipeline.drain_ready_batches(far_future);

        // 5. Convert and send through channel
        let mut rng = ChaCha20Rng::seed_from_u64(99);
        let mut sent_count = 0;
        for batch in &batches {
            for queued_tuple in batch {
                let wire_bytes = serialize_queued_tuple(queued_tuple);
                let tier = sensitivity_tier_u8(queued_tuple);
                let payload =
                    crate::bridge::ShareablePayload::from_wire_bytes(wire_bytes, tier, &mut rng);
                sender
                    .try_send(payload)
                    .expect("channel should not be full");
                sent_count += 1;
            }
        }

        assert_eq!(
            sent_count, 5,
            "All 5 queued tuples should be drained and sent"
        );

        // 6. Verify received payloads
        let mut received = Vec::new();
        while let Ok(p) = rx.try_recv() {
            received.push(p);
        }

        assert_eq!(received.len(), 5, "All 5 sent payloads should be received");

        for payload in &received {
            assert_eq!(
                payload.sensitivity_tier,
                SensitivityTier::S4Low.as_u8(),
                "Receipt tuples should be S4"
            );
            assert!(
                (5..=10).contains(&payload.stem_hops),
                "S4 stem hops should be in 5..=10, got {}",
                payload.stem_hops
            );
            assert!(
                payload.tuple_id != [0u8; 20],
                "tuple_id should be non-zero (BLAKE3 hash)"
            );
            assert!(
                payload.wire_bytes.len() <= 256,
                "wire_bytes must be <= 256 bytes, got {}",
                payload.wire_bytes.len()
            );
        }
    }

    /// Test 4: Channel backpressure -- small capacity, fill, drain, refill.
    ///
    /// Verifies that the MpscTupleSender returns ChannelFull when capacity
    /// is exhausted and accepts new sends after draining, matching the
    /// privacy-first design (drop, don't buffer).
    ///
    /// Spec: D5 Section 6 Test 6.
    #[test]
    fn test_channel_backpressure() {
        use crate::bridge::tuple_sender::{MpscTupleSender, SendError};

        // Small capacity for testing
        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::bridge::ShareablePayload>(4);
        let sender = MpscTupleSender::new(tx);

        let make_payload =
            |id: u8| crate::bridge::ShareablePayload::new(vec![id; 10], 2, 10, [id; 20]);

        // 1. Fill the channel (4 sends should succeed)
        for i in 0..4u8 {
            sender
                .try_send(make_payload(i))
                .expect("should succeed before full");
        }

        // 2. 5th send should fail with ChannelFull
        let result = sender.try_send(make_payload(4));
        assert_eq!(
            result,
            Err(SendError::ChannelFull),
            "Channel should be full after 4 sends"
        );

        // 3. Receive 1 to free space
        let received = rx.try_recv().expect("should receive from full channel");
        assert_eq!(received.wire_bytes, vec![0u8; 10]);

        // 4. Now one more send should succeed
        sender
            .try_send(make_payload(5))
            .expect("should succeed after draining 1");

        // 5. Drain all remaining and verify total
        let mut total_received = 1; // already received 1 above
        while rx.try_recv().is_ok() {
            total_received += 1;
        }
        assert_eq!(
            total_received, 5,
            "Should receive all 5 successfully sent payloads"
        );
    }

    // -----------------------------------------------------------------------
    // Test JSON fixtures
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Full pipeline integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pipeline_medical_bill_full_chain() {
        let mut pipeline = LocalPipeline::new();
        pipeline.load_rules(medical_bill_rules());

        assert_eq!(pipeline.production_count(), 2);

        let result = pipeline
            .process_extraction(medical_bill_json(), "/test/medical_bill.pdf")
            .expect("processing should succeed");

        // 2 relationships -> 2 RawTuples -> 2 WMEs
        assert_eq!(
            result.tuples_created, 2,
            "Should create 2 tuples from 2 relationships"
        );
        assert_eq!(result.wmes_inserted, 2, "All tuples should become WMEs");

        // Rule 1001 should fire on the charged_total WME
        // Rule 1002 should fire on the patient_at WME
        assert_eq!(
            result.fired_productions.len(),
            2,
            "Both rules should fire: charged_total and patient_at"
        );

        let rule_ids: Vec<u32> = result
            .fired_productions
            .iter()
            .map(|fp| fp.rule_id)
            .collect();
        assert!(
            rule_ids.contains(&1001),
            "Rule 1001 (charged_total) should fire"
        );
        assert!(
            rule_ids.contains(&1002),
            "Rule 1002 (patient_at) should fire"
        );

        // Verify WMEs are in working memory
        assert_eq!(pipeline.wme_count(), 2);
    }

    #[test]
    fn test_pipeline_lease_agreement_full_chain() {
        let mut pipeline = LocalPipeline::new();
        pipeline.load_rules(lease_agreement_rules());

        assert_eq!(pipeline.production_count(), 2);

        let result = pipeline
            .process_extraction(lease_agreement_json(), "/test/lease.pdf")
            .expect("processing should succeed");

        assert_eq!(result.tuples_created, 2);
        assert_eq!(result.wmes_inserted, 2);

        assert_eq!(
            result.fired_productions.len(),
            2,
            "Both lease rules should fire"
        );

        let rule_ids: Vec<u32> = result
            .fired_productions
            .iter()
            .map(|fp| fp.rule_id)
            .collect();
        assert!(
            rule_ids.contains(&2001),
            "Rule 2001 (charges_rent) should fire"
        );
        assert!(
            rule_ids.contains(&2002),
            "Rule 2002 (charges_late_fee) should fire"
        );
    }

    #[test]
    fn test_pipeline_all_rules_both_documents() {
        let mut pipeline = LocalPipeline::new();
        pipeline.load_rules(all_test_rules());

        assert_eq!(pipeline.production_count(), 4);

        // Process medical bill
        let r1 = pipeline
            .process_extraction(medical_bill_json(), "/test/medical.pdf")
            .unwrap();
        assert_eq!(r1.tuples_created, 2);
        assert_eq!(r1.fired_productions.len(), 2);

        // Process lease agreement (same pipeline, shared dictionary + engine)
        let r2 = pipeline
            .process_extraction(lease_agreement_json(), "/test/lease.pdf")
            .unwrap();
        assert_eq!(r2.tuples_created, 2);
        assert_eq!(r2.fired_productions.len(), 2);

        // Total WMEs in engine
        assert_eq!(pipeline.wme_count(), 4);

        // No cross-domain firings: medical rules don't fire on lease data
        let r1_ids: Vec<u32> = r1.fired_productions.iter().map(|fp| fp.rule_id).collect();
        let r2_ids: Vec<u32> = r2.fired_productions.iter().map(|fp| fp.rule_id).collect();
        for id in &r1_ids {
            assert!(*id >= 1001 && *id <= 1002, "Medical rules only");
        }
        for id in &r2_ids {
            assert!(*id >= 2001 && *id <= 2002, "Lease rules only");
        }
    }

    #[test]
    fn test_pipeline_malformed_json() {
        let mut pipeline = LocalPipeline::new();
        pipeline.load_rules(all_test_rules());

        let result = pipeline.process_extraction("not valid json", "/test/bad.pdf");
        assert!(result.is_err(), "Malformed JSON should return Err");
        assert!(
            result.unwrap_err().contains("Failed to parse"),
            "Error message should describe parsing failure"
        );
    }

    #[test]
    fn test_pipeline_missing_entity_references() {
        let json = r#"{
            "document_category": "medical_bill",
            "entities": [
                {"id": "e1", "name": "Hospital", "type": "organization", "value": "Hospital"}
            ],
            "relationships": [
                {"source": "e1", "target": "e_missing", "relationship": "charged_total", "context": null},
                {"source": "e_ghost", "target": "e1", "relationship": "patient_at", "context": null}
            ]
        }"#;

        let mut pipeline = LocalPipeline::new();
        pipeline.load_rules(medical_bill_rules());

        let result = pipeline
            .process_extraction(json, "/test/missing_refs.pdf")
            .expect("Should succeed but skip bad references");

        // Both relationships reference non-existent entities, so 0 tuples
        assert_eq!(
            result.tuples_created, 0,
            "Missing entity refs should be skipped"
        );
        assert_eq!(result.wmes_inserted, 0);
        assert_eq!(result.fired_productions.len(), 0);
    }

    #[test]
    fn test_pipeline_empty_extraction() {
        let json = r#"{
            "document_category": "general",
            "entities": [],
            "relationships": []
        }"#;

        let mut pipeline = LocalPipeline::new();
        let result = pipeline
            .process_extraction(json, "/test/empty.pdf")
            .expect("Empty extraction should succeed");

        assert_eq!(result.tuples_created, 0);
        assert_eq!(result.wmes_inserted, 0);
        assert_eq!(result.fired_productions.len(), 0);
    }

    #[test]
    fn test_pipeline_sequential_documents() {
        let mut pipeline = LocalPipeline::new();
        pipeline.load_rules(all_test_rules());

        // Process 3 documents sequentially
        for i in 0..3 {
            let r = pipeline
                .process_extraction(medical_bill_json(), &format!("/test/doc_{}.pdf", i))
                .unwrap();
            assert_eq!(r.tuples_created, 2);
            assert_eq!(r.fired_productions.len(), 2);
        }

        // All WMEs should be in working memory
        assert_eq!(pipeline.wme_count(), 6, "3 docs x 2 WMEs each");
    }

    #[test]
    fn test_pipeline_confidence_propagation() {
        let mut pipeline = LocalPipeline::new();
        pipeline.load_rules(medical_bill_rules());

        let result = pipeline
            .process_extraction(medical_bill_json(), "/test/bill.pdf")
            .unwrap();

        for fp in &result.fired_productions {
            // Chained CF = rule_cf * extraction_cf
            // extraction_cf is 1.0 (default in pipeline), so chained = rule_cf * 1.0
            assert!(fp.chained_cf > 0.0, "Chained CF should be positive");
            assert!(fp.chained_cf <= 1.0, "Chained CF should be <= 1.0");
            assert!(
                (fp.chained_cf - fp.confidence * fp.extraction_cf).abs() < 1e-6,
                "Chained CF should equal confidence * extraction_cf"
            );
        }
    }

    #[test]
    fn test_pipeline_no_matching_rules() {
        // Load only medical rules, process a lease document
        let mut pipeline = LocalPipeline::new();
        pipeline.load_rules(medical_bill_rules());

        let result = pipeline
            .process_extraction(lease_agreement_json(), "/test/lease.pdf")
            .unwrap();

        // WMEs are created, but no rules match (wrong document_category + relations)
        assert_eq!(result.tuples_created, 2);
        assert_eq!(result.wmes_inserted, 2);
        assert_eq!(
            result.fired_productions.len(),
            0,
            "Medical rules should not fire on lease data"
        );
    }

    #[test]
    fn test_pipeline_missing_json_field() {
        let json = r#"{"document_category": "general"}"#;

        let mut pipeline = LocalPipeline::new();
        let result = pipeline.process_extraction(json, "/test/bad.pdf");
        assert!(result.is_err(), "Missing required fields should return Err");
    }

    #[test]
    fn test_production_spec_rule_helpers() {
        let medical = medical_bill_rules();
        assert_eq!(medical.len(), 2);
        assert_eq!(medical[0].rule_id, 1001);
        assert_eq!(medical[1].rule_id, 1002);

        let lease = lease_agreement_rules();
        assert_eq!(lease.len(), 2);
        assert_eq!(lease[0].rule_id, 2001);
        assert_eq!(lease[1].rule_id, 2002);

        let all = all_test_rules();
        assert_eq!(all.len(), 4);
    }
}
