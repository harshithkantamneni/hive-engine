//! Engine core: WME insertion -> alpha network lookup -> conjunction check -> fired productions.
//!
//! The AlphaOutput trait provides the extension point for a future beta network.
//!
//! Optimization: "most-selective-first" strategy.
//! For each WME, probe every field index to find candidates, then check conjunction.
//! The scratch array avoids per-WME allocation.

use crate::alpha_network::{
    AlphaCondition, AlphaNetwork, CompositeKey, ConditionField, FieldIndex,
};
use crate::dictionary::Dictionary;
use crate::jtms::{ConclusionId, Jtms};
use crate::production::{FiredProduction, Production, RuleStatus};
use crate::wme::{Wme, WmeKey};
use slotmap::SlotMap;

/// Extension point for a future beta network.
/// The current implementation provides only DirectToProduction (alpha-only path);
/// a FeedToBetaNode variant can be added later.
pub trait AlphaOutput {
    fn on_production_fire(&mut self, fired: &FiredProduction);
}

/// Default output: collects fired productions into a Vec.
pub struct CollectOutput {
    pub fired: Vec<FiredProduction>,
}

impl CollectOutput {
    pub fn new() -> Self {
        Self { fired: Vec::new() }
    }

    pub fn clear(&mut self) {
        self.fired.clear();
    }
}

impl Default for CollectOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl AlphaOutput for CollectOutput {
    fn on_production_fire(&mut self, fired: &FiredProduction) {
        self.fired.push(fired.clone());
    }
}

/// Compact condition representation for verification.
/// Stored per-production for direct field checking.
#[derive(Debug, Clone, Copy)]
pub struct CompactCondition {
    pub field: ConditionField,
    pub value_id: u16,
}

/// The Rete-II alpha engine.
///
/// Core loop:
/// 1. WME enters -> hash lookup on each indexed field
/// 2. Collect candidate productions via bitmask accumulation
/// 3. Check conjunction: all condition bits set?
/// 4. Fire matched productions
pub struct Engine {
    /// Working memory: SlotMap for O(1) insert/remove with generational keys.
    pub working_memory: SlotMap<WmeKey, Wme>,
    /// The compiled alpha network.
    pub alpha_network: AlphaNetwork,
    /// All registered productions (rules).
    pub productions: Vec<Production>,
    /// Conditions per production, for direct verification.
    pub production_conditions: Vec<Vec<CompactCondition>>,
    /// Productions NOT in the composite index (fallback path).
    pub secondary_productions: Vec<u32>,
    /// Scratch space (retained for potential future use).
    match_scratch: Vec<u64>,
    #[allow(dead_code)] // Reserved for candidate accumulation optimization.
    candidate_scratch: Vec<u32>,

    // Dictionaries for field encoding
    pub entity_type_dict: Dictionary,
    pub entity_role_dict: Dictionary,
    pub entity_gen_dict: Dictionary,
    pub relation_dict: Dictionary,
    pub doc_category_dict: Dictionary,

    /// JTMS: Justification-based Truth Maintenance System.
    /// Tracks justifications, belief states, and handles retraction cascades.
    pub jtms: Jtms,
}

impl Engine {
    pub fn new() -> Self {
        Self {
            working_memory: SlotMap::with_key(),
            alpha_network: AlphaNetwork::new(),
            productions: Vec::new(),
            production_conditions: Vec::new(),
            secondary_productions: Vec::new(),
            match_scratch: Vec::new(),
            candidate_scratch: Vec::new(),
            entity_type_dict: Dictionary::new(),
            entity_role_dict: Dictionary::new(),
            entity_gen_dict: Dictionary::new(),
            relation_dict: Dictionary::new(),
            doc_category_dict: Dictionary::new(),
            jtms: Jtms::new(),
        }
    }

    /// Add a production (rule) with its conditions to the engine.
    /// Returns the production index.
    pub fn add_production(
        &mut self,
        rule_id: u32,
        conditions: &[AlphaCondition],
        status: RuleStatus,
        confidence: f32,
    ) -> u32 {
        let prod_idx = self.productions.len() as u32;
        let prod = Production::new(rule_id, conditions.len() as u8, status, confidence);
        self.productions.push(prod);

        // Store compact conditions for direct verification
        let compact: Vec<CompactCondition> = conditions
            .iter()
            .map(|c| CompactCondition {
                field: c.field,
                value_id: c.value_id,
            })
            .collect();
        self.production_conditions.push(compact);

        // Compile each condition into the alpha network
        for (bit, cond) in conditions.iter().enumerate() {
            self.alpha_network.add_condition(cond, prod_idx, bit as u8);
        }

        // Register in composite index if rule has the 3 primary fields
        let mut ea_type_val = None;
        let mut rel_val = None;
        let mut doc_cat_val = None;
        for cond in conditions {
            match cond.field {
                ConditionField::EntityAType => ea_type_val = Some(cond.value_id),
                ConditionField::Relation => rel_val = Some(cond.value_id),
                ConditionField::DocumentCategory => doc_cat_val = Some(cond.value_id),
                _ => {}
            }
        }
        if let (Some(ea), Some(rel), Some(doc)) = (ea_type_val, rel_val, doc_cat_val) {
            let key = CompositeKey::new(ea, rel, doc as u8);
            self.alpha_network
                .primary_composite_idx
                .entry(key)
                .or_default()
                .push(prod_idx);
        } else {
            // Rule missing one of the 3 primary fields -- use fallback path
            self.secondary_productions.push(prod_idx);
        }

        // Ensure scratch space can hold this production
        if self.match_scratch.len() <= prod_idx as usize {
            self.match_scratch.resize(prod_idx as usize + 1, 0);
        }

        prod_idx
    }

    /// Insert a WME into working memory and fire matching productions.
    ///
    /// This is the HOT PATH. Approximate cost budget:
    /// - 5 hash lookups (~250 cycles)
    /// - Bitmask accumulation (~500 cycles for 100 candidates)
    /// - Production firing (~2000 cycles for 10 fires)
    ///
    /// Target: < 1us total on M3 Pro.
    #[inline(never)]
    pub fn insert_wme(&mut self, wme: Wme) -> Vec<FiredProduction> {
        let mut result = Vec::new();
        self.insert_wme_into(&wme, &mut result);
        // Store in working memory
        self.working_memory.insert(wme);
        result
    }

    /// Insert WME and collect results into provided output vec (avoids allocation).
    ///
    /// Fast path: Use composite index (entity_a_type, relation, doc_category) to get a
    /// small candidate set (~10-50 rules), then verify remaining conditions directly.
    /// This avoids the O(1400) scatter-write pattern of probing all 8 field indexes.
    ///
    /// Fallback path: For rules not in the composite index (missing one of the 3 primary
    /// fields), use the traditional bit-accumulation approach on secondary indexes.
    #[inline(always)]
    pub fn insert_wme_into(&mut self, wme: &Wme, output: &mut Vec<FiredProduction>) {
        output.clear();

        let net = &self.alpha_network;
        let productions = &self.productions;
        let prod_conditions = &self.production_conditions;

        // Fast path: composite index lookup (single hash lookup)
        let key = CompositeKey::new(wme.entity_a_type, wme.relation, wme.document_category);
        if let Some(candidates) = net.primary_composite_idx.get(&key) {
            for &prod_idx in candidates {
                let prod = &productions[prod_idx as usize];
                if !prod.status.fires() {
                    continue;
                }

                // Verify remaining conditions (0-3 extra beyond the 3 primary)
                let conditions = &prod_conditions[prod_idx as usize];
                let mut all_match = true;
                for cond in conditions.iter() {
                    let matches = match cond.field {
                        // These 3 already matched via composite key
                        ConditionField::EntityAType => true,
                        ConditionField::Relation => true,
                        ConditionField::DocumentCategory => true,
                        // Verify remaining conditions
                        ConditionField::EntityARole => wme.entity_a_role == cond.value_id,
                        ConditionField::EntityAGen => wme.entity_a_gen == cond.value_id,
                        ConditionField::EntityBType => wme.entity_b_type == cond.value_id,
                        ConditionField::EntityBRole => wme.entity_b_role == cond.value_id,
                        ConditionField::EntityBGen => wme.entity_b_gen == cond.value_id,
                        ConditionField::AmountBucket => {
                            let mask = cond.value_id as u8;
                            wme.amount_bucket < 8 && (mask >> wme.amount_bucket) & 1 == 1
                        }
                    };
                    if !matches {
                        all_match = false;
                        break;
                    }
                }

                if all_match {
                    let chained_cf = prod.confidence * wme.extraction_cf;
                    output.push(FiredProduction {
                        rule_id: prod.rule_id,
                        confidence: prod.confidence,
                        extraction_cf: wme.extraction_cf,
                        chained_cf,
                    });
                }
            }
        }

        // Fallback path: rules not in composite index (rare -- rules without all 3 primary fields)
        // Use bit-accumulation on non-composite-indexed productions.
        // This is handled by checking the secondary_productions list.
        for &prod_idx in &self.secondary_productions {
            let prod = &productions[prod_idx as usize];
            if !prod.status.fires() {
                continue;
            }

            let conditions = &prod_conditions[prod_idx as usize];
            let mut all_match = true;
            for cond in conditions.iter() {
                let matches = match cond.field {
                    ConditionField::EntityAType => wme.entity_a_type == cond.value_id,
                    ConditionField::EntityARole => wme.entity_a_role == cond.value_id,
                    ConditionField::EntityAGen => wme.entity_a_gen == cond.value_id,
                    ConditionField::Relation => wme.relation == cond.value_id,
                    ConditionField::EntityBType => wme.entity_b_type == cond.value_id,
                    ConditionField::EntityBRole => wme.entity_b_role == cond.value_id,
                    ConditionField::EntityBGen => wme.entity_b_gen == cond.value_id,
                    ConditionField::DocumentCategory => {
                        wme.document_category == cond.value_id as u8
                    }
                    ConditionField::AmountBucket => {
                        let mask = cond.value_id as u8;
                        wme.amount_bucket < 8 && (mask >> wme.amount_bucket) & 1 == 1
                    }
                };
                if !matches {
                    all_match = false;
                    break;
                }
            }

            if all_match {
                let chained_cf = prod.confidence * wme.extraction_cf;
                output.push(FiredProduction {
                    rule_id: prod.rule_id,
                    confidence: prod.confidence,
                    extraction_cf: wme.extraction_cf,
                    chained_cf,
                });
            }
        }
    }

    /// Insert a WME with JTMS justification tracking.
    ///
    /// For each fired production, creates a JTMS justification linking the conclusion
    /// to the rule and the inserted WME. Returns (WmeKey, fired_productions, conclusion_ids).
    pub fn insert_wme_with_jtms(
        &mut self,
        wme: Wme,
        is_system: bool,
    ) -> (WmeKey, Vec<FiredProduction>, Vec<ConclusionId>) {
        let mut fired = Vec::new();
        self.insert_wme_into(&wme, &mut fired);

        // Store in working memory and get the key
        let wme_key = self.working_memory.insert(wme);

        // Create JTMS justifications for each fired production
        let mut conclusion_ids = Vec::with_capacity(fired.len());
        for fp in &fired {
            if let Some(cid) = self.jtms.add_justification(
                fp.rule_id,
                vec![wme_key],
                fp.chained_cf,
                1, // chain_depth = 1 for direct alpha-network firings
                is_system,
            ) {
                conclusion_ids.push(cid);
            }
        }

        (wme_key, fired, conclusion_ids)
    }

    /// Retract a WME from working memory and trigger JTMS cascade retraction.
    ///
    /// Returns the list of ConclusionIds that were retracted (transitioned IN -> OUT).
    pub fn retract_wme(&mut self, wme_key: WmeKey) -> Vec<ConclusionId> {
        // Remove from working memory
        self.working_memory.remove(wme_key);

        // Trigger JTMS retraction cascade
        self.jtms.retract_wme(wme_key)
    }

    /// Number of registered productions.
    pub fn production_count(&self) -> usize {
        self.productions.len()
    }

    /// Number of WMEs in working memory.
    pub fn wme_count(&self) -> usize {
        self.working_memory.len()
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

/// Free function to probe a field index and accumulate bits.
/// Split out to avoid borrow checker conflicts in Engine methods.
#[inline(always)]
#[allow(dead_code)] // Retained as alternative probe implementation for benchmarking.
fn probe_field(index: &FieldIndex, value: u16, scratch: &mut [u64], candidates: &mut Vec<u32>) {
    for entry in index.lookup(value) {
        let bits = &mut scratch[entry.production_idx as usize];
        if *bits == 0 {
            candidates.push(entry.production_idx);
        }
        *bits |= 1u64 << entry.condition_bit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alpha_network::ConditionField;

    fn make_test_engine() -> Engine {
        let mut engine = Engine::new();

        let org = engine.entity_type_dict.get_or_insert("organization");
        let provider = engine.entity_role_dict.get_or_insert("provider");
        let hospital = engine.entity_gen_dict.get_or_insert("hospital");
        let billed_at = engine.relation_dict.get_or_insert("billed_at");
        let amount = engine.entity_type_dict.get_or_insert("amount");
        let medical = engine.doc_category_dict.get_or_insert("medical_bill");

        let conditions = vec![
            AlphaCondition {
                field: ConditionField::EntityAType,
                value_id: org,
            },
            AlphaCondition {
                field: ConditionField::EntityARole,
                value_id: provider,
            },
            AlphaCondition {
                field: ConditionField::EntityAGen,
                value_id: hospital,
            },
            AlphaCondition {
                field: ConditionField::Relation,
                value_id: billed_at,
            },
            AlphaCondition {
                field: ConditionField::EntityBType,
                value_id: amount,
            },
            AlphaCondition {
                field: ConditionField::DocumentCategory,
                value_id: medical,
            },
        ];

        engine.add_production(127, &conditions, RuleStatus::Active, 0.72);
        engine
    }

    #[test]
    fn test_matching_wme_fires() {
        let mut engine = make_test_engine();

        let org = engine.entity_type_dict.get_id("organization").unwrap();
        let provider = engine.entity_role_dict.get_id("provider").unwrap();
        let hospital = engine.entity_gen_dict.get_id("hospital").unwrap();
        let billed_at = engine.relation_dict.get_id("billed_at").unwrap();
        let amount = engine.entity_type_dict.get_id("amount").unwrap();
        let medical = engine.doc_category_dict.get_id("medical_bill").unwrap();

        let wme = Wme::new(
            org,
            provider,
            hospital,
            billed_at,
            amount,
            0,
            0,
            3,
            medical as u8,
            0.91,
        );

        let fired = engine.insert_wme(wme);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule_id, 127);
        assert!((fired[0].chained_cf - 0.72 * 0.91).abs() < 0.001);
    }

    #[test]
    fn test_non_matching_wme_does_not_fire() {
        let mut engine = make_test_engine();

        let person = engine.entity_type_dict.get_or_insert("person");
        let tenant = engine.entity_role_dict.get_or_insert("tenant");

        let wme = Wme::new(person, tenant, 0, 0, 0, 0, 0, 0, 0, 0.85);
        let fired = engine.insert_wme(wme);
        assert_eq!(fired.len(), 0);
    }

    #[test]
    fn test_dormant_rule_does_not_fire() {
        let mut engine = Engine::new();
        let org = engine.entity_type_dict.get_or_insert("organization");
        let conditions = vec![AlphaCondition {
            field: ConditionField::EntityAType,
            value_id: org,
        }];
        engine.add_production(1, &conditions, RuleStatus::Dormant, 0.5);

        let wme = Wme::new(org, 0, 0, 0, 0, 0, 0, 255, 0, 0.9);
        let fired = engine.insert_wme(wme);
        assert_eq!(fired.len(), 0);
    }

    #[test]
    fn test_multiple_rules_fire() {
        let mut engine = Engine::new();
        let org = engine.entity_type_dict.get_or_insert("organization");
        let billed = engine.relation_dict.get_or_insert("billed_at");

        engine.add_production(
            1,
            &[AlphaCondition {
                field: ConditionField::EntityAType,
                value_id: org,
            }],
            RuleStatus::Active,
            0.8,
        );

        engine.add_production(
            2,
            &[
                AlphaCondition {
                    field: ConditionField::EntityAType,
                    value_id: org,
                },
                AlphaCondition {
                    field: ConditionField::Relation,
                    value_id: billed,
                },
            ],
            RuleStatus::Active,
            0.6,
        );

        let wme = Wme::new(org, 0, 0, billed, 0, 0, 0, 255, 0, 0.9);
        let fired = engine.insert_wme(wme);
        assert_eq!(fired.len(), 2);
    }

    // ==== JTMS Integration Tests ====

    #[test]
    fn test_jtms_integration_insert_and_retract() {
        use crate::jtms::BeliefState;

        let mut engine = make_test_engine();

        let org = engine.entity_type_dict.get_id("organization").unwrap();
        let provider = engine.entity_role_dict.get_id("provider").unwrap();
        let hospital = engine.entity_gen_dict.get_id("hospital").unwrap();
        let billed_at = engine.relation_dict.get_id("billed_at").unwrap();
        let amount = engine.entity_type_dict.get_id("amount").unwrap();
        let medical = engine.doc_category_dict.get_id("medical_bill").unwrap();

        let wme = Wme::new(
            org,
            provider,
            hospital,
            billed_at,
            amount,
            0,
            0,
            3,
            medical as u8,
            0.91,
        );

        // Insert with JTMS tracking
        let (wme_key, fired, conclusion_ids) = engine.insert_wme_with_jtms(wme, false);
        assert_eq!(fired.len(), 1, "One production should fire");
        assert_eq!(conclusion_ids.len(), 1, "One JTMS conclusion created");

        let cid = conclusion_ids[0];
        assert_eq!(engine.jtms.belief_state(cid), Some(BeliefState::In));
        assert!(engine.jtms.combined_cf(cid).unwrap() > 0.0);

        // Verify chained CF is correct: 0.72 * 0.91 = 0.6552
        let expected_cf = 0.72_f32 * 0.91_f32;
        assert!(
            (engine.jtms.combined_cf(cid).unwrap() - expected_cf).abs() < 0.001,
            "Expected CF {}, got {}",
            expected_cf,
            engine.jtms.combined_cf(cid).unwrap()
        );

        // Retract the WME -> conclusion should go OUT
        let retracted = engine.retract_wme(wme_key);
        assert_eq!(retracted.len(), 1);
        assert_eq!(retracted[0], cid);
        assert_eq!(engine.jtms.belief_state(cid), Some(BeliefState::Out));
        assert_eq!(
            engine.wme_count(),
            0,
            "WME should be removed from working memory"
        );
    }

    #[test]
    fn test_jtms_integration_multiple_wmes_same_rule() {
        use crate::jtms::BeliefState;

        let mut engine = make_test_engine();

        let org = engine.entity_type_dict.get_id("organization").unwrap();
        let provider = engine.entity_role_dict.get_id("provider").unwrap();
        let hospital = engine.entity_gen_dict.get_id("hospital").unwrap();
        let billed_at = engine.relation_dict.get_id("billed_at").unwrap();
        let amount = engine.entity_type_dict.get_id("amount").unwrap();
        let medical = engine.doc_category_dict.get_id("medical_bill").unwrap();

        // Insert two matching WMEs -- each creates its own conclusion
        let wme1 = Wme::new(
            org,
            provider,
            hospital,
            billed_at,
            amount,
            0,
            0,
            3,
            medical as u8,
            0.91,
        );
        let wme2 = Wme::new(
            org,
            provider,
            hospital,
            billed_at,
            amount,
            0,
            0,
            5,
            medical as u8,
            0.85,
        );

        let (key1, _, cids1) = engine.insert_wme_with_jtms(wme1, false);
        let (key2, _, cids2) = engine.insert_wme_with_jtms(wme2, false);

        assert_eq!(cids1.len(), 1);
        assert_eq!(cids2.len(), 1);
        assert_ne!(
            cids1[0], cids2[0],
            "Different WMEs produce different conclusions"
        );

        // Retract WME 1 -> only its conclusion goes OUT
        let retracted = engine.retract_wme(key1);
        assert_eq!(retracted.len(), 1);
        assert_eq!(engine.jtms.belief_state(cids1[0]), Some(BeliefState::Out));
        assert_eq!(engine.jtms.belief_state(cids2[0]), Some(BeliefState::In));

        // Retract WME 2 -> its conclusion also goes OUT
        let retracted = engine.retract_wme(key2);
        assert_eq!(retracted.len(), 1);
        assert_eq!(engine.jtms.belief_state(cids2[0]), Some(BeliefState::Out));
    }
}
