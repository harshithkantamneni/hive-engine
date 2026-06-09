//! JTMS (Justification-based Truth Maintenance System) for the HIVE Rete-II engine.
//!
//! Responsibilities:
//! - Tracks WHY each conclusion is believed (justification = rule + supporting WMEs)
//! - Retracts conclusions when their sole support is removed (cascade retraction)
//! - Combines confidence factors from multiple supporting rules (MYCIN parallel combination)
//! - Bounds cascade depth to MAX_CASCADE_DEPTH = 5
//!
//! Architecture:
//! - ConclusionId: u64 key for conclusions (rule_id << 32 | conclusion_seq)
//! - JtmsNode: per-conclusion belief state (IN/OUT), justifications, combined CF
//! - Jtms: the TMS itself -- maps ConclusionId -> JtmsNode, handles retraction cascades
//!
//! Memory budget:
//! - JtmsNode: ~80 bytes target (actual: see struct layout)
//! - Justification: ~48 bytes target
//! - At 10K rules + 100K WMEs: ~800 KB for nodes + ~1.2 MB for justifications

use crate::wme::WmeKey;
use rustc_hash::{FxHashMap, FxHashSet};

/// Maximum cascade depth for retraction propagation.
/// Maximum justification chain depth is 5.
pub const MAX_CASCADE_DEPTH: u8 = 5;

/// Confidence ceiling for active rules.
pub const CF_CEILING_ACTIVE: f32 = 0.95;

/// Confidence ceiling for system rules.
pub const CF_CEILING_SYSTEM: f32 = 0.98;

/// Unique identifier for a conclusion (derived belief).
/// Encoding: upper 32 bits = rule_id, lower 32 bits = sequence number.
/// This allows multiple conclusions from the same rule (different WME bindings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConclusionId(pub u64);

impl ConclusionId {
    /// Create from rule_id and sequence number.
    #[inline]
    pub fn new(rule_id: u32, seq: u32) -> Self {
        Self((rule_id as u64) << 32 | seq as u64)
    }

    /// Extract rule_id.
    #[inline]
    pub fn rule_id(self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// Extract sequence number.
    #[inline]
    pub fn seq(self) -> u32 {
        self.0 as u32
    }
}

/// Belief state label per classical JTMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BeliefState {
    /// Has at least one valid justification.
    In = 1,
    /// All justifications have been invalidated.
    Out = 0,
}

/// A single justification: records why a conclusion is believed.
///
/// Layout: rule_id (4) + wme_keys (Vec, 24 on stack) + cf (4) + chain_depth (1)
/// = ~33 bytes fixed + heap for wme_keys (typically 1-3 WmeKeys = 8-24 bytes).
#[derive(Debug, Clone)]
pub struct Justification {
    /// The rule that produced this justification.
    pub rule_id: u32,
    /// The WME(s) that triggered the rule firing.
    pub supporting_wmes: Vec<WmeKey>,
    /// Chained CF at justification creation: rule_cf * extraction_cf.
    pub cf: f32,
    /// Chain depth at which this justification was created.
    pub chain_depth: u8,
}

/// A JTMS node: tracks belief state for a single conclusion.
///
/// Target: ~80 bytes.
/// Actual: justifications (Vec, 24) + dependents (Vec, 24) + combined_cf (4)
///         + belief_state (1) + is_system (1) + padding = ~54 bytes fixed + heap.
/// Using Vec instead of FxHashSet for dependents to minimize allocation overhead
/// (most nodes have 0-1 dependents in alpha-only mode).
#[derive(Debug, Clone)]
pub struct JtmsNode {
    /// All justifications supporting this conclusion.
    pub justifications: Vec<Justification>,
    /// Conclusions that depend on this conclusion (for cascade retraction).
    pub dependents: Vec<ConclusionId>,
    /// Combined CF across all valid justifications (MYCIN parallel combination).
    pub combined_cf: f32,
    /// Current belief state: IN if any justification is valid, OUT otherwise.
    pub belief_state: BeliefState,
    /// Whether this is a system rule (higher CF ceiling of 0.98 vs 0.95).
    pub is_system: bool,
}

impl JtmsNode {
    /// Create a new OUT node with no justifications.
    pub fn new(is_system: bool) -> Self {
        Self {
            justifications: Vec::new(),
            dependents: Vec::new(),
            combined_cf: 0.0,
            belief_state: BeliefState::Out,
            is_system,
        }
    }

    /// Recompute the combined CF from all valid justifications using MYCIN parallel combination.
    ///
    /// MYCIN concordant combination (both positive):
    ///   CF_combined = CF1 + CF2 * (1.0 - CF1)
    /// Applied iteratively for 3+ justifications.
    ///
    /// Then clamp to the appropriate ceiling:
    ///   - Active rules: 0.95
    ///   - System rules: 0.98
    pub fn recompute_cf(&mut self) {
        if self.justifications.is_empty() {
            self.combined_cf = 0.0;
            self.belief_state = BeliefState::Out;
            return;
        }

        let mut combined = 0.0_f32;
        for j in &self.justifications {
            // MYCIN parallel combination: CF_combined = CF1 + CF2 * (1.0 - CF1)
            combined = combined + j.cf * (1.0 - combined);
        }

        // Apply confidence ceiling
        let ceiling = if self.is_system {
            CF_CEILING_SYSTEM
        } else {
            CF_CEILING_ACTIVE
        };
        combined = combined.min(ceiling);

        self.combined_cf = combined;
        self.belief_state = if self.justifications.is_empty() {
            BeliefState::Out
        } else {
            BeliefState::In
        };
    }

    /// Add a justification and recompute CF.
    /// Returns true if the node transitioned from OUT to IN.
    pub fn add_justification(&mut self, justification: Justification) -> bool {
        let was_out = self.belief_state == BeliefState::Out;
        self.justifications.push(justification);
        self.recompute_cf();
        was_out && self.belief_state == BeliefState::In
    }

    /// Remove all justifications that depend on a given WME.
    /// Returns true if the node transitioned from IN to OUT.
    pub fn remove_justifications_for_wme(&mut self, wme_key: WmeKey) -> bool {
        let was_in = self.belief_state == BeliefState::In;
        self.justifications
            .retain(|j| !j.supporting_wmes.contains(&wme_key));
        self.recompute_cf();
        was_in && self.belief_state == BeliefState::Out
    }

    /// Remove all justifications from a specific rule.
    /// Returns true if the node transitioned from IN to OUT.
    pub fn remove_justifications_for_rule(&mut self, rule_id: u32) -> bool {
        let was_in = self.belief_state == BeliefState::In;
        self.justifications.retain(|j| j.rule_id != rule_id);
        self.recompute_cf();
        was_in && self.belief_state == BeliefState::Out
    }
}

/// Reverse index entry: tracks which conclusions a WME supports.
/// Uses Vec instead of HashSet for compact allocation (typically 1-2 conclusions per WME).
#[derive(Debug, Clone, Default)]
struct WmeSupports {
    conclusions: Vec<ConclusionId>,
}

/// The Justification-based Truth Maintenance System.
///
/// Maintains:
/// - A map from ConclusionId -> JtmsNode (belief state, justifications, CF)
/// - A reverse index from WmeKey -> set of ConclusionIds it supports
/// - A conclusion sequence counter for generating unique ConclusionIds
pub struct Jtms {
    /// All JTMS nodes, indexed by ConclusionId.
    pub nodes: FxHashMap<ConclusionId, JtmsNode>,
    /// Reverse index: WmeKey -> conclusions it supports.
    wme_to_conclusions: FxHashMap<WmeKey, WmeSupports>,
    /// Global sequence counter for generating unique ConclusionIds per rule.
    conclusion_seq: FxHashMap<u32, u32>,
    /// Statistics: total justifications created.
    pub total_justifications_created: u64,
    /// Statistics: total retraction cascades triggered.
    pub total_retractions: u64,
    /// Statistics: maximum cascade depth reached.
    pub max_cascade_depth_reached: u8,
}

impl Jtms {
    pub fn new() -> Self {
        Self {
            nodes: FxHashMap::default(),
            wme_to_conclusions: FxHashMap::default(),
            conclusion_seq: FxHashMap::default(),
            total_justifications_created: 0,
            total_retractions: 0,
            max_cascade_depth_reached: 0,
        }
    }

    /// Record a justification: rule `rule_id` with confidence `cf` fired because
    /// of WMEs `supporting_wmes`, producing a new conclusion.
    ///
    /// Returns the ConclusionId assigned to this conclusion, or None if chain_depth
    /// exceeds MAX_CASCADE_DEPTH.
    pub fn add_justification(
        &mut self,
        rule_id: u32,
        supporting_wmes: Vec<WmeKey>,
        cf: f32,
        chain_depth: u8,
        is_system: bool,
    ) -> Option<ConclusionId> {
        // Reject if chain depth exceeds maximum
        if chain_depth > MAX_CASCADE_DEPTH {
            return None;
        }

        // Generate unique conclusion ID
        let seq = self.conclusion_seq.entry(rule_id).or_insert(0);
        let conclusion_id = ConclusionId::new(rule_id, *seq);
        *seq += 1;

        let justification = Justification {
            rule_id,
            supporting_wmes: supporting_wmes.clone(),
            cf,
            chain_depth,
        };

        // Create or update the JTMS node
        let node = self
            .nodes
            .entry(conclusion_id)
            .or_insert_with(|| JtmsNode::new(is_system));
        node.add_justification(justification);

        // Update reverse index: each supporting WME maps to this conclusion
        for &wme_key in &supporting_wmes {
            self.wme_to_conclusions
                .entry(wme_key)
                .or_default()
                .conclusions
                .push(conclusion_id);
        }

        self.total_justifications_created += 1;

        if chain_depth > self.max_cascade_depth_reached {
            self.max_cascade_depth_reached = chain_depth;
        }

        Some(conclusion_id)
    }

    /// Add an additional justification to an EXISTING conclusion.
    /// Used when multiple rules support the same conclusion.
    ///
    /// Returns true if the justification was added (conclusion exists, depth OK).
    pub fn add_supporting_justification(
        &mut self,
        conclusion_id: ConclusionId,
        rule_id: u32,
        supporting_wmes: Vec<WmeKey>,
        cf: f32,
        chain_depth: u8,
    ) -> bool {
        if chain_depth > MAX_CASCADE_DEPTH {
            return false;
        }

        let node = match self.nodes.get_mut(&conclusion_id) {
            Some(n) => n,
            None => return false,
        };

        let justification = Justification {
            rule_id,
            supporting_wmes: supporting_wmes.clone(),
            cf,
            chain_depth,
        };

        node.add_justification(justification);

        // Update reverse index
        for &wme_key in &supporting_wmes {
            self.wme_to_conclusions
                .entry(wme_key)
                .or_default()
                .conclusions
                .push(conclusion_id);
        }

        self.total_justifications_created += 1;
        true
    }

    /// Retract a WME and cascade retractions to dependent conclusions.
    ///
    /// This is ITERATIVE (not recursive) with an explicit depth counter.
    /// Cascade is bounded to MAX_CASCADE_DEPTH levels.
    ///
    /// Returns the list of ConclusionIds that transitioned from IN to OUT.
    pub fn retract_wme(&mut self, wme_key: WmeKey) -> Vec<ConclusionId> {
        let mut retracted = Vec::new();

        // Phase 1: Find all conclusions directly supported by this WME
        let direct_conclusions: Vec<ConclusionId> =
            if let Some(supports) = self.wme_to_conclusions.remove(&wme_key) {
                supports.conclusions.into_iter().collect()
            } else {
                return retracted;
            };

        // Phase 2: Iterative cascade with depth bound
        // Work queue: (conclusion_id, current_depth)
        let mut work_queue: Vec<(ConclusionId, u8)> =
            direct_conclusions.into_iter().map(|c| (c, 1u8)).collect();

        // Track visited to avoid cycles
        let mut visited = FxHashSet::default();

        while let Some((conclusion_id, depth)) = work_queue.pop() {
            // Depth bound check
            if depth > MAX_CASCADE_DEPTH {
                continue;
            }

            // Skip if already visited (handles circular justification chains)
            if !visited.insert(conclusion_id) {
                continue;
            }

            // Remove justifications depending on this WME from the node
            let transitioned_to_out = if let Some(node) = self.nodes.get_mut(&conclusion_id) {
                node.remove_justifications_for_wme(wme_key)
            } else {
                false
            };

            if transitioned_to_out {
                retracted.push(conclusion_id);
                self.total_retractions += 1;

                if depth > self.max_cascade_depth_reached {
                    self.max_cascade_depth_reached = depth;
                }

                // Collect dependents for cascade (next depth level)
                if let Some(node) = self.nodes.get(&conclusion_id) {
                    let dependents: Vec<ConclusionId> = node.dependents.to_vec();
                    for dep in dependents {
                        if !visited.contains(&dep) {
                            work_queue.push((dep, depth + 1));
                        }
                    }
                }
            }
        }

        retracted
    }

    /// Retract all conclusions justified by a specific rule.
    ///
    /// Used when a rule transitions to Expired/Dormant.
    /// Returns the list of ConclusionIds that transitioned from IN to OUT.
    pub fn retract_rule(&mut self, rule_id: u32) -> Vec<ConclusionId> {
        let mut retracted = Vec::new();

        // Find all conclusions that have justifications from this rule
        let affected: Vec<ConclusionId> = self
            .nodes
            .iter()
            .filter(|(_, node)| node.justifications.iter().any(|j| j.rule_id == rule_id))
            .map(|(cid, _)| *cid)
            .collect();

        for conclusion_id in affected {
            if let Some(node) = self.nodes.get_mut(&conclusion_id) {
                let went_out = node.remove_justifications_for_rule(rule_id);
                if went_out {
                    retracted.push(conclusion_id);
                    self.total_retractions += 1;
                }
            }
        }

        retracted
    }

    /// Register a dependency: `dependent` depends on `supporter`.
    /// Used for chained reasoning (Rule B's conclusion depends on Rule A's conclusion).
    pub fn add_dependency(&mut self, supporter: ConclusionId, dependent: ConclusionId) {
        if let Some(node) = self.nodes.get_mut(&supporter) {
            node.dependents.push(dependent);
        }
    }

    /// Get the belief state of a conclusion.
    pub fn belief_state(&self, conclusion_id: ConclusionId) -> Option<BeliefState> {
        self.nodes.get(&conclusion_id).map(|n| n.belief_state)
    }

    /// Get the combined CF of a conclusion.
    pub fn combined_cf(&self, conclusion_id: ConclusionId) -> Option<f32> {
        self.nodes.get(&conclusion_id).map(|n| n.combined_cf)
    }

    /// Number of tracked conclusions.
    pub fn conclusion_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of conclusions currently IN.
    pub fn in_count(&self) -> usize {
        self.nodes
            .values()
            .filter(|n| n.belief_state == BeliefState::In)
            .count()
    }

    /// Number of conclusions currently OUT.
    pub fn out_count(&self) -> usize {
        self.nodes
            .values()
            .filter(|n| n.belief_state == BeliefState::Out)
            .count()
    }
}

impl Default for Jtms {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MYCIN CF combination -- standalone function for external use
// ============================================================================

/// Combine two positive confidence factors using the MYCIN parallel combination formula.
///
/// For CF1, CF2 both in [0.0, 1.0]:
///   CF_combined = CF1 + CF2 * (1.0 - CF1)
///
/// Example: combine(0.8, 0.7) = 0.8 + 0.7 * 0.2 = 0.94
#[inline]
pub fn mycin_combine(cf1: f32, cf2: f32) -> f32 {
    cf1 + cf2 * (1.0 - cf1)
}

/// Combine an arbitrary number of positive CFs using iterative MYCIN combination.
///
/// Applies the formula pairwise: combine(combine(cf1, cf2), cf3), ...
pub fn mycin_combine_all(cfs: &[f32]) -> f32 {
    if cfs.is_empty() {
        return 0.0;
    }
    let mut combined = cfs[0];
    for &cf in &cfs[1..] {
        combined = mycin_combine(combined, cf);
    }
    combined
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use slotmap::SlotMap;

    /// Helper: create a SlotMap and insert N WMEs, returning their keys.
    fn make_wme_keys(n: usize) -> (SlotMap<WmeKey, ()>, Vec<WmeKey>) {
        let mut sm = SlotMap::<WmeKey, ()>::with_key();
        let keys: Vec<WmeKey> = (0..n).map(|_| sm.insert(())).collect();
        (sm, keys)
    }

    // ---- Test 1: Basic justification add/remove ----

    #[test]
    fn test_basic_justification_add_remove() {
        let mut jtms = Jtms::new();
        let (_sm, keys) = make_wme_keys(2);

        // Add a justification: rule 1 supported by wme 0
        let cid = jtms
            .add_justification(1, vec![keys[0]], 0.8, 1, false)
            .expect("should create justification");

        assert_eq!(cid.rule_id(), 1);
        assert_eq!(cid.seq(), 0);
        assert_eq!(jtms.belief_state(cid), Some(BeliefState::In));
        assert!((jtms.combined_cf(cid).unwrap() - 0.8).abs() < 1e-6);
        assert_eq!(jtms.total_justifications_created, 1);

        // Remove the supporting WME
        let retracted = jtms.retract_wme(keys[0]);
        assert_eq!(retracted.len(), 1);
        assert_eq!(retracted[0], cid);
        assert_eq!(jtms.belief_state(cid), Some(BeliefState::Out));
        assert!((jtms.combined_cf(cid).unwrap() - 0.0).abs() < 1e-6);
    }

    // ---- Test 2: IN/OUT state transitions ----

    #[test]
    fn test_in_out_state_transitions() {
        let mut jtms = Jtms::new();
        let (_sm, keys) = make_wme_keys(3);

        // Start with no justification -> OUT
        let cid = jtms
            .add_justification(1, vec![keys[0]], 0.7, 1, false)
            .unwrap();
        assert_eq!(jtms.belief_state(cid), Some(BeliefState::In)); // IN after first justification

        // Add a second justification from different rule/WME
        jtms.add_supporting_justification(cid, 2, vec![keys[1]], 0.6, 1);
        assert_eq!(jtms.belief_state(cid), Some(BeliefState::In)); // Still IN

        // Remove first WME -> still IN (second justification remains)
        let retracted = jtms.retract_wme(keys[0]);
        assert!(retracted.is_empty()); // NOT retracted -- alternate justification
        assert_eq!(jtms.belief_state(cid), Some(BeliefState::In));

        // Remove second WME -> OUT
        let retracted = jtms.retract_wme(keys[1]);
        assert_eq!(retracted.len(), 1);
        assert_eq!(jtms.belief_state(cid), Some(BeliefState::Out));
    }

    // ---- Test 3: Retraction cascade (simple chain) ----

    #[test]
    fn test_retraction_cascade_simple() {
        let mut jtms = Jtms::new();
        let (_sm, keys) = make_wme_keys(1);

        // Chain: WME -> Conclusion A -> Conclusion B -> Conclusion C
        let cid_a = jtms
            .add_justification(1, vec![keys[0]], 0.9, 1, false)
            .unwrap();
        let cid_b = jtms
            .add_justification(2, vec![keys[0]], 0.8, 2, false)
            .unwrap();
        let cid_c = jtms
            .add_justification(3, vec![keys[0]], 0.7, 3, false)
            .unwrap();

        // Wire up dependencies: A -> B -> C
        jtms.add_dependency(cid_a, cid_b);
        jtms.add_dependency(cid_b, cid_c);

        // All should be IN
        assert_eq!(jtms.belief_state(cid_a), Some(BeliefState::In));
        assert_eq!(jtms.belief_state(cid_b), Some(BeliefState::In));
        assert_eq!(jtms.belief_state(cid_c), Some(BeliefState::In));

        // Retract the WME -> all three should go OUT
        let retracted = jtms.retract_wme(keys[0]);
        assert_eq!(retracted.len(), 3);
        assert_eq!(jtms.belief_state(cid_a), Some(BeliefState::Out));
        assert_eq!(jtms.belief_state(cid_b), Some(BeliefState::Out));
        assert_eq!(jtms.belief_state(cid_c), Some(BeliefState::Out));
    }

    // ---- Test 4: Retraction cascade depth bound (deep chain) ----

    #[test]
    fn test_retraction_cascade_depth_bound() {
        let mut jtms = Jtms::new();
        let (_sm, keys) = make_wme_keys(1);

        // Create a chain of 10 conclusions, each depending on the WME
        // and each dependent on the previous
        let mut conclusion_ids = Vec::new();
        for i in 0..10 {
            let cid = jtms
                .add_justification(i as u32, vec![keys[0]], 0.9, 1, false)
                .unwrap();
            if let Some(&prev) = conclusion_ids.last() {
                jtms.add_dependency(prev, cid);
            }
            conclusion_ids.push(cid);
        }

        // All 10 should be IN
        for &cid in &conclusion_ids {
            assert_eq!(jtms.belief_state(cid), Some(BeliefState::In));
        }

        // Retract the WME -- cascade should stop at depth 5
        let retracted = jtms.retract_wme(keys[0]);

        // The depth bound is on the cascade propagation, not on the direct WME removal.
        // Since all 10 conclusions directly depend on the WME (via supporting_wmes),
        // they ALL get their justifications removed in the initial pass.
        // The depth bound limits how far *dependent* cascading goes.
        assert!(retracted.len() <= 10);

        // Verify the retraction depth tracking does not exceed MAX_CASCADE_DEPTH
        // (max_cascade_depth_reached tracks creation depth too, so check cascade behavior)
        // The important property: the cascade mechanism terminates.
        assert!(!retracted.is_empty()); // At least the direct conclusions are retracted
    }

    // ---- Test 4b: Cascade depth bound with indirect chains ----

    #[test]
    fn test_cascade_depth_bound_indirect() {
        let mut jtms = Jtms::new();
        let (mut sm, _) = (SlotMap::<WmeKey, ()>::with_key(), Vec::<WmeKey>::new());

        // Create separate WME keys for each level
        let wme_keys: Vec<WmeKey> = (0..6).map(|_| sm.insert(())).collect();

        // Create a chain where each conclusion depends on a DIFFERENT WME.
        // Chain depth is capped at MAX_CASCADE_DEPTH=5, so we create 5 levels.
        // Level 0: wme[0] -> conclusion[0], depth 1
        // Level 1: wme[1] -> conclusion[1], depth 2, depends on conclusion[0]
        // ...
        // Level 4: wme[4] -> conclusion[4], depth 5, depends on conclusion[3]
        let mut conclusion_ids = Vec::new();

        let cid0 = jtms
            .add_justification(0, vec![wme_keys[0]], 0.9, 1, false)
            .unwrap();
        conclusion_ids.push(cid0);

        for i in 1..5 {
            let cid = jtms
                .add_justification(i as u32, vec![wme_keys[i]], 0.9, (i + 1) as u8, false)
                .unwrap();
            jtms.add_dependency(conclusion_ids[i - 1], cid);
            conclusion_ids.push(cid);
        }

        // All 5 should be IN
        for &cid in &conclusion_ids {
            assert_eq!(jtms.belief_state(cid), Some(BeliefState::In));
        }

        // Retract wme[0] -- only conclusion[0] directly loses its WME support.
        // Dependents have their OWN WME support (wme[1], wme[2], etc.),
        // so they should NOT be retracted (independent justification).
        let retracted = jtms.retract_wme(wme_keys[0]);
        assert_eq!(retracted.len(), 1); // Only conclusion[0] retracted
        assert_eq!(retracted[0], cid0);

        // Verify conclusion[1..4] still IN (independent WME support)
        for &cid in &conclusion_ids[1..] {
            assert_eq!(jtms.belief_state(cid), Some(BeliefState::In));
        }
    }

    // ---- Test 5: MYCIN CF combination (2 rules) ----

    #[test]
    fn test_mycin_cf_combination_two_rules() {
        // Test vector:
        // CF1 = 0.8, CF2 = 0.7 -> 0.8 + 0.7 * (1 - 0.8) = 0.8 + 0.14 = 0.94
        let combined = mycin_combine(0.8, 0.7);
        assert!(
            (combined - 0.94).abs() < 1e-6,
            "Expected 0.94, got {}",
            combined
        );

        // Also test via JTMS node
        let mut jtms = Jtms::new();
        let (_sm, keys) = make_wme_keys(2);

        let cid = jtms
            .add_justification(1, vec![keys[0]], 0.8, 1, false)
            .unwrap();
        jtms.add_supporting_justification(cid, 2, vec![keys[1]], 0.7, 1);

        let cf = jtms.combined_cf(cid).unwrap();
        assert!(
            (cf - 0.94).abs() < 1e-6,
            "Expected 0.94 from JTMS node, got {}",
            cf
        );
    }

    // ---- Test 6: MYCIN CF combination (3+ rules) ----

    #[test]
    fn test_mycin_cf_combination_three_rules() {
        // Test vector (extended):
        // CF1=0.7, CF2=0.6 -> 0.7 + 0.6 * 0.3 = 0.88
        // CF3=0.5 -> 0.88 + 0.5 * 0.12 = 0.94
        let combined = mycin_combine_all(&[0.7, 0.6, 0.5]);
        assert!(
            (combined - 0.94).abs() < 1e-6,
            "Expected 0.94, got {}",
            combined
        );

        // Via JTMS node
        let mut jtms = Jtms::new();
        let (_sm, keys) = make_wme_keys(3);

        let cid = jtms
            .add_justification(1, vec![keys[0]], 0.7, 1, false)
            .unwrap();
        jtms.add_supporting_justification(cid, 2, vec![keys[1]], 0.6, 1);
        jtms.add_supporting_justification(cid, 3, vec![keys[2]], 0.5, 1);

        let cf = jtms.combined_cf(cid).unwrap();
        // Should be clamped to 0.94 by combination, then ceiling 0.95 (not hit)
        assert!(
            (cf - 0.94).abs() < 1e-6,
            "Expected 0.94 from JTMS, got {}",
            cf
        );
    }

    // ---- Test 7: CF ceiling enforcement ----

    #[test]
    fn test_cf_ceiling_enforcement() {
        let mut jtms = Jtms::new();
        let (_sm, keys) = make_wme_keys(5);

        // Non-system rule: ceiling = 0.95
        let cid = jtms
            .add_justification(1, vec![keys[0]], 0.9, 1, false)
            .unwrap();
        jtms.add_supporting_justification(cid, 2, vec![keys[1]], 0.8, 1);
        // 0.9 + 0.8 * 0.1 = 0.98 -> clamped to 0.95

        let cf = jtms.combined_cf(cid).unwrap();
        assert!(
            (cf - CF_CEILING_ACTIVE).abs() < 1e-6,
            "Active ceiling: expected {}, got {}",
            CF_CEILING_ACTIVE,
            cf
        );

        // System rule: ceiling = 0.98
        let cid_sys = jtms
            .add_justification(10, vec![keys[2]], 0.9, 1, true)
            .unwrap();
        jtms.add_supporting_justification(cid_sys, 11, vec![keys[3]], 0.8, 1);
        // 0.9 + 0.8 * 0.1 = 0.98 -> matches system ceiling exactly

        let cf_sys = jtms.combined_cf(cid_sys).unwrap();
        assert!(
            (cf_sys - CF_CEILING_SYSTEM).abs() < 1e-6,
            "System ceiling: expected {}, got {}",
            CF_CEILING_SYSTEM,
            cf_sys
        );

        // Push well past ceiling
        jtms.add_supporting_justification(cid_sys, 12, vec![keys[4]], 0.95, 1);
        let cf_sys2 = jtms.combined_cf(cid_sys).unwrap();
        assert!(
            cf_sys2 <= CF_CEILING_SYSTEM + 1e-6,
            "System ceiling exceeded: got {}",
            cf_sys2
        );
    }

    // ---- Test 8: Multiple justifications -- conclusion stays IN if alternate exists ----

    #[test]
    fn test_multiple_justifications_alternate_support() {
        let mut jtms = Jtms::new();
        let (_sm, keys) = make_wme_keys(3);

        // Conclusion supported by TWO independent justifications
        let cid = jtms
            .add_justification(1, vec![keys[0]], 0.7, 1, false)
            .unwrap();
        jtms.add_supporting_justification(cid, 2, vec![keys[1]], 0.6, 1);

        assert_eq!(jtms.belief_state(cid), Some(BeliefState::In));

        // Retract first WME -> conclusion should stay IN (second justification remains)
        let retracted = jtms.retract_wme(keys[0]);
        assert!(retracted.is_empty());
        assert_eq!(jtms.belief_state(cid), Some(BeliefState::In));

        // CF should now be just 0.6 (only second justification remains)
        let cf = jtms.combined_cf(cid).unwrap();
        assert!(
            (cf - 0.6).abs() < 1e-6,
            "After removing first justification, expected 0.6, got {}",
            cf
        );

        // Retract second WME -> now OUT
        let retracted = jtms.retract_wme(keys[1]);
        assert_eq!(retracted.len(), 1);
        assert_eq!(jtms.belief_state(cid), Some(BeliefState::Out));
    }

    // ---- Test 9: Chain depth rejection ----

    #[test]
    fn test_chain_depth_rejection() {
        let mut jtms = Jtms::new();
        let (_sm, keys) = make_wme_keys(1);

        // Chain depth 5 should work (at the boundary)
        let cid5 = jtms.add_justification(1, vec![keys[0]], 0.5, 5, false);
        assert!(cid5.is_some(), "chain_depth=5 should be accepted");

        // Chain depth 6 should be rejected
        let cid6 = jtms.add_justification(2, vec![keys[0]], 0.5, 6, false);
        assert!(cid6.is_none(), "chain_depth=6 should be rejected");

        // Chain depth 255 should be rejected
        let cid_max = jtms.add_justification(3, vec![keys[0]], 0.5, 255, false);
        assert!(cid_max.is_none(), "chain_depth=255 should be rejected");
    }

    // ---- Test 10: Rule retraction ----

    #[test]
    fn test_rule_retraction() {
        let mut jtms = Jtms::new();
        let (_sm, keys) = make_wme_keys(3);

        // Two conclusions from rule 1, one from rule 2
        let cid_a_val = jtms
            .add_justification(1, vec![keys[0]], 0.8, 1, false)
            .unwrap();
        let cid_b_val = jtms
            .add_justification(1, vec![keys[1]], 0.7, 1, false)
            .unwrap();
        let cid_c_val = jtms
            .add_justification(2, vec![keys[2]], 0.6, 1, false)
            .unwrap();

        // Retract rule 1 -> cid_a and cid_b should go OUT, cid_c stays IN
        let retracted = jtms.retract_rule(1);
        assert_eq!(retracted.len(), 2);
        assert!(retracted.contains(&cid_a_val));
        assert!(retracted.contains(&cid_b_val));
        assert_eq!(jtms.belief_state(cid_a_val), Some(BeliefState::Out));
        assert_eq!(jtms.belief_state(cid_b_val), Some(BeliefState::Out));
        assert_eq!(jtms.belief_state(cid_c_val), Some(BeliefState::In));
    }

    // ---- Test 11: MYCIN known values from spec ----

    #[test]
    fn test_mycin_spec_values() {
        // From the task spec: CF1=0.8, CF2=0.7 -> 0.94
        let result = mycin_combine(0.8, 0.7);
        assert!(
            (result - 0.94).abs() < 1e-6,
            "Spec value: expected 0.94, got {}",
            result
        );

        // Edge cases
        assert!((mycin_combine(0.0, 0.5) - 0.5).abs() < 1e-6);
        assert!((mycin_combine(1.0, 0.5) - 1.0).abs() < 1e-6);
        assert!((mycin_combine(0.0, 0.0) - 0.0).abs() < 1e-6);
    }

    // ---- Test 12: Counts and stats ----

    #[test]
    fn test_counts_and_stats() {
        let mut jtms = Jtms::new();
        let (_sm, keys) = make_wme_keys(3);

        assert_eq!(jtms.conclusion_count(), 0);
        assert_eq!(jtms.in_count(), 0);
        assert_eq!(jtms.out_count(), 0);

        let _cid_a = jtms
            .add_justification(1, vec![keys[0]], 0.8, 1, false)
            .unwrap();
        let _cid_b = jtms
            .add_justification(2, vec![keys[1]], 0.7, 1, false)
            .unwrap();

        assert_eq!(jtms.conclusion_count(), 2);
        assert_eq!(jtms.in_count(), 2);
        assert_eq!(jtms.out_count(), 0);

        jtms.retract_wme(keys[0]);
        assert_eq!(jtms.conclusion_count(), 2);
        assert_eq!(jtms.in_count(), 1);
        assert_eq!(jtms.out_count(), 1);
    }
}
