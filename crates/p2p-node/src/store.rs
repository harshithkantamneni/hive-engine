//! Local rule store with CRDT merge semantics.
//!
//! Implements version reconciliation.
//! Version ordering: higher version wins; on tie, evidence count breaks it.

use crate::rule::{RuleMessage, ShardKey};
use std::collections::HashMap;

/// Result of merging a rule into the local store.
#[derive(Debug, PartialEq)]
pub enum MergeResult {
    /// Incoming rule was accepted as a newer version.
    Accepted,
    /// Incoming rule was rejected (local is newer or equal).
    Rejected,
    /// This is a brand-new rule not previously seen.
    New,
}

/// Local rule store indexed by rule_id.
pub struct RuleStore {
    rules: HashMap<u64, RuleMessage>,
    /// Shard key string -> list of rule_ids in that shard.
    shard_index: HashMap<String, Vec<u64>>,
}

impl Default for RuleStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleStore {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            shard_index: HashMap::new(),
        }
    }

    pub fn get(&self, rule_id: u64) -> Option<&RuleMessage> {
        self.rules.get(&rule_id)
    }

    pub fn get_shard_rules(&self, shard_key: &ShardKey) -> Vec<&RuleMessage> {
        let key = shard_key.to_string();
        self.shard_index
            .get(&key)
            .map(|ids| ids.iter().filter_map(|id| self.rules.get(id)).collect())
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Insert or merge a rule. Uses version-based CRDT merge:
    /// higher version wins; same version, higher evidence count wins.
    pub fn merge(&mut self, incoming: RuleMessage) -> MergeResult {
        let rule_id = incoming.rule_id;

        if let Some(local) = self.rules.get(&rule_id) {
            if is_newer(&incoming, local) {
                let shard_str = incoming.shard_key().to_string();
                self.rules.insert(rule_id, incoming);
                if !self.shard_index.contains_key(&shard_str) {
                    self.shard_index.entry(shard_str).or_default().push(rule_id);
                }
                MergeResult::Accepted
            } else {
                MergeResult::Rejected
            }
        } else {
            let shard_str = incoming.shard_key().to_string();
            self.rules.insert(rule_id, incoming);
            self.shard_index.entry(shard_str).or_default().push(rule_id);
            MergeResult::New
        }
    }
}

/// Determine whether version `a` is newer than `b`.
/// Ordering:
/// 1. Higher version number always wins.
/// 2. Same version: higher evidence count wins.
/// 3. Tie: keep existing.
pub fn is_newer(a: &RuleMessage, b: &RuleMessage) -> bool {
    if a.version > b.version {
        return true;
    }
    if a.version < b.version {
        return false;
    }
    // Same version: evidence count tiebreak
    if a.evidence_count > b.evidence_count {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{create_test_rule, SensitivityTier};

    #[test]
    fn test_higher_version_wins() {
        let a = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        let mut b = a.clone();
        b.version = 2;
        assert!(is_newer(&b, &a));
        assert!(!is_newer(&a, &b));
    }

    #[test]
    fn test_evidence_tiebreak() {
        let mut a = create_test_rule("receipt", SensitivityTier::S4, 1, 0.80);
        a.evidence_count = 100;
        let mut b = a.clone();
        b.evidence_count = 80;
        assert!(is_newer(&a, &b));
        assert!(!is_newer(&b, &a));
    }

    #[test]
    fn test_tie_keeps_existing() {
        let a = create_test_rule("receipt", SensitivityTier::S4, 1, 0.80);
        let b = a.clone();
        assert!(!is_newer(&a, &b));
        assert!(!is_newer(&b, &a));
    }

    #[test]
    fn test_store_merge_new() {
        let mut store = RuleStore::new();
        let rule = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        assert_eq!(store.merge(rule), MergeResult::New);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_store_merge_newer_accepted() {
        let mut store = RuleStore::new();
        let r1 = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        store.merge(r1);

        let mut r2 = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.90);
        r2.version = 2;
        assert_eq!(store.merge(r2), MergeResult::Accepted);
        assert_eq!(store.get(1).unwrap().version, 2);
    }

    #[test]
    fn test_store_merge_older_rejected() {
        let mut store = RuleStore::new();
        let mut r2 = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        r2.version = 2;
        store.merge(r2);

        let r1 = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        assert_eq!(store.merge(r1), MergeResult::Rejected);
    }

    #[test]
    fn test_store_shard_query() {
        let mut store = RuleStore::new();
        let shard = ShardKey::new("medical_bill", SensitivityTier::S1);

        store.merge(create_test_rule(
            "medical_bill",
            SensitivityTier::S1,
            1,
            0.85,
        ));
        store.merge(create_test_rule(
            "medical_bill",
            SensitivityTier::S1,
            2,
            0.75,
        ));
        store.merge(create_test_rule("lease", SensitivityTier::S3, 3, 0.60));

        assert_eq!(store.get_shard_rules(&shard).len(), 2);
        let lease_shard = ShardKey::new("lease", SensitivityTier::S3);
        assert_eq!(store.get_shard_rules(&lease_shard).len(), 1);
    }
}
