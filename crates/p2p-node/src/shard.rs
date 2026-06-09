//! Shard assignment logic and topic mapping.
//!
//! Maps (document_category, sensitivity_tier) to Gossipsub topics and DHT keys.
//! 10 categories x 4 tiers = 40 logical shards per R9.

use crate::rule::{SensitivityTier, ShardKey, DOCUMENT_CATEGORIES, SENSITIVITY_TIERS};
use libp2p::gossipsub;

/// Generate all 40 shard keys (10 categories x 4 tiers).
pub fn all_shard_keys() -> Vec<ShardKey> {
    let mut keys = Vec::with_capacity(40);
    for cat in DOCUMENT_CATEGORIES {
        for tier in SENSITIVITY_TIERS {
            keys.push(ShardKey::new(cat, tier.clone()));
        }
    }
    keys
}

/// Generate all 40 Gossipsub IdentTopics for subscription.
pub fn all_shard_topics() -> Vec<gossipsub::IdentTopic> {
    all_shard_keys()
        .iter()
        .map(|key| gossipsub::IdentTopic::new(key.topic_name()))
        .collect()
}

/// Look up the shard key for a given category and tier. Returns None if
/// the category is not recognized.
pub fn assign_shard(doc_category: &str, tier: SensitivityTier) -> Option<ShardKey> {
    if DOCUMENT_CATEGORIES.contains(&doc_category) {
        Some(ShardKey::new(doc_category, tier))
    } else {
        None
    }
}

/// Get the Gossipsub topic for a given shard key.
pub fn shard_topic(key: &ShardKey) -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(key.topic_name())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_shard_keys_count() {
        let keys = all_shard_keys();
        assert_eq!(keys.len(), 40);
    }

    #[test]
    fn test_all_shard_topics_count() {
        let topics = all_shard_topics();
        assert_eq!(topics.len(), 40);
    }

    #[test]
    fn test_shard_assignment_valid() {
        let shard = assign_shard("medical_bill", SensitivityTier::S1);
        assert!(shard.is_some());
        let shard = shard.unwrap();
        assert_eq!(shard.doc_category, "medical_bill");
        assert_eq!(shard.sensitivity_tier, SensitivityTier::S1);
        assert_eq!(shard.topic_name(), "hive/rules/medical_bill/S1");
    }

    #[test]
    fn test_shard_assignment_invalid_category() {
        let shard = assign_shard("unknown_category", SensitivityTier::S1);
        assert!(shard.is_none());
    }

    #[test]
    fn test_shard_assignment_all_combinations() {
        for cat in DOCUMENT_CATEGORIES {
            for tier in SENSITIVITY_TIERS {
                let shard = assign_shard(cat, tier.clone());
                assert!(
                    shard.is_some(),
                    "Shard should exist for ({}, {:?})",
                    cat,
                    tier
                );
            }
        }
    }

    #[test]
    fn test_topic_hash_consistency() {
        let key = ShardKey::new("credit_card", SensitivityTier::S2);
        let topic1 = shard_topic(&key);
        let topic2 = shard_topic(&key);
        assert_eq!(topic1.hash(), topic2.hash());
    }
}
