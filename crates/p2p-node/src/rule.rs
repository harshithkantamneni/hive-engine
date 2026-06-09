//! Rule data structures for HIVE rule distribution.
//!
//! Carried over from N4 (p2p-shard) without modification:
//! - 10 document categories x 4 sensitivity tiers = 40 logical shards
//! - Ed25519 signatures for rule authenticity
//! - serde_json serialization for human-readable wire format
//! - CRDT-compatible lifecycle states

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Sensitivity tiers
// ---------------------------------------------------------------------------

/// Sensitivity tiers from R9: S1 (highest) to S4 (lowest).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum SensitivityTier {
    S1,
    S2,
    S3,
    S4,
}

impl fmt::Display for SensitivityTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SensitivityTier::S1 => write!(f, "S1"),
            SensitivityTier::S2 => write!(f, "S2"),
            SensitivityTier::S3 => write!(f, "S3"),
            SensitivityTier::S4 => write!(f, "S4"),
        }
    }
}

impl SensitivityTier {
    // NOTE: returns Option rather than Result, so std::str::FromStr is not an
    // appropriate shape; keeping the inherent method avoids churn at callsites.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "S1" => Some(SensitivityTier::S1),
            "S2" => Some(SensitivityTier::S2),
            "S3" => Some(SensitivityTier::S3),
            "S4" => Some(SensitivityTier::S4),
            _ => None,
        }
    }

    pub fn all() -> &'static [SensitivityTier] {
        SENSITIVITY_TIERS
    }
}

/// All 4 sensitivity tiers in order.
pub const SENSITIVITY_TIERS: &[SensitivityTier] = &[
    SensitivityTier::S1,
    SensitivityTier::S2,
    SensitivityTier::S3,
    SensitivityTier::S4,
];

// ---------------------------------------------------------------------------
// Document categories (exactly per N4 task spec)
// ---------------------------------------------------------------------------

/// The 10 document categories as specified in the N4 task.
pub const DOCUMENT_CATEGORIES: &[&str] = &[
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

/// Default sensitivity tier mapping per document category (from R9).
pub fn default_tier_for_category(category: &str) -> SensitivityTier {
    match category {
        "medical_bill" => SensitivityTier::S1,
        "insurance_eob" => SensitivityTier::S1,
        "prescription" => SensitivityTier::S1,
        "bank_statement" => SensitivityTier::S2,
        "pay_stub" => SensitivityTier::S2,
        "credit_card" => SensitivityTier::S2,
        "lease" => SensitivityTier::S3,
        "government_form" => SensitivityTier::S3,
        "utility_bill" => SensitivityTier::S3,
        "receipt" => SensitivityTier::S4,
        _ => SensitivityTier::S4,
    }
}

// ---------------------------------------------------------------------------
// Shard key
// ---------------------------------------------------------------------------

/// Composite shard key: (document_category, sensitivity_tier).
/// 10 categories x 4 tiers = 40 logical shards.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShardKey {
    pub doc_category: String,
    pub sensitivity_tier: SensitivityTier,
}

impl ShardKey {
    pub fn new(doc_category: &str, tier: SensitivityTier) -> Self {
        Self {
            doc_category: doc_category.to_string(),
            sensitivity_tier: tier,
        }
    }

    /// Gossipsub topic name per N4 spec: hive/rules/{doc_category}/{sensitivity_tier}
    pub fn topic_name(&self) -> String {
        format!("hive/rules/{}/{}", self.doc_category, self.sensitivity_tier)
    }

    /// DHT key per R9: BLAKE3("hive-rule-shard-v1" || category || tier)
    pub fn dht_key(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hive-rule-shard-v1");
        hasher.update(self.doc_category.as_bytes());
        hasher.update(self.sensitivity_tier.to_string().as_bytes());
        *hasher.finalize().as_bytes()
    }
}

impl fmt::Display for ShardKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.doc_category, self.sensitivity_tier)
    }
}

// ---------------------------------------------------------------------------
// Rule message (per N4 task spec)
// ---------------------------------------------------------------------------

/// The rule message transmitted over the P2P network.
/// Serialized via serde_json for human-readable prototype format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleMessage {
    pub rule_id: u64,
    pub version: u32,
    pub doc_category: String,
    pub sensitivity_tier: String,
    /// HRL rule condition
    pub condition: String,
    /// HRL rule conclusion
    pub conclusion: String,
    pub confidence: f32,
    pub evidence_count: u32,
    /// Ed25519 signature (64 bytes)
    pub signature: Vec<u8>,
    pub publisher_id: String,
}

impl RuleMessage {
    /// Derive the ShardKey from the rule's category and tier fields.
    pub fn shard_key(&self) -> ShardKey {
        let tier = SensitivityTier::from_str(&self.sensitivity_tier).unwrap_or(SensitivityTier::S4);
        ShardKey::new(&self.doc_category, tier)
    }

    /// Serialize to JSON bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("JSON serialization should not fail")
    }

    /// Deserialize from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }

    /// Validate basic message structure.
    pub fn validate(&self) -> Result<(), String> {
        if !DOCUMENT_CATEGORIES.contains(&self.doc_category.as_str()) {
            return Err(format!("Unknown document category: {}", self.doc_category));
        }
        if SensitivityTier::from_str(&self.sensitivity_tier).is_none() {
            return Err(format!(
                "Invalid sensitivity tier: {}",
                self.sensitivity_tier
            ));
        }
        if self.confidence < 0.0 || self.confidence > 1.0 {
            return Err(format!(
                "Confidence {} out of range [0, 1]",
                self.confidence
            ));
        }
        if self.condition.is_empty() {
            return Err("Empty condition".to_string());
        }
        if self.conclusion.is_empty() {
            return Err("Empty conclusion".to_string());
        }
        Ok(())
    }

    /// Create the bytes over which the signature is computed.
    fn signable_bytes(&self) -> Vec<u8> {
        let mut msg = self.clone();
        msg.signature = Vec::new();
        serde_json::to_vec(&msg).expect("JSON serialization should not fail")
    }

    /// Sign this rule with an Ed25519 signing key.
    pub fn sign(&mut self, key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let bytes = self.signable_bytes();
        let sig = key.sign(&bytes);
        self.signature = sig.to_bytes().to_vec();
    }

    /// Verify the Ed25519 signature.
    pub fn verify_signature(&self, public_key: &ed25519_dalek::VerifyingKey) -> bool {
        use ed25519_dalek::Verifier;
        if self.signature.len() != 64 {
            return false;
        }
        let bytes = self.signable_bytes();
        let sig_bytes: [u8; 64] = match self.signature[..64].try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        public_key.verify(&bytes, &sig).is_ok()
    }
}

/// Create a test rule with sensible defaults.
pub fn create_test_rule(
    category: &str,
    tier: SensitivityTier,
    rule_id: u64,
    confidence: f32,
) -> RuleMessage {
    RuleMessage {
        rule_id,
        version: 1,
        doc_category: category.to_string(),
        sensitivity_tier: tier.to_string(),
        condition: format!(
            "entity_a_type = 'organization' AND doc_category = '{}'",
            category
        ),
        conclusion: "typical_range(500, 2000)".to_string(),
        confidence,
        evidence_count: 50,
        signature: Vec::new(),
        publisher_id: "test-peer".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shard_key_topic_name() {
        let shard = ShardKey::new("medical_bill", SensitivityTier::S1);
        assert_eq!(shard.topic_name(), "hive/rules/medical_bill/S1");

        let shard2 = ShardKey::new("receipt", SensitivityTier::S4);
        assert_eq!(shard2.topic_name(), "hive/rules/receipt/S4");
    }

    #[test]
    fn test_all_40_shards() {
        let mut topics = Vec::new();
        for cat in DOCUMENT_CATEGORIES {
            for tier in SENSITIVITY_TIERS {
                let shard = ShardKey::new(cat, tier.clone());
                topics.push(shard.topic_name());
            }
        }
        assert_eq!(topics.len(), 40);
        let unique: std::collections::HashSet<_> = topics.iter().collect();
        assert_eq!(unique.len(), 40);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let rule = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        let bytes = rule.to_bytes();
        let decoded = RuleMessage::from_bytes(&bytes).unwrap();
        assert_eq!(rule, decoded);
        assert!(
            bytes.len() < 1024,
            "Rule message {} bytes exceeds 1024 byte limit",
            bytes.len()
        );
    }

    #[test]
    fn test_validate_valid_rule() {
        let rule = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_validate_bad_category() {
        let mut rule = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        rule.doc_category = "unknown".to_string();
        assert!(rule.validate().is_err());
    }

    #[test]
    fn test_validate_bad_confidence() {
        let mut rule = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        rule.confidence = 1.5;
        assert!(rule.validate().is_err());
    }

    #[test]
    fn test_ed25519_sign_verify() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key();

        let mut rule = create_test_rule("bank_statement", SensitivityTier::S2, 42, 0.72);
        rule.sign(&key);

        assert!(
            rule.verify_signature(&pubkey),
            "Valid signature should verify"
        );

        // Tamper
        let mut tampered = rule.clone();
        tampered.confidence = 0.99;
        assert!(
            !tampered.verify_signature(&pubkey),
            "Tampered rule should fail"
        );
    }

    #[test]
    fn test_dht_key_deterministic() {
        let shard = ShardKey::new("medical_bill", SensitivityTier::S1);
        let key1 = shard.dht_key();
        let key2 = shard.dht_key();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_rule_shard_key_derivation() {
        let rule = create_test_rule("lease", SensitivityTier::S3, 10, 0.6);
        let shard = rule.shard_key();
        assert_eq!(shard.doc_category, "lease");
        assert_eq!(shard.sensitivity_tier, SensitivityTier::S3);
        assert_eq!(shard.topic_name(), "hive/rules/lease/S3");
    }
}
