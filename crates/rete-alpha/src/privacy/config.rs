//! Privacy pipeline configuration, loaded from TOML.
//!
//! All tunable privacy parameters live here -- nothing is hardcoded in stage modules.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ─── Top-level config ───────────────────────────────────────────────────────

/// Root configuration struct mapping 1:1 to `privacy_config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    pub general: GeneralConfig,
    pub tiers: TierConfig,
    pub epsilon: EpsilonConfig,
    pub field_weights: FieldWeightsConfig,
    pub k_thresholds: KThresholdsConfig,
    pub l_diversity: LDiversityConfig,
    pub budget_ceilings: BudgetCeilingsConfig,
    pub budget_composition: BudgetCompositionConfig,
    pub jitter: JitterConfig,
    pub batching: BatchingConfig,
    pub cold_start: ColdStartConfig,
    pub amount_buckets: AmountBucketsConfig,
    pub dandelion: DandelionConfig,
    pub pii_allowlist: PiiAllowlistConfig,
}

// ─── Section configs ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub pipeline_version: String,
    pub fail_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierConfig {
    pub s1_categories: Vec<String>,
    pub s2_categories: Vec<String>,
    pub s3_categories: Vec<String>,
    pub s4_categories: Vec<String>,
    pub default_tier: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpsilonConfig {
    pub s1: f64,
    pub s2: f64,
    pub s3: f64,
    pub s4: f64,
}

impl EpsilonConfig {
    /// Get epsilon for a tier by index (0-based: S1=0, S4=3).
    pub fn for_tier_index(&self, idx: usize) -> f64 {
        match idx {
            0 => self.s1,
            1 => self.s2,
            2 => self.s3,
            3 => self.s4,
            _ => self.s2, // conservative default
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldWeightsConfig {
    pub entity_b_value: f64,
    pub amount_bucket: f64,
    pub relationship: f64,
    pub entity_a_type: f64,
    pub entity_b_type: f64,
    pub region: f64,
    pub time_period: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KThresholdsConfig {
    /// k thresholds per network phase: [Bootstrap, Growth, Maturity, Scale]
    pub s1: Vec<u64>,
    pub s2: Vec<u64>,
    pub s3: Vec<u64>,
    pub s4: Vec<u64>,
}

impl KThresholdsConfig {
    /// Get k threshold for a tier index and network phase index.
    pub fn get(&self, tier_idx: usize, phase_idx: usize) -> u64 {
        let thresholds = match tier_idx {
            0 => &self.s1,
            1 => &self.s2,
            2 => &self.s3,
            3 => &self.s4,
            _ => &self.s2,
        };
        thresholds.get(phase_idx).copied().unwrap_or(thresholds[0])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LDiversityConfig {
    pub s1: f64,
    pub s2: f64,
    pub s3: f64,
    pub s4: f64,
}

impl LDiversityConfig {
    /// Get l-diversity entropy threshold for a tier by index.
    pub fn for_tier_index(&self, idx: usize) -> f64 {
        match idx {
            0 => self.s1,
            1 => self.s2,
            2 => self.s3,
            3 => self.s4,
            _ => self.s2,
        }
    }
}

/// Budget ceiling values per tier, stored as a map (TOML inline tables).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetCeilingsConfig {
    pub daily: TierCeilingValues,
    pub weekly: TierCeilingValues,
    pub lifetime: TierCeilingValues,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierCeilingValues {
    pub s1: f64,
    pub s2: f64,
    pub s3: f64,
    pub s4: f64,
}

impl TierCeilingValues {
    /// Get ceiling for a tier by index.
    pub fn for_tier_index(&self, idx: usize) -> f64 {
        match idx {
            0 => self.s1,
            1 => self.s2,
            2 => self.s3,
            3 => self.s4,
            _ => self.s2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetCompositionConfig {
    pub renyi_orders: Vec<f64>,
    pub delta: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterConfig {
    /// [min_seconds, max_seconds] per tier
    pub s1: Vec<u64>,
    pub s2: Vec<u64>,
    pub s3: Vec<u64>,
    pub s4: Vec<u64>,
}

impl JitterConfig {
    /// Get (min, max) jitter range in seconds for a tier by index.
    pub fn range_for_tier_index(&self, idx: usize) -> (u64, u64) {
        let pair = match idx {
            0 => &self.s1,
            1 => &self.s2,
            2 => &self.s3,
            3 => &self.s4,
            _ => &self.s2,
        };
        (
            pair.first().copied().unwrap_or(0),
            pair.get(1).copied().unwrap_or(3600),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchingConfig {
    pub min_batch_size: HashMap<String, u64>,
    pub max_hold_seconds: HashMap<String, u64>,
    pub drain_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColdStartConfig {
    /// [Bootstrap, Growth, Maturity] thresholds -- Scale is everything above the last.
    pub phase_thresholds: Vec<u64>,
    pub s1_enable_medical_contributors: u64,
    pub s2_enable_domain_contributors: u64,
    pub s3_enable_total_users: u64,
    pub s4_enable_total_users: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmountBucketsConfig {
    pub boundaries: Vec<f64>,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DandelionConfig {
    pub stem_min: u32,
    pub stem_max: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiAllowlistConfig {
    pub allowed_entity_types: Vec<String>,
    pub allowed_roles: Vec<String>,
    pub direct_id_types: Vec<String>,
}

// ─── Loading ────────────────────────────────────────────────────────────────

impl PrivacyConfig {
    /// Load configuration from a TOML file at the given path.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        toml::from_str(&content).map_err(|e| format!("Failed to parse TOML config: {}", e))
    }

    /// Return a default configuration with all specified parameter values.
    /// Used as a fallback when no config file is available.
    pub fn default_config() -> Self {
        Self {
            general: GeneralConfig {
                pipeline_version: "1.0".into(),
                fail_mode: "suppress".into(),
            },
            tiers: TierConfig {
                s1_categories: vec![
                    "medical_bill".into(),
                    "medical_note".into(),
                    "insurance_eob".into(),
                    "prescription".into(),
                ],
                s2_categories: vec![
                    "lease".into(),
                    "contract".into(),
                    "insurance_policy".into(),
                    "government_form".into(),
                    "bank_statement".into(),
                    "pay_stub".into(),
                ],
                s3_categories: vec!["utility_bill".into(), "terms_of_service".into()],
                s4_categories: vec!["receipt".into(), "restaurant_receipt".into()],
                default_tier: 2,
            },
            epsilon: EpsilonConfig {
                s1: 1.0,
                s2: 2.0,
                s3: 4.0,
                s4: 8.0,
            },
            field_weights: FieldWeightsConfig {
                entity_b_value: 0.30,
                amount_bucket: 0.25,
                relationship: 0.15,
                entity_a_type: 0.10,
                entity_b_type: 0.10,
                region: 0.05,
                time_period: 0.05,
            },
            k_thresholds: KThresholdsConfig {
                s1: vec![100, 200, 300, 400],
                s2: vec![50, 100, 150, 200],
                s3: vec![15, 30, 50, 75],
                s4: vec![8, 15, 20, 30],
            },
            l_diversity: LDiversityConfig {
                s1: 2.3,
                s2: 2.0,
                s3: 1.6,
                s4: 1.0,
            },
            budget_ceilings: BudgetCeilingsConfig {
                daily: TierCeilingValues {
                    s1: 2.0,
                    s2: 6.0,
                    s3: 16.0,
                    s4: 32.0,
                },
                weekly: TierCeilingValues {
                    s1: 10.0,
                    s2: 30.0,
                    s3: 80.0,
                    s4: 160.0,
                },
                lifetime: TierCeilingValues {
                    s1: 100.0,
                    s2: 500.0,
                    s3: 2000.0,
                    s4: 5000.0,
                },
            },
            budget_composition: BudgetCompositionConfig {
                renyi_orders: vec![1.5, 2.0, 3.0, 5.0, 10.0, 25.0, 50.0, 100.0],
                delta: 1e-6,
            },
            jitter: JitterConfig {
                s1: vec![3600, 86400],
                s2: vec![3600, 43200],
                s3: vec![3600, 21600],
                s4: vec![0, 3600],
            },
            batching: BatchingConfig {
                min_batch_size: [
                    ("s1".into(), 10),
                    ("s2".into(), 8),
                    ("s3".into(), 5),
                    ("s4".into(), 3),
                ]
                .iter()
                .cloned()
                .collect(),
                max_hold_seconds: [
                    ("s1".into(), 172800),
                    ("s2".into(), 86400),
                    ("s3".into(), 43200),
                    ("s4".into(), 7200),
                ]
                .iter()
                .cloned()
                .collect(),
                drain_interval_seconds: 900,
            },
            cold_start: ColdStartConfig {
                phase_thresholds: vec![10_000, 100_000, 1_000_000],
                s1_enable_medical_contributors: 10_000,
                s2_enable_domain_contributors: 5_000,
                s3_enable_total_users: 1_000,
                s4_enable_total_users: 500,
            },
            amount_buckets: AmountBucketsConfig {
                boundaries: vec![100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0, 100000.0],
                labels: vec![
                    "$0-$100".into(),
                    "$100-$500".into(),
                    "$500-$1K".into(),
                    "$1K-$5K".into(),
                    "$5K-$10K".into(),
                    "$10K-$50K".into(),
                    "$50K-$100K".into(),
                    "$100K+".into(),
                ],
            },
            dandelion: DandelionConfig {
                stem_min: 5,
                stem_max: 15,
            },
            pii_allowlist: PiiAllowlistConfig {
                allowed_entity_types: vec![
                    "organization".into(),
                    "procedure".into(),
                    "diagnosis".into(),
                    "product".into(),
                    "vehicle".into(),
                    "medication".into(),
                    "amount".into(),
                    "percentage".into(),
                    "code".into(),
                    "term".into(),
                    "legal_mechanism".into(),
                    "certification".into(),
                ],
                allowed_roles: vec![
                    "provider".into(),
                    "insurer".into(),
                    "landlord".into(),
                    "merchant".into(),
                    "employer".into(),
                    "charge".into(),
                    "fee".into(),
                    "payment".into(),
                    "deductible".into(),
                    "premium".into(),
                    "billing_code".into(),
                    "category_code".into(),
                ],
                direct_id_types: vec![
                    "person".into(),
                    "email".into(),
                    "phone".into(),
                    "address".into(),
                    "ssn".into(),
                    "account_number".into(),
                    "policy_number".into(),
                    "member_id".into(),
                    "medical_record_number".into(),
                    "npi_number".into(),
                    "tax_id".into(),
                    "date_of_birth".into(),
                ],
            },
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn config_toml_path() -> std::path::PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        std::path::PathBuf::from(manifest_dir)
            .join("config")
            .join("privacy_config.toml")
    }

    #[test]
    fn load_from_toml_file() {
        let config =
            PrivacyConfig::load(config_toml_path()).expect("Should load privacy_config.toml");
        assert_eq!(config.general.pipeline_version, "1.0");
        assert_eq!(config.general.fail_mode, "suppress");
    }

    #[test]
    fn default_config_matches_spec() {
        let config = PrivacyConfig::default_config();
        assert_eq!(config.epsilon.s1, 1.0);
        assert_eq!(config.epsilon.s2, 2.0);
        assert_eq!(config.epsilon.s3, 4.0);
        assert_eq!(config.epsilon.s4, 8.0);
    }

    #[test]
    fn tier_categories_complete() {
        let config = PrivacyConfig::default_config();
        assert!(config
            .tiers
            .s1_categories
            .contains(&"medical_bill".to_string()));
        assert!(config
            .tiers
            .s2_categories
            .contains(&"bank_statement".to_string()));
        assert!(config
            .tiers
            .s3_categories
            .contains(&"utility_bill".to_string()));
        assert!(config.tiers.s4_categories.contains(&"receipt".to_string()));
    }

    #[test]
    fn k_thresholds_4_phases_per_tier() {
        let config = PrivacyConfig::default_config();
        assert_eq!(config.k_thresholds.s1.len(), 4);
        assert_eq!(config.k_thresholds.s2.len(), 4);
        assert_eq!(config.k_thresholds.s3.len(), 4);
        assert_eq!(config.k_thresholds.s4.len(), 4);
    }

    #[test]
    fn k_thresholds_get_accessor() {
        let config = PrivacyConfig::default_config();
        // S1 at Growth phase => 200
        assert_eq!(config.k_thresholds.get(0, 1), 200);
        // S4 at Bootstrap => 8
        assert_eq!(config.k_thresholds.get(3, 0), 8);
    }

    #[test]
    fn epsilon_for_tier_index() {
        let config = PrivacyConfig::default_config();
        assert!((config.epsilon.for_tier_index(0) - 1.0).abs() < 1e-10);
        assert!((config.epsilon.for_tier_index(3) - 8.0).abs() < 1e-10);
    }

    #[test]
    fn budget_ceilings_daily() {
        let config = PrivacyConfig::default_config();
        assert!((config.budget_ceilings.daily.s1 - 2.0).abs() < 1e-10);
        assert!((config.budget_ceilings.daily.s4 - 32.0).abs() < 1e-10);
    }

    #[test]
    fn budget_ceilings_weekly() {
        let config = PrivacyConfig::default_config();
        assert!((config.budget_ceilings.weekly.s1 - 10.0).abs() < 1e-10);
    }

    #[test]
    fn budget_ceilings_lifetime() {
        let config = PrivacyConfig::default_config();
        assert!((config.budget_ceilings.lifetime.s1 - 100.0).abs() < 1e-10);
        assert!((config.budget_ceilings.lifetime.s4 - 5000.0).abs() < 1e-10);
    }

    #[test]
    fn field_weights_sum_to_one() {
        let w = &PrivacyConfig::default_config().field_weights;
        let sum = w.entity_b_value
            + w.amount_bucket
            + w.relationship
            + w.entity_a_type
            + w.entity_b_type
            + w.region
            + w.time_period;
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "Field weights must sum to 1.0, got {}",
            sum
        );
    }

    #[test]
    fn jitter_ranges_valid() {
        let config = PrivacyConfig::default_config();
        let (min, max) = config.jitter.range_for_tier_index(0); // S1
        assert_eq!(min, 3600);
        assert_eq!(max, 86400);
        let (min, max) = config.jitter.range_for_tier_index(3); // S4
        assert_eq!(min, 0);
        assert_eq!(max, 3600);
    }

    #[test]
    fn cold_start_thresholds() {
        let config = PrivacyConfig::default_config();
        assert_eq!(
            config.cold_start.phase_thresholds,
            vec![10_000, 100_000, 1_000_000]
        );
    }

    #[test]
    fn amount_bucket_boundaries() {
        let config = PrivacyConfig::default_config();
        assert_eq!(config.amount_buckets.boundaries.len(), 7);
        assert_eq!(config.amount_buckets.labels.len(), 8);
        assert!((config.amount_buckets.boundaries[0] - 100.0).abs() < 1e-10);
    }

    #[test]
    fn pii_allowlist_populated() {
        let config = PrivacyConfig::default_config();
        assert!(!config.pii_allowlist.allowed_entity_types.is_empty());
        assert!(!config.pii_allowlist.direct_id_types.is_empty());
        assert!(config
            .pii_allowlist
            .direct_id_types
            .contains(&"ssn".to_string()));
    }

    #[test]
    fn renyi_orders_eight() {
        let config = PrivacyConfig::default_config();
        assert_eq!(config.budget_composition.renyi_orders.len(), 8);
        assert!((config.budget_composition.delta - 1e-6).abs() < 1e-12);
    }

    #[test]
    fn l_diversity_thresholds() {
        let config = PrivacyConfig::default_config();
        assert!((config.l_diversity.s1 - 2.3).abs() < 1e-10);
        assert!((config.l_diversity.s4 - 1.0).abs() < 1e-10);
    }

    #[test]
    fn load_from_toml_file_and_verify_sections() {
        let config =
            PrivacyConfig::load(config_toml_path()).expect("Should load privacy_config.toml");

        // Verify a sampling of values match the TOML file
        assert_eq!(config.epsilon.s1, 1.0);
        assert_eq!(config.k_thresholds.s1, vec![100, 200, 300, 400]);
        assert_eq!(
            config.cold_start.phase_thresholds,
            vec![10_000, 100_000, 1_000_000]
        );
        assert_eq!(config.dandelion.stem_min, 5);
        assert_eq!(config.dandelion.stem_max, 15);
    }

    #[test]
    fn default_config_serde_roundtrip() {
        let config = PrivacyConfig::default_config();
        let toml_str = toml::to_string(&config).expect("Should serialize to TOML");
        let deserialized: PrivacyConfig =
            toml::from_str(&toml_str).expect("Should deserialize from TOML");
        assert_eq!(deserialized.epsilon.s1, config.epsilon.s1);
        assert_eq!(deserialized.k_thresholds.s1, config.k_thresholds.s1);
    }
}
