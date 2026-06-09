//! Stage 4: Pattern Hashing (HMAC-BLAKE3 with device-local key).
//!
//! Computes HMAC-BLAKE3 hashes using a device-local key and constructs
//! PatternKey aggregation keys. Produces up to 2 resolution levels per tuple:
//!   - Level 0 (primary): uses all generalized fields as-is.
//!   - Level 1 (coarse): further generalizes the strongest quasi-identifier
//!     by one level, then hashes with an independent level-1 derived key.
//!
//! Key derivation uses HKDF-BLAKE3 so that different resolution levels
//! produce independent, non-correlatable keys.

use crate::privacy::config::PrivacyConfig;
use crate::privacy::types::{GeneralizedTuple, HashedTuple, PatternKey};

use rand::rngs::OsRng;
use rand::TryRngCore;

// ─── Configuration ─────────────────────────────────────────────────────────

/// Hasher-specific configuration extracted from PrivacyConfig.
#[derive(Debug, Clone)]
pub struct HasherConfig {
    /// Maximum number of resolution levels to emit (1 or 2).
    pub max_resolution_levels: u8,
    /// Maximum generalization level for entity_b coarsening.
    pub max_entity_b_gen_level: u8,
    /// Maximum generalization level for source_region coarsening.
    pub max_region_gen_level: u8,
}

impl HasherConfig {
    /// Extract hasher config from the top-level PrivacyConfig.
    /// Uses sensible defaults.
    pub fn from_privacy_config(_config: &PrivacyConfig) -> Self {
        Self {
            max_resolution_levels: 2,
            max_entity_b_gen_level: 4,
            max_region_gen_level: 3,
        }
    }

    /// Default configuration for tests.
    pub fn default_config() -> Self {
        Self {
            max_resolution_levels: 2,
            max_entity_b_gen_level: 4,
            max_region_gen_level: 3,
        }
    }
}

// ─── Device Key ────────────────────────────────────────────────────────────

/// A 256-bit device-local master key used for HMAC-BLAKE3 pattern hashing.
///
/// The master key never leaves the device. Per-level subkeys are derived
/// using HKDF-BLAKE3 so that hashes at different resolution levels are
/// cryptographically independent and cannot be correlated.
#[derive(Clone)]
pub struct DeviceKey {
    master_key: [u8; 32],
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKey")
            .field("master_key", &"[REDACTED]")
            .finish()
    }
}

impl DeviceKey {
    /// Generate a new random device key using CSPRNG (OsRng).
    ///
    /// This must only be called once per device installation. The key
    /// should then be persisted to the OS keychain or an encrypted file.
    pub fn generate() -> Self {
        let mut master_key = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut master_key)
            .expect("OS CSPRNG failure: cannot generate device key");
        Self { master_key }
    }

    /// Load from raw bytes (e.g., from keychain or encrypted file).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { master_key: bytes }
    }

    /// Export the master key as raw bytes for persistent storage.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.master_key
    }

    /// Derive a level-specific subkey using HKDF-BLAKE3.
    ///
    /// Different resolution levels get independent keys so hashes
    /// at different levels cannot be correlated. This uses blake3's
    /// `derive_key` context mechanism which provides HKDF-like
    /// domain separation.
    pub fn derive_level_key(&self, resolution_level: u8) -> [u8; 32] {
        let context = format!("HIVE PatternHash Level {}", resolution_level);
        let mut hasher = blake3::Hasher::new_derive_key(&context);
        hasher.update(&self.master_key);
        let hash = hasher.finalize();
        *hash.as_bytes()
    }
}

// ─── Pattern Hasher ────────────────────────────────────────────────────────

/// Stage 4 of the privacy pipeline.
///
/// Takes a `GeneralizedTuple` (output of Stage 3) and produces 1-2
/// `HashedTuple` values, one per resolution level. The hash is computed
/// using HMAC-BLAKE3 with a device-local key, making pattern hashes
/// unique to each device and non-reversible.
pub struct PatternHasher {
    device_key: DeviceKey,
    config: HasherConfig,
}

impl PatternHasher {
    /// Create a PatternHasher with an existing device key and config.
    pub fn new(device_key: DeviceKey, config: &PrivacyConfig) -> Self {
        Self {
            device_key,
            config: HasherConfig::from_privacy_config(config),
        }
    }

    /// Create a PatternHasher with an explicit HasherConfig (useful for tests).
    pub fn with_config(device_key: DeviceKey, config: HasherConfig) -> Self {
        Self { device_key, config }
    }

    /// Hash a generalized tuple, producing 1-2 HashedTuples.
    ///
    /// - Level 0 = primary (uses all generalized fields as-is).
    /// - Level 1 = coarse (further generalizes the strongest quasi-identifier
    ///   by one level, then hashes with a level-1 derived key).
    ///
    /// Returns a Vec with 1 entry (level 0 only) or 2 entries (level 0 + level 1).
    pub fn hash(&self, tuple: GeneralizedTuple) -> Vec<HashedTuple> {
        let mut results = Vec::with_capacity(2);

        // ── Level 0: primary resolution ────────────────────────────────
        let pattern_key_0 = build_pattern_key(&tuple);
        let level_0_key = self.device_key.derive_level_key(0);
        let hash_0 = compute_hash(&level_0_key, &pattern_key_0);

        results.push(HashedTuple {
            inner: tuple.clone(),
            pattern_hash: hash_0,
            pattern_key: pattern_key_0,
            resolution_level: 0,
        });

        // ── Level 1: coarse resolution (if applicable) ─────────────────
        if self.config.max_resolution_levels >= 2 {
            if let Some((coarse_key, coarse_tuple)) = self.build_coarse_level(&tuple) {
                let level_1_key = self.device_key.derive_level_key(1);
                let hash_1 = compute_hash(&level_1_key, &coarse_key);

                results.push(HashedTuple {
                    inner: coarse_tuple,
                    pattern_hash: hash_1,
                    pattern_key: coarse_key,
                    resolution_level: 1,
                });
            }
        }

        results
    }

    /// Attempt to build the coarse (level-1) resolution.
    ///
    /// Heuristic for V1 to identify the strongest quasi-identifier:
    /// 1. If entity_b_gen_level < max, coarsen entity_b_gen.
    /// 2. Else if source_region gen is coarsenable, coarsen it.
    /// 3. Else skip level 1.
    fn build_coarse_level(
        &self,
        tuple: &GeneralizedTuple,
    ) -> Option<(PatternKey, GeneralizedTuple)> {
        // Try entity_b first (highest field weight = 0.30)
        if tuple.entity_b_gen_level < self.config.max_entity_b_gen_level {
            if let Some(coarsened) =
                coarsen_value("entity_b", &tuple.entity_b_gen, tuple.entity_b_gen_level)
            {
                let mut coarse_tuple = tuple.clone();
                coarse_tuple.entity_b_gen = coarsened;
                coarse_tuple.entity_b_gen_level = tuple.entity_b_gen_level + 1;

                let coarse_key = build_pattern_key(&coarse_tuple);
                return Some((coarse_key, coarse_tuple));
            }
        }

        // Try source_region next (field weight = 0.05, but useful for diversity)
        if let Some(coarsened) = coarsen_region(&tuple.source_region) {
            let mut coarse_tuple = tuple.clone();
            coarse_tuple.source_region = coarsened;

            let coarse_key = build_pattern_key(&coarse_tuple);
            return Some((coarse_key, coarse_tuple));
        }

        // Cannot coarsen further -- level 1 is skipped
        None
    }
}

// ─── PatternKey construction ───────────────────────────────────────────────

/// Build a PatternKey from a GeneralizedTuple by extracting the 9 aggregation
/// fields.
fn build_pattern_key(tuple: &GeneralizedTuple) -> PatternKey {
    PatternKey {
        entity_a_type: tuple.entity_a_type.clone(),
        entity_a_gen: tuple.entity_a_gen.clone(),
        entity_a_gen_level: tuple.entity_a_gen_level,
        relation: tuple.relation.clone(),
        entity_b_type: tuple.entity_b_type.clone(),
        entity_b_gen: tuple.entity_b_gen.clone(),
        entity_b_gen_level: tuple.entity_b_gen_level,
        amount_bucket: tuple.amount_bucket,
        document_category: tuple.document_category.clone(),
    }
}

// ─── HMAC-BLAKE3 hash computation ──────────────────────────────────────────

/// Compute HMAC-BLAKE3 hash of a PatternKey using a derived level key.
///
/// The canonical string format is deterministic and fixed-order:
/// ```text
/// {entity_a_type}|{entity_a_gen}:{entity_a_gen_level}|{relation}|{entity_b_type}|{entity_b_gen}:{entity_b_gen_level}|{amount_bucket}|{document_category}
/// ```
///
/// Uses `blake3::keyed_hash` which provides HMAC-equivalent security
/// (PRF under the key).
fn compute_hash(key: &[u8; 32], pattern_key: &PatternKey) -> [u8; 32] {
    let canonical = canonical_string(pattern_key);
    *blake3::keyed_hash(key, canonical.as_bytes()).as_bytes()
}

/// Produce a deterministic canonical string from a PatternKey.
///
/// The field order is fixed to ensure identical inputs always produce
/// identical hashes regardless of struct field iteration order.
fn canonical_string(pk: &PatternKey) -> String {
    format!(
        "{}|{}:{}|{}|{}|{}:{}|{}|{}",
        pk.entity_a_type,
        pk.entity_a_gen,
        pk.entity_a_gen_level,
        pk.relation,
        pk.entity_b_type,
        pk.entity_b_gen,
        pk.entity_b_gen_level,
        pk.amount_bucket,
        pk.document_category,
    )
}

// ─── Coarsening helpers ────────────────────────────────────────────────────

/// Coarsen a field value by one generalization level.
///
/// This embeds minimal hierarchy data for the most common fields.
/// The generalizer.rs module (being built in parallel) will have the
/// full hierarchy; this is a self-contained subset for V1.
///
/// Returns `None` if no coarsening is available for the given value.
fn coarsen_value(field: &str, value: &str, current_level: u8) -> Option<String> {
    match field {
        "entity_b" => coarsen_entity_b(value, current_level),
        _ => None,
    }
}

/// Coarsen entity_b values using embedded hierarchy data.
///
/// Medical procedures hierarchy (most common in S1):
///   L0: specific procedure (e.g., "bilateral_cochlear_implant")
///   L1: procedure subcategory (e.g., "ear_surgery")
///   L2: procedure category (e.g., "surgical_procedure")
///   L3: service type (e.g., "medical_service")
///   L4: top (e.g., "*")
///
/// Financial/retail hierarchy (S3/S4):
///   L0: specific item
///   L1: item category
///   L2: spending category
///   L3: top
fn coarsen_entity_b(value: &str, current_level: u8) -> Option<String> {
    // Level 0 -> Level 1 mappings (specific -> subcategory)
    let l0_to_l1: &[(&str, &str)] = &[
        // Medical procedures
        ("bilateral_cochlear_implant", "ear_surgery"),
        ("cochlear_implant", "ear_surgery"),
        ("tympanoplasty", "ear_surgery"),
        ("myringotomy", "ear_surgery"),
        ("knee_replacement", "orthopedic_surgery"),
        ("hip_replacement", "orthopedic_surgery"),
        ("acl_reconstruction", "orthopedic_surgery"),
        ("spinal_fusion", "orthopedic_surgery"),
        ("appendectomy", "abdominal_surgery"),
        ("cholecystectomy", "abdominal_surgery"),
        ("hernia_repair", "abdominal_surgery"),
        ("coronary_bypass", "cardiac_surgery"),
        ("valve_replacement", "cardiac_surgery"),
        ("stent_placement", "cardiac_procedure"),
        ("angioplasty", "cardiac_procedure"),
        ("mri_scan", "diagnostic_imaging"),
        ("ct_scan", "diagnostic_imaging"),
        ("x_ray", "diagnostic_imaging"),
        ("ultrasound", "diagnostic_imaging"),
        ("blood_test", "laboratory_test"),
        ("urinalysis", "laboratory_test"),
        ("biopsy", "laboratory_test"),
        // Financial
        ("groceries", "food_and_beverage"),
        ("restaurant_meal", "food_and_beverage"),
        ("coffee", "food_and_beverage"),
        ("gasoline", "transportation"),
        ("car_repair", "transportation"),
        ("parking", "transportation"),
        ("electricity", "utilities"),
        ("water", "utilities"),
        ("natural_gas", "utilities"),
        ("internet", "utilities"),
        ("rent_payment", "housing"),
        ("mortgage_payment", "housing"),
    ];

    // Level 1 -> Level 2 mappings (subcategory -> category)
    let l1_to_l2: &[(&str, &str)] = &[
        ("ear_surgery", "surgical_procedure"),
        ("orthopedic_surgery", "surgical_procedure"),
        ("abdominal_surgery", "surgical_procedure"),
        ("cardiac_surgery", "surgical_procedure"),
        ("cardiac_procedure", "medical_procedure"),
        ("diagnostic_imaging", "medical_procedure"),
        ("laboratory_test", "medical_procedure"),
        ("food_and_beverage", "consumer_spending"),
        ("transportation", "consumer_spending"),
        ("utilities", "household_expense"),
        ("housing", "household_expense"),
    ];

    // Level 2 -> Level 3 mappings (category -> service type)
    let l2_to_l3: &[(&str, &str)] = &[
        ("surgical_procedure", "medical_service"),
        ("medical_procedure", "medical_service"),
        ("consumer_spending", "expense"),
        ("household_expense", "expense"),
    ];

    // Level 3 -> Level 4 mappings (service type -> top)
    let l3_to_l4: &[(&str, &str)] = &[("medical_service", "*"), ("expense", "*")];

    let mappings: &[(&str, &str)] = match current_level {
        0 => l0_to_l1,
        1 => l1_to_l2,
        2 => l2_to_l3,
        3 => l3_to_l4,
        _ => return None,
    };

    let value_lower = value.to_lowercase();
    for &(from, to) in mappings {
        if value_lower == from {
            return Some(to.to_string());
        }
    }

    None
}

/// Coarsen a geographic region by one level.
///
/// Region hierarchy:
///   L0: state/subregion (e.g., "US-CA", "US-NY")
///   L1: region (e.g., "US-West", "US-Northeast")
///   L2: country (e.g., "US")
///   L3: top ("*")
fn coarsen_region(value: &str) -> Option<String> {
    // State -> Region mappings
    let state_to_region: &[(&str, &str)] = &[
        // West
        ("US-CA", "US-West"),
        ("US-WA", "US-West"),
        ("US-OR", "US-West"),
        ("US-NV", "US-West"),
        ("US-AZ", "US-West"),
        ("US-CO", "US-West"),
        ("US-UT", "US-West"),
        ("US-NM", "US-West"),
        ("US-HI", "US-West"),
        ("US-AK", "US-West"),
        ("US-ID", "US-West"),
        ("US-MT", "US-West"),
        ("US-WY", "US-West"),
        // Northeast
        ("US-NY", "US-Northeast"),
        ("US-NJ", "US-Northeast"),
        ("US-PA", "US-Northeast"),
        ("US-CT", "US-Northeast"),
        ("US-MA", "US-Northeast"),
        ("US-RI", "US-Northeast"),
        ("US-VT", "US-Northeast"),
        ("US-NH", "US-Northeast"),
        ("US-ME", "US-Northeast"),
        // South
        ("US-TX", "US-South"),
        ("US-FL", "US-South"),
        ("US-GA", "US-South"),
        ("US-NC", "US-South"),
        ("US-SC", "US-South"),
        ("US-VA", "US-South"),
        ("US-TN", "US-South"),
        ("US-AL", "US-South"),
        ("US-MS", "US-South"),
        ("US-LA", "US-South"),
        ("US-AR", "US-South"),
        ("US-KY", "US-South"),
        ("US-WV", "US-South"),
        ("US-OK", "US-South"),
        ("US-MD", "US-South"),
        ("US-DC", "US-South"),
        ("US-DE", "US-South"),
        // Midwest
        ("US-IL", "US-Midwest"),
        ("US-OH", "US-Midwest"),
        ("US-MI", "US-Midwest"),
        ("US-IN", "US-Midwest"),
        ("US-WI", "US-Midwest"),
        ("US-MN", "US-Midwest"),
        ("US-IA", "US-Midwest"),
        ("US-MO", "US-Midwest"),
        ("US-KS", "US-Midwest"),
        ("US-NE", "US-Midwest"),
        ("US-ND", "US-Midwest"),
        ("US-SD", "US-Midwest"),
    ];

    // Region -> Country mappings
    let region_to_country: &[(&str, &str)] = &[
        ("US-West", "US"),
        ("US-Northeast", "US"),
        ("US-South", "US"),
        ("US-Midwest", "US"),
    ];

    // Country -> Top
    let country_to_top: &[(&str, &str)] = &[("US", "*")];

    // Try state -> region first
    for &(from, to) in state_to_region {
        if value == from {
            return Some(to.to_string());
        }
    }

    // Try region -> country
    for &(from, to) in region_to_country {
        if value == from {
            return Some(to.to_string());
        }
    }

    // Try country -> top
    for &(from, to) in country_to_top {
        if value == from {
            return Some(to.to_string());
        }
    }

    None
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::types::SensitivityTier;

    // ── Test helpers ───────────────────────────────────────────────────

    /// Fixed test key for deterministic tests.
    fn test_key() -> DeviceKey {
        DeviceKey::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ])
    }

    /// A second key for cross-device unlinkability tests.
    fn test_key_2() -> DeviceKey {
        DeviceKey::from_bytes([
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0A,
        ])
    }

    fn default_config() -> HasherConfig {
        HasherConfig::default_config()
    }

    /// Create a standard medical bill tuple for testing.
    fn medical_tuple() -> GeneralizedTuple {
        GeneralizedTuple {
            entity_a_type: "organization".into(),
            entity_a_gen: "medical_provider".into(),
            entity_a_gen_level: 2,
            entity_a_role: "provider".into(),
            entity_b_type: "procedure".into(),
            entity_b_gen: "ear_surgery".into(),
            entity_b_gen_level: 1,
            entity_b_role: "charge".into(),
            relation: "charges".into(),
            amount_bucket: 4,
            document_category: "medical_bill".into(),
            sensitivity_tier: SensitivityTier::S1Critical,
            source_region: "US-Northeast".into(),
            time_period: "2026-Q1".into(),
        }
    }

    /// Create a receipt tuple for testing.
    fn receipt_tuple() -> GeneralizedTuple {
        GeneralizedTuple {
            entity_a_type: "organization".into(),
            entity_a_gen: "retailer".into(),
            entity_a_gen_level: 1,
            entity_a_role: "merchant".into(),
            entity_b_type: "product".into(),
            entity_b_gen: "groceries".into(),
            entity_b_gen_level: 0,
            entity_b_role: "charge".into(),
            relation: "sold".into(),
            amount_bucket: 1,
            document_category: "receipt".into(),
            sensitivity_tier: SensitivityTier::S4Low,
            source_region: "US-CA".into(),
            time_period: "2026-Q1".into(),
        }
    }

    /// Create a tuple at max generalization (cannot be coarsened).
    fn max_gen_tuple() -> GeneralizedTuple {
        GeneralizedTuple {
            entity_a_type: "organization".into(),
            entity_a_gen: "*".into(),
            entity_a_gen_level: 4,
            entity_a_role: "provider".into(),
            entity_b_type: "procedure".into(),
            entity_b_gen: "*".into(),
            entity_b_gen_level: 4,
            entity_b_role: "charge".into(),
            relation: "charges".into(),
            amount_bucket: 4,
            document_category: "medical_bill".into(),
            sensitivity_tier: SensitivityTier::S1Critical,
            source_region: "*".into(),
            time_period: "2026".into(),
        }
    }

    // ── DeviceKey tests ────────────────────────────────────────────────

    #[test]
    fn device_key_generate_produces_nonzero_key() {
        let key = DeviceKey::generate();
        let bytes = key.to_bytes();
        // A CSPRNG key should not be all zeros (probability 2^-256)
        assert_ne!(bytes, [0u8; 32]);
    }

    #[test]
    fn device_key_generate_produces_unique_keys() {
        let key1 = DeviceKey::generate();
        let key2 = DeviceKey::generate();
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn device_key_from_bytes_roundtrip() {
        let original = [42u8; 32];
        let key = DeviceKey::from_bytes(original);
        assert_eq!(key.to_bytes(), original);
    }

    #[test]
    fn device_key_from_bytes_preserves_exact_bytes() {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let key = DeviceKey::from_bytes(bytes);
        assert_eq!(key.to_bytes(), bytes);
    }

    #[test]
    fn device_key_debug_redacts_master_key() {
        let key = test_key();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("0x01"));
    }

    // ── HKDF key derivation tests ──────────────────────────────────────

    #[test]
    fn derive_level_key_level_0_vs_level_1_differ() {
        let key = test_key();
        let k0 = key.derive_level_key(0);
        let k1 = key.derive_level_key(1);
        assert_ne!(k0, k1, "Level 0 and Level 1 keys must be independent");
    }

    #[test]
    fn derive_level_key_deterministic() {
        let key = test_key();
        let k0a = key.derive_level_key(0);
        let k0b = key.derive_level_key(0);
        assert_eq!(k0a, k0b, "Same level must produce same derived key");
    }

    #[test]
    fn derive_level_key_different_master_keys_produce_different_derived_keys() {
        let key1 = test_key();
        let key2 = test_key_2();
        let k1_l0 = key1.derive_level_key(0);
        let k2_l0 = key2.derive_level_key(0);
        assert_ne!(
            k1_l0, k2_l0,
            "Different master keys must produce different level keys"
        );
    }

    #[test]
    fn derive_level_key_all_levels_independent() {
        let key = test_key();
        let keys: Vec<[u8; 32]> = (0..5).map(|l| key.derive_level_key(l)).collect();
        // All pairs must differ
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "Level {} and {} must differ", i, j);
            }
        }
    }

    #[test]
    fn derive_level_key_changing_master_changes_all_derived() {
        let key1 = test_key();
        let key2 = test_key_2();
        for level in 0..3u8 {
            let d1 = key1.derive_level_key(level);
            let d2 = key2.derive_level_key(level);
            assert_ne!(
                d1, d2,
                "Different master -> different derived at level {}",
                level
            );
        }
    }

    #[test]
    fn derive_level_key_nonzero_output() {
        let key = test_key();
        for level in 0..5u8 {
            let derived = key.derive_level_key(level);
            assert_ne!(
                derived, [0u8; 32],
                "Derived key at level {} should not be all zeros",
                level
            );
        }
    }

    // ── Canonical string tests ─────────────────────────────────────────

    #[test]
    fn canonical_string_format_correct() {
        let pk = PatternKey {
            entity_a_type: "organization".into(),
            entity_a_gen: "medical_provider".into(),
            entity_a_gen_level: 2,
            relation: "charges".into(),
            entity_b_type: "procedure".into(),
            entity_b_gen: "ear_surgery".into(),
            entity_b_gen_level: 1,
            amount_bucket: 4,
            document_category: "medical_bill".into(),
        };
        let cs = canonical_string(&pk);
        assert_eq!(
            cs,
            "organization|medical_provider:2|charges|procedure|ear_surgery:1|4|medical_bill"
        );
    }

    #[test]
    fn canonical_string_deterministic() {
        let pk = PatternKey {
            entity_a_type: "org".into(),
            entity_a_gen: "gen_a".into(),
            entity_a_gen_level: 0,
            relation: "rel".into(),
            entity_b_type: "proc".into(),
            entity_b_gen: "gen_b".into(),
            entity_b_gen_level: 1,
            amount_bucket: 3,
            document_category: "cat".into(),
        };
        let cs1 = canonical_string(&pk);
        let cs2 = canonical_string(&pk);
        assert_eq!(cs1, cs2);
    }

    #[test]
    fn canonical_string_different_fields_differ() {
        let pk1 = PatternKey {
            entity_a_type: "org".into(),
            entity_a_gen: "gen_a".into(),
            entity_a_gen_level: 0,
            relation: "rel".into(),
            entity_b_type: "proc".into(),
            entity_b_gen: "gen_b".into(),
            entity_b_gen_level: 1,
            amount_bucket: 3,
            document_category: "cat".into(),
        };
        let mut pk2 = pk1.clone();
        pk2.entity_b_gen = "gen_c".into();
        assert_ne!(canonical_string(&pk1), canonical_string(&pk2));
    }

    #[test]
    fn canonical_string_level_change_differs() {
        let pk1 = PatternKey {
            entity_a_type: "org".into(),
            entity_a_gen: "gen_a".into(),
            entity_a_gen_level: 0,
            relation: "rel".into(),
            entity_b_type: "proc".into(),
            entity_b_gen: "gen_b".into(),
            entity_b_gen_level: 1,
            amount_bucket: 3,
            document_category: "cat".into(),
        };
        let mut pk2 = pk1.clone();
        pk2.entity_b_gen_level = 2;
        assert_ne!(canonical_string(&pk1), canonical_string(&pk2));
    }

    #[test]
    fn canonical_string_amount_bucket_change_differs() {
        let pk1 = PatternKey {
            entity_a_type: "org".into(),
            entity_a_gen: "gen_a".into(),
            entity_a_gen_level: 0,
            relation: "rel".into(),
            entity_b_type: "proc".into(),
            entity_b_gen: "gen_b".into(),
            entity_b_gen_level: 1,
            amount_bucket: 3,
            document_category: "cat".into(),
        };
        let mut pk2 = pk1.clone();
        pk2.amount_bucket = 7;
        assert_ne!(canonical_string(&pk1), canonical_string(&pk2));
    }

    // ── HMAC-BLAKE3 hash tests ─────────────────────────────────────────

    #[test]
    fn compute_hash_deterministic_same_key_same_input() {
        let key = test_key().derive_level_key(0);
        let pk = build_pattern_key(&medical_tuple());
        let h1 = compute_hash(&key, &pk);
        let h2 = compute_hash(&key, &pk);
        assert_eq!(h1, h2, "Same key + same input must produce same hash");
    }

    #[test]
    fn compute_hash_different_keys_different_output() {
        let pk = build_pattern_key(&medical_tuple());
        let k1 = test_key().derive_level_key(0);
        let k2 = test_key_2().derive_level_key(0);
        let h1 = compute_hash(&k1, &pk);
        let h2 = compute_hash(&k2, &pk);
        assert_ne!(h1, h2, "Different keys must produce different hashes");
    }

    #[test]
    fn compute_hash_different_inputs_different_output() {
        let key = test_key().derive_level_key(0);
        let pk1 = build_pattern_key(&medical_tuple());
        let pk2 = build_pattern_key(&receipt_tuple());
        let h1 = compute_hash(&key, &pk1);
        let h2 = compute_hash(&key, &pk2);
        assert_ne!(h1, h2, "Different inputs must produce different hashes");
    }

    #[test]
    fn compute_hash_nonzero_output() {
        let key = test_key().derive_level_key(0);
        let pk = build_pattern_key(&medical_tuple());
        let h = compute_hash(&key, &pk);
        assert_ne!(h, [0u8; 32], "Hash output should not be all zeros");
    }

    #[test]
    fn compute_hash_uses_keyed_hash_not_plain() {
        // Verify that changing the key changes the output (proving keyed_hash is used)
        let pk = build_pattern_key(&medical_tuple());
        let canonical = canonical_string(&pk);
        let plain_hash = *blake3::hash(canonical.as_bytes()).as_bytes();
        let keyed_hash = compute_hash(&test_key().derive_level_key(0), &pk);
        assert_ne!(
            plain_hash, keyed_hash,
            "Must use keyed_hash, not plain hash"
        );
    }

    // ── PatternKey construction tests ──────────────────────────────────

    #[test]
    fn build_pattern_key_extracts_correct_fields() {
        let tuple = medical_tuple();
        let pk = build_pattern_key(&tuple);
        assert_eq!(pk.entity_a_type, "organization");
        assert_eq!(pk.entity_a_gen, "medical_provider");
        assert_eq!(pk.entity_a_gen_level, 2);
        assert_eq!(pk.relation, "charges");
        assert_eq!(pk.entity_b_type, "procedure");
        assert_eq!(pk.entity_b_gen, "ear_surgery");
        assert_eq!(pk.entity_b_gen_level, 1);
        assert_eq!(pk.amount_bucket, 4);
        assert_eq!(pk.document_category, "medical_bill");
    }

    #[test]
    fn build_pattern_key_does_not_include_role() {
        let tuple = medical_tuple();
        let pk = build_pattern_key(&tuple);
        // PatternKey should NOT contain entity_a_role or entity_b_role
        let pk_debug = format!("{:?}", pk);
        assert!(!pk_debug.contains("entity_a_role"));
        assert!(!pk_debug.contains("entity_b_role"));
    }

    #[test]
    fn build_pattern_key_does_not_include_source_region() {
        let tuple = medical_tuple();
        let pk = build_pattern_key(&tuple);
        // source_region and time_period are NOT part of PatternKey
        let pk_debug = format!("{:?}", pk);
        assert!(!pk_debug.contains("source_region"));
        assert!(!pk_debug.contains("time_period"));
    }

    #[test]
    fn build_pattern_key_equality_from_identical_tuples() {
        let t1 = medical_tuple();
        let t2 = medical_tuple();
        assert_eq!(build_pattern_key(&t1), build_pattern_key(&t2));
    }

    #[test]
    fn build_pattern_key_inequality_from_different_tuples() {
        let t1 = medical_tuple();
        let t2 = receipt_tuple();
        assert_ne!(build_pattern_key(&t1), build_pattern_key(&t2));
    }

    // ── Coarsening tests ───────────────────────────────────────────────

    #[test]
    fn coarsen_entity_b_level0_to_level1() {
        let result = coarsen_entity_b("bilateral_cochlear_implant", 0);
        assert_eq!(result, Some("ear_surgery".to_string()));
    }

    #[test]
    fn coarsen_entity_b_level1_to_level2() {
        let result = coarsen_entity_b("ear_surgery", 1);
        assert_eq!(result, Some("surgical_procedure".to_string()));
    }

    #[test]
    fn coarsen_entity_b_level2_to_level3() {
        let result = coarsen_entity_b("surgical_procedure", 2);
        assert_eq!(result, Some("medical_service".to_string()));
    }

    #[test]
    fn coarsen_entity_b_level3_to_level4() {
        let result = coarsen_entity_b("medical_service", 3);
        assert_eq!(result, Some("*".to_string()));
    }

    #[test]
    fn coarsen_entity_b_level4_returns_none() {
        let result = coarsen_entity_b("*", 4);
        assert_eq!(result, None);
    }

    #[test]
    fn coarsen_entity_b_unknown_value_returns_none() {
        let result = coarsen_entity_b("obscure_procedure_xyz", 0);
        assert_eq!(result, None);
    }

    #[test]
    fn coarsen_entity_b_financial_level0_to_level1() {
        let result = coarsen_entity_b("groceries", 0);
        assert_eq!(result, Some("food_and_beverage".to_string()));
    }

    #[test]
    fn coarsen_entity_b_financial_level1_to_level2() {
        let result = coarsen_entity_b("food_and_beverage", 1);
        assert_eq!(result, Some("consumer_spending".to_string()));
    }

    #[test]
    fn coarsen_entity_b_case_insensitive() {
        let result = coarsen_entity_b("Bilateral_Cochlear_Implant", 0);
        assert_eq!(result, Some("ear_surgery".to_string()));
    }

    #[test]
    fn coarsen_region_state_to_region() {
        assert_eq!(coarsen_region("US-CA"), Some("US-West".to_string()));
        assert_eq!(coarsen_region("US-NY"), Some("US-Northeast".to_string()));
        assert_eq!(coarsen_region("US-TX"), Some("US-South".to_string()));
        assert_eq!(coarsen_region("US-IL"), Some("US-Midwest".to_string()));
    }

    #[test]
    fn coarsen_region_region_to_country() {
        assert_eq!(coarsen_region("US-West"), Some("US".to_string()));
        assert_eq!(coarsen_region("US-Northeast"), Some("US".to_string()));
        assert_eq!(coarsen_region("US-South"), Some("US".to_string()));
        assert_eq!(coarsen_region("US-Midwest"), Some("US".to_string()));
    }

    #[test]
    fn coarsen_region_country_to_top() {
        assert_eq!(coarsen_region("US"), Some("*".to_string()));
    }

    #[test]
    fn coarsen_region_top_returns_none() {
        assert_eq!(coarsen_region("*"), None);
    }

    #[test]
    fn coarsen_region_unknown_returns_none() {
        assert_eq!(coarsen_region("UK-London"), None);
    }

    // ── PatternHasher integration tests ────────────────────────────────

    #[test]
    fn hash_produces_level_0() {
        let hasher = PatternHasher::with_config(test_key(), default_config());
        let results = hasher.hash(medical_tuple());
        assert!(!results.is_empty());
        assert_eq!(results[0].resolution_level, 0);
    }

    #[test]
    fn hash_produces_two_levels_when_coarsenable() {
        let hasher = PatternHasher::with_config(test_key(), default_config());
        // entity_b_gen = "ear_surgery" at level 1, max = 4, so coarsenable
        let results = hasher.hash(medical_tuple());
        assert_eq!(results.len(), 2, "Should produce 2 resolution levels");
        assert_eq!(results[0].resolution_level, 0);
        assert_eq!(results[1].resolution_level, 1);
    }

    #[test]
    fn hash_level_1_has_coarsened_entity_b() {
        let hasher = PatternHasher::with_config(test_key(), default_config());
        let results = hasher.hash(medical_tuple());
        assert_eq!(results.len(), 2);
        // Level 0: ear_surgery at level 1
        assert_eq!(results[0].pattern_key.entity_b_gen, "ear_surgery");
        assert_eq!(results[0].pattern_key.entity_b_gen_level, 1);
        // Level 1: surgical_procedure at level 2
        assert_eq!(results[1].pattern_key.entity_b_gen, "surgical_procedure");
        assert_eq!(results[1].pattern_key.entity_b_gen_level, 2);
    }

    #[test]
    fn hash_level_0_and_level_1_have_different_hashes() {
        let hasher = PatternHasher::with_config(test_key(), default_config());
        let results = hasher.hash(medical_tuple());
        assert_eq!(results.len(), 2);
        assert_ne!(
            results[0].pattern_hash, results[1].pattern_hash,
            "Level 0 and Level 1 hashes must differ (different keys + different inputs)"
        );
    }

    #[test]
    fn hash_max_two_levels() {
        let hasher = PatternHasher::with_config(test_key(), default_config());
        let results = hasher.hash(medical_tuple());
        assert!(
            results.len() <= 2,
            "Must produce at most 2 resolution levels"
        );
    }

    #[test]
    fn hash_max_gen_tuple_only_one_level_via_region_fallback() {
        // max_gen_tuple has entity_b at level 4 (max), source_region = "*"
        let hasher = PatternHasher::with_config(test_key(), default_config());
        let results = hasher.hash(max_gen_tuple());
        // Both entity_b and region are at max, so only level 0
        assert_eq!(
            results.len(),
            1,
            "Should produce only 1 level when nothing coarsenable"
        );
    }

    #[test]
    fn hash_receipt_tuple_coarsens_entity_b() {
        let hasher = PatternHasher::with_config(test_key(), default_config());
        // receipt_tuple entity_b_gen = "groceries" at level 0
        let results = hasher.hash(receipt_tuple());
        assert_eq!(results.len(), 2);
        assert_eq!(results[1].pattern_key.entity_b_gen, "food_and_beverage");
        assert_eq!(results[1].pattern_key.entity_b_gen_level, 1);
    }

    #[test]
    fn hash_deterministic_same_key_same_input() {
        let hasher = PatternHasher::with_config(test_key(), default_config());
        let r1 = hasher.hash(medical_tuple());
        let r2 = hasher.hash(medical_tuple());
        assert_eq!(r1.len(), r2.len());
        for (a, b) in r1.iter().zip(r2.iter()) {
            assert_eq!(a.pattern_hash, b.pattern_hash);
            assert_eq!(a.resolution_level, b.resolution_level);
            assert_eq!(a.pattern_key, b.pattern_key);
        }
    }

    #[test]
    fn hash_cross_device_unlinkable() {
        let hasher1 = PatternHasher::with_config(test_key(), default_config());
        let hasher2 = PatternHasher::with_config(test_key_2(), default_config());
        let r1 = hasher1.hash(medical_tuple());
        let r2 = hasher2.hash(medical_tuple());
        // Same input but different device keys -> different hashes
        assert_ne!(r1[0].pattern_hash, r2[0].pattern_hash);
    }

    #[test]
    fn hash_inner_tuple_preserved_at_level_0() {
        let hasher = PatternHasher::with_config(test_key(), default_config());
        let tuple = medical_tuple();
        let results = hasher.hash(tuple.clone());
        // Level 0 inner should be identical to input
        assert_eq!(results[0].inner.entity_a_type, tuple.entity_a_type);
        assert_eq!(results[0].inner.entity_b_gen, tuple.entity_b_gen);
        assert_eq!(
            results[0].inner.entity_b_gen_level,
            tuple.entity_b_gen_level
        );
        assert_eq!(results[0].inner.source_region, tuple.source_region);
    }

    #[test]
    fn hash_with_single_level_config() {
        let config = HasherConfig {
            max_resolution_levels: 1,
            ..default_config()
        };
        let hasher = PatternHasher::with_config(test_key(), config);
        let results = hasher.hash(medical_tuple());
        assert_eq!(
            results.len(),
            1,
            "Should produce only 1 level when config says max=1"
        );
        assert_eq!(results[0].resolution_level, 0);
    }

    #[test]
    fn hash_from_privacy_config() {
        let config = PrivacyConfig::default_config();
        let hasher = PatternHasher::new(test_key(), &config);
        let results = hasher.hash(medical_tuple());
        assert!(!results.is_empty());
        assert!(results.len() <= 2);
    }

    #[test]
    fn hash_region_fallback_when_entity_b_at_max() {
        // Create a tuple where entity_b is at max but source_region is coarsenable
        let tuple = GeneralizedTuple {
            entity_a_type: "organization".into(),
            entity_a_gen: "provider".into(),
            entity_a_gen_level: 1,
            entity_a_role: "provider".into(),
            entity_b_type: "procedure".into(),
            entity_b_gen: "*".into(),
            entity_b_gen_level: 4, // at max
            entity_b_role: "charge".into(),
            relation: "charges".into(),
            amount_bucket: 3,
            document_category: "medical_bill".into(),
            sensitivity_tier: SensitivityTier::S1Critical,
            source_region: "US-CA".into(), // coarsenable
            time_period: "2026-Q1".into(),
        };
        let hasher = PatternHasher::with_config(test_key(), default_config());
        let results = hasher.hash(tuple);
        assert_eq!(results.len(), 2, "Should fall back to region coarsening");
        // Level 1 should have coarsened region (not part of PatternKey,
        // but reflected in the inner tuple)
        assert_eq!(results[1].inner.source_region, "US-West");
    }

    // ── Security property tests ────────────────────────────────────────

    #[test]
    fn security_deterministic_property() {
        // Property 1: Same input + same key = same hash (always)
        let hasher = PatternHasher::with_config(test_key(), default_config());
        let tuple = receipt_tuple();
        for _ in 0..10 {
            let r = hasher.hash(tuple.clone());
            let r2 = hasher.hash(tuple.clone());
            assert_eq!(r[0].pattern_hash, r2[0].pattern_hash);
        }
    }

    #[test]
    fn security_cross_device_unlinkability() {
        // Property 2: Different keys + same input = different hashes (always)
        let tuple = medical_tuple();
        for i in 0..10u8 {
            let mut bytes_a = [0u8; 32];
            bytes_a[0] = i;
            let mut bytes_b = [0u8; 32];
            bytes_b[0] = i + 100;
            let ha = PatternHasher::with_config(DeviceKey::from_bytes(bytes_a), default_config());
            let hb = PatternHasher::with_config(DeviceKey::from_bytes(bytes_b), default_config());
            let ra = ha.hash(tuple.clone());
            let rb = hb.hash(tuple.clone());
            assert_ne!(ra[0].pattern_hash, rb[0].pattern_hash);
        }
    }

    #[test]
    fn security_level_independence() {
        // Property 3: Level 0 key != Level 1 key (always)
        let key = test_key();
        assert_ne!(key.derive_level_key(0), key.derive_level_key(1));
    }

    #[test]
    fn security_hkdf_independence() {
        // Property 4: Changing master key changes all derived keys
        let k1 = test_key();
        let k2 = test_key_2();
        for level in 0..3u8 {
            assert_ne!(
                k1.derive_level_key(level),
                k2.derive_level_key(level),
                "Master key change must cascade to level {}",
                level
            );
        }
    }

    #[test]
    fn security_canonical_ordering_fixed() {
        // Property 5: Field order in canonical string is fixed
        let pk = PatternKey {
            entity_a_type: "A".into(),
            entity_a_gen: "B".into(),
            entity_a_gen_level: 1,
            relation: "C".into(),
            entity_b_type: "D".into(),
            entity_b_gen: "E".into(),
            entity_b_gen_level: 2,
            amount_bucket: 3,
            document_category: "F".into(),
        };
        let expected = "A|B:1|C|D|E:2|3|F";
        assert_eq!(canonical_string(&pk), expected);
        // Run 100 times to ensure no ordering randomness
        for _ in 0..100 {
            assert_eq!(canonical_string(&pk), expected);
        }
    }

    // ── HasherConfig tests ─────────────────────────────────────────────

    #[test]
    fn hasher_config_from_privacy_config() {
        let pc = PrivacyConfig::default_config();
        let hc = HasherConfig::from_privacy_config(&pc);
        assert_eq!(hc.max_resolution_levels, 2);
        assert_eq!(hc.max_entity_b_gen_level, 4);
        assert_eq!(hc.max_region_gen_level, 3);
    }

    #[test]
    fn hasher_config_default() {
        let hc = HasherConfig::default_config();
        assert_eq!(hc.max_resolution_levels, 2);
    }
}
