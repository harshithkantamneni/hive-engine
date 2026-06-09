//! Stage 7 of the Privacy Pipeline: OUE (Optimized Unary Encoding)
//!
//! Encodes each quasi-identifier field of an l-diversity-checked tuple into a
//! noisy bit vector satisfying epsilon-Local Differential Privacy (LDP). This
//! is the core DP mechanism that makes shared tuples privacy-preserving.
//!
//! ## Algorithm
//!
//! For each field value v in domain D of size d:
//!
//! ```text
//! p = 0.5                             // P(keep 1-bit)
//! q = 1.0 / (exp(epsilon) + 1.0)     // P(flip 0-bit to 1)
//!
//! output = BitVector(d, all_zeros)
//! FOR i = 0 TO d-1:
//!     IF i == value_index:
//!         output[i] = (rng.uniform() < p) ? 1 : 0
//!     ELSE:
//!         output[i] = (rng.uniform() < q) ? 1 : 0
//! RETURN output
//! ```
//!
//! ## Per-Tuple Epsilon by Tier
//!
//! | Tier | Epsilon | OUE q     |
//! |------|---------|-----------|
//! | S1   | 1.0     | ~0.269    |
//! | S2   | 2.0     | ~0.119    |
//! | S3   | 4.0     | ~0.018    |
//! | S4   | 8.0     | ~0.00034  |
//!
//! ## Field Epsilon Weights (sequential composition)
//!
//! Per-field epsilon = tier_epsilon * field_weight. The weights sum to 1.0,
//! so total epsilon consumed = tier_epsilon (by sequential composition).

use super::config::PrivacyConfig;
use super::frequency_tables::FrequencyTables;
use super::types::{EncodedTuple, LCheckedTuple, OueFieldVector, SensitivityTier};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// ─── Constants ──────────────────────────────────────────────────────────────

/// OUE probability of keeping the true bit (always 0.5).
const OUE_P: f64 = 0.5;

/// Field names in the order they are encoded, matching the config weight keys.
const FIELD_NAMES: [&str; 7] = [
    "entity_b_value",
    "amount_bucket",
    "relationship",
    "entity_a_type",
    "entity_b_type",
    "region",
    "time_period",
];

/// Default domain sizes for V1 (used when frequency tables are unavailable).
/// Indexed in the same order as FIELD_NAMES.
const DEFAULT_DOMAIN_SIZES: [u16; 7] = [
    120, // entity_b_value: medical terms, the largest domain
    9,   // amount_bucket: 0-7 + 0xFF
    23,  // relationship (relation)
    17,  // entity_a_type
    34,  // entity_b_type
    51,  // region (source_region): states + DC
    12,  // time_period: months or quarters
];

// ─── Trait ───────────────────────────────────────────────────────────────────

/// Trait for OUE encoding. Allows mocking in downstream stages.
pub trait OueEncoder {
    /// Encode tuple fields using OUE with CSPRNG.
    /// Returns None if budget pre-check fails (tier_epsilon > remaining_budget).
    fn encode(&self, l_checked: LCheckedTuple, remaining_budget: f64) -> Option<EncodedTuple>;
}

// ─── Core OUE Functions ─────────────────────────────────────────────────────

/// Compute OUE q parameter: probability of flipping a 0-bit to 1.
///
/// q = 1.0 / (exp(epsilon) + 1.0)
#[inline]
pub fn oue_q(epsilon: f64) -> f64 {
    1.0 / (epsilon.exp() + 1.0)
}

/// Encode a single field value using OUE into a packed bit vector.
///
/// - `value_index`: the index of the true value in domain [0, domain_size)
/// - `domain_size`: total number of possible values for this field
/// - `epsilon`: per-field epsilon budget
/// - `rng`: ChaCha20Rng instance (CSPRNG seeded from OsRng)
///
/// Returns a Vec<u8> with bits packed in big-endian order within each byte.
/// Bit i is stored at byte (i / 8), bit position (7 - (i % 8)).
pub fn oue_encode_field(
    value_index: usize,
    domain_size: usize,
    epsilon: f64,
    rng: &mut ChaCha20Rng,
) -> Vec<u8> {
    let q = oue_q(epsilon);
    let num_bytes = domain_size.div_ceil(8);
    let mut bits = vec![0u8; num_bytes];

    for i in 0..domain_size {
        let threshold = if i == value_index { OUE_P } else { q };
        let sample: f64 = rng.random();
        if sample < threshold {
            // Set bit i: byte = i / 8, bit position = 7 - (i % 8) (big-endian)
            let byte_idx = i / 8;
            let bit_pos = 7 - (i % 8);
            bits[byte_idx] |= 1 << bit_pos;
        }
    }

    bits
}

/// Extract bit i from a packed bit vector (big-endian bit order within each byte).
///
/// Returns true if the bit is set, false otherwise.
#[inline]
pub fn get_bit(bits: &[u8], index: usize) -> bool {
    let byte_idx = index / 8;
    let bit_pos = 7 - (index % 8);
    if byte_idx >= bits.len() {
        return false;
    }
    (bits[byte_idx] >> bit_pos) & 1 == 1
}

/// Set bit i in a packed bit vector (big-endian bit order within each byte).
#[inline]
pub fn set_bit(bits: &mut [u8], index: usize) {
    let byte_idx = index / 8;
    let bit_pos = 7 - (index % 8);
    if byte_idx < bits.len() {
        bits[byte_idx] |= 1 << bit_pos;
    }
}

/// Clear bit i in a packed bit vector.
#[inline]
pub fn clear_bit(bits: &mut [u8], index: usize) {
    let byte_idx = index / 8;
    let bit_pos = 7 - (index % 8);
    if byte_idx < bits.len() {
        bits[byte_idx] &= !(1 << bit_pos);
    }
}

// ─── Value-to-Index Mapping ─────────────────────────────────────────────────

/// Deterministic mapping of a string field value to a domain index.
///
/// Uses BLAKE3 hash for deterministic, uniform distribution across the domain.
/// This avoids needing a full lookup table while ensuring the same value always
/// maps to the same index.
pub fn value_to_index(value: &str, domain_size: u16) -> usize {
    if domain_size == 0 {
        return 0;
    }
    let hash = blake3::hash(value.as_bytes());
    let hash_bytes = hash.as_bytes();
    // Use first 8 bytes for a u64, then mod domain_size
    let h = u64::from_le_bytes([
        hash_bytes[0],
        hash_bytes[1],
        hash_bytes[2],
        hash_bytes[3],
        hash_bytes[4],
        hash_bytes[5],
        hash_bytes[6],
        hash_bytes[7],
    ]);
    (h % domain_size as u64) as usize
}

// ─── Field Extraction ───────────────────────────────────────────────────────

/// Extract the 7 field values from an LCheckedTuple for OUE encoding.
///
/// Returns values in the same order as FIELD_NAMES:
/// [entity_b_value, amount_bucket, relationship, entity_a_type,
///  entity_b_type, region, time_period]
fn extract_field_values(l_checked: &LCheckedTuple) -> [String; 7] {
    let inner = &l_checked.inner.inner.inner; // GeneralizedTuple
    [
        inner.entity_b_gen.clone(),      // entity_b_value
        inner.amount_bucket.to_string(), // amount_bucket
        inner.relation.clone(),          // relationship
        inner.entity_a_type.clone(),     // entity_a_type
        inner.entity_b_type.clone(),     // entity_b_type
        inner.source_region.clone(),     // region
        inner.time_period.clone(),       // time_period
    ]
}

// ─── OueEncoderImpl ─────────────────────────────────────────────────────────

/// Concrete OUE encoder implementation. Holds the privacy config and
/// frequency tables for domain size resolution.
pub struct OueEncoderImpl {
    config: PrivacyConfig,
    freq_tables: FrequencyTables,
}

impl OueEncoderImpl {
    /// Create a new OUE encoder with the given configuration.
    pub fn new(config: PrivacyConfig) -> Self {
        Self {
            config,
            freq_tables: FrequencyTables::new(),
        }
    }

    /// Create a new OUE encoder with explicit frequency tables (for testing).
    pub fn with_freq_tables(config: PrivacyConfig, freq_tables: FrequencyTables) -> Self {
        Self {
            config,
            freq_tables,
        }
    }

    /// Get the per-field epsilon weight from the config.
    fn field_weight(&self, field_name: &str) -> f64 {
        match field_name {
            "entity_b_value" => self.config.field_weights.entity_b_value,
            "amount_bucket" => self.config.field_weights.amount_bucket,
            "relationship" => self.config.field_weights.relationship,
            "entity_a_type" => self.config.field_weights.entity_a_type,
            "entity_b_type" => self.config.field_weights.entity_b_type,
            "region" => self.config.field_weights.region,
            "time_period" => self.config.field_weights.time_period,
            _ => 0.0,
        }
    }

    /// Get the tier epsilon from config.
    fn tier_epsilon(&self, tier: SensitivityTier) -> f64 {
        self.config.epsilon.for_tier_index(tier.index())
    }

    /// Resolve the domain size for a field. Prefers frequency table sizes,
    /// falls back to V1 defaults.
    fn domain_size_for_field(&self, field_idx: usize) -> u16 {
        // Map field names to frequency table lookup keys
        let ft_key = match FIELD_NAMES[field_idx] {
            "entity_b_value" => "entity_b_value",
            "amount_bucket" => "amount_bucket",
            "relationship" => "relation",
            "entity_a_type" => "entity_a_type",
            "entity_b_type" => "entity_b_type",
            "region" => "source_region",
            "time_period" => "time_period",
            _ => return DEFAULT_DOMAIN_SIZES[field_idx],
        };
        let ft_size = self.freq_tables.domain_size(ft_key);
        if ft_size > 1 {
            ft_size
        } else {
            DEFAULT_DOMAIN_SIZES[field_idx]
        }
    }
}

impl OueEncoder for OueEncoderImpl {
    fn encode(&self, l_checked: LCheckedTuple, remaining_budget: f64) -> Option<EncodedTuple> {
        // Determine tier and epsilon
        let tier = l_checked.inner.inner.inner.sensitivity_tier;
        let tier_eps = self.tier_epsilon(tier);

        // Budget pre-check: reject if insufficient budget
        if tier_eps > remaining_budget {
            return None;
        }

        // Seed ChaCha20Rng from OsRng (CSPRNG requirement)
        let mut rng = ChaCha20Rng::from_os_rng();

        // Extract field values
        let field_values = extract_field_values(&l_checked);

        // Encode each field
        let mut oue_vectors = Vec::with_capacity(7);
        for (idx, field_name) in FIELD_NAMES.iter().enumerate() {
            let weight = self.field_weight(field_name);
            let field_eps = tier_eps * weight;
            let domain_size = self.domain_size_for_field(idx);
            let value_idx = value_to_index(&field_values[idx], domain_size);
            let bits = oue_encode_field(value_idx, domain_size as usize, field_eps, &mut rng);

            oue_vectors.push(OueFieldVector {
                field_name: field_name.to_string(),
                domain_size,
                epsilon: field_eps,
                bits,
            });
        }

        Some(EncodedTuple {
            inner: l_checked,
            oue_vectors,
            epsilon_consumed: tier_eps,
        })
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::types::{
        GeneralizedTuple, HashedTuple, KCheckedTuple, LCheckedTuple, PatternKey, SensitivityTier,
    };

    // ── Test helpers ─────────────────────────────────────────────────────

    /// Build a minimal LCheckedTuple for testing.
    // Test helper; each argument is a distinct QID whose encoding is
    // exercised directly in OUE tests.
    #[allow(clippy::too_many_arguments)]
    fn make_l_checked(
        tier: SensitivityTier,
        entity_b_gen: &str,
        amount_bucket: u8,
        relation: &str,
        entity_a_type: &str,
        entity_b_type: &str,
        source_region: &str,
        time_period: &str,
    ) -> LCheckedTuple {
        let gen = GeneralizedTuple {
            entity_a_type: entity_a_type.into(),
            entity_a_gen: "healthcare_provider".into(),
            entity_a_gen_level: 1,
            entity_a_role: "provider".into(),
            entity_b_type: entity_b_type.into(),
            entity_b_gen: entity_b_gen.into(),
            entity_b_gen_level: 1,
            entity_b_role: "charge".into(),
            relation: relation.into(),
            amount_bucket,
            document_category: match tier {
                SensitivityTier::S1Critical => "medical_bill",
                SensitivityTier::S2High => "bank_statement",
                SensitivityTier::S3Medium => "utility_bill",
                SensitivityTier::S4Low => "receipt",
            }
            .into(),
            sensitivity_tier: tier,
            source_region: source_region.into(),
            time_period: time_period.into(),
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
        LCheckedTuple {
            inner: k_checked,
            l_entropy: 2.5,
        }
    }

    /// Build a default L-checked tuple for convenience.
    fn default_l_checked(tier: SensitivityTier) -> LCheckedTuple {
        make_l_checked(
            tier,
            "imaging",
            3,
            "charges",
            "organization",
            "procedure",
            "CA",
            "2025-Q3",
        )
    }

    /// Build a default encoder using the default config.
    fn make_encoder() -> OueEncoderImpl {
        OueEncoderImpl::new(PrivacyConfig::default_config())
    }

    // ── OUE math correctness: p and q values ────────────────────────────

    #[test]
    fn oue_p_is_half() {
        assert!((OUE_P - 0.5).abs() < 1e-15, "OUE p must be exactly 0.5");
    }

    #[test]
    fn oue_q_s1_epsilon_1() {
        let q = oue_q(1.0);
        let expected = 1.0 / (1.0_f64.exp() + 1.0);
        assert!(
            (q - expected).abs() < 1e-10,
            "S1 q: expected {}, got {}",
            expected,
            q
        );
        assert!(
            (q - 0.269).abs() < 0.001,
            "S1 q should be ~0.269, got {}",
            q
        );
    }

    #[test]
    fn oue_q_s2_epsilon_2() {
        let q = oue_q(2.0);
        let expected = 1.0 / (2.0_f64.exp() + 1.0);
        assert!(
            (q - expected).abs() < 1e-10,
            "S2 q: expected {}, got {}",
            expected,
            q
        );
        assert!(
            (q - 0.119).abs() < 0.001,
            "S2 q should be ~0.119, got {}",
            q
        );
    }

    #[test]
    fn oue_q_s3_epsilon_4() {
        let q = oue_q(4.0);
        let expected = 1.0 / (4.0_f64.exp() + 1.0);
        assert!(
            (q - expected).abs() < 1e-10,
            "S3 q: expected {}, got {}",
            expected,
            q
        );
        assert!(
            (q - 0.018).abs() < 0.001,
            "S3 q should be ~0.018, got {}",
            q
        );
    }

    #[test]
    fn oue_q_s4_epsilon_8() {
        let q = oue_q(8.0);
        let expected = 1.0 / (8.0_f64.exp() + 1.0);
        assert!(
            (q - expected).abs() < 1e-10,
            "S4 q: expected {}, got {}",
            expected,
            q
        );
        assert!(
            (q - 0.00034).abs() < 0.0001,
            "S4 q should be ~0.00034, got {}",
            q
        );
    }

    #[test]
    fn oue_q_monotonically_decreasing_with_epsilon() {
        let q1 = oue_q(1.0);
        let q2 = oue_q(2.0);
        let q4 = oue_q(4.0);
        let q8 = oue_q(8.0);
        assert!(q1 > q2, "q(1.0) > q(2.0)");
        assert!(q2 > q4, "q(2.0) > q(4.0)");
        assert!(q4 > q8, "q(4.0) > q(8.0)");
    }

    #[test]
    fn oue_q_approaches_half_at_zero_epsilon() {
        let q = oue_q(0.0);
        assert!((q - 0.5).abs() < 1e-10, "q(0) should be 0.5, got {}", q);
    }

    #[test]
    fn oue_q_approaches_zero_at_large_epsilon() {
        let q = oue_q(50.0);
        assert!(q < 1e-20, "q(50) should be near-zero, got {}", q);
    }

    // ── Bit packing: pack/unpack round-trip ─────────────────────────────

    #[test]
    fn bit_pack_single_bit_0() {
        let mut bits = vec![0u8; 1];
        set_bit(&mut bits, 0);
        assert!(get_bit(&bits, 0), "Bit 0 should be set");
        assert!(!get_bit(&bits, 1), "Bit 1 should not be set");
    }

    #[test]
    fn bit_pack_single_bit_7() {
        let mut bits = vec![0u8; 1];
        set_bit(&mut bits, 7);
        assert!(get_bit(&bits, 7), "Bit 7 should be set");
        assert!(!get_bit(&bits, 0), "Bit 0 should not be set");
    }

    #[test]
    fn bit_pack_cross_byte_boundary() {
        let mut bits = vec![0u8; 2];
        set_bit(&mut bits, 7);
        set_bit(&mut bits, 8);
        assert!(get_bit(&bits, 7), "Bit 7 should be set");
        assert!(get_bit(&bits, 8), "Bit 8 should be set");
        assert!(!get_bit(&bits, 6), "Bit 6 should not be set");
        assert!(!get_bit(&bits, 9), "Bit 9 should not be set");
    }

    #[test]
    fn bit_pack_all_bits_in_byte() {
        let mut bits = vec![0u8; 1];
        for i in 0..8 {
            set_bit(&mut bits, i);
        }
        assert_eq!(bits[0], 0xFF, "All 8 bits set should be 0xFF");
        for i in 0..8 {
            assert!(get_bit(&bits, i), "Bit {} should be set", i);
        }
    }

    #[test]
    fn bit_pack_set_clear_roundtrip() {
        let mut bits = vec![0u8; 2];
        set_bit(&mut bits, 3);
        set_bit(&mut bits, 11);
        assert!(get_bit(&bits, 3));
        assert!(get_bit(&bits, 11));
        clear_bit(&mut bits, 3);
        assert!(!get_bit(&bits, 3));
        assert!(get_bit(&bits, 11));
    }

    #[test]
    fn bit_pack_big_endian_order() {
        // Bit 0 should be the MSB of byte 0
        let mut bits = vec![0u8; 1];
        set_bit(&mut bits, 0);
        assert_eq!(bits[0], 0x80, "Bit 0 = MSB = 0x80");

        let mut bits = vec![0u8; 1];
        set_bit(&mut bits, 7);
        assert_eq!(bits[0], 0x01, "Bit 7 = LSB = 0x01");
    }

    #[test]
    fn bit_get_out_of_range() {
        let bits = vec![0xFF; 1];
        assert!(
            !get_bit(&bits, 8),
            "Bit 8 in 1-byte vec should return false"
        );
        assert!(
            !get_bit(&bits, 100),
            "Bit 100 in 1-byte vec should return false"
        );
    }

    // ── Bit vector length correctness ───────────────────────────────────

    #[test]
    fn bit_vector_length_exact_byte() {
        let mut rng = ChaCha20Rng::from_os_rng();
        let bits = oue_encode_field(0, 8, 1.0, &mut rng);
        assert_eq!(bits.len(), 1, "8 bits should fit in 1 byte");
    }

    #[test]
    fn bit_vector_length_partial_byte() {
        let mut rng = ChaCha20Rng::from_os_rng();
        let bits = oue_encode_field(0, 9, 1.0, &mut rng);
        assert_eq!(bits.len(), 2, "9 bits should need 2 bytes");
    }

    #[test]
    fn bit_vector_length_one_bit() {
        let mut rng = ChaCha20Rng::from_os_rng();
        let bits = oue_encode_field(0, 1, 1.0, &mut rng);
        assert_eq!(bits.len(), 1, "1 bit should need 1 byte");
    }

    #[test]
    fn bit_vector_length_large_domain() {
        let mut rng = ChaCha20Rng::from_os_rng();
        let bits = oue_encode_field(0, 256, 1.0, &mut rng);
        assert_eq!(bits.len(), 32, "256 bits = 32 bytes");
    }

    #[test]
    fn bit_vector_length_domain_120() {
        let mut rng = ChaCha20Rng::from_os_rng();
        let bits = oue_encode_field(0, 120, 1.0, &mut rng);
        assert_eq!(bits.len(), 15, "120 bits = 15 bytes");
    }

    // ── CSPRNG usage ────────────────────────────────────────────────────

    #[test]
    fn csprng_seeded_rng_produces_different_outputs() {
        // Two independently seeded ChaCha20Rng should produce different bit vectors
        // (with overwhelmingly high probability for any non-trivial domain)
        let mut rng1 = ChaCha20Rng::from_os_rng();
        let mut rng2 = ChaCha20Rng::from_os_rng();
        let bits1 = oue_encode_field(5, 64, 2.0, &mut rng1);
        let bits2 = oue_encode_field(5, 64, 2.0, &mut rng2);
        // With 64 bits and q~0.119, expected ~7.6 noise bits -> different outputs
        // This test can technically fail with probability ~2^-64 but effectively never will
        assert_ne!(
            bits1, bits2,
            "Two CSPRNG encodings should differ (probabilistic)"
        );
    }

    #[test]
    fn csprng_deterministic_with_same_seed() {
        let seed = [42u8; 32];
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let mut rng2 = ChaCha20Rng::from_seed(seed);
        let bits1 = oue_encode_field(3, 32, 2.0, &mut rng1);
        let bits2 = oue_encode_field(3, 32, 2.0, &mut rng2);
        assert_eq!(bits1, bits2, "Same seed should produce identical output");
    }

    // ── Statistical tests ───────────────────────────────────────────────

    #[test]
    fn statistical_true_bit_rate_p_half() {
        // Over many trials, the true bit should be set ~50% of the time (p=0.5)
        let mut rng = ChaCha20Rng::from_os_rng();
        let trials = 10_000;
        let value_index = 5;
        let domain_size = 32;
        let epsilon = 2.0;
        let mut true_bit_set_count = 0u64;

        for _ in 0..trials {
            let bits = oue_encode_field(value_index, domain_size, epsilon, &mut rng);
            if get_bit(&bits, value_index) {
                true_bit_set_count += 1;
            }
        }

        let observed_p = true_bit_set_count as f64 / trials as f64;
        // With 10K trials, p=0.5, stdev = sqrt(0.25/10000) = 0.005
        // Allow 6-sigma tolerance: 0.03
        assert!(
            (observed_p - 0.5).abs() < 0.03,
            "True bit should be set ~50% of the time, observed {}%",
            observed_p * 100.0
        );
    }

    #[test]
    fn statistical_false_bit_rate_s1_q() {
        // For S1 epsilon=1.0, q~0.269. False bits should be set ~26.9% of the time.
        let mut rng = ChaCha20Rng::from_os_rng();
        let trials = 5_000;
        let value_index = 0;
        let domain_size = 32;
        let epsilon = 1.0; // S1
        let expected_q = oue_q(epsilon);
        let mut false_bit_set_count = 0u64;
        let num_false_bits = (domain_size - 1) as u64;

        for _ in 0..trials {
            let bits = oue_encode_field(value_index, domain_size, epsilon, &mut rng);
            for i in 1..domain_size {
                if get_bit(&bits, i) {
                    false_bit_set_count += 1;
                }
            }
        }

        let observed_q = false_bit_set_count as f64 / (trials as f64 * num_false_bits as f64);
        // Allow generous tolerance for statistical tests
        assert!(
            (observed_q - expected_q).abs() < 0.02,
            "False bit rate should be ~{}, observed {}",
            expected_q,
            observed_q
        );
    }

    #[test]
    fn statistical_false_bit_rate_s2_q() {
        let mut rng = ChaCha20Rng::from_os_rng();
        let trials = 5_000;
        let value_index = 0;
        let domain_size = 32;
        let epsilon = 2.0; // S2
        let expected_q = oue_q(epsilon);
        let mut false_bit_set_count = 0u64;
        let num_false_bits = (domain_size - 1) as u64;

        for _ in 0..trials {
            let bits = oue_encode_field(value_index, domain_size, epsilon, &mut rng);
            for i in 1..domain_size {
                if get_bit(&bits, i) {
                    false_bit_set_count += 1;
                }
            }
        }

        let observed_q = false_bit_set_count as f64 / (trials as f64 * num_false_bits as f64);
        assert!(
            (observed_q - expected_q).abs() < 0.02,
            "S2 false bit rate should be ~{}, observed {}",
            expected_q,
            observed_q
        );
    }

    #[test]
    fn statistical_false_bit_rate_s3_q() {
        let mut rng = ChaCha20Rng::from_os_rng();
        let trials = 5_000;
        let value_index = 0;
        let domain_size = 32;
        let epsilon = 4.0; // S3
        let expected_q = oue_q(epsilon);
        let mut false_bit_set_count = 0u64;
        let num_false_bits = (domain_size - 1) as u64;

        for _ in 0..trials {
            let bits = oue_encode_field(value_index, domain_size, epsilon, &mut rng);
            for i in 1..domain_size {
                if get_bit(&bits, i) {
                    false_bit_set_count += 1;
                }
            }
        }

        let observed_q = false_bit_set_count as f64 / (trials as f64 * num_false_bits as f64);
        assert!(
            (observed_q - expected_q).abs() < 0.01,
            "S3 false bit rate should be ~{}, observed {}",
            expected_q,
            observed_q
        );
    }

    #[test]
    fn statistical_false_bit_rate_s4_q() {
        let mut rng = ChaCha20Rng::from_os_rng();
        let trials = 5_000;
        let value_index = 0;
        let domain_size = 32;
        let epsilon = 8.0; // S4
        let expected_q = oue_q(epsilon);
        let mut false_bit_set_count = 0u64;
        let num_false_bits = (domain_size - 1) as u64;

        for _ in 0..trials {
            let bits = oue_encode_field(value_index, domain_size, epsilon, &mut rng);
            for i in 1..domain_size {
                if get_bit(&bits, i) {
                    false_bit_set_count += 1;
                }
            }
        }

        let observed_q = false_bit_set_count as f64 / (trials as f64 * num_false_bits as f64);
        assert!(
            (observed_q - expected_q).abs() < 0.005,
            "S4 false bit rate should be ~{}, observed {}",
            expected_q,
            observed_q
        );
    }

    // ── Budget pre-check ────────────────────────────────────────────────

    #[test]
    fn budget_precheck_insufficient_returns_none() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S1Critical);
        // S1 epsilon = 1.0, remaining = 0.5 -> insufficient
        let result = encoder.encode(l_checked, 0.5);
        assert!(
            result.is_none(),
            "Should return None when budget < tier epsilon"
        );
    }

    #[test]
    fn budget_precheck_zero_remaining_returns_none() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S1Critical);
        let result = encoder.encode(l_checked, 0.0);
        assert!(result.is_none(), "Should return None when budget is 0");
    }

    #[test]
    fn budget_precheck_exact_remaining_returns_some() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S1Critical);
        // S1 epsilon = 1.0, remaining = 1.0 -> exact match, should succeed
        let result = encoder.encode(l_checked, 1.0);
        assert!(
            result.is_some(),
            "Should return Some when budget == tier epsilon"
        );
    }

    #[test]
    fn budget_precheck_surplus_returns_some() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S2High);
        // S2 epsilon = 2.0, remaining = 10.0 -> surplus
        let result = encoder.encode(l_checked, 10.0);
        assert!(
            result.is_some(),
            "Should return Some when budget > tier epsilon"
        );
    }

    #[test]
    fn budget_precheck_s2_insufficient() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S2High);
        // S2 epsilon = 2.0, remaining = 1.5 -> insufficient
        let result = encoder.encode(l_checked, 1.5);
        assert!(result.is_none(), "S2 should be rejected with 1.5 budget");
    }

    #[test]
    fn budget_precheck_s3_sufficient() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S3Medium);
        // S3 epsilon = 4.0, remaining = 5.0
        let result = encoder.encode(l_checked, 5.0);
        assert!(result.is_some(), "S3 should succeed with 5.0 budget");
    }

    #[test]
    fn budget_precheck_s4_sufficient() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S4Low);
        // S4 epsilon = 8.0, remaining = 10.0
        let result = encoder.encode(l_checked, 10.0);
        assert!(result.is_some(), "S4 should succeed with 10.0 budget");
    }

    #[test]
    fn budget_precheck_s4_insufficient() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S4Low);
        // S4 epsilon = 8.0, remaining = 7.0
        let result = encoder.encode(l_checked, 7.0);
        assert!(result.is_none(), "S4 should be rejected with 7.0 budget");
    }

    // ── Field weight correctness ────────────────────────────────────────

    #[test]
    fn field_weights_sum_to_one() {
        let encoder = make_encoder();
        let sum: f64 = FIELD_NAMES.iter().map(|f| encoder.field_weight(f)).sum();
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "Field weights must sum to 1.0, got {}",
            sum
        );
    }

    #[test]
    fn field_epsilon_sum_equals_tier_epsilon_s1() {
        let encoder = make_encoder();
        let tier_eps = encoder.tier_epsilon(SensitivityTier::S1Critical);
        let field_eps_sum: f64 = FIELD_NAMES
            .iter()
            .map(|f| tier_eps * encoder.field_weight(f))
            .sum();
        assert!(
            (field_eps_sum - tier_eps).abs() < 1e-10,
            "Sum of field epsilons should equal tier epsilon: {} vs {}",
            field_eps_sum,
            tier_eps
        );
    }

    #[test]
    fn field_epsilon_sum_equals_tier_epsilon_s4() {
        let encoder = make_encoder();
        let tier_eps = encoder.tier_epsilon(SensitivityTier::S4Low);
        let field_eps_sum: f64 = FIELD_NAMES
            .iter()
            .map(|f| tier_eps * encoder.field_weight(f))
            .sum();
        assert!(
            (field_eps_sum - tier_eps).abs() < 1e-10,
            "Sum of field epsilons should equal tier epsilon: {} vs {}",
            field_eps_sum,
            tier_eps
        );
    }

    #[test]
    fn field_weight_entity_b_value_is_largest() {
        let encoder = make_encoder();
        let ebv = encoder.field_weight("entity_b_value");
        for f in &FIELD_NAMES[1..] {
            assert!(
                ebv >= encoder.field_weight(f),
                "entity_b_value should have the largest weight"
            );
        }
    }

    #[test]
    fn field_weight_unknown_field_is_zero() {
        let encoder = make_encoder();
        assert!(
            (encoder.field_weight("nonexistent") - 0.0).abs() < 1e-15,
            "Unknown field weight should be 0"
        );
    }

    // ── All 4 tiers: full encoding ──────────────────────────────────────

    #[test]
    fn encode_s1_critical() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S1Critical);
        let result = encoder
            .encode(l_checked, 10.0)
            .expect("S1 encode should succeed");
        assert_eq!(result.oue_vectors.len(), 7, "Should encode 7 fields");
        assert!(
            (result.epsilon_consumed - 1.0).abs() < 1e-10,
            "S1 epsilon_consumed should be 1.0"
        );
    }

    #[test]
    fn encode_s2_high() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S2High);
        let result = encoder
            .encode(l_checked, 10.0)
            .expect("S2 encode should succeed");
        assert_eq!(result.oue_vectors.len(), 7);
        assert!(
            (result.epsilon_consumed - 2.0).abs() < 1e-10,
            "S2 epsilon_consumed should be 2.0"
        );
    }

    #[test]
    fn encode_s3_medium() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S3Medium);
        let result = encoder
            .encode(l_checked, 10.0)
            .expect("S3 encode should succeed");
        assert_eq!(result.oue_vectors.len(), 7);
        assert!(
            (result.epsilon_consumed - 4.0).abs() < 1e-10,
            "S3 epsilon_consumed should be 4.0"
        );
    }

    #[test]
    fn encode_s4_low() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S4Low);
        let result = encoder
            .encode(l_checked, 10.0)
            .expect("S4 encode should succeed");
        assert_eq!(result.oue_vectors.len(), 7);
        assert!(
            (result.epsilon_consumed - 8.0).abs() < 1e-10,
            "S4 epsilon_consumed should be 8.0"
        );
    }

    // ── EncodedTuple field correctness ──────────────────────────────────

    #[test]
    fn encoded_tuple_preserves_inner() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S1Critical);
        let original_entropy = l_checked.l_entropy;
        let result = encoder
            .encode(l_checked, 10.0)
            .expect("encode should succeed");
        assert!(
            (result.inner.l_entropy - original_entropy).abs() < 1e-10,
            "Inner LCheckedTuple should be preserved"
        );
    }

    #[test]
    fn encoded_tuple_field_names_match() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S2High);
        let result = encoder
            .encode(l_checked, 10.0)
            .expect("encode should succeed");
        let names: Vec<&str> = result
            .oue_vectors
            .iter()
            .map(|v| v.field_name.as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "entity_b_value",
                "amount_bucket",
                "relationship",
                "entity_a_type",
                "entity_b_type",
                "region",
                "time_period",
            ]
        );
    }

    #[test]
    fn encoded_tuple_epsilon_per_field_sums_to_tier() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S2High);
        let result = encoder
            .encode(l_checked, 10.0)
            .expect("encode should succeed");
        let field_eps_sum: f64 = result.oue_vectors.iter().map(|v| v.epsilon).sum();
        assert!(
            (field_eps_sum - 2.0).abs() < 1e-10,
            "Per-field epsilon sum should equal tier epsilon: {}",
            field_eps_sum
        );
    }

    #[test]
    fn encoded_tuple_bit_vector_sizes_match_domain() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S1Critical);
        let result = encoder
            .encode(l_checked, 10.0)
            .expect("encode should succeed");
        for v in &result.oue_vectors {
            let expected_bytes = (v.domain_size as usize).div_ceil(8);
            assert_eq!(
                v.bits.len(),
                expected_bytes,
                "Field '{}': bit vector should be {} bytes for domain_size {}",
                v.field_name,
                expected_bytes,
                v.domain_size
            );
        }
    }

    #[test]
    fn encoded_tuple_epsilon_consumed_matches_tier() {
        let encoder = make_encoder();
        for tier in [
            SensitivityTier::S1Critical,
            SensitivityTier::S2High,
            SensitivityTier::S3Medium,
            SensitivityTier::S4Low,
        ] {
            let l_checked = default_l_checked(tier);
            let tier_eps = encoder.tier_epsilon(tier);
            let result = encoder
                .encode(l_checked, 100.0)
                .expect("encode should succeed");
            assert!(
                (result.epsilon_consumed - tier_eps).abs() < 1e-10,
                "Tier {:?}: epsilon_consumed should be {}",
                tier,
                tier_eps
            );
        }
    }

    // ── Value-to-index mapping ──────────────────────────────────────────

    #[test]
    fn value_to_index_deterministic() {
        let idx1 = value_to_index("imaging", 120);
        let idx2 = value_to_index("imaging", 120);
        assert_eq!(idx1, idx2, "Same value should always map to same index");
    }

    #[test]
    fn value_to_index_within_range() {
        let domain_size = 120u16;
        for value in &["imaging", "surgery", "mri", "blood_test", "hospital"] {
            let idx = value_to_index(value, domain_size);
            assert!(
                idx < domain_size as usize,
                "'{}' -> {} should be < {}",
                value,
                idx,
                domain_size
            );
        }
    }

    #[test]
    fn value_to_index_different_values_likely_different() {
        // Different values should map to different indices (with high probability)
        let idx1 = value_to_index("imaging", 1000);
        let idx2 = value_to_index("surgery", 1000);
        let idx3 = value_to_index("laboratory", 1000);
        // Not guaranteed, but overwhelmingly likely with domain_size=1000
        assert!(
            idx1 != idx2 || idx2 != idx3,
            "Different values should likely map to different indices"
        );
    }

    #[test]
    fn value_to_index_domain_size_one() {
        let idx = value_to_index("anything", 1);
        assert_eq!(idx, 0, "Domain size 1 should always map to index 0");
    }

    #[test]
    fn value_to_index_domain_size_zero() {
        let idx = value_to_index("anything", 0);
        assert_eq!(idx, 0, "Domain size 0 should return 0");
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn encode_field_domain_size_one() {
        let mut rng = ChaCha20Rng::from_os_rng();
        let bits = oue_encode_field(0, 1, 2.0, &mut rng);
        assert_eq!(bits.len(), 1, "Domain size 1 should produce 1 byte");
        // Only bit 0 matters; it should be set ~50% of the time
    }

    #[test]
    fn encode_field_domain_size_very_large() {
        let mut rng = ChaCha20Rng::from_os_rng();
        let domain_size = 1024;
        let bits = oue_encode_field(0, domain_size, 2.0, &mut rng);
        assert_eq!(bits.len(), 128, "1024 bits = 128 bytes");
    }

    #[test]
    fn encode_field_epsilon_very_small() {
        // Very small epsilon -> q ~ 0.5, lots of noise
        let mut rng = ChaCha20Rng::from_os_rng();
        let bits = oue_encode_field(0, 32, 0.001, &mut rng);
        assert_eq!(bits.len(), 4, "32 bits = 4 bytes");
        // With q~0.5, expect ~50% of all bits set (very noisy)
    }

    #[test]
    fn encode_field_epsilon_very_large() {
        // Very large epsilon -> q ~ 0, minimal noise
        let mut rng = ChaCha20Rng::from_os_rng();
        let trials = 100;
        let mut all_zero_false_bits = 0;
        for _ in 0..trials {
            let bits = oue_encode_field(0, 32, 50.0, &mut rng);
            // Count false bits that are set
            let false_bits_set: u32 = (1..32).map(|i| if get_bit(&bits, i) { 1 } else { 0 }).sum();
            if false_bits_set == 0 {
                all_zero_false_bits += 1;
            }
        }
        // With q~0, nearly all false bits should be 0 in every trial
        assert!(
            all_zero_false_bits > 90,
            "With very large epsilon, false bits should almost never be set: {}/100 had all-zero false bits",
            all_zero_false_bits
        );
    }

    #[test]
    fn encode_field_value_index_at_end() {
        let mut rng = ChaCha20Rng::from_os_rng();
        let domain_size = 32;
        let value_index = 31; // Last position
        let bits = oue_encode_field(value_index, domain_size, 2.0, &mut rng);
        assert_eq!(bits.len(), 4);
        // The true bit at position 31 should still have p=0.5 behavior
    }

    #[test]
    fn encode_field_value_index_middle() {
        let mut rng = ChaCha20Rng::from_os_rng();
        let bits = oue_encode_field(16, 32, 2.0, &mut rng);
        assert_eq!(bits.len(), 4);
    }

    // ── Domain size resolution ──────────────────────────────────────────

    #[test]
    fn domain_size_uses_frequency_tables() {
        let encoder = make_encoder();
        // entity_b_value should get a size > 100 from frequency tables
        let size = encoder.domain_size_for_field(0);
        assert!(
            size > 100,
            "entity_b_value domain should be large from freq tables, got {}",
            size
        );
    }

    #[test]
    fn domain_size_all_fields_positive() {
        let encoder = make_encoder();
        for (idx, name) in FIELD_NAMES.iter().enumerate() {
            let size = encoder.domain_size_for_field(idx);
            assert!(
                size > 0,
                "Field {} domain size should be > 0, got {}",
                name,
                size
            );
        }
    }

    // ── Field extraction ────────────────────────────────────────────────

    #[test]
    fn field_extraction_correct_values() {
        let l_checked = make_l_checked(
            SensitivityTier::S1Critical,
            "imaging",
            3,
            "charges",
            "organization",
            "procedure",
            "CA",
            "2025-Q3",
        );
        let values = extract_field_values(&l_checked);
        assert_eq!(values[0], "imaging", "entity_b_value");
        assert_eq!(values[1], "3", "amount_bucket");
        assert_eq!(values[2], "charges", "relationship");
        assert_eq!(values[3], "organization", "entity_a_type");
        assert_eq!(values[4], "procedure", "entity_b_type");
        assert_eq!(values[5], "CA", "region");
        assert_eq!(values[6], "2025-Q3", "time_period");
    }

    // ── Multiple encodings differ (randomness) ──────────────────────────

    #[test]
    fn two_encodings_of_same_tuple_differ() {
        let encoder = make_encoder();
        let l1 = default_l_checked(SensitivityTier::S2High);
        let l2 = default_l_checked(SensitivityTier::S2High);
        let r1 = encoder.encode(l1, 10.0).expect("encode should succeed");
        let r2 = encoder.encode(l2, 10.0).expect("encode should succeed");
        // At least one field's bits should differ (with overwhelming probability)
        let any_different = r1
            .oue_vectors
            .iter()
            .zip(r2.oue_vectors.iter())
            .any(|(a, b)| a.bits != b.bits);
        assert!(
            any_different,
            "Two encodings should produce different bit vectors"
        );
    }

    // ── OueEncoder trait usage ──────────────────────────────────────────

    #[test]
    fn trait_object_works() {
        let encoder: Box<dyn OueEncoder> = Box::new(make_encoder());
        let l_checked = default_l_checked(SensitivityTier::S2High);
        let result = encoder.encode(l_checked, 10.0);
        assert!(result.is_some(), "Trait object encoding should work");
    }

    // ── Full-pipeline field epsilon values ───────────────────────────────

    #[test]
    fn per_field_epsilon_s1_entity_b_value() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S1Critical);
        let result = encoder
            .encode(l_checked, 10.0)
            .expect("encode should succeed");
        let ebv = result
            .oue_vectors
            .iter()
            .find(|v| v.field_name == "entity_b_value")
            .unwrap();
        // S1 eps = 1.0, entity_b_value weight = 0.30 -> field eps = 0.30
        assert!(
            (ebv.epsilon - 0.30).abs() < 1e-10,
            "entity_b_value epsilon should be 0.30, got {}",
            ebv.epsilon
        );
    }

    #[test]
    fn per_field_epsilon_s2_amount_bucket() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S2High);
        let result = encoder
            .encode(l_checked, 10.0)
            .expect("encode should succeed");
        let ab = result
            .oue_vectors
            .iter()
            .find(|v| v.field_name == "amount_bucket")
            .unwrap();
        // S2 eps = 2.0, amount_bucket weight = 0.25 -> field eps = 0.50
        assert!(
            (ab.epsilon - 0.50).abs() < 1e-10,
            "amount_bucket epsilon should be 0.50, got {}",
            ab.epsilon
        );
    }

    #[test]
    fn per_field_epsilon_s3_region() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S3Medium);
        let result = encoder
            .encode(l_checked, 10.0)
            .expect("encode should succeed");
        let reg = result
            .oue_vectors
            .iter()
            .find(|v| v.field_name == "region")
            .unwrap();
        // S3 eps = 4.0, region weight = 0.05 -> field eps = 0.20
        assert!(
            (reg.epsilon - 0.20).abs() < 1e-10,
            "region epsilon should be 0.20, got {}",
            reg.epsilon
        );
    }

    #[test]
    fn per_field_epsilon_s4_time_period() {
        let encoder = make_encoder();
        let l_checked = default_l_checked(SensitivityTier::S4Low);
        let result = encoder
            .encode(l_checked, 10.0)
            .expect("encode should succeed");
        let tp = result
            .oue_vectors
            .iter()
            .find(|v| v.field_name == "time_period")
            .unwrap();
        // S4 eps = 8.0, time_period weight = 0.05 -> field eps = 0.40
        assert!(
            (tp.epsilon - 0.40).abs() < 1e-10,
            "time_period epsilon should be 0.40, got {}",
            tp.epsilon
        );
    }
}
