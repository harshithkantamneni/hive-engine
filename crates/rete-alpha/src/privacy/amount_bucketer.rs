//! Stage 2 of the Privacy Pipeline: Amount Bucketer
//!
//! Replaces exact monetary amounts with logarithmic bucket indices (0-7 or 0xFF for N/A).
//! Uses the specified boundaries: $100, $500, $1K, $5K, $10K, $50K, $100K.
//!
//! This module does NOT reuse `tuple_adapter::compute_bucket()` because the old
//! boundaries ($10, $50, $100, $500, $1K, $5K, $50K) differ from the boundaries
//! this stage requires.

use super::types::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default bucket boundaries (upper-exclusive thresholds).
/// A value >= boundaries[i-1] and < boundaries[i] maps to bucket i.
const DEFAULT_BOUNDARIES: [f64; 7] = [
    100.0,     // bucket 0/1 boundary
    500.0,     // bucket 1/2 boundary
    1_000.0,   // bucket 2/3 boundary
    5_000.0,   // bucket 3/4 boundary
    10_000.0,  // bucket 4/5 boundary
    50_000.0,  // bucket 5/6 boundary
    100_000.0, // bucket 6/7 boundary
];

/// Human-readable labels for each bucket index (0-7).
pub const BUCKET_LABELS: [&str; 8] = [
    "$0-$100",
    "$100-$500",
    "$500-$1K",
    "$1K-$5K",
    "$5K-$10K",
    "$10K-$50K",
    "$50K-$100K",
    "$100K+",
];

/// Sentinel value for amounts that are absent, negative, NaN, or unparseable.
pub const BUCKET_NA: u8 = 0xFF;

// ---------------------------------------------------------------------------
// PrivacyConfig stub (minimal subset needed by this module)
// ---------------------------------------------------------------------------

/// Minimal view of the privacy configuration consumed by AmountBucketer.
/// The full `PrivacyConfig` will be defined in `privacy/config.rs`; this
/// struct provides a forward-compatible interface so the bucketer can be
/// constructed from config without depending on the full config module yet.
pub struct PrivacyConfig {
    /// Optional override for bucket boundaries. If empty, the defaults are used.
    pub amount_bucket_boundaries: Vec<f64>,
}

// ---------------------------------------------------------------------------
// AmountBucketer
// ---------------------------------------------------------------------------

/// Stage 2 processor: replaces exact dollar amounts with a bucket index.
///
/// The bucketer holds a sorted list of boundaries. Given an amount `v >= 0`:
///   - bucket = number of boundaries that are <= v (capped at len(boundaries)).
///
/// Special cases:
///   - `None`, `NaN`, negative => `BUCKET_NA` (0xFF)
///   - `0.0` => bucket 0 (valid, falls in $0-$100 range)
pub struct AmountBucketer {
    boundaries: Vec<f64>,
}

impl AmountBucketer {
    /// Construct from a `PrivacyConfig`. Uses config-provided boundaries if
    /// non-empty, otherwise falls back to the defaults.
    pub fn new(config: &PrivacyConfig) -> Self {
        if config.amount_bucket_boundaries.is_empty() {
            Self::with_defaults()
        } else {
            AmountBucketer {
                boundaries: config.amount_bucket_boundaries.clone(),
            }
        }
    }

    /// Construct with the default boundaries.
    pub fn with_defaults() -> Self {
        AmountBucketer {
            boundaries: DEFAULT_BOUNDARIES.to_vec(),
        }
    }

    /// Transform a `PiiStrippedTuple` into a `BucketedTuple`.
    ///
    /// All fields except `amount` / `amount_bucket` are copied unchanged.
    /// The exact amount is replaced by its bucket index.
    pub fn bucket(&self, stripped: PiiStrippedTuple) -> BucketedTuple {
        let amount_bucket = self.compute_bucket(stripped.amount);

        BucketedTuple {
            entity_a_type: stripped.entity_a_type,
            entity_a_role: stripped.entity_a_role,
            entity_b_type: stripped.entity_b_type,
            entity_b_value: stripped.entity_b_value,
            entity_b_role: stripped.entity_b_role,
            relation: stripped.relation,
            amount_bucket,
            document_category: stripped.document_category,
            sensitivity_tier: stripped.sensitivity_tier,
            source_region: stripped.source_region,
            time_period: stripped.time_period,
        }
    }

    /// Pure helper: compute the bucket index for an optional amount without
    /// performing the full tuple transformation.
    ///
    /// Returns 0-7 for valid amounts, or `BUCKET_NA` for None/NaN/negative.
    pub fn compute_bucket(&self, amount: Option<f64>) -> u8 {
        match amount {
            None => BUCKET_NA,
            Some(v) if v.is_nan() || v < 0.0 => BUCKET_NA,
            Some(v) => {
                // Linear scan over (at most 7) boundaries.
                // Could use binary search, but 7 comparisons is already O(1).
                let mut bucket: u8 = 0;
                for &boundary in &self.boundaries {
                    if v >= boundary {
                        bucket += 1;
                    } else {
                        break;
                    }
                }
                bucket
            }
        }
    }

    /// Return the human-readable label for a bucket index.
    ///
    /// Returns "N/A" for `BUCKET_NA` and "unknown" for any other out-of-range value.
    pub fn bucket_label(bucket: u8) -> &'static str {
        if bucket == BUCKET_NA {
            "N/A"
        } else if (bucket as usize) < BUCKET_LABELS.len() {
            BUCKET_LABELS[bucket as usize]
        } else {
            "unknown"
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal `PiiStrippedTuple` with the given amount.
    fn make_stripped(amount: Option<f64>) -> PiiStrippedTuple {
        PiiStrippedTuple {
            entity_a_type: "organization".into(),
            entity_a_role: "provider".into(),
            entity_b_type: "procedure".into(),
            entity_b_value: "office_visit".into(),
            entity_b_role: "charge".into(),
            relation: "charges".into(),
            amount,
            document_category: "medical_bill".into(),
            sensitivity_tier: SensitivityTier::S1Critical,
            source_region: "US-Northeast".into(),
            time_period: "2026-Q1".into(),
        }
    }

    fn bucketer() -> AmountBucketer {
        AmountBucketer::with_defaults()
    }

    // -----------------------------------------------------------------------
    // Bucket 0: $0 - $100 (< $100)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bucket_0_zero() {
        assert_eq!(bucketer().compute_bucket(Some(0.0)), 0);
    }

    #[test]
    fn test_bucket_0_small_amount() {
        assert_eq!(bucketer().compute_bucket(Some(0.01)), 0);
    }

    #[test]
    fn test_bucket_0_just_below_boundary() {
        assert_eq!(bucketer().compute_bucket(Some(99.99)), 0);
    }

    // -----------------------------------------------------------------------
    // Bucket 1: $100 - $500 (>= $100, < $500)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bucket_1_exact_boundary() {
        assert_eq!(bucketer().compute_bucket(Some(100.0)), 1);
    }

    #[test]
    fn test_bucket_1_just_above_boundary() {
        assert_eq!(bucketer().compute_bucket(Some(100.01)), 1);
    }

    #[test]
    fn test_bucket_1_mid_range() {
        assert_eq!(bucketer().compute_bucket(Some(250.0)), 1);
    }

    // -----------------------------------------------------------------------
    // Bucket 2: $500 - $1,000 (>= $500, < $1,000)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bucket_2_exact_boundary() {
        assert_eq!(bucketer().compute_bucket(Some(500.0)), 2);
    }

    #[test]
    fn test_bucket_2_mid_range() {
        assert_eq!(bucketer().compute_bucket(Some(750.0)), 2);
    }

    // -----------------------------------------------------------------------
    // Bucket 3: $1,000 - $5,000 (>= $1,000, < $5,000)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bucket_3_exact_boundary() {
        assert_eq!(bucketer().compute_bucket(Some(1_000.0)), 3);
    }

    #[test]
    fn test_bucket_3_just_below_next() {
        assert_eq!(bucketer().compute_bucket(Some(4_999.99)), 3);
    }

    // -----------------------------------------------------------------------
    // Bucket 4: $5,000 - $10,000 (>= $5,000, < $10,000)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bucket_4_exact_boundary() {
        assert_eq!(bucketer().compute_bucket(Some(5_000.0)), 4);
    }

    #[test]
    fn test_bucket_4_boundary_precision() {
        // $4,999.99 should be bucket 3, $5,000.00 should be bucket 4
        assert_eq!(bucketer().compute_bucket(Some(4_999.99)), 3);
        assert_eq!(bucketer().compute_bucket(Some(5_000.00)), 4);
    }

    // -----------------------------------------------------------------------
    // Bucket 5: $10,000 - $50,000 (>= $10,000, < $50,000)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bucket_5_exact_boundary() {
        assert_eq!(bucketer().compute_bucket(Some(10_000.0)), 5);
    }

    #[test]
    fn test_bucket_5_mid_range() {
        assert_eq!(bucketer().compute_bucket(Some(25_000.0)), 5);
    }

    // -----------------------------------------------------------------------
    // Bucket 6: $50,000 - $100,000 (>= $50,000, < $100,000)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bucket_6_exact_boundary() {
        assert_eq!(bucketer().compute_bucket(Some(50_000.0)), 6);
    }

    #[test]
    fn test_bucket_6_mid_range() {
        assert_eq!(bucketer().compute_bucket(Some(75_000.0)), 6);
    }

    // -----------------------------------------------------------------------
    // Bucket 7: $100,000+ (>= $100,000)
    // -----------------------------------------------------------------------

    #[test]
    fn test_bucket_7_exact_boundary() {
        assert_eq!(bucketer().compute_bucket(Some(100_000.0)), 7);
    }

    #[test]
    fn test_bucket_7_very_large() {
        assert_eq!(bucketer().compute_bucket(Some(1_000_000.0)), 7);
    }

    // -----------------------------------------------------------------------
    // N/A cases (0xFF)
    // -----------------------------------------------------------------------

    #[test]
    fn test_none_amount() {
        assert_eq!(bucketer().compute_bucket(None), BUCKET_NA);
    }

    #[test]
    fn test_nan_amount() {
        assert_eq!(bucketer().compute_bucket(Some(f64::NAN)), BUCKET_NA);
    }

    #[test]
    fn test_negative_amount() {
        assert_eq!(bucketer().compute_bucket(Some(-1.0)), BUCKET_NA);
    }

    #[test]
    fn test_large_negative_amount() {
        assert_eq!(bucketer().compute_bucket(Some(-500.0)), BUCKET_NA);
    }

    #[test]
    fn test_negative_infinity() {
        assert_eq!(
            bucketer().compute_bucket(Some(f64::NEG_INFINITY)),
            BUCKET_NA
        );
    }

    #[test]
    fn test_positive_infinity() {
        // +Infinity is a valid large number, should land in bucket 7
        assert_eq!(bucketer().compute_bucket(Some(f64::INFINITY)), 7);
    }

    // -----------------------------------------------------------------------
    // Bucket labels
    // -----------------------------------------------------------------------

    #[test]
    fn test_bucket_labels_all() {
        assert_eq!(AmountBucketer::bucket_label(0), "$0-$100");
        assert_eq!(AmountBucketer::bucket_label(1), "$100-$500");
        assert_eq!(AmountBucketer::bucket_label(2), "$500-$1K");
        assert_eq!(AmountBucketer::bucket_label(3), "$1K-$5K");
        assert_eq!(AmountBucketer::bucket_label(4), "$5K-$10K");
        assert_eq!(AmountBucketer::bucket_label(5), "$10K-$50K");
        assert_eq!(AmountBucketer::bucket_label(6), "$50K-$100K");
        assert_eq!(AmountBucketer::bucket_label(7), "$100K+");
    }

    #[test]
    fn test_bucket_label_na() {
        assert_eq!(AmountBucketer::bucket_label(BUCKET_NA), "N/A");
    }

    #[test]
    fn test_bucket_label_unknown() {
        assert_eq!(AmountBucketer::bucket_label(8), "unknown");
        assert_eq!(AmountBucketer::bucket_label(200), "unknown");
    }

    // -----------------------------------------------------------------------
    // Full tuple transformation: field pass-through
    // -----------------------------------------------------------------------

    #[test]
    fn test_bucket_tuple_fields_pass_through() {
        let b = bucketer();
        let stripped = make_stripped(Some(2_500.0));
        let bucketed = b.bucket(stripped);

        assert_eq!(bucketed.entity_a_type, "organization");
        assert_eq!(bucketed.entity_a_role, "provider");
        assert_eq!(bucketed.entity_b_type, "procedure");
        assert_eq!(bucketed.entity_b_value, "office_visit");
        assert_eq!(bucketed.entity_b_role, "charge");
        assert_eq!(bucketed.relation, "charges");
        assert_eq!(bucketed.amount_bucket, 3); // $2,500 -> bucket 3 ($1K-$5K)
        assert_eq!(bucketed.document_category, "medical_bill");
        assert_eq!(bucketed.sensitivity_tier, SensitivityTier::S1Critical);
        assert_eq!(bucketed.source_region, "US-Northeast");
        assert_eq!(bucketed.time_period, "2026-Q1");
    }

    #[test]
    fn test_bucket_tuple_none_amount() {
        let b = bucketer();
        let stripped = make_stripped(None);
        let bucketed = b.bucket(stripped);
        assert_eq!(bucketed.amount_bucket, BUCKET_NA);
    }

    // -----------------------------------------------------------------------
    // Constructor: from config
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_with_empty_config_uses_defaults() {
        let config = PrivacyConfig {
            amount_bucket_boundaries: vec![],
        };
        let b = AmountBucketer::new(&config);
        assert_eq!(b.compute_bucket(Some(99.99)), 0);
        assert_eq!(b.compute_bucket(Some(100.0)), 1);
    }

    #[test]
    fn test_new_with_custom_boundaries() {
        let config = PrivacyConfig {
            amount_bucket_boundaries: vec![50.0, 200.0],
        };
        let b = AmountBucketer::new(&config);
        assert_eq!(b.compute_bucket(Some(25.0)), 0); // < 50
        assert_eq!(b.compute_bucket(Some(50.0)), 1); // >= 50, < 200
        assert_eq!(b.compute_bucket(Some(200.0)), 2); // >= 200
    }

    // -----------------------------------------------------------------------
    // Verify new boundaries differ from old tuple_adapter boundaries
    // -----------------------------------------------------------------------

    #[test]
    fn test_p6_boundaries_differ_from_old() {
        let b = bucketer();
        // Old boundary: $10 was bucket 0/1 split.
        // New: $10 is still bucket 0 (< $100).
        assert_eq!(b.compute_bucket(Some(10.0)), 0);

        // Old boundary: $50 was bucket 1/2 split.
        // New: $50 is still bucket 0 (< $100).
        assert_eq!(b.compute_bucket(Some(50.0)), 0);

        // Old: $100 -> bucket 3. New: $100 -> bucket 1.
        assert_eq!(b.compute_bucket(Some(100.0)), 1);

        // Old: $10,000 -> bucket 6 ($5K-$50K). New: $10,000 -> bucket 5 ($10K-$50K).
        assert_eq!(b.compute_bucket(Some(10_000.0)), 5);
    }
}
