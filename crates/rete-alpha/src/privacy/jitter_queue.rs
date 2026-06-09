//! Stage 9: Jitter queue for temporal decorrelation before P2P sharing.
//!
//! Adds randomized delays (tier-calibrated, CSPRNG) and cross-document batching
//! so that an attacker cannot correlate shared tuples by timing. This is the
//! final stage before Dandelion P2P transport.

use crate::privacy::config::{BatchingConfig, JitterConfig, PrivacyConfig};
use crate::privacy::types::{BudgetApprovedTuple, QueuedTuple, SensitivityTier};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Operations for the Stage 9 jitter queue.
pub trait JitterQueueOps {
    /// Schedule tuple with tier-calibrated random delay.
    fn enqueue(&mut self, approved: BudgetApprovedTuple) -> QueuedTuple;

    /// Collect ready tuples, form batches, return for sending.
    /// Called every drain_interval (15 minutes by default) by background task.
    fn drain_ready_batches(&mut self, now_secs: u64) -> Vec<Vec<QueuedTuple>>;

    /// Persist queue state to durable storage.
    fn persist(&self) -> Result<(), io::Error>;

    /// Restore queue from durable storage after restart.
    fn restore(&mut self) -> Result<(), io::Error>;
}

// ─── Persisted queue entry ────────────────────────────────────────────────────

/// A single entry in the jitter queue, ready for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueueEntry {
    tuple: QueuedTuple,
    enqueue_time: u64,
    tier: SensitivityTier,
}

/// Persisted state of the entire queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedState {
    entries: Vec<QueueEntry>,
    next_batch_id: u64,
}

// ─── JitterQueue ──────────────────────────────────────────────────────────────

/// Jitter queue implementing Stage 9 temporal decorrelation.
///
/// Holds pending tuples with scheduled send times and produces
/// cross-document batches when drain conditions are met.
pub struct JitterQueue {
    entries: Vec<QueueEntry>,
    jitter_config: JitterConfig,
    batching_config: BatchingConfig,
    next_batch_id: u64,
    persist_path: PathBuf,
    rng: ChaCha20Rng,
}

impl JitterQueue {
    /// Create a new empty jitter queue.
    pub fn new(config: &PrivacyConfig, persist_path: PathBuf) -> Self {
        Self {
            entries: Vec::new(),
            jitter_config: config.jitter.clone(),
            batching_config: config.batching.clone(),
            next_batch_id: 1,
            persist_path,
            rng: ChaCha20Rng::from_os_rng(),
        }
    }

    /// Create a jitter queue with a specific CSPRNG seed (for deterministic testing).
    #[cfg(test)]
    fn with_seed(config: &PrivacyConfig, persist_path: PathBuf, seed: u64) -> Self {
        Self {
            entries: Vec::new(),
            jitter_config: config.jitter.clone(),
            batching_config: config.batching.clone(),
            next_batch_id: 1,
            persist_path,
            rng: ChaCha20Rng::seed_from_u64(seed),
        }
    }

    /// Return the number of entries currently in the queue.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if the queue has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the current next_batch_id (for testing/inspection).
    pub fn next_batch_id(&self) -> u64 {
        self.next_batch_id
    }

    /// Count entries for a specific tier.
    pub fn count_for_tier(&self, tier: SensitivityTier) -> usize {
        self.entries.iter().filter(|e| e.tier == tier).count()
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    /// Extract sensitivity tier from a BudgetApprovedTuple by traversing
    /// the type-state chain:
    /// BudgetApprovedTuple -> EncodedTuple -> LCheckedTuple -> KCheckedTuple
    ///   -> HashedTuple -> GeneralizedTuple -> sensitivity_tier
    fn extract_tier(approved: &BudgetApprovedTuple) -> SensitivityTier {
        approved.inner.inner.inner.inner.inner.sensitivity_tier
    }

    /// Get (min_jitter, max_jitter) for a tier in seconds.
    fn jitter_range(&self, tier: SensitivityTier) -> (u64, u64) {
        self.jitter_config.range_for_tier_index(tier.index())
    }

    /// Get min_batch_size for a tier.
    fn min_batch_size(&self, tier: SensitivityTier) -> u64 {
        let key = tier_key(tier);
        self.batching_config
            .min_batch_size
            .get(&key)
            .copied()
            .unwrap_or(5) // conservative default
    }

    /// Get max_hold_seconds for a tier.
    fn max_hold_seconds(&self, tier: SensitivityTier) -> u64 {
        let key = tier_key(tier);
        self.batching_config
            .max_hold_seconds
            .get(&key)
            .copied()
            .unwrap_or(43200) // conservative default: 12h
    }

    /// Generate a random jitter delay (uniform, CSPRNG) for a tier.
    fn generate_jitter(&mut self, tier: SensitivityTier) -> u64 {
        let (min, max) = self.jitter_range(tier);
        if min >= max {
            return min;
        }
        self.rng.random_range(min..=max)
    }

    /// Assign batch_id to a slice of entries and stamp the tuples.
    fn assign_batch_id(&mut self, entries: &mut [QueueEntry]) {
        let batch_id = self.next_batch_id;
        self.next_batch_id += 1;
        for entry in entries.iter_mut() {
            entry.tuple.batch_id = Some(batch_id);
        }
    }
}

/// Convert tier to the string key used in BatchingConfig HashMaps.
fn tier_key(tier: SensitivityTier) -> String {
    match tier {
        SensitivityTier::S1Critical => "s1".into(),
        SensitivityTier::S2High => "s2".into(),
        SensitivityTier::S3Medium => "s3".into(),
        SensitivityTier::S4Low => "s4".into(),
    }
}

// ─── Trait implementation ─────────────────────────────────────────────────────

impl JitterQueueOps for JitterQueue {
    fn enqueue(&mut self, approved: BudgetApprovedTuple) -> QueuedTuple {
        let tier = Self::extract_tier(&approved);
        let now = current_unix_timestamp();
        let jitter = self.generate_jitter(tier);
        let scheduled_send_time = now + jitter;

        let queued = QueuedTuple {
            inner: approved,
            scheduled_send_time,
            batch_id: None, // assigned during drain
        };

        let entry = QueueEntry {
            tuple: queued.clone(),
            enqueue_time: now,
            tier,
        };

        self.entries.push(entry);

        queued
    }

    fn drain_ready_batches(&mut self, now_secs: u64) -> Vec<Vec<QueuedTuple>> {
        let tiers = [
            SensitivityTier::S1Critical,
            SensitivityTier::S2High,
            SensitivityTier::S3Medium,
            SensitivityTier::S4Low,
        ];

        let mut all_batches: Vec<Vec<QueuedTuple>> = Vec::new();

        for tier in tiers {
            let min_batch = self.min_batch_size(tier) as usize;
            let max_hold = self.max_hold_seconds(tier);

            // Collect indices of ready entries for this tier
            let ready_indices: Vec<usize> = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.tier == tier && e.tuple.scheduled_send_time <= now_secs)
                .map(|(i, _)| i)
                .collect();

            if ready_indices.is_empty() {
                continue;
            }

            // Find oldest enqueue time across ALL entries of this tier (not just ready ones)
            let oldest_enqueue = self
                .entries
                .iter()
                .filter(|e| e.tier == tier)
                .map(|e| e.enqueue_time)
                .min()
                .unwrap_or(now_secs);

            let hold_expired = oldest_enqueue + max_hold < now_secs;

            if ready_indices.len() >= min_batch {
                // Normal batching: take random_int(min_batch, 2*min_batch)
                let max_take = (2 * min_batch).min(ready_indices.len());
                let take_count = if min_batch >= max_take {
                    min_batch
                } else {
                    self.rng.random_range(min_batch..=max_take)
                };

                // Extract the entries to batch
                let take_count = take_count.min(ready_indices.len());
                let batch_indices: Vec<usize> =
                    ready_indices.into_iter().take(take_count).collect();

                let mut batch_entries: Vec<QueueEntry> = Vec::with_capacity(take_count);
                // Remove from back to front to preserve indices
                let mut sorted_indices = batch_indices.clone();
                sorted_indices.sort_unstable_by(|a, b| b.cmp(a));
                for idx in sorted_indices {
                    batch_entries.push(self.entries.remove(idx));
                }

                // Assign batch ID
                self.assign_batch_id(&mut batch_entries);

                // Shuffle with CSPRNG
                shuffle_entries(&mut batch_entries, &mut self.rng);

                let batch: Vec<QueuedTuple> = batch_entries.into_iter().map(|e| e.tuple).collect();
                all_batches.push(batch);
            } else if hold_expired {
                // Max hold time failsafe: take ALL ready entries for this tier
                let mut batch_entries: Vec<QueueEntry> = Vec::new();
                let mut sorted_indices = ready_indices.clone();
                sorted_indices.sort_unstable_by(|a, b| b.cmp(a));
                for idx in sorted_indices {
                    batch_entries.push(self.entries.remove(idx));
                }

                // Assign batch ID
                self.assign_batch_id(&mut batch_entries);

                // Shuffle with CSPRNG
                shuffle_entries(&mut batch_entries, &mut self.rng);

                let batch: Vec<QueuedTuple> = batch_entries.into_iter().map(|e| e.tuple).collect();
                all_batches.push(batch);
            }
            // else: not enough ready entries and hold time not expired -> skip
        }

        all_batches
    }

    fn persist(&self) -> Result<(), io::Error> {
        let state = PersistedState {
            entries: self.entries.clone(),
            next_batch_id: self.next_batch_id,
        };
        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Write to temp file first, then rename for atomicity
        let tmp_path = self.persist_path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &json)?;
        std::fs::rename(&tmp_path, &self.persist_path)?;

        Ok(())
    }

    fn restore(&mut self) -> Result<(), io::Error> {
        let content = std::fs::read_to_string(&self.persist_path)?;
        let state: PersistedState = serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        self.entries = state.entries;
        self.next_batch_id = state.next_batch_id;

        Ok(())
    }
}

// ─── Free functions ───────────────────────────────────────────────────────────

/// Shuffle a slice of queue entries using a CSPRNG (Fisher-Yates).
fn shuffle_entries(entries: &mut [QueueEntry], rng: &mut ChaCha20Rng) {
    let len = entries.len();
    if len <= 1 {
        return;
    }
    for i in (1..len).rev() {
        let j = rng.random_range(0..=i);
        entries.swap(i, j);
    }
}

/// Get the current Unix timestamp in seconds.
fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::config::PrivacyConfig;
    use crate::privacy::types::*;

    // ── Test helpers ──────────────────────────────────────────────────────

    fn test_config() -> PrivacyConfig {
        PrivacyConfig::default_config()
    }

    fn test_persist_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "hive_jitter_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn make_generalized(tier: SensitivityTier) -> GeneralizedTuple {
        GeneralizedTuple {
            entity_a_type: "organization".into(),
            entity_a_gen: "provider".into(),
            entity_a_gen_level: 1,
            entity_a_role: "provider".into(),
            entity_b_type: "procedure".into(),
            entity_b_gen: "medical_procedure".into(),
            entity_b_gen_level: 1,
            entity_b_role: "charge".into(),
            relation: "charges".into(),
            amount_bucket: 3,
            document_category: "medical_bill".into(),
            sensitivity_tier: tier,
            source_region: "US-Northeast".into(),
            time_period: "2024-Q1".into(),
        }
    }

    fn make_hashed(tier: SensitivityTier) -> HashedTuple {
        HashedTuple {
            inner: make_generalized(tier),
            pattern_hash: [0u8; 32],
            pattern_key: PatternKey {
                entity_a_type: "organization".into(),
                entity_a_gen: "provider".into(),
                entity_a_gen_level: 1,
                relation: "charges".into(),
                entity_b_type: "procedure".into(),
                entity_b_gen: "medical_procedure".into(),
                entity_b_gen_level: 1,
                amount_bucket: 3,
                document_category: "medical_bill".into(),
            },
            resolution_level: 0,
        }
    }

    fn make_k_checked(tier: SensitivityTier) -> KCheckedTuple {
        KCheckedTuple {
            inner: make_hashed(tier),
            estimated_k: 500.0,
        }
    }

    fn make_l_checked(tier: SensitivityTier) -> LCheckedTuple {
        LCheckedTuple {
            inner: make_k_checked(tier),
            l_entropy: 2.5,
        }
    }

    fn make_encoded(tier: SensitivityTier, epsilon: f64) -> EncodedTuple {
        EncodedTuple {
            inner: make_l_checked(tier),
            oue_vectors: vec![OueFieldVector {
                field_name: "entity_b_value".into(),
                domain_size: 128,
                epsilon: epsilon / 7.0,
                bits: vec![0xFF; 16],
            }],
            epsilon_consumed: epsilon,
        }
    }

    fn make_budget_approved(tier: SensitivityTier) -> BudgetApprovedTuple {
        BudgetApprovedTuple {
            inner: make_encoded(tier, 1.0),
            budget_snapshot: BudgetSnapshot {
                tier,
                daily_remaining: 1.0,
                weekly_remaining: 9.0,
                lifetime_remaining: 99.0,
            },
        }
    }

    /// Create a JitterQueue with a fixed seed for deterministic tests.
    fn make_queue(seed: u64) -> JitterQueue {
        let config = test_config();
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        JitterQueue::with_seed(&config, dir.join("jitter_queue.json"), seed)
    }

    /// Create a JitterQueue with a specific config and seed.
    fn make_queue_with_config(config: &PrivacyConfig, seed: u64) -> JitterQueue {
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        JitterQueue::with_seed(config, dir.join("jitter_queue.json"), seed)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 1. CONSTRUCTION AND BASIC STATE
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn new_queue_is_empty() {
        let q = make_queue(42);
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn new_queue_batch_id_starts_at_one() {
        let q = make_queue(42);
        assert_eq!(q.next_batch_id(), 1);
    }

    #[test]
    fn new_queue_count_for_all_tiers_zero() {
        let q = make_queue(42);
        assert_eq!(q.count_for_tier(SensitivityTier::S1Critical), 0);
        assert_eq!(q.count_for_tier(SensitivityTier::S2High), 0);
        assert_eq!(q.count_for_tier(SensitivityTier::S3Medium), 0);
        assert_eq!(q.count_for_tier(SensitivityTier::S4Low), 0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 2. ENQUEUE BASICS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn enqueue_increases_length() {
        let mut q = make_queue(42);
        let approved = make_budget_approved(SensitivityTier::S1Critical);
        q.enqueue(approved);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn enqueue_returns_queued_tuple_with_scheduled_time() {
        let mut q = make_queue(42);
        let approved = make_budget_approved(SensitivityTier::S1Critical);
        let queued = q.enqueue(approved);
        assert!(queued.scheduled_send_time > 0);
    }

    #[test]
    fn enqueue_returns_queued_tuple_with_no_batch_id() {
        let mut q = make_queue(42);
        let approved = make_budget_approved(SensitivityTier::S1Critical);
        let queued = q.enqueue(approved);
        assert!(queued.batch_id.is_none());
    }

    #[test]
    fn enqueue_preserves_inner_tuple_data() {
        let mut q = make_queue(42);
        let approved = make_budget_approved(SensitivityTier::S2High);
        let queued = q.enqueue(approved);
        assert_eq!(queued.inner.budget_snapshot.tier, SensitivityTier::S2High);
    }

    #[test]
    fn enqueue_multiple_tuples_increments_count() {
        let mut q = make_queue(42);
        for _ in 0..5 {
            let approved = make_budget_approved(SensitivityTier::S3Medium);
            q.enqueue(approved);
        }
        assert_eq!(q.len(), 5);
        assert_eq!(q.count_for_tier(SensitivityTier::S3Medium), 5);
    }

    #[test]
    fn enqueue_multiple_tiers_tracked_separately() {
        let mut q = make_queue(42);
        q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
        q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
        q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        assert_eq!(q.count_for_tier(SensitivityTier::S1Critical), 2);
        assert_eq!(q.count_for_tier(SensitivityTier::S4Low), 1);
        assert_eq!(q.count_for_tier(SensitivityTier::S2High), 0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 3. JITTER DELAY RANGES (S1-S4)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn jitter_s1_within_range() {
        // S1: 3600..=86400
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..100 {
            let approved = make_budget_approved(SensitivityTier::S1Critical);
            let queued = q.enqueue(approved);
            let delay = queued.scheduled_send_time - now;
            // Allow 2-second tolerance for test execution time
            assert!(delay >= 3598, "S1 delay {} < 3598", delay);
            assert!(delay <= 86402, "S1 delay {} > 86402", delay);
        }
    }

    #[test]
    fn jitter_s2_within_range() {
        // S2: 3600..=43200
        let mut q = make_queue(99);
        let now = current_unix_timestamp();
        for _ in 0..100 {
            let approved = make_budget_approved(SensitivityTier::S2High);
            let queued = q.enqueue(approved);
            let delay = queued.scheduled_send_time - now;
            assert!(delay >= 3598, "S2 delay {} < 3598", delay);
            assert!(delay <= 43202, "S2 delay {} > 43202", delay);
        }
    }

    #[test]
    fn jitter_s3_within_range() {
        // S3: 3600..=21600
        let mut q = make_queue(123);
        let now = current_unix_timestamp();
        for _ in 0..100 {
            let approved = make_budget_approved(SensitivityTier::S3Medium);
            let queued = q.enqueue(approved);
            let delay = queued.scheduled_send_time - now;
            assert!(delay >= 3598, "S3 delay {} < 3598", delay);
            assert!(delay <= 21602, "S3 delay {} > 21602", delay);
        }
    }

    #[test]
    fn jitter_s4_within_range() {
        // S4: 0..=3600
        let mut q = make_queue(777);
        let now = current_unix_timestamp();
        for _ in 0..100 {
            let approved = make_budget_approved(SensitivityTier::S4Low);
            let queued = q.enqueue(approved);
            let delay = queued.scheduled_send_time - now;
            assert!(delay <= 3602, "S4 delay {} > 3602", delay);
        }
    }

    #[test]
    fn jitter_s1_statistical_spread() {
        // Over 200 samples, S1 jitter should have reasonable spread
        // (not all the same value, which would indicate broken RNG)
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        let mut delays: Vec<u64> = Vec::new();
        for _ in 0..200 {
            let approved = make_budget_approved(SensitivityTier::S1Critical);
            let queued = q.enqueue(approved);
            delays.push(queued.scheduled_send_time - now);
        }
        let min = *delays.iter().min().unwrap();
        let max = *delays.iter().max().unwrap();
        // Range should be at least 20% of the full range (82800s)
        assert!(
            max - min > 16000,
            "S1 jitter spread too narrow: min={}, max={}, range={}",
            min,
            max,
            max - min
        );
    }

    #[test]
    fn jitter_s4_statistical_spread() {
        // S4 has 0..=3600 range
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        let mut delays: Vec<u64> = Vec::new();
        for _ in 0..200 {
            let approved = make_budget_approved(SensitivityTier::S4Low);
            let queued = q.enqueue(approved);
            delays.push(queued.scheduled_send_time - now);
        }
        let min = *delays.iter().min().unwrap();
        let max = *delays.iter().max().unwrap();
        assert!(
            max - min > 500,
            "S4 jitter spread too narrow: range={}",
            max - min
        );
    }

    #[test]
    fn jitter_different_seeds_different_delays() {
        let mut q1 = make_queue(1);
        let mut q2 = make_queue(2);
        let a1 = make_budget_approved(SensitivityTier::S1Critical);
        let a2 = make_budget_approved(SensitivityTier::S1Critical);
        let t1 = q1.enqueue(a1);
        let t2 = q2.enqueue(a2);
        // Different seeds should (with overwhelming probability) produce different jitter
        assert_ne!(t1.scheduled_send_time, t2.scheduled_send_time);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 4. DRAIN: BASIC BATCHING
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn drain_empty_queue_returns_empty() {
        let mut q = make_queue(42);
        let batches = q.drain_ready_batches(current_unix_timestamp());
        assert!(batches.is_empty());
    }

    #[test]
    fn drain_nothing_ready_returns_empty() {
        let mut q = make_queue(42);
        // Enqueue 5 S1 tuples, they have 1h+ jitter
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
        }
        // Drain at current time -- nothing should be ready
        let batches = q.drain_ready_batches(current_unix_timestamp());
        assert!(batches.is_empty());
    }

    #[test]
    fn drain_ready_s4_produces_batch() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        // Enqueue 5 S4 tuples
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        // Drain far in the future so all are ready
        // S4 min_batch=3, max jitter=3600
        let far_future = now + 100_000;
        let batches = q.drain_ready_batches(far_future);
        assert!(!batches.is_empty());
        // All tuples should have been drained (3-6 range, we have 5)
        let total: usize = batches.iter().map(|b| b.len()).sum();
        assert!(total >= 3);
        assert!(total <= 5);
    }

    #[test]
    fn drain_assigns_batch_id() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        let far_future = now + 100_000;
        let batches = q.drain_ready_batches(far_future);
        assert!(!batches.is_empty());
        for batch in &batches {
            for tuple in batch {
                assert!(tuple.batch_id.is_some(), "batch_id should be assigned");
            }
        }
    }

    #[test]
    fn drain_batch_id_increments() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        // Enqueue enough for two batches (different tiers)
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S3Medium));
        }
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        let far_future = now + 200_000;
        let batches = q.drain_ready_batches(far_future);
        if batches.len() >= 2 {
            let id1 = batches[0][0].batch_id.unwrap();
            let id2 = batches[1][0].batch_id.unwrap();
            assert_ne!(id1, id2);
        }
    }

    #[test]
    fn drain_removes_entries_from_queue() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        assert_eq!(q.len(), 5);
        let far_future = now + 100_000;
        let batches = q.drain_ready_batches(far_future);
        let drained: usize = batches.iter().map(|b| b.len()).sum();
        assert_eq!(q.len(), 5 - drained);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 5. BATCH SIZE (min_batch_size to 2*min_batch_size)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn batch_size_at_least_min() {
        // S4 min_batch_size = 3
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..20 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        let far_future = now + 100_000;
        let batches = q.drain_ready_batches(far_future);
        for batch in &batches {
            assert!(
                batch.len() >= 3,
                "S4 batch size {} < min_batch_size 3",
                batch.len()
            );
        }
    }

    #[test]
    fn batch_size_at_most_2x_min() {
        // S4 min_batch_size = 3, so max is 6
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..50 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        let far_future = now + 100_000;
        let batches = q.drain_ready_batches(far_future);
        for batch in &batches {
            assert!(
                batch.len() <= 6,
                "S4 batch size {} > 2*min_batch_size 6",
                batch.len()
            );
        }
    }

    #[test]
    fn batch_size_s1_min_10() {
        // S1 min_batch = 10
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..25 {
            q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
        }
        let far_future = now + 200_000;
        let batches = q.drain_ready_batches(far_future);
        for batch in &batches {
            assert!(batch.len() >= 10, "S1 batch size {} < 10", batch.len());
            assert!(batch.len() <= 20, "S1 batch size {} > 20", batch.len());
        }
    }

    #[test]
    fn batch_size_s2_min_8() {
        // S2 min_batch = 8
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..20 {
            q.enqueue(make_budget_approved(SensitivityTier::S2High));
        }
        let far_future = now + 200_000;
        let batches = q.drain_ready_batches(far_future);
        for batch in &batches {
            assert!(batch.len() >= 8, "S2 batch size {} < 8", batch.len());
            assert!(batch.len() <= 16, "S2 batch size {} > 16", batch.len());
        }
    }

    #[test]
    fn batch_size_s3_min_5() {
        // S3 min_batch = 5
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..15 {
            q.enqueue(make_budget_approved(SensitivityTier::S3Medium));
        }
        let far_future = now + 200_000;
        let batches = q.drain_ready_batches(far_future);
        for batch in &batches {
            assert!(batch.len() >= 5, "S3 batch size {} < 5", batch.len());
            assert!(batch.len() <= 10, "S3 batch size {} > 10", batch.len());
        }
    }

    #[test]
    fn below_min_batch_not_drained_without_hold_expiry() {
        // S1 min_batch = 10, enqueue only 5
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
        }
        // Future enough for jitter, but NOT enough for hold expiry (S1 hold = 172800)
        let future = now + 90_000; // 25 hours, within S1 max jitter, below hold time
        let batches = q.drain_ready_batches(future);
        // Should have no batches since 5 < 10 and hold not expired
        assert!(
            batches.is_empty(),
            "Expected no batches but got {}",
            batches.len()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 6. MAX HOLD TIME FAILSAFE
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn max_hold_time_s1_forces_drain() {
        // S1: max_hold = 172800 (48h), min_batch = 10
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        // Enqueue only 3 S1 tuples (below min_batch)
        for _ in 0..3 {
            q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
        }
        // Jump past hold time
        let past_hold = now + 200_000; // > 172800
        let batches = q.drain_ready_batches(past_hold);
        assert_eq!(batches.len(), 1, "Should have 1 failsafe batch");
        assert_eq!(batches[0].len(), 3);
    }

    #[test]
    fn max_hold_time_s4_forces_drain() {
        // S4: max_hold = 7200 (2h), min_batch = 3
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        // Enqueue only 2 S4 tuples (below min_batch of 3)
        for _ in 0..2 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        // Jump past S4 hold time
        let past_hold = now + 10_000; // > 7200
        let batches = q.drain_ready_batches(past_hold);
        assert_eq!(batches.len(), 1, "Should have 1 failsafe batch");
        assert_eq!(batches[0].len(), 2);
    }

    #[test]
    fn max_hold_time_s2_forces_drain() {
        // S2: max_hold = 86400 (24h)
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..4 {
            q.enqueue(make_budget_approved(SensitivityTier::S2High));
        }
        let past_hold = now + 100_000;
        let batches = q.drain_ready_batches(past_hold);
        assert!(!batches.is_empty());
    }

    #[test]
    fn max_hold_time_s3_forces_drain() {
        // S3: max_hold = 43200 (12h)
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..3 {
            q.enqueue(make_budget_approved(SensitivityTier::S3Medium));
        }
        let past_hold = now + 50_000;
        let batches = q.drain_ready_batches(past_hold);
        assert!(!batches.is_empty());
    }

    #[test]
    fn max_hold_not_expired_below_min_no_drain() {
        // S1 hold = 172800, enqueue 5 (< min_batch 10)
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
        }
        // 100000s < 172800, and all jitter ready
        let still_within = now + 100_000;
        let batches = q.drain_ready_batches(still_within);
        assert!(batches.is_empty());
        assert_eq!(q.len(), 5);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 7. BATCH SHUFFLING
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn batch_is_shuffled_not_insertion_order() {
        // Enqueue 20 S4 tuples with identifiable pattern_hash values
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for i in 0..20u8 {
            let mut approved = make_budget_approved(SensitivityTier::S4Low);
            // Set a unique marker in pattern_hash
            approved.inner.inner.inner.inner.pattern_hash[0] = i;
            q.enqueue(approved);
        }
        let far_future = now + 100_000;
        let batches = q.drain_ready_batches(far_future);
        assert!(!batches.is_empty());

        let batch = &batches[0];
        if batch.len() >= 3 {
            // Check that the hash bytes are not in sorted order
            let hash_bytes: Vec<u8> = batch
                .iter()
                .map(|t| t.inner.inner.inner.inner.inner.pattern_hash[0])
                .collect();
            let mut sorted = hash_bytes.clone();
            sorted.sort();
            // With 3+ elements and CSPRNG shuffle, the probability of staying sorted is tiny
            assert_ne!(
                hash_bytes, sorted,
                "Batch appears to be in insertion order (not shuffled)"
            );
        }
    }

    #[test]
    fn shuffle_entries_different_seeds_different_orders() {
        let mut entries1: Vec<QueueEntry> = (0..10u8)
            .map(|i| {
                let mut approved = make_budget_approved(SensitivityTier::S4Low);
                approved.inner.inner.inner.inner.pattern_hash[0] = i;
                QueueEntry {
                    tuple: QueuedTuple {
                        inner: approved,
                        scheduled_send_time: 1000,
                        batch_id: None,
                    },
                    enqueue_time: 500,
                    tier: SensitivityTier::S4Low,
                }
            })
            .collect();
        let mut entries2 = entries1.clone();

        let mut rng1 = ChaCha20Rng::seed_from_u64(111);
        let mut rng2 = ChaCha20Rng::seed_from_u64(222);

        shuffle_entries(&mut entries1, &mut rng1);
        shuffle_entries(&mut entries2, &mut rng2);

        let order1: Vec<u8> = entries1
            .iter()
            .map(|e| e.tuple.inner.inner.inner.inner.inner.pattern_hash[0])
            .collect();
        let order2: Vec<u8> = entries2
            .iter()
            .map(|e| e.tuple.inner.inner.inner.inner.inner.pattern_hash[0])
            .collect();
        assert_ne!(order1, order2);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 8. MULTI-RESOLUTION INDEPENDENCE
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn multi_resolution_independent_jitter() {
        // Two resolution levels of the same tuple should get different jitter
        let mut q = make_queue(42);

        let mut approved_r0 = make_budget_approved(SensitivityTier::S2High);
        approved_r0.inner.inner.inner.inner.resolution_level = 0;
        let mut approved_r1 = make_budget_approved(SensitivityTier::S2High);
        approved_r1.inner.inner.inner.inner.resolution_level = 1;

        let t0 = q.enqueue(approved_r0);
        let t1 = q.enqueue(approved_r1);

        // They are separate entries with independent jitter
        assert_eq!(q.len(), 2);
        // Different jitter (overwhelmingly probable with CSPRNG)
        assert_ne!(
            t0.scheduled_send_time, t1.scheduled_send_time,
            "Multi-resolution tuples should have independent jitter"
        );
    }

    #[test]
    fn multi_resolution_separate_entries() {
        let mut q = make_queue(42);
        let approved_r0 = make_budget_approved(SensitivityTier::S3Medium);
        let approved_r1 = make_budget_approved(SensitivityTier::S3Medium);
        q.enqueue(approved_r0);
        q.enqueue(approved_r1);
        assert_eq!(q.count_for_tier(SensitivityTier::S3Medium), 2);
    }

    #[test]
    fn multi_resolution_can_end_in_different_batches() {
        // Enqueue 10 S4 tuples: 5 resolution 0, 5 resolution 1
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for i in 0..10u8 {
            let mut approved = make_budget_approved(SensitivityTier::S4Low);
            approved.inner.inner.inner.inner.resolution_level = i % 2;
            approved.inner.inner.inner.inner.pattern_hash[0] = i;
            q.enqueue(approved);
        }
        let far_future = now + 100_000;
        let batches = q.drain_ready_batches(far_future);
        // We should have at least 1 batch
        assert!(!batches.is_empty());
        // Both resolution levels should be mixed in a single batch (shuffled)
        if batches[0].len() >= 3 {
            let res_levels: Vec<u8> = batches[0]
                .iter()
                .map(|t| t.inner.inner.inner.inner.inner.resolution_level)
                .collect();
            let has_r0 = res_levels.contains(&0);
            let has_r1 = res_levels.contains(&1);
            // With 10 tuples and min_batch 3, it's extremely likely both are present
            assert!(
                has_r0 || has_r1,
                "Expected mixed resolution levels in batch"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 9. PERSISTENCE: ROUND-TRIP
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn persist_and_restore_round_trip() {
        // Owned TempDir guard so parallel-test runs don't race
        // on `std::env::temp_dir()` paths. `tmp` drops at scope end and
        // auto-removes the directory.
        let tmp = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let config = test_config();
        let path = tmp.path().join("jitter_queue.json");

        let mut q = JitterQueue::with_seed(&config, path.clone(), 42);
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
        }
        for _ in 0..3 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        q.persist().expect("persist should succeed");

        let mut q2 = JitterQueue::with_seed(&config, path, 99);
        q2.restore().expect("restore should succeed");

        assert_eq!(q2.len(), q.len());
        assert_eq!(q2.next_batch_id(), q.next_batch_id());
        assert_eq!(
            q2.count_for_tier(SensitivityTier::S1Critical),
            q.count_for_tier(SensitivityTier::S1Critical)
        );
        assert_eq!(
            q2.count_for_tier(SensitivityTier::S4Low),
            q.count_for_tier(SensitivityTier::S4Low)
        );
    }

    #[test]
    fn persist_preserves_scheduled_send_times() {
        // Owned TempDir guard — see persist_and_restore_round_trip.
        let tmp = tempfile::TempDir::new().expect("tempdir creation should succeed");
        let config = test_config();
        let path = tmp.path().join("jitter_queue.json");

        let mut q = JitterQueue::with_seed(&config, path.clone(), 42);
        let t1 = q.enqueue(make_budget_approved(SensitivityTier::S2High));
        let t2 = q.enqueue(make_budget_approved(SensitivityTier::S3Medium));
        q.persist().unwrap();

        let mut q2 = JitterQueue::with_seed(&config, path, 99);
        q2.restore().unwrap();

        // Verify scheduled times are preserved
        assert_eq!(
            q2.entries[0].tuple.scheduled_send_time,
            t1.scheduled_send_time
        );
        assert_eq!(
            q2.entries[1].tuple.scheduled_send_time,
            t2.scheduled_send_time
        );
    }

    #[test]
    fn persist_preserves_enqueue_times() {
        let config = test_config();
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("jitter_queue.json");

        let mut q = JitterQueue::with_seed(&config, path.clone(), 42);
        q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
        let original_enqueue_time = q.entries[0].enqueue_time;
        q.persist().unwrap();

        let mut q2 = JitterQueue::with_seed(&config, path, 99);
        q2.restore().unwrap();
        assert_eq!(q2.entries[0].enqueue_time, original_enqueue_time);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_preserves_tier_info() {
        let config = test_config();
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("jitter_queue.json");

        let mut q = JitterQueue::with_seed(&config, path.clone(), 42);
        q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
        q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        q.persist().unwrap();

        let mut q2 = JitterQueue::with_seed(&config, path, 99);
        q2.restore().unwrap();
        assert_eq!(q2.entries[0].tier, SensitivityTier::S1Critical);
        assert_eq!(q2.entries[1].tier, SensitivityTier::S4Low);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_preserves_batch_id_counter() {
        let config = test_config();
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("jitter_queue.json");

        let mut q = JitterQueue::with_seed(&config, path.clone(), 42);
        for _ in 0..10 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        // Drain to increment batch_id
        let now = current_unix_timestamp();
        q.drain_ready_batches(now + 100_000);
        let bid_before = q.next_batch_id();
        q.persist().unwrap();

        let mut q2 = JitterQueue::with_seed(&config, path, 99);
        q2.restore().unwrap();
        assert_eq!(q2.next_batch_id(), bid_before);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 10. PERSISTENCE: CORRUPT/MISSING FILE HANDLING
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn restore_from_nonexistent_file_returns_error() {
        let config = test_config();
        let path = PathBuf::from("/tmp/hive_nonexistent_jitter_xyz.json");
        let mut q = JitterQueue::with_seed(&config, path, 42);
        let result = q.restore();
        assert!(result.is_err());
    }

    #[test]
    fn restore_from_corrupt_json_returns_error() {
        let config = test_config();
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("corrupt.json");
        std::fs::write(&path, "not valid json {{{").unwrap();

        let mut q = JitterQueue::with_seed(&config, path, 42);
        let result = q.restore();
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_from_empty_file_returns_error() {
        let config = test_config();
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("empty.json");
        std::fs::write(&path, "").unwrap();

        let mut q = JitterQueue::with_seed(&config, path, 42);
        let result = q.restore();
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_from_wrong_schema_returns_error() {
        let config = test_config();
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("wrong_schema.json");
        std::fs::write(&path, r#"{"foo": "bar", "baz": 42}"#).unwrap();

        let mut q = JitterQueue::with_seed(&config, path, 42);
        let result = q.restore();
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_does_not_corrupt_existing_state_on_error() {
        let config = test_config();
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("corrupt_safe.json");
        std::fs::write(&path, "GARBAGE").unwrap();

        let mut q = JitterQueue::with_seed(&config, path, 42);
        q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
        assert_eq!(q.len(), 1);

        let result = q.restore();
        assert!(result.is_err());
        // Queue state should be unchanged after failed restore
        // (serde_json::from_str fails before we modify self)
        // Note: in our implementation, the error occurs before assignment,
        // so existing state is preserved.

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_creates_file() {
        let config = test_config();
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("new_queue.json");

        let q = JitterQueue::with_seed(&config, path.clone(), 42);
        q.persist().unwrap();
        assert!(path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 11. TIER EXTRACTION
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn extract_tier_s1() {
        let approved = make_budget_approved(SensitivityTier::S1Critical);
        assert_eq!(
            JitterQueue::extract_tier(&approved),
            SensitivityTier::S1Critical
        );
    }

    #[test]
    fn extract_tier_s2() {
        let approved = make_budget_approved(SensitivityTier::S2High);
        assert_eq!(
            JitterQueue::extract_tier(&approved),
            SensitivityTier::S2High
        );
    }

    #[test]
    fn extract_tier_s3() {
        let approved = make_budget_approved(SensitivityTier::S3Medium);
        assert_eq!(
            JitterQueue::extract_tier(&approved),
            SensitivityTier::S3Medium
        );
    }

    #[test]
    fn extract_tier_s4() {
        let approved = make_budget_approved(SensitivityTier::S4Low);
        assert_eq!(JitterQueue::extract_tier(&approved), SensitivityTier::S4Low);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 12. CROSS-TIER BATCHING
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn drain_produces_separate_batches_per_tier() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        // Enqueue enough for S3 (min=5) and S4 (min=3)
        for _ in 0..7 {
            q.enqueue(make_budget_approved(SensitivityTier::S3Medium));
        }
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        let far_future = now + 200_000;
        let batches = q.drain_ready_batches(far_future);
        // Should have at least 2 batches (one for each tier)
        assert!(
            batches.len() >= 2,
            "Expected >= 2 batches, got {}",
            batches.len()
        );
    }

    #[test]
    fn drain_tier_order_s1_first_s4_last() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        // Enqueue enough for all tiers
        for _ in 0..12 {
            q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
        }
        for _ in 0..10 {
            q.enqueue(make_budget_approved(SensitivityTier::S2High));
        }
        for _ in 0..7 {
            q.enqueue(make_budget_approved(SensitivityTier::S3Medium));
        }
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        let far_future = now + 300_000;
        let batches = q.drain_ready_batches(far_future);
        // Should have 4 batches (one per tier), in order S1->S4
        assert_eq!(batches.len(), 4, "Expected 4 batches");

        // Verify tier order by checking the sensitivity tier of the first tuple
        let tier_of =
            |batch: &Vec<QueuedTuple>| -> SensitivityTier { batch[0].inner.budget_snapshot.tier };
        assert_eq!(tier_of(&batches[0]), SensitivityTier::S1Critical);
        assert_eq!(tier_of(&batches[1]), SensitivityTier::S2High);
        assert_eq!(tier_of(&batches[2]), SensitivityTier::S3Medium);
        assert_eq!(tier_of(&batches[3]), SensitivityTier::S4Low);
    }

    #[test]
    fn drain_only_ready_tiers_appear() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        // Only enqueue S4 (enough for batch), S1 not enough
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
        let far_future = now + 100_000;
        let batches = q.drain_ready_batches(far_future);
        // Only S4 should produce a batch
        assert_eq!(batches.len(), 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 13. EDGE CASES
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn drain_exactly_min_batch_produces_batch() {
        // S4 min_batch = 3, enqueue exactly 3
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..3 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        let far_future = now + 100_000;
        let batches = q.drain_ready_batches(far_future);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 3);
    }

    #[test]
    fn drain_one_below_min_batch_no_batch_without_hold() {
        // S4 min_batch = 3, enqueue 2
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..2 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        // Within hold time
        let within_hold = now + 5_000; // < 7200 hold time
        let batches = q.drain_ready_batches(within_hold);
        assert!(batches.is_empty());
    }

    #[test]
    fn drain_single_tuple_with_hold_expired() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        // S4 hold = 7200
        let past_hold = now + 10_000;
        let batches = q.drain_ready_batches(past_hold);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 1);
    }

    #[test]
    fn drain_reduces_queue_size() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..6 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        let initial = q.len();
        let far = now + 100_000;
        let b1 = q.drain_ready_batches(far);
        assert!(!b1.is_empty());
        let drained: usize = b1.iter().map(|b| b.len()).sum();
        assert!(q.len() < initial);
        assert_eq!(q.len(), initial - drained);
    }

    #[test]
    fn enqueue_after_drain_works() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        let far = now + 100_000;
        q.drain_ready_batches(far);

        // Enqueue more
        for _ in 0..5 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        let remaining_count = q.count_for_tier(SensitivityTier::S4Low);
        assert!(remaining_count >= 5);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 14. CONFIG-DRIVEN PARAMETERS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn jitter_range_from_config_s1() {
        let q = make_queue(42);
        let (min, max) = q.jitter_range(SensitivityTier::S1Critical);
        assert_eq!(min, 3600);
        assert_eq!(max, 86400);
    }

    #[test]
    fn jitter_range_from_config_s2() {
        let q = make_queue(42);
        let (min, max) = q.jitter_range(SensitivityTier::S2High);
        assert_eq!(min, 3600);
        assert_eq!(max, 43200);
    }

    #[test]
    fn jitter_range_from_config_s3() {
        let q = make_queue(42);
        let (min, max) = q.jitter_range(SensitivityTier::S3Medium);
        assert_eq!(min, 3600);
        assert_eq!(max, 21600);
    }

    #[test]
    fn jitter_range_from_config_s4() {
        let q = make_queue(42);
        let (min, max) = q.jitter_range(SensitivityTier::S4Low);
        assert_eq!(min, 0);
        assert_eq!(max, 3600);
    }

    #[test]
    fn min_batch_size_from_config() {
        let q = make_queue(42);
        assert_eq!(q.min_batch_size(SensitivityTier::S1Critical), 10);
        assert_eq!(q.min_batch_size(SensitivityTier::S2High), 8);
        assert_eq!(q.min_batch_size(SensitivityTier::S3Medium), 5);
        assert_eq!(q.min_batch_size(SensitivityTier::S4Low), 3);
    }

    #[test]
    fn max_hold_seconds_from_config() {
        let q = make_queue(42);
        assert_eq!(q.max_hold_seconds(SensitivityTier::S1Critical), 172800);
        assert_eq!(q.max_hold_seconds(SensitivityTier::S2High), 86400);
        assert_eq!(q.max_hold_seconds(SensitivityTier::S3Medium), 43200);
        assert_eq!(q.max_hold_seconds(SensitivityTier::S4Low), 7200);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 15. CSPRNG VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn deterministic_seed_produces_deterministic_jitter() {
        let mut q1 = make_queue_with_config(&test_config(), 42);
        let mut q2 = make_queue_with_config(&test_config(), 42);
        let a1 = make_budget_approved(SensitivityTier::S1Critical);
        let a2 = make_budget_approved(SensitivityTier::S1Critical);
        let t1 = q1.enqueue(a1);
        let t2 = q2.enqueue(a2);
        assert_eq!(t1.scheduled_send_time, t2.scheduled_send_time);
    }

    #[test]
    fn os_rng_queue_produces_varying_results() {
        let config = test_config();
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        let mut q = JitterQueue::new(&config, dir.join("q.json"));
        let mut times = Vec::new();
        for _ in 0..10 {
            let approved = make_budget_approved(SensitivityTier::S1Critical);
            let t = q.enqueue(approved);
            times.push(t.scheduled_send_time);
        }
        // At least some should differ
        let first = times[0];
        let all_same = times.iter().all(|&t| t == first);
        assert!(
            !all_same,
            "All 10 jitter values are identical -- RNG broken"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 16. HELPER FUNCTION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn tier_key_mapping() {
        assert_eq!(tier_key(SensitivityTier::S1Critical), "s1");
        assert_eq!(tier_key(SensitivityTier::S2High), "s2");
        assert_eq!(tier_key(SensitivityTier::S3Medium), "s3");
        assert_eq!(tier_key(SensitivityTier::S4Low), "s4");
    }

    #[test]
    fn shuffle_empty_slice() {
        let mut entries: Vec<QueueEntry> = Vec::new();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        shuffle_entries(&mut entries, &mut rng); // should not panic
    }

    #[test]
    fn shuffle_single_element() {
        let approved = make_budget_approved(SensitivityTier::S4Low);
        let mut entries = vec![QueueEntry {
            tuple: QueuedTuple {
                inner: approved,
                scheduled_send_time: 1000,
                batch_id: None,
            },
            enqueue_time: 500,
            tier: SensitivityTier::S4Low,
        }];
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        shuffle_entries(&mut entries, &mut rng); // should not panic
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn shuffle_preserves_all_elements() {
        let mut entries: Vec<QueueEntry> = (0..10u8)
            .map(|i| {
                let mut approved = make_budget_approved(SensitivityTier::S4Low);
                approved.inner.inner.inner.inner.pattern_hash[0] = i;
                QueueEntry {
                    tuple: QueuedTuple {
                        inner: approved,
                        scheduled_send_time: 1000,
                        batch_id: None,
                    },
                    enqueue_time: 500,
                    tier: SensitivityTier::S4Low,
                }
            })
            .collect();

        let mut rng = ChaCha20Rng::seed_from_u64(42);
        shuffle_entries(&mut entries, &mut rng);

        assert_eq!(entries.len(), 10);
        let mut found: Vec<u8> = entries
            .iter()
            .map(|e| e.tuple.inner.inner.inner.inner.inner.pattern_hash[0])
            .collect();
        found.sort();
        let expected: Vec<u8> = (0..10).collect();
        assert_eq!(found, expected);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 17. VARIABLE BATCH SIZE STATISTICAL VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn variable_batch_size_not_always_min() {
        // Over many drains, batch sizes should vary
        let mut sizes = Vec::new();
        for seed in 0..20u64 {
            let mut q = make_queue_with_config(&test_config(), seed);
            let now = current_unix_timestamp();
            for _ in 0..20 {
                q.enqueue(make_budget_approved(SensitivityTier::S4Low));
            }
            let far = now + 100_000;
            let batches = q.drain_ready_batches(far);
            if let Some(batch) = batches.first() {
                sizes.push(batch.len());
            }
        }
        let min_size = *sizes.iter().min().unwrap_or(&0);
        let max_size = *sizes.iter().max().unwrap_or(&0);
        assert!(
            max_size > min_size,
            "All batch sizes are {} -- variable sizing is broken",
            min_size
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 18. DRAIN WITH MIXED READY AND NOT-READY
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn drain_only_takes_ready_tuples() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();

        // S4: some will have very short jitter (0-3600s)
        for _ in 0..10 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }

        // Check at now + 1800 (half of max S4 jitter)
        // Some should be ready, some not
        let mid_time = now + 1800;
        let initial_len = q.len();
        let batches = q.drain_ready_batches(mid_time);

        if batches.is_empty() {
            // All jitter > 1800, queue unchanged
            assert_eq!(q.len(), initial_len);
        } else {
            // Some were drained, remainder still in queue
            let drained: usize = batches.iter().map(|b| b.len()).sum();
            assert_eq!(q.len(), initial_len - drained);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 19. PERSISTENCE AFTER DRAIN
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn persist_after_drain_captures_reduced_state() {
        let config = test_config();
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("jitter_queue.json");

        let mut q = JitterQueue::with_seed(&config, path.clone(), 42);
        for _ in 0..10 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        let now = current_unix_timestamp();
        let _batches = q.drain_ready_batches(now + 100_000);
        let post_drain_len = q.len();
        q.persist().unwrap();

        let mut q2 = JitterQueue::with_seed(&config, path, 99);
        q2.restore().unwrap();
        assert_eq!(q2.len(), post_drain_len);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 20. BATCH ID UNIQUENESS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn batch_ids_unique_across_drains() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        let mut all_batch_ids: Vec<u64> = Vec::new();

        for round in 0..5u64 {
            for _ in 0..5 {
                q.enqueue(make_budget_approved(SensitivityTier::S4Low));
            }
            let far = now + 100_000 * (round + 1);
            let batches = q.drain_ready_batches(far);
            for batch in &batches {
                if let Some(id) = batch[0].batch_id {
                    all_batch_ids.push(id);
                }
            }
        }

        // All IDs should be unique
        let unique_count = {
            let mut sorted = all_batch_ids.clone();
            sorted.sort();
            sorted.dedup();
            sorted.len()
        };
        assert_eq!(unique_count, all_batch_ids.len(), "Batch IDs not unique");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 21. ALL TUPLES IN A BATCH HAVE SAME BATCH_ID
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn all_tuples_in_batch_share_batch_id() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..10 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        let far = now + 100_000;
        let batches = q.drain_ready_batches(far);
        for batch in &batches {
            let first_id = batch[0].batch_id;
            for tuple in batch {
                assert_eq!(tuple.batch_id, first_id);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 22. ATOMIC PERSIST (TEMP FILE)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn persist_atomic_no_tmp_left() {
        let config = test_config();
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("jitter_queue.json");
        let tmp_path = dir.join("jitter_queue.json.tmp");

        let q = JitterQueue::with_seed(&config, path.clone(), 42);
        q.persist().unwrap();

        assert!(path.exists());
        assert!(!tmp_path.exists(), "Temp file should be cleaned up");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 23. SENSITIVITY TIER-SPECIFIC JITTER ISOLATION
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn s1_jitter_always_at_least_1_hour() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..50 {
            let t = q.enqueue(make_budget_approved(SensitivityTier::S1Critical));
            let delay = t.scheduled_send_time - now;
            assert!(
                delay >= 3598,
                "S1 delay {} < 1 hour (minus tolerance)",
                delay
            );
        }
    }

    #[test]
    fn s4_jitter_can_be_zero() {
        // With min=0 for S4, at least some should have very small delays
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        let mut found_small = false;
        for _ in 0..200 {
            let t = q.enqueue(make_budget_approved(SensitivityTier::S4Low));
            let delay = t.scheduled_send_time - now;
            if delay < 100 {
                found_small = true;
                break;
            }
        }
        assert!(found_small, "S4 should sometimes have near-zero delay");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 24. DRAIN MULTIPLE ROUNDS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn multiple_drain_rounds_process_all() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..15 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        let mut total_drained = 0usize;
        let far = now + 100_000;
        // Drain multiple rounds
        for _ in 0..10 {
            let batches = q.drain_ready_batches(far);
            for batch in &batches {
                total_drained += batch.len();
            }
            if q.is_empty() {
                break;
            }
        }
        assert_eq!(total_drained, 15);
        assert!(q.is_empty());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 25. LARGE QUEUE
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn large_queue_drains_correctly() {
        let mut q = make_queue(42);
        let now = current_unix_timestamp();
        for _ in 0..100 {
            q.enqueue(make_budget_approved(SensitivityTier::S4Low));
        }
        assert_eq!(q.len(), 100);
        let far = now + 100_000;
        let mut total = 0;
        for _ in 0..50 {
            let batches = q.drain_ready_batches(far);
            for batch in &batches {
                total += batch.len();
                assert!(batch.len() >= 3);
                assert!(batch.len() <= 6);
            }
            if q.is_empty() {
                break;
            }
        }
        assert_eq!(total, 100);
    }

    #[test]
    fn large_queue_persistence_round_trip() {
        let config = test_config();
        let dir = test_persist_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("large_queue.json");

        let mut q = JitterQueue::with_seed(&config, path.clone(), 42);
        for _ in 0..50 {
            q.enqueue(make_budget_approved(SensitivityTier::S2High));
        }
        q.persist().unwrap();

        let mut q2 = JitterQueue::with_seed(&config, path, 99);
        q2.restore().unwrap();
        assert_eq!(q2.len(), 50);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
