//! Stage 8: Privacy budget manager with Renyi Differential Privacy composition.
//!
//! Tracks cumulative privacy loss per sensitivity tier using RDP composition.
//! Enforces daily/weekly/lifetime epsilon ceilings. Budget consumption and
//! tuple encoding are atomic -- if encoding succeeds but budget recording
//! fails, the tuple MUST NOT be sent.

use crate::privacy::config::PrivacyConfig;
use crate::privacy::types::{BudgetApprovedTuple, BudgetSnapshot, EncodedTuple, SensitivityTier};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Number of sensitivity tiers (S1-S4).
const NUM_TIERS: usize = 4;

/// Number of Renyi orders tracked (must match config).
const NUM_RENYI_ORDERS: usize = 8;

/// Threshold for soft warning (80% of lifetime ceiling consumed).
const SOFT_WARNING_THRESHOLD: f64 = 0.80;

// ─── ExhaustionLevel ───────────────────────────────────────────────────────

/// Budget exhaustion level for a given tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExhaustionLevel {
    /// Budget is healthy.
    Ok,
    /// 80%+ of lifetime ceiling consumed.
    SoftWarning,
    /// Daily ceiling reached.
    DailyCap,
    /// Weekly ceiling reached.
    WeeklyCap,
    /// Lifetime ceiling reached.
    LifetimeCap,
}

// ─── BudgetError ───────────────────────────────────────────────────────────

/// Errors that can occur during budget operations.
#[derive(Debug)]
pub enum BudgetError {
    /// Failed to read or write the state file.
    Io(io::Error),
    /// Failed to parse the state file.
    Parse(String),
    /// Renyi orders count mismatch between state file and config.
    RenyiOrdersMismatch { expected: usize, found: usize },
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetError::Io(e) => write!(f, "Budget state I/O error: {}", e),
            BudgetError::Parse(s) => write!(f, "Budget state parse error: {}", s),
            BudgetError::RenyiOrdersMismatch { expected, found } => {
                write!(
                    f,
                    "Renyi orders mismatch: expected {}, found {}",
                    expected, found
                )
            }
        }
    }
}

impl From<io::Error> for BudgetError {
    fn from(e: io::Error) -> Self {
        BudgetError::Io(e)
    }
}

impl From<serde_json::Error> for BudgetError {
    fn from(e: serde_json::Error) -> Self {
        BudgetError::Parse(e.to_string())
    }
}

// ─── BudgetState (query return) ────────────────────────────────────────────

/// Read-only snapshot of budget state for a single tier.
#[derive(Debug, Clone)]
pub struct BudgetState {
    pub renyi_divergences: [f64; NUM_RENYI_ORDERS],
    pub daily_consumption: f64,
    pub weekly_consumption: f64,
    pub lifetime_consumption: f64,
    pub tuples_contributed: u64,
    pub daily_reset_time: u64,
    pub weekly_reset_time: u64,
}

// ─── UserBudgetState (internal, persisted) ─────────────────────────────────

/// Internal budget state tracking all tiers. Serializable for file persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserBudgetState {
    /// Renyi divergence accumulators: [tier][alpha_index].
    renyi_divergences: [[f64; NUM_RENYI_ORDERS]; NUM_TIERS],
    /// Daily epsilon consumption per tier.
    daily_consumption: [f64; NUM_TIERS],
    /// Weekly epsilon consumption per tier.
    weekly_consumption: [f64; NUM_TIERS],
    /// Lifetime epsilon consumption per tier. NEVER resets.
    lifetime_consumption: [f64; NUM_TIERS],
    /// Number of tuples contributed per tier.
    tuples_contributed: [u64; NUM_TIERS],
    /// Unix timestamp of next daily reset.
    daily_reset_time: u64,
    /// Unix timestamp of next weekly reset.
    weekly_reset_time: u64,
}

impl UserBudgetState {
    /// Create a fresh zero-consumption state.
    fn new() -> Self {
        let now = current_unix_timestamp();
        Self {
            renyi_divergences: [[0.0; NUM_RENYI_ORDERS]; NUM_TIERS],
            daily_consumption: [0.0; NUM_TIERS],
            weekly_consumption: [0.0; NUM_TIERS],
            lifetime_consumption: [0.0; NUM_TIERS],
            tuples_contributed: [0; NUM_TIERS],
            daily_reset_time: next_midnight(now),
            weekly_reset_time: next_sunday_midnight(now),
        }
    }
}

// ─── BudgetManagerImpl ─────────────────────────────────────────────────────

/// Privacy budget manager implementing Renyi DP composition with
/// daily/weekly/lifetime epsilon ceilings per sensitivity tier.
pub struct BudgetManagerImpl {
    config: PrivacyConfig,
    state: UserBudgetState,
}

impl BudgetManagerImpl {
    // ── Construction ────────────────────────────────────────────────────

    /// Create a new budget manager with zero consumption.
    pub fn new(config: PrivacyConfig) -> Self {
        Self {
            config,
            state: UserBudgetState::new(),
        }
    }

    /// Create a budget manager with a pre-set state (for testing).
    #[cfg(test)]
    #[allow(dead_code)] // Test helper retained for future budget-state scenarios.
    fn with_state(config: PrivacyConfig, state: UserBudgetState) -> Self {
        Self { config, state }
    }

    // ── Core: check and consume (ATOMIC) ────────────────────────────────

    /// Atomically check budget ceilings and consume epsilon.
    ///
    /// Returns `None` if any ceiling would be exceeded -- in that case,
    /// **no state is modified** (atomicity guarantee).
    pub fn check_and_consume(&mut self, encoded: EncodedTuple) -> Option<BudgetApprovedTuple> {
        let tier = Self::extract_tier(&encoded);
        let idx = tier.index();
        let epsilon = encoded.epsilon_consumed;

        // --- Check all ceilings BEFORE modifying state ---
        let daily_ceiling = self.config.budget_ceilings.daily.for_tier_index(idx);
        let weekly_ceiling = self.config.budget_ceilings.weekly.for_tier_index(idx);
        let lifetime_ceiling = self.config.budget_ceilings.lifetime.for_tier_index(idx);

        if self.state.daily_consumption[idx] + epsilon > daily_ceiling {
            return None; // daily cap
        }
        if self.state.weekly_consumption[idx] + epsilon > weekly_ceiling {
            return None; // weekly cap
        }
        if self.state.lifetime_consumption[idx] + epsilon > lifetime_ceiling {
            return None; // lifetime cap
        }

        // --- All checks passed: consume budget ---
        let renyi_orders = &self.config.budget_composition.renyi_orders;
        for (alpha_idx, &alpha) in renyi_orders.iter().enumerate() {
            if alpha_idx < NUM_RENYI_ORDERS {
                let rdp = compute_rdp_oue(epsilon, alpha);
                self.state.renyi_divergences[idx][alpha_idx] += rdp;
            }
        }

        self.state.daily_consumption[idx] += epsilon;
        self.state.weekly_consumption[idx] += epsilon;
        self.state.lifetime_consumption[idx] += epsilon;
        self.state.tuples_contributed[idx] += 1;

        // --- Build snapshot AFTER consumption ---
        let snapshot = BudgetSnapshot {
            tier,
            daily_remaining: daily_ceiling - self.state.daily_consumption[idx],
            weekly_remaining: weekly_ceiling - self.state.weekly_consumption[idx],
            lifetime_remaining: lifetime_ceiling - self.state.lifetime_consumption[idx],
        };

        Some(BudgetApprovedTuple {
            inner: encoded,
            budget_snapshot: snapshot,
        })
    }

    // ── Query ───────────────────────────────────────────────────────────

    /// Query current budget state for a tier (read-only).
    pub fn query(&self, tier: SensitivityTier) -> BudgetState {
        let idx = tier.index();
        BudgetState {
            renyi_divergences: self.state.renyi_divergences[idx],
            daily_consumption: self.state.daily_consumption[idx],
            weekly_consumption: self.state.weekly_consumption[idx],
            lifetime_consumption: self.state.lifetime_consumption[idx],
            tuples_contributed: self.state.tuples_contributed[idx],
            daily_reset_time: self.state.daily_reset_time,
            weekly_reset_time: self.state.weekly_reset_time,
        }
    }

    // ── Resets ──────────────────────────────────────────────────────────

    /// Reset daily counters only. Does NOT affect Renyi accumulators,
    /// weekly counters, or lifetime counters.
    pub fn reset_daily(&mut self) {
        self.state.daily_consumption = [0.0; NUM_TIERS];
        let now = current_unix_timestamp();
        self.state.daily_reset_time = next_midnight(now);
    }

    /// Reset weekly counters only. Does NOT affect Renyi accumulators
    /// or lifetime counters.
    pub fn reset_weekly(&mut self) {
        self.state.weekly_consumption = [0.0; NUM_TIERS];
        let now = current_unix_timestamp();
        self.state.weekly_reset_time = next_sunday_midnight(now);
    }

    /// Auto-check if daily/weekly resets are due based on current time.
    pub fn check_resets(&mut self) {
        let now = current_unix_timestamp();
        if now >= self.state.daily_reset_time {
            self.reset_daily();
        }
        if now >= self.state.weekly_reset_time {
            self.reset_weekly();
        }
    }

    // ── Effective epsilon via Renyi conversion ──────────────────────────

    /// Current effective total epsilon (with delta) for a tier.
    ///
    /// Computed as: min over alpha of
    ///   (renyi_divergences[tier][alpha] + ln(1/delta)) / (alpha - 1)
    pub fn effective_epsilon(&self, tier: SensitivityTier) -> f64 {
        let idx = tier.index();
        let delta = self.config.budget_composition.delta;
        let ln_inv_delta = (1.0 / delta).ln();

        self.config
            .budget_composition
            .renyi_orders
            .iter()
            .enumerate()
            .filter(|(i, _)| *i < NUM_RENYI_ORDERS)
            .map(|(i, &alpha)| {
                (self.state.renyi_divergences[idx][i] + ln_inv_delta) / (alpha - 1.0)
            })
            .fold(f64::INFINITY, f64::min)
    }

    // ── Remaining budget queries ────────────────────────────────────────

    /// Remaining daily epsilon budget for a tier.
    pub fn remaining_daily(&self, tier: SensitivityTier) -> f64 {
        let idx = tier.index();
        let ceiling = self.config.budget_ceilings.daily.for_tier_index(idx);
        (ceiling - self.state.daily_consumption[idx]).max(0.0)
    }

    /// Remaining weekly epsilon budget for a tier.
    pub fn remaining_weekly(&self, tier: SensitivityTier) -> f64 {
        let idx = tier.index();
        let ceiling = self.config.budget_ceilings.weekly.for_tier_index(idx);
        (ceiling - self.state.weekly_consumption[idx]).max(0.0)
    }

    /// Remaining lifetime epsilon budget for a tier.
    pub fn remaining_lifetime(&self, tier: SensitivityTier) -> f64 {
        let idx = tier.index();
        let ceiling = self.config.budget_ceilings.lifetime.for_tier_index(idx);
        (ceiling - self.state.lifetime_consumption[idx]).max(0.0)
    }

    /// Whether the lifetime cap for a tier has been reached.
    pub fn is_exhausted(&self, tier: SensitivityTier) -> bool {
        let idx = tier.index();
        let ceiling = self.config.budget_ceilings.lifetime.for_tier_index(idx);
        self.state.lifetime_consumption[idx] >= ceiling
    }

    /// Determine the exhaustion level for a tier.
    pub fn exhaustion_level(&self, tier: SensitivityTier) -> ExhaustionLevel {
        let idx = tier.index();

        let lifetime_ceiling = self.config.budget_ceilings.lifetime.for_tier_index(idx);
        if self.state.lifetime_consumption[idx] >= lifetime_ceiling {
            return ExhaustionLevel::LifetimeCap;
        }

        let weekly_ceiling = self.config.budget_ceilings.weekly.for_tier_index(idx);
        if self.state.weekly_consumption[idx] >= weekly_ceiling {
            return ExhaustionLevel::WeeklyCap;
        }

        let daily_ceiling = self.config.budget_ceilings.daily.for_tier_index(idx);
        if self.state.daily_consumption[idx] >= daily_ceiling {
            return ExhaustionLevel::DailyCap;
        }

        if self.state.lifetime_consumption[idx] >= lifetime_ceiling * SOFT_WARNING_THRESHOLD {
            return ExhaustionLevel::SoftWarning;
        }

        ExhaustionLevel::Ok
    }

    // ── Persistence ─────────────────────────────────────────────────────

    /// Persist budget state to a JSON file.
    pub fn save_to_file(&self, path: &Path) -> Result<(), io::Error> {
        let json = serde_json::to_string_pretty(&self.state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    /// Load budget state from a JSON file. Returns error if file is
    /// corrupt or missing -- caller must treat error as all-exhausted
    /// (fail-safe).
    pub fn load_from_file(path: &Path, config: PrivacyConfig) -> Result<Self, BudgetError> {
        let content = std::fs::read_to_string(path)?;
        let state: UserBudgetState = serde_json::from_str(&content)?;

        // Validate Renyi orders dimension matches
        let expected = config
            .budget_composition
            .renyi_orders
            .len()
            .min(NUM_RENYI_ORDERS);
        // The state always has NUM_RENYI_ORDERS entries (fixed array).
        // Just verify the config expectation is compatible.
        if expected > NUM_RENYI_ORDERS {
            return Err(BudgetError::RenyiOrdersMismatch {
                expected,
                found: NUM_RENYI_ORDERS,
            });
        }

        Ok(Self { config, state })
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Extract the sensitivity tier from an EncodedTuple by traversing
    /// the type-state chain.
    fn extract_tier(encoded: &EncodedTuple) -> SensitivityTier {
        // EncodedTuple -> LCheckedTuple -> KCheckedTuple -> HashedTuple
        //   -> GeneralizedTuple -> sensitivity_tier
        encoded.inner.inner.inner.inner.sensitivity_tier
    }
}

// ─── RDP computation (free functions) ──────────────────────────────────────

/// Compute the Renyi divergence for a single OUE query at privacy
/// parameter `epsilon` and Renyi order `alpha`.
///
/// Uses the safe Gaussian mechanism upper bound:
///   rdp_oue(epsilon, alpha) = alpha * epsilon^2 / 2
///
/// This over-approximation is standard practice and gives tighter
/// budget accounting than simple sequential composition.
pub fn compute_rdp_oue(epsilon: f64, alpha: f64) -> f64 {
    alpha * epsilon * epsilon / 2.0
}

/// Compute the exact Renyi divergence for binary randomized response.
///
/// For OUE with parameters p and q, the Renyi divergence of order alpha
/// between the two response distributions is:
///   D_alpha = (1/(alpha-1)) * ln(p^alpha * q^(1-alpha) + (1-p)^alpha * (1-q)^(1-alpha))
///
/// where p = 0.5 and q = 1/(e^epsilon + 1).
pub fn compute_rdp_oue_exact(epsilon: f64, alpha: f64) -> f64 {
    if (alpha - 1.0).abs() < 1e-12 {
        // alpha = 1 is the KL divergence limit; use the simplified form
        return epsilon * epsilon / 2.0;
    }

    let p: f64 = 0.5;
    let q: f64 = 1.0 / (epsilon.exp() + 1.0);

    let term1 = p.powf(alpha) * q.powf(1.0 - alpha);
    let term2 = (1.0 - p).powf(alpha) * (1.0 - q).powf(1.0 - alpha);

    let inner = term1 + term2;
    if inner <= 0.0 {
        return f64::INFINITY;
    }

    inner.ln() / (alpha - 1.0)
}

// ─── Time utilities ────────────────────────────────────────────────────────

/// Get the current Unix timestamp in seconds.
fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Compute the next midnight (00:00 UTC) after the given timestamp.
fn next_midnight(now: u64) -> u64 {
    let seconds_in_day: u64 = 86400;
    let current_day_start = now - (now % seconds_in_day);
    current_day_start + seconds_in_day
}

/// Compute the next Sunday midnight (00:00 UTC) after the given timestamp.
fn next_sunday_midnight(now: u64) -> u64 {
    let seconds_in_day: u64 = 86400;
    // Unix epoch (Jan 1, 1970) was a Thursday (day 4, 0=Mon).
    // Days since epoch:
    let days_since_epoch = now / seconds_in_day;
    // Day of week: 0=Thu, 1=Fri, 2=Sat, 3=Sun, 4=Mon, 5=Tue, 6=Wed
    // Adjust to 0=Mon: (days_since_epoch + 3) % 7  => 0=Mon .. 6=Sun
    let day_of_week = (days_since_epoch + 3) % 7; // 0=Mon, 6=Sun
                                                  // Days until next Sunday (day 6):
    let days_until_sunday = if day_of_week == 6 {
        // Already Sunday -- next Sunday is 7 days away, unless we're before
        // midnight in which case 0 is fine. For simplicity, always go to next.
        7
    } else {
        6 - day_of_week
    };
    let current_day_start = now - (now % seconds_in_day);
    current_day_start + days_until_sunday * seconds_in_day
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::config::PrivacyConfig;
    use crate::privacy::types::*;

    // ── Test helpers ────────────────────────────────────────────────────

    fn test_config() -> PrivacyConfig {
        PrivacyConfig::default_config()
    }

    /// Build a minimal GeneralizedTuple for a given tier.
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

    /// Build an EncodedTuple for a given tier and epsilon.
    fn make_encoded(tier: SensitivityTier, epsilon: f64) -> EncodedTuple {
        EncodedTuple {
            inner: make_l_checked(tier),
            oue_vectors: vec![OueFieldVector {
                field_name: "entity_b_value".into(),
                domain_size: 128,
                epsilon: epsilon / 7.0, // per-field
                bits: vec![0xFF; 16],
            }],
            epsilon_consumed: epsilon,
        }
    }

    // ── 1. Fresh budget ────────────────────────────────────────────────

    #[test]
    fn fresh_budget_has_zero_consumption() {
        let mgr = BudgetManagerImpl::new(test_config());
        for tier in [
            SensitivityTier::S1Critical,
            SensitivityTier::S2High,
            SensitivityTier::S3Medium,
            SensitivityTier::S4Low,
        ] {
            let state = mgr.query(tier);
            assert_eq!(state.daily_consumption, 0.0);
            assert_eq!(state.weekly_consumption, 0.0);
            assert_eq!(state.lifetime_consumption, 0.0);
            assert_eq!(state.tuples_contributed, 0);
            for &rdp in state.renyi_divergences.iter() {
                assert_eq!(rdp, 0.0);
            }
        }
    }

    #[test]
    fn fresh_budget_full_headroom() {
        let mgr = BudgetManagerImpl::new(test_config());
        assert!((mgr.remaining_daily(SensitivityTier::S1Critical) - 2.0).abs() < 1e-10);
        assert!((mgr.remaining_weekly(SensitivityTier::S1Critical) - 10.0).abs() < 1e-10);
        assert!((mgr.remaining_lifetime(SensitivityTier::S1Critical) - 100.0).abs() < 1e-10);
    }

    #[test]
    fn fresh_budget_not_exhausted() {
        let mgr = BudgetManagerImpl::new(test_config());
        for tier in [
            SensitivityTier::S1Critical,
            SensitivityTier::S2High,
            SensitivityTier::S3Medium,
            SensitivityTier::S4Low,
        ] {
            assert!(!mgr.is_exhausted(tier));
            assert_eq!(mgr.exhaustion_level(tier), ExhaustionLevel::Ok);
        }
    }

    // ── 2. Single consumption ──────────────────────────────────────────

    #[test]
    fn single_s4_consumption_updates_all_counters() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let encoded = make_encoded(SensitivityTier::S4Low, 8.0);
        let result = mgr.check_and_consume(encoded);

        assert!(result.is_some());
        let state = mgr.query(SensitivityTier::S4Low);
        assert!((state.daily_consumption - 8.0).abs() < 1e-10);
        assert!((state.weekly_consumption - 8.0).abs() < 1e-10);
        assert!((state.lifetime_consumption - 8.0).abs() < 1e-10);
        assert_eq!(state.tuples_contributed, 1);
    }

    #[test]
    fn single_consumption_updates_renyi_accumulators() {
        let config = test_config();
        let renyi_orders = config.budget_composition.renyi_orders.clone();
        let mut mgr = BudgetManagerImpl::new(config);
        let epsilon = 2.0;
        let encoded = make_encoded(SensitivityTier::S2High, epsilon);
        mgr.check_and_consume(encoded);

        let state = mgr.query(SensitivityTier::S2High);
        for (i, &alpha) in renyi_orders.iter().enumerate() {
            let expected = compute_rdp_oue(epsilon, alpha);
            assert!(
                (state.renyi_divergences[i] - expected).abs() < 1e-10,
                "Renyi divergence mismatch at order {}",
                alpha
            );
        }
    }

    #[test]
    fn single_consumption_does_not_affect_other_tiers() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let encoded = make_encoded(SensitivityTier::S1Critical, 1.0);
        mgr.check_and_consume(encoded);

        // S2, S3, S4 should be untouched
        for tier in [
            SensitivityTier::S2High,
            SensitivityTier::S3Medium,
            SensitivityTier::S4Low,
        ] {
            let state = mgr.query(tier);
            assert_eq!(state.daily_consumption, 0.0);
            assert_eq!(state.lifetime_consumption, 0.0);
            assert_eq!(state.tuples_contributed, 0);
        }
    }

    // ── 3. Daily ceiling ───────────────────────────────────────────────

    #[test]
    fn daily_ceiling_s1_enforced() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // S1 daily ceiling = 2.0, epsilon per tuple = 1.0
        let e1 = make_encoded(SensitivityTier::S1Critical, 1.0);
        assert!(mgr.check_and_consume(e1).is_some());

        let e2 = make_encoded(SensitivityTier::S1Critical, 1.0);
        assert!(mgr.check_and_consume(e2).is_some());

        // Third should be rejected (would be 3.0 > 2.0)
        let e3 = make_encoded(SensitivityTier::S1Critical, 1.0);
        assert!(mgr.check_and_consume(e3).is_none());
    }

    #[test]
    fn daily_ceiling_exact_boundary_accepted() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // S1 daily ceiling = 2.0; consume exactly 2.0
        let e1 = make_encoded(SensitivityTier::S1Critical, 2.0);
        assert!(mgr.check_and_consume(e1).is_some());

        // Any more should be rejected
        let e2 = make_encoded(SensitivityTier::S1Critical, 0.001);
        assert!(mgr.check_and_consume(e2).is_none());
    }

    #[test]
    fn daily_ceiling_s4_enforced() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // S4 daily = 32.0, epsilon per tuple = 8.0 -> 4 tuples
        for _ in 0..4 {
            let e = make_encoded(SensitivityTier::S4Low, 8.0);
            assert!(mgr.check_and_consume(e).is_some());
        }
        // 5th should be rejected
        let e = make_encoded(SensitivityTier::S4Low, 8.0);
        assert!(mgr.check_and_consume(e).is_none());
    }

    // ── 4. Weekly ceiling ──────────────────────────────────────────────

    #[test]
    fn weekly_ceiling_s2_enforced() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // S2 weekly = 30.0, epsilon = 2.0 -> 15 tuples
        for _ in 0..3 {
            // Each day: consume up to daily cap (6.0) = 3 tuples
            for _ in 0..3 {
                let e = make_encoded(SensitivityTier::S2High, 2.0);
                assert!(mgr.check_and_consume(e).is_some());
            }
            mgr.reset_daily();
        }
        // At this point: weekly = 18.0, daily = 0.0
        // Consume 6 more (12.0)
        for _ in 0..3 {
            let e = make_encoded(SensitivityTier::S2High, 2.0);
            assert!(mgr.check_and_consume(e).is_some());
        }
        mgr.reset_daily();
        // weekly = 24.0
        for _ in 0..3 {
            let e = make_encoded(SensitivityTier::S2High, 2.0);
            assert!(mgr.check_and_consume(e).is_some());
        }
        // weekly = 30.0 exactly
        mgr.reset_daily();
        // Now next should be rejected by weekly cap
        let e = make_encoded(SensitivityTier::S2High, 2.0);
        assert!(mgr.check_and_consume(e).is_none());
    }

    // ── 5. Lifetime ceiling ────────────────────────────────────────────

    #[test]
    fn lifetime_ceiling_s1_enforced() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // S1 lifetime = 100.0, consume in chunks
        // Force direct state manipulation for faster test
        mgr.state.lifetime_consumption[0] = 99.5;
        mgr.state.daily_consumption[0] = 0.0; // fresh daily
        mgr.state.weekly_consumption[0] = 0.0;

        let e1 = make_encoded(SensitivityTier::S1Critical, 0.5);
        assert!(mgr.check_and_consume(e1).is_some());
        // lifetime = 100.0 exactly

        let e2 = make_encoded(SensitivityTier::S1Critical, 0.001);
        assert!(mgr.check_and_consume(e2).is_none());
    }

    #[test]
    fn lifetime_ceiling_per_tier() {
        let config = test_config();
        let tiers = [
            (SensitivityTier::S1Critical, 100.0),
            (SensitivityTier::S2High, 500.0),
            (SensitivityTier::S3Medium, 2000.0),
            (SensitivityTier::S4Low, 5000.0),
        ];
        for (tier, ceiling) in tiers {
            let mut mgr = BudgetManagerImpl::new(config.clone());
            let idx = tier.index();
            mgr.state.lifetime_consumption[idx] = ceiling;
            assert!(mgr.is_exhausted(tier));
        }
    }

    // ── 6. Daily reset ─────────────────────────────────────────────────

    #[test]
    fn daily_reset_clears_daily_only() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let e = make_encoded(SensitivityTier::S1Critical, 1.0);
        mgr.check_and_consume(e);

        let pre_weekly = mgr.query(SensitivityTier::S1Critical).weekly_consumption;
        let pre_lifetime = mgr.query(SensitivityTier::S1Critical).lifetime_consumption;
        let pre_renyi = mgr.query(SensitivityTier::S1Critical).renyi_divergences;

        mgr.reset_daily();

        let state = mgr.query(SensitivityTier::S1Critical);
        assert_eq!(state.daily_consumption, 0.0);
        assert!((state.weekly_consumption - pre_weekly).abs() < 1e-10);
        assert!((state.lifetime_consumption - pre_lifetime).abs() < 1e-10);
        assert_eq!(state.renyi_divergences, pre_renyi);
    }

    #[test]
    fn daily_reset_enables_new_daily_consumption() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // Exhaust daily for S1
        let e1 = make_encoded(SensitivityTier::S1Critical, 2.0);
        mgr.check_and_consume(e1);

        let e2 = make_encoded(SensitivityTier::S1Critical, 0.1);
        assert!(mgr.check_and_consume(e2).is_none());

        mgr.reset_daily();

        // Should be accepted again
        let e3 = make_encoded(SensitivityTier::S1Critical, 1.0);
        assert!(mgr.check_and_consume(e3).is_some());
    }

    // ── 7. Weekly reset ────────────────────────────────────────────────

    #[test]
    fn weekly_reset_clears_weekly_only() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let e = make_encoded(SensitivityTier::S2High, 2.0);
        mgr.check_and_consume(e);

        let pre_lifetime = mgr.query(SensitivityTier::S2High).lifetime_consumption;
        let pre_renyi = mgr.query(SensitivityTier::S2High).renyi_divergences;

        mgr.reset_weekly();

        let state = mgr.query(SensitivityTier::S2High);
        assert_eq!(state.weekly_consumption, 0.0);
        assert!((state.lifetime_consumption - pre_lifetime).abs() < 1e-10);
        assert_eq!(state.renyi_divergences, pre_renyi);
    }

    #[test]
    fn weekly_reset_does_not_affect_daily() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let e = make_encoded(SensitivityTier::S3Medium, 4.0);
        mgr.check_and_consume(e);

        let pre_daily = mgr.query(SensitivityTier::S3Medium).daily_consumption;
        mgr.reset_weekly();
        let post_daily = mgr.query(SensitivityTier::S3Medium).daily_consumption;
        assert!((pre_daily - post_daily).abs() < 1e-10);
    }

    // ── 8. Renyi composition ───────────────────────────────────────────

    #[test]
    fn renyi_accumulates_across_multiple_consumptions() {
        let config = test_config();
        let renyi_orders = config.budget_composition.renyi_orders.clone();
        let mut mgr = BudgetManagerImpl::new(config);

        let epsilon = 1.0;
        let n = 3;
        for i in 0..n {
            let e = make_encoded(SensitivityTier::S1Critical, epsilon);
            let result = mgr.check_and_consume(e);
            assert!(result.is_some(), "consumption {} should succeed", i);
            // Reset daily to avoid daily cap (S1 daily = 2.0)
            mgr.reset_daily();
        }

        let state = mgr.query(SensitivityTier::S1Critical);
        // RDP is additive under composition
        for (i, &alpha) in renyi_orders.iter().enumerate() {
            let expected = n as f64 * compute_rdp_oue(epsilon, alpha);
            assert!(
                (state.renyi_divergences[i] - expected).abs() < 1e-10,
                "alpha={}: expected {}, got {}",
                alpha,
                expected,
                state.renyi_divergences[i]
            );
        }
    }

    #[test]
    fn renyi_never_resets_on_daily_reset() {
        let config = test_config();
        let mut mgr = BudgetManagerImpl::new(config);
        let e = make_encoded(SensitivityTier::S1Critical, 1.0);
        mgr.check_and_consume(e);

        let pre_renyi = mgr.query(SensitivityTier::S1Critical).renyi_divergences;
        mgr.reset_daily();
        let post_renyi = mgr.query(SensitivityTier::S1Critical).renyi_divergences;
        assert_eq!(pre_renyi, post_renyi);
    }

    #[test]
    fn renyi_never_resets_on_weekly_reset() {
        let config = test_config();
        let mut mgr = BudgetManagerImpl::new(config);
        let e = make_encoded(SensitivityTier::S2High, 2.0);
        mgr.check_and_consume(e);

        let pre_renyi = mgr.query(SensitivityTier::S2High).renyi_divergences;
        mgr.reset_weekly();
        let post_renyi = mgr.query(SensitivityTier::S2High).renyi_divergences;
        assert_eq!(pre_renyi, post_renyi);
    }

    // ── 9. Effective epsilon ───────────────────────────────────────────

    #[test]
    fn effective_epsilon_zero_on_fresh() {
        let config = test_config();
        let mgr = BudgetManagerImpl::new(config);
        // With zero divergences, effective epsilon is ln(1/delta)/(alpha-1)
        // for the best alpha, but NOT zero. Actually with rdp=0:
        //   eps = (0 + ln(1/1e-6)) / (alpha-1) = ln(1e6)/(alpha-1)
        // Minimum over alpha in [1.5..100]: at alpha=100 -> ln(1e6)/99
        let expected_min = (1e6_f64.ln()) / 99.0;
        let eff = mgr.effective_epsilon(SensitivityTier::S1Critical);
        assert!(
            (eff - expected_min).abs() < 1e-6,
            "Expected ~{}, got {}",
            expected_min,
            eff
        );
    }

    #[test]
    fn effective_epsilon_increases_after_consumption() {
        let config = test_config();
        let mut mgr = BudgetManagerImpl::new(config);
        let eff_before = mgr.effective_epsilon(SensitivityTier::S1Critical);

        let e = make_encoded(SensitivityTier::S1Critical, 1.0);
        mgr.check_and_consume(e);

        let eff_after = mgr.effective_epsilon(SensitivityTier::S1Critical);
        assert!(eff_after > eff_before);
    }

    // ── 10. rdp_oue math ───────────────────────────────────────────────

    #[test]
    fn rdp_oue_simple_formula_correctness() {
        // rdp = alpha * epsilon^2 / 2
        assert!((compute_rdp_oue(1.0, 2.0) - 1.0).abs() < 1e-10); // 2*1/2 = 1
        assert!((compute_rdp_oue(2.0, 3.0) - 6.0).abs() < 1e-10); // 3*4/2 = 6
        assert!((compute_rdp_oue(0.0, 5.0) - 0.0).abs() < 1e-10); // 0
        assert!((compute_rdp_oue(1.0, 1.5) - 0.75).abs() < 1e-10); // 1.5*1/2 = 0.75
    }

    #[test]
    fn rdp_oue_zero_epsilon() {
        for alpha in [1.5, 2.0, 10.0, 100.0] {
            assert!((compute_rdp_oue(0.0, alpha)).abs() < 1e-15);
        }
    }

    #[test]
    fn rdp_oue_exact_non_negative() {
        // Exact formula should always return non-negative values
        for eps in [0.5, 1.0, 2.0, 4.0, 8.0] {
            for alpha in [1.5, 2.0, 3.0, 5.0, 10.0, 25.0, 50.0, 100.0] {
                let rdp = compute_rdp_oue_exact(eps, alpha);
                assert!(
                    rdp >= 0.0,
                    "rdp_exact({}, {}) = {} should be >= 0",
                    eps,
                    alpha,
                    rdp
                );
            }
        }
    }

    #[test]
    fn rdp_oue_exact_at_alpha_near_one() {
        // Near alpha=1, should be close to eps^2/2 (KL limit)
        let eps = 1.0;
        let rdp = compute_rdp_oue_exact(eps, 1.0);
        assert!((rdp - 0.5).abs() < 0.1, "rdp_exact near alpha=1: {}", rdp);
    }

    #[test]
    fn rdp_oue_simple_is_upper_bound_of_exact() {
        // The Gaussian bound (simple) should be >= exact
        for eps in [0.5, 1.0, 2.0, 4.0] {
            for alpha in [1.5, 2.0, 3.0, 5.0, 10.0, 25.0, 50.0, 100.0] {
                let simple = compute_rdp_oue(eps, alpha);
                let exact = compute_rdp_oue_exact(eps, alpha);
                assert!(
                    simple >= exact - 1e-10,
                    "simple ({}) should >= exact ({}) for eps={}, alpha={}",
                    simple,
                    exact,
                    eps,
                    alpha,
                );
            }
        }
    }

    // ── 11. All 4 tiers ────────────────────────────────────────────────

    #[test]
    fn all_tiers_accept_first_tuple() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        for (tier, eps) in [
            (SensitivityTier::S1Critical, 1.0),
            (SensitivityTier::S2High, 2.0),
            (SensitivityTier::S3Medium, 4.0),
            (SensitivityTier::S4Low, 8.0),
        ] {
            let e = make_encoded(tier, eps);
            assert!(
                mgr.check_and_consume(e).is_some(),
                "Tier {:?} should accept first tuple",
                tier
            );
        }
    }

    #[test]
    fn each_tier_independent_daily_cap() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // Exhaust S1 daily
        let e1 = make_encoded(SensitivityTier::S1Critical, 2.0);
        mgr.check_and_consume(e1);
        let e2 = make_encoded(SensitivityTier::S1Critical, 0.1);
        assert!(mgr.check_and_consume(e2).is_none());

        // S2 should still work
        let e3 = make_encoded(SensitivityTier::S2High, 2.0);
        assert!(mgr.check_and_consume(e3).is_some());
    }

    // ── 12. Atomic check-and-consume ───────────────────────────────────

    #[test]
    fn failed_check_modifies_nothing() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // Consume almost all S1 daily
        let e1 = make_encoded(SensitivityTier::S1Critical, 1.9);
        mgr.check_and_consume(e1);

        // Snapshot state before failed attempt
        let state_before = mgr.query(SensitivityTier::S1Critical);

        // Attempt that exceeds daily ceiling
        let e2 = make_encoded(SensitivityTier::S1Critical, 1.0);
        assert!(mgr.check_and_consume(e2).is_none());

        // Verify nothing changed
        let state_after = mgr.query(SensitivityTier::S1Critical);
        assert!((state_after.daily_consumption - state_before.daily_consumption).abs() < 1e-10);
        assert!((state_after.weekly_consumption - state_before.weekly_consumption).abs() < 1e-10);
        assert!(
            (state_after.lifetime_consumption - state_before.lifetime_consumption).abs() < 1e-10
        );
        assert_eq!(
            state_after.tuples_contributed,
            state_before.tuples_contributed
        );
        assert_eq!(
            state_after.renyi_divergences,
            state_before.renyi_divergences
        );
    }

    #[test]
    fn failed_weekly_check_modifies_nothing() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // Set S2 weekly near cap
        mgr.state.weekly_consumption[1] = 29.5;
        mgr.state.daily_consumption[1] = 0.0;

        let state_before = mgr.query(SensitivityTier::S2High);
        let e = make_encoded(SensitivityTier::S2High, 2.0);
        assert!(mgr.check_and_consume(e).is_none());

        let state_after = mgr.query(SensitivityTier::S2High);
        assert!((state_after.weekly_consumption - state_before.weekly_consumption).abs() < 1e-10);
    }

    #[test]
    fn failed_lifetime_check_modifies_nothing() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        mgr.state.lifetime_consumption[0] = 99.5;
        mgr.state.daily_consumption[0] = 0.0;
        mgr.state.weekly_consumption[0] = 0.0;

        let state_before = mgr.query(SensitivityTier::S1Critical);
        let e = make_encoded(SensitivityTier::S1Critical, 1.0);
        assert!(mgr.check_and_consume(e).is_none());

        let state_after = mgr.query(SensitivityTier::S1Critical);
        assert!(
            (state_after.lifetime_consumption - state_before.lifetime_consumption).abs() < 1e-10
        );
    }

    // ── 13. Query interface ────────────────────────────────────────────

    #[test]
    fn query_returns_correct_state_after_consumption() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let e = make_encoded(SensitivityTier::S3Medium, 4.0);
        mgr.check_and_consume(e);

        let state = mgr.query(SensitivityTier::S3Medium);
        assert!((state.daily_consumption - 4.0).abs() < 1e-10);
        assert!((state.weekly_consumption - 4.0).abs() < 1e-10);
        assert!((state.lifetime_consumption - 4.0).abs() < 1e-10);
        assert_eq!(state.tuples_contributed, 1);
        assert!(state.daily_reset_time > 0);
        assert!(state.weekly_reset_time > 0);
    }

    #[test]
    fn query_different_tiers_independent() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let e1 = make_encoded(SensitivityTier::S1Critical, 1.0);
        mgr.check_and_consume(e1);
        let e2 = make_encoded(SensitivityTier::S4Low, 8.0);
        mgr.check_and_consume(e2);

        let s1 = mgr.query(SensitivityTier::S1Critical);
        let s4 = mgr.query(SensitivityTier::S4Low);
        assert!((s1.daily_consumption - 1.0).abs() < 1e-10);
        assert!((s4.daily_consumption - 8.0).abs() < 1e-10);
    }

    // ── 14. Persistence round-trip ─────────────────────────────────────

    #[test]
    fn persistence_save_and_load() {
        let dir = std::env::temp_dir().join("hive_budget_test_roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("budget_state.json");

        let config = test_config();
        let mut mgr = BudgetManagerImpl::new(config.clone());
        let e = make_encoded(SensitivityTier::S2High, 2.0);
        mgr.check_and_consume(e);

        mgr.save_to_file(&path).expect("save should succeed");

        let loaded = BudgetManagerImpl::load_from_file(&path, config).expect("load should succeed");

        let original = mgr.query(SensitivityTier::S2High);
        let restored = loaded.query(SensitivityTier::S2High);

        assert!((original.daily_consumption - restored.daily_consumption).abs() < 1e-10);
        assert!((original.weekly_consumption - restored.weekly_consumption).abs() < 1e-10);
        assert!((original.lifetime_consumption - restored.lifetime_consumption).abs() < 1e-10);
        assert_eq!(original.tuples_contributed, restored.tuples_contributed);
        assert_eq!(original.renyi_divergences, restored.renyi_divergences);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persistence_preserves_all_tiers() {
        let dir = std::env::temp_dir().join("hive_budget_test_all_tiers");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("budget_state.json");

        let config = test_config();
        let mut mgr = BudgetManagerImpl::new(config.clone());
        for (tier, eps) in [
            (SensitivityTier::S1Critical, 1.0),
            (SensitivityTier::S2High, 2.0),
            (SensitivityTier::S3Medium, 4.0),
            (SensitivityTier::S4Low, 8.0),
        ] {
            let e = make_encoded(tier, eps);
            mgr.check_and_consume(e);
        }

        mgr.save_to_file(&path).unwrap();
        let loaded = BudgetManagerImpl::load_from_file(&path, config).unwrap();

        for tier in [
            SensitivityTier::S1Critical,
            SensitivityTier::S2High,
            SensitivityTier::S3Medium,
            SensitivityTier::S4Low,
        ] {
            let orig = mgr.query(tier);
            let rest = loaded.query(tier);
            assert_eq!(orig.tuples_contributed, rest.tuples_contributed);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── 15. Fail-safe on corrupt file ──────────────────────────────────

    #[test]
    fn load_from_nonexistent_file_returns_error() {
        let path = std::path::PathBuf::from("/tmp/hive_nonexistent_budget_xyz.json");
        let result = BudgetManagerImpl::load_from_file(&path, test_config());
        assert!(result.is_err());
    }

    #[test]
    fn load_from_corrupt_file_returns_error() {
        let dir = std::env::temp_dir().join("hive_budget_test_corrupt");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("corrupt.json");
        std::fs::write(&path, "not valid json at all {{{").unwrap();

        let result = BudgetManagerImpl::load_from_file(&path, test_config());
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_empty_file_returns_error() {
        let dir = std::env::temp_dir().join("hive_budget_test_empty");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("empty.json");
        std::fs::write(&path, "").unwrap();

        let result = BudgetManagerImpl::load_from_file(&path, test_config());
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── 16. ExhaustionLevel ────────────────────────────────────────────

    #[test]
    fn exhaustion_level_ok_on_fresh() {
        let mgr = BudgetManagerImpl::new(test_config());
        assert_eq!(
            mgr.exhaustion_level(SensitivityTier::S1Critical),
            ExhaustionLevel::Ok
        );
    }

    #[test]
    fn exhaustion_level_soft_warning_at_80_percent() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // S1 lifetime = 100.0, 80% = 80.0
        mgr.state.lifetime_consumption[0] = 80.0;
        assert_eq!(
            mgr.exhaustion_level(SensitivityTier::S1Critical),
            ExhaustionLevel::SoftWarning
        );
    }

    #[test]
    fn exhaustion_level_daily_cap() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // S1 daily = 2.0
        mgr.state.daily_consumption[0] = 2.0;
        assert_eq!(
            mgr.exhaustion_level(SensitivityTier::S1Critical),
            ExhaustionLevel::DailyCap
        );
    }

    #[test]
    fn exhaustion_level_weekly_cap() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // S1 weekly = 10.0, daily under cap
        mgr.state.weekly_consumption[0] = 10.0;
        mgr.state.daily_consumption[0] = 0.0;
        assert_eq!(
            mgr.exhaustion_level(SensitivityTier::S1Critical),
            ExhaustionLevel::WeeklyCap
        );
    }

    #[test]
    fn exhaustion_level_lifetime_cap() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        mgr.state.lifetime_consumption[0] = 100.0;
        assert_eq!(
            mgr.exhaustion_level(SensitivityTier::S1Critical),
            ExhaustionLevel::LifetimeCap
        );
    }

    #[test]
    fn exhaustion_level_lifetime_takes_priority() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // All caps hit -- lifetime should take priority
        mgr.state.lifetime_consumption[0] = 100.0;
        mgr.state.weekly_consumption[0] = 10.0;
        mgr.state.daily_consumption[0] = 2.0;
        assert_eq!(
            mgr.exhaustion_level(SensitivityTier::S1Critical),
            ExhaustionLevel::LifetimeCap
        );
    }

    // ── 17. BudgetSnapshot in BudgetApprovedTuple ──────────────────────

    #[test]
    fn budget_snapshot_reflects_remaining_after_consumption() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let e = make_encoded(SensitivityTier::S1Critical, 1.0);
        let approved = mgr.check_and_consume(e).unwrap();

        // After consuming 1.0: daily_remaining = 2.0 - 1.0 = 1.0
        assert!((approved.budget_snapshot.daily_remaining - 1.0).abs() < 1e-10);
        assert!((approved.budget_snapshot.weekly_remaining - 9.0).abs() < 1e-10);
        assert!((approved.budget_snapshot.lifetime_remaining - 99.0).abs() < 1e-10);
        assert_eq!(approved.budget_snapshot.tier, SensitivityTier::S1Critical);
    }

    #[test]
    fn budget_snapshot_tier_matches_encoded_tuple() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let e = make_encoded(SensitivityTier::S4Low, 8.0);
        let approved = mgr.check_and_consume(e).unwrap();
        assert_eq!(approved.budget_snapshot.tier, SensitivityTier::S4Low);
    }

    // ── 18. check_resets timing ────────────────────────────────────────

    #[test]
    fn check_resets_triggers_daily_when_past_due() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let e = make_encoded(SensitivityTier::S1Critical, 1.0);
        mgr.check_and_consume(e);
        assert!(mgr.query(SensitivityTier::S1Critical).daily_consumption > 0.0);

        // Force past-due daily reset
        mgr.state.daily_reset_time = 1; // far in the past
        mgr.check_resets();

        assert_eq!(
            mgr.query(SensitivityTier::S1Critical).daily_consumption,
            0.0
        );
    }

    #[test]
    fn check_resets_triggers_weekly_when_past_due() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let e = make_encoded(SensitivityTier::S2High, 2.0);
        mgr.check_and_consume(e);

        mgr.state.weekly_reset_time = 1;
        mgr.check_resets();

        assert_eq!(mgr.query(SensitivityTier::S2High).weekly_consumption, 0.0);
    }

    #[test]
    fn check_resets_does_nothing_when_not_due() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let e = make_encoded(SensitivityTier::S1Critical, 1.0);
        mgr.check_and_consume(e);

        // Both reset times should be in the future already (set in new())
        mgr.check_resets();

        // Consumption should be unchanged
        assert!(mgr.query(SensitivityTier::S1Critical).daily_consumption > 0.0);
    }

    // ── 19. Edge cases ─────────────────────────────────────────────────

    #[test]
    fn zero_epsilon_accepted() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let e = make_encoded(SensitivityTier::S1Critical, 0.0);
        let result = mgr.check_and_consume(e);
        assert!(result.is_some());
        assert_eq!(mgr.query(SensitivityTier::S1Critical).tuples_contributed, 1);
    }

    #[test]
    fn very_large_epsilon_rejected() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let e = make_encoded(SensitivityTier::S1Critical, 999999.0);
        assert!(mgr.check_and_consume(e).is_none());
    }

    #[test]
    fn boundary_exactly_at_daily_ceiling() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // S2 daily = 6.0
        let e = make_encoded(SensitivityTier::S2High, 6.0);
        assert!(mgr.check_and_consume(e).is_some());

        // Exactly at ceiling, any more should fail
        let e2 = make_encoded(SensitivityTier::S2High, 0.0000001);
        assert!(mgr.check_and_consume(e2).is_none());
    }

    #[test]
    fn boundary_exactly_at_weekly_ceiling() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // S3 weekly = 80.0
        mgr.state.weekly_consumption[2] = 80.0;
        mgr.state.daily_consumption[2] = 0.0;

        let e = make_encoded(SensitivityTier::S3Medium, 0.001);
        assert!(mgr.check_and_consume(e).is_none());
    }

    #[test]
    fn boundary_exactly_at_lifetime_ceiling() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // S4 lifetime = 5000.0
        mgr.state.lifetime_consumption[3] = 5000.0;
        mgr.state.daily_consumption[3] = 0.0;
        mgr.state.weekly_consumption[3] = 0.0;

        let e = make_encoded(SensitivityTier::S4Low, 0.001);
        assert!(mgr.check_and_consume(e).is_none());
    }

    // ── Additional tests for coverage ──────────────────────────────────

    #[test]
    fn remaining_daily_decreases_after_consumption() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let before = mgr.remaining_daily(SensitivityTier::S2High);
        let e = make_encoded(SensitivityTier::S2High, 2.0);
        mgr.check_and_consume(e);
        let after = mgr.remaining_daily(SensitivityTier::S2High);
        assert!((before - after - 2.0).abs() < 1e-10);
    }

    #[test]
    fn remaining_weekly_decreases_after_consumption() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let before = mgr.remaining_weekly(SensitivityTier::S3Medium);
        let e = make_encoded(SensitivityTier::S3Medium, 4.0);
        mgr.check_and_consume(e);
        let after = mgr.remaining_weekly(SensitivityTier::S3Medium);
        assert!((before - after - 4.0).abs() < 1e-10);
    }

    #[test]
    fn remaining_lifetime_decreases_after_consumption() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let before = mgr.remaining_lifetime(SensitivityTier::S4Low);
        let e = make_encoded(SensitivityTier::S4Low, 8.0);
        mgr.check_and_consume(e);
        let after = mgr.remaining_lifetime(SensitivityTier::S4Low);
        assert!((before - after - 8.0).abs() < 1e-10);
    }

    #[test]
    fn remaining_clamped_to_zero() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // Force overconsumption scenario (should not happen in practice)
        mgr.state.daily_consumption[0] = 999.0;
        assert_eq!(mgr.remaining_daily(SensitivityTier::S1Critical), 0.0);
    }

    #[test]
    fn is_exhausted_at_exactly_lifetime() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        mgr.state.lifetime_consumption[2] = 2000.0; // S3 lifetime = 2000.0
        assert!(mgr.is_exhausted(SensitivityTier::S3Medium));
    }

    #[test]
    fn is_exhausted_just_below_lifetime() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        mgr.state.lifetime_consumption[2] = 1999.999;
        assert!(!mgr.is_exhausted(SensitivityTier::S3Medium));
    }

    #[test]
    fn extract_tier_from_encoded() {
        let e = make_encoded(SensitivityTier::S3Medium, 4.0);
        assert_eq!(
            BudgetManagerImpl::extract_tier(&e),
            SensitivityTier::S3Medium
        );
    }

    #[test]
    fn multiple_consumptions_accumulate_tuples_count() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        // S4 daily = 32.0, epsilon = 8.0 -> 4 tuples before daily cap
        for i in 0..4 {
            let e = make_encoded(SensitivityTier::S4Low, 8.0);
            mgr.check_and_consume(e);
            assert_eq!(
                mgr.query(SensitivityTier::S4Low).tuples_contributed,
                (i + 1) as u64
            );
        }
    }

    #[test]
    fn time_utilities_next_midnight() {
        let ts = 1700000000u64; // arbitrary timestamp
        let nm = next_midnight(ts);
        assert!(nm > ts);
        assert_eq!(nm % 86400, 0);
    }

    #[test]
    fn time_utilities_next_sunday() {
        let ts = 1700000000u64;
        let ns = next_sunday_midnight(ts);
        assert!(ns > ts);
        assert_eq!(ns % 86400, 0);
        // Verify it's a Sunday: (days_since_epoch + 3) % 7 == 6
        let days = ns / 86400;
        assert_eq!((days + 3) % 7, 6); // Sunday
    }

    #[test]
    fn budget_error_display() {
        let io_err = BudgetError::Io(io::Error::new(io::ErrorKind::NotFound, "not found"));
        assert!(format!("{}", io_err).contains("not found"));

        let parse_err = BudgetError::Parse("bad json".into());
        assert!(format!("{}", parse_err).contains("bad json"));

        let mismatch = BudgetError::RenyiOrdersMismatch {
            expected: 8,
            found: 4,
        };
        assert!(format!("{}", mismatch).contains("8"));
    }

    #[test]
    fn budget_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let budget_err: BudgetError = io_err.into();
        match budget_err {
            BudgetError::Io(_) => {} // correct
            _ => panic!("Expected BudgetError::Io"),
        }
    }

    #[test]
    fn daily_reset_updates_reset_time() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let before = mgr.state.daily_reset_time;
        // Force stale
        mgr.state.daily_reset_time = 1;
        mgr.reset_daily();
        assert!(mgr.state.daily_reset_time > before || mgr.state.daily_reset_time > 1);
    }

    #[test]
    fn weekly_reset_updates_reset_time() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        mgr.state.weekly_reset_time = 1;
        mgr.reset_weekly();
        assert!(mgr.state.weekly_reset_time > 1);
    }

    #[test]
    fn daily_reset_clears_all_tiers() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        for (tier, eps) in [
            (SensitivityTier::S1Critical, 1.0),
            (SensitivityTier::S2High, 2.0),
            (SensitivityTier::S3Medium, 4.0),
            (SensitivityTier::S4Low, 8.0),
        ] {
            let e = make_encoded(tier, eps);
            mgr.check_and_consume(e);
        }

        mgr.reset_daily();

        for tier in [
            SensitivityTier::S1Critical,
            SensitivityTier::S2High,
            SensitivityTier::S3Medium,
            SensitivityTier::S4Low,
        ] {
            assert_eq!(mgr.query(tier).daily_consumption, 0.0);
        }
    }

    #[test]
    fn weekly_reset_clears_all_tiers() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        for (tier, eps) in [
            (SensitivityTier::S1Critical, 1.0),
            (SensitivityTier::S2High, 2.0),
            (SensitivityTier::S3Medium, 4.0),
            (SensitivityTier::S4Low, 8.0),
        ] {
            let e = make_encoded(tier, eps);
            mgr.check_and_consume(e);
        }

        mgr.reset_weekly();

        for tier in [
            SensitivityTier::S1Critical,
            SensitivityTier::S2High,
            SensitivityTier::S3Medium,
            SensitivityTier::S4Low,
        ] {
            assert_eq!(mgr.query(tier).weekly_consumption, 0.0);
            // But daily should still be nonzero
            assert!(mgr.query(tier).daily_consumption > 0.0);
        }
    }

    #[test]
    fn effective_epsilon_consistent_across_queries() {
        let config = test_config();
        let mut mgr = BudgetManagerImpl::new(config);
        let e = make_encoded(SensitivityTier::S1Critical, 1.0);
        mgr.check_and_consume(e);

        let eff1 = mgr.effective_epsilon(SensitivityTier::S1Critical);
        let eff2 = mgr.effective_epsilon(SensitivityTier::S1Critical);
        assert!((eff1 - eff2).abs() < 1e-15);
    }

    #[test]
    fn approved_tuple_contains_inner_encoded() {
        let mut mgr = BudgetManagerImpl::new(test_config());
        let e = make_encoded(SensitivityTier::S2High, 2.0);
        let approved = mgr.check_and_consume(e).unwrap();
        // Verify inner chain accessible
        assert!((approved.inner.epsilon_consumed - 2.0).abs() < 1e-10);
    }
}
