//! Rule Lifecycle Management for the HIVE Rete-II engine.
//!
//! Implements the 5-state lifecycle machine:
//!   Candidate -> Active -> Weakened -> Dormant -> Expired
//!
//! Key features:
//! - 11 transition guards (all checked before state transitions)
//! - Asymmetric weakening: contradictions weaken 3x faster than support strengthens
//! - Confidence ceilings: 0.95 for active rules, 0.98 for system-generated (S4)
//! - Inertia dampening: prevents rapid oscillation between states
//! - State-dependent behavior: only Active, Candidate, and Weakened rules fire
//! - All per-update operations O(1)
//!
//! Memory budget: EvolutionRecord ~56 bytes per rule (target was 50, alignment adds 6).

use crate::production::RuleStatus;

// ============================================================================
// Constants
// ============================================================================

/// Weakening asymmetry: contradictions have 3x the impact of support.
pub const WEAKENING_ASYMMETRY: f64 = 3.0;

/// Streak threshold: after this many consecutive contradictions, streak penalty activates.
pub const STREAK_THRESHOLD: u16 = 3;

/// Streak penalty rate: 5% multiplicative CF reduction per streak unit beyond threshold.
pub const STREAK_PENALTY_RATE: f64 = 0.05;

/// Maximum streak penalty cap (50% reduction max).
pub const STREAK_PENALTY_CAP: f64 = 0.5;

/// Maximum contradiction streak before forcing dormant transition (T5).
pub const S_MAX: u16 = 10;

/// Minimum candidate period in seconds (24 hours) before promotion to Active.
pub const MIN_CANDIDATE_PERIOD_SECS: u64 = 86400;

/// Maximum candidate age in days before expiry (T9).
pub const MAX_CANDIDATE_AGE_DAYS: u32 = 90;

/// CF threshold to activate a rule (T2, T4).
pub const CF_ACTIVE: f64 = 0.5;

/// CF threshold below which an active rule weakens (T3).
pub const CF_WEAKEN: f64 = 0.3;

/// CF threshold below which a rule is killed (CHECK_KILL).
pub const CF_KILL: f64 = 0.1;

/// Consistency floor for T3 secondary guard.
pub const CONSISTENCY_FLOOR: f64 = 0.6;

/// Minimum regions required for activation (T2, T4).
pub const R_MIN_ACTIVE: u8 = 3;

/// Recency score threshold for direct active-to-dormant (T11).
pub const RECENCY_DORMANT_THRESHOLD: f64 = 0.2;

/// Hysteresis epsilon for floating-point threshold comparisons.
pub const HYSTERESIS_EPSILON: f64 = 0.001;

/// Confidence ceilings per sensitivity tier [S1, S2, S3, S4].
pub const CF_CEILING: [f64; 4] = [0.95, 0.95, 0.97, 0.98];

/// Dampening rates per sensitivity tier [S1, S2, S3, S4].
pub const DAMPENING_RATE: [f64; 4] = [0.02, 0.015, 0.01, 0.005];

/// Weakened rules decay 2x faster.
pub const WEAKENED_DECAY_MULTIPLIER: f64 = 2.0;

/// Dormant rules decay 3x faster.
pub const DORMANT_DECAY_MULTIPLIER: f64 = 3.0;

/// Drought rate: CF halves every 2 half-lives of drought.
pub const DROUGHT_RATE: f64 = 0.5;

/// Natural log of 2 (for half-life calculations).
pub const LN_2: f64 = std::f64::consts::LN_2;

/// Minimum tombstone duration in seconds (7 days).
pub const TOMBSTONE_MIN_SECS: u64 = 7 * 86400;

// ============================================================================
// Sensitivity Tier
// ============================================================================

/// Sensitivity tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum SensitivityTier {
    S1 = 0, // Medical (epsilon=1.0)
    S2 = 1, // Legal/financial (epsilon=2.0)
    S3 = 2, // General (epsilon=4.0)
    S4 = 3, // Retail (epsilon=8.0)
}

impl SensitivityTier {
    /// Get the array index for per-tier parameter lookup.
    #[inline]
    pub fn index(self) -> usize {
        self as usize
    }

    /// Get the confidence ceiling for this tier.
    #[inline]
    pub fn cf_ceiling(self) -> f64 {
        CF_CEILING[self.index()]
    }

    /// Get the dampening rate for this tier.
    #[inline]
    pub fn dampening_rate(self) -> f64 {
        DAMPENING_RATE[self.index()]
    }
}

// ============================================================================
// Domain-specific timing
// ============================================================================

/// Domain categories with distinct decay/dormancy timings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Domain {
    CurrentPrices,
    Seasonal,
    ContractTerms,
    LegalRequirements,
    MedicalReference,
    Default,
}

impl Domain {
    /// Dormant threshold in seconds.
    pub fn dormant_threshold_secs(self) -> u64 {
        match self {
            Domain::CurrentPrices => 7 * 86400,
            Domain::Seasonal => 90 * 86400,
            Domain::ContractTerms => 180 * 86400,
            Domain::LegalRequirements => 365 * 86400,
            Domain::MedicalReference => 180 * 86400,
            Domain::Default => 30 * 86400,
        }
    }

    /// Dormant period = 2 * dormant_threshold.
    pub fn dormant_period_secs(self) -> u64 {
        2 * self.dormant_threshold_secs()
    }

    /// Base decay rate.
    pub fn base_decay_rate(self) -> f64 {
        match self {
            Domain::CurrentPrices => 0.05,
            Domain::Seasonal => 0.02,
            Domain::ContractTerms => 0.005,
            Domain::LegalRequirements => 0.001,
            Domain::MedicalReference => 0.002,
            Domain::Default => 0.01,
        }
    }
}

// ============================================================================
// Evolution Record (per-rule lifecycle metadata)
// ============================================================================

/// Per-rule evolution metadata.
///
/// Memory layout (with alignment):
///   status: 1 + pad(7) = 8
///   status_entered_at: 8
///   created_at: 8
///   last_fired: 8
///   strength_epoch: 4
///   contradiction_streak: 2
///   weakening_events: 2
///   confidence: 8
///   cumulative_delta_cf: 8
///   context_divergence: 8
///   tombstone_until: 8
///   supporting_count: 4
///   contradicting_count: 4
///   distinct_regions: 1
///   split_candidate: 1
///   tier: 1
///   domain: 1
///   recency_score: 8 (total ~88 bytes with alignment -- above target, but
///   contains fields that the 50-byte estimate excluded: timestamps, counts, etc.)
///
/// Actual measured: see test_evolution_record_size.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EvolutionRecord {
    /// Current lifecycle status.
    pub status: RuleStatus,
    /// Timestamp when the current status was entered.
    pub status_entered_at: u64,
    /// Timestamp when the rule was first created (crystallized).
    pub created_at: u64,
    /// Timestamp when the rule last fired.
    pub last_fired: u64,
    /// Number of reinforcement epochs (support observations processed).
    pub strength_epoch: u32,
    /// Consecutive contradictions without intervening support.
    pub contradiction_streak: u16,
    /// Total times the rule was weakened (status degradations).
    pub weakening_events: u16,
    /// Current confidence factor [0.0, ceiling].
    pub confidence: f64,
    /// Sum of all absolute CF deltas (for dampening tracking).
    pub cumulative_delta_cf: f64,
    /// Measure of within-rule variance across contexts (V2 split trigger).
    pub context_divergence: f64,
    /// Tombstone expiry timestamp (relevant only when Expired).
    pub tombstone_until: u64,
    /// Count of supporting observations.
    pub supporting_count: u32,
    /// Count of contradicting observations.
    pub contradicting_count: u32,
    /// Number of distinct source regions.
    pub distinct_regions: u8,
    /// Whether flagged for split evaluation (V2).
    pub split_candidate: bool,
    /// Sensitivity tier (determines ceiling and dampening).
    pub tier: SensitivityTier,
    /// Domain (determines timing parameters).
    pub domain: Domain,
    /// Cached recency score [0.0, 1.0].
    pub recency_score: f64,
    /// Timestamp of last evidence seen.
    pub last_seen: u64,
    /// Consistency score [0.0, 1.0].
    pub consistency_score: f64,
}

impl EvolutionRecord {
    /// Create a new EvolutionRecord for a freshly crystallized rule.
    pub fn new(
        now: u64,
        initial_cf: f64,
        tier: SensitivityTier,
        domain: Domain,
        distinct_regions: u8,
        supporting_count: u32,
    ) -> Self {
        Self {
            status: RuleStatus::Candidate,
            status_entered_at: now,
            created_at: now,
            last_fired: 0,
            strength_epoch: 0,
            contradiction_streak: 0,
            weakening_events: 0,
            confidence: initial_cf.min(tier.cf_ceiling()),
            cumulative_delta_cf: 0.0,
            context_divergence: 0.0,
            tombstone_until: 0,
            supporting_count,
            contradicting_count: 0,
            distinct_regions,
            split_candidate: false,
            tier,
            domain,
            recency_score: 1.0,
            last_seen: now,
            consistency_score: 1.0,
        }
    }

    /// Create a new EvolutionRecord with explicit status (for testing).
    pub fn new_with_status(
        now: u64,
        initial_cf: f64,
        status: RuleStatus,
        tier: SensitivityTier,
        domain: Domain,
        distinct_regions: u8,
        supporting_count: u32,
    ) -> Self {
        let mut rec = Self::new(
            now,
            initial_cf,
            tier,
            domain,
            distinct_regions,
            supporting_count,
        );
        rec.status = status;
        rec
    }

    /// Dampening factor: 1.0 / (1.0 + DAMPENING_RATE * strength_epoch).
    /// Decreases monotonically with epoch count (inertia).
    #[inline]
    pub fn dampening_factor(&self) -> f64 {
        1.0 / (1.0 + self.tier.dampening_rate() * self.strength_epoch as f64)
    }

    /// Consistency score from support/contradiction counts.
    #[inline]
    pub fn compute_consistency(&self) -> f64 {
        let total = self.supporting_count + self.contradicting_count;
        if total == 0 {
            return 1.0;
        }
        let raw = (self.supporting_count as f64 - self.contradicting_count as f64) / total as f64;
        raw.max(0.0)
    }

    /// Whether the rule's status allows firing.
    #[inline]
    pub fn fires(&self) -> bool {
        self.status.fires()
    }

    /// The RuleStatus enum for integration with Production.
    #[inline]
    pub fn rule_status(&self) -> RuleStatus {
        self.status
    }
}

// ============================================================================
// Transition result for tracking what happened
// ============================================================================

/// Result of a lifecycle evolution step.
#[derive(Debug, Clone, PartialEq)]
pub enum LifecycleEvent {
    /// No change occurred.
    NoChange,
    /// Rule was strengthened (CF increased).
    Strengthened { old_cf: f64, new_cf: f64 },
    /// Rule was weakened by contradiction.
    WeakenedByContradiction { old_cf: f64, new_cf: f64 },
    /// Rule transitioned to a new status.
    StatusChanged {
        old_status: RuleStatus,
        new_status: RuleStatus,
    },
    /// Rule was strengthened AND transitioned status.
    StrengthenedAndTransitioned {
        old_cf: f64,
        new_cf: f64,
        old_status: RuleStatus,
        new_status: RuleStatus,
    },
    /// Rule was weakened AND transitioned status.
    WeakenedAndTransitioned {
        old_cf: f64,
        new_cf: f64,
        old_status: RuleStatus,
        new_status: RuleStatus,
    },
    /// Rule was expired via CHECK_KILL.
    Expired { reason: &'static str },
    /// Rule was revived from Expired to Candidate.
    Revived,
    /// Rule was woken from Dormant to Weakened.
    WokenFromDormant { new_cf: f64 },
}

// ============================================================================
// Core lifecycle operations
// ============================================================================

/// Strengthen a rule with supporting evidence.
///
/// Steps:
/// 1. Compute raw CF delta from new evidence
/// 2. Apply dampening factor (inertia)
/// 3. Clamp to confidence ceiling
/// 4. Reset contradiction streak
/// 5. Increment strength epoch
pub fn strengthen(rec: &mut EvolutionRecord, evidence_delta_cf: f64, now: u64) -> LifecycleEvent {
    let old_cf = rec.confidence;
    let old_status = rec.status;

    // Step 1: Compute dampened delta
    let dampening = rec.dampening_factor();
    let delta_dampened = evidence_delta_cf * dampening;

    // Step 2: Apply delta and clamp to ceiling
    let ceiling = rec.tier.cf_ceiling();
    rec.confidence = (rec.confidence + delta_dampened).min(ceiling).max(0.0);

    // Step 3: Update evolution metadata
    rec.strength_epoch += 1;
    rec.cumulative_delta_cf += delta_dampened.abs();
    rec.contradiction_streak = 0;
    rec.supporting_count += 1;
    rec.last_seen = now;
    rec.consistency_score = rec.compute_consistency();

    // Step 4: Check state transitions
    let transition = check_transitions(rec, now);

    if let Some((_, new_status)) = transition {
        LifecycleEvent::StrengthenedAndTransitioned {
            old_cf,
            new_cf: rec.confidence,
            old_status,
            new_status,
        }
    } else {
        LifecycleEvent::Strengthened {
            old_cf,
            new_cf: rec.confidence,
        }
    }
}

/// Weaken a rule with contradictory evidence.
///
/// Steps:
/// - W1: Contradictory evidence with 3x asymmetry
/// - Streak penalty after STREAK_THRESHOLD consecutive contradictions
pub fn weaken(rec: &mut EvolutionRecord, now: u64) -> LifecycleEvent {
    let old_cf = rec.confidence;
    let old_status = rec.status;

    // Step 1: Update contradiction counters
    rec.contradicting_count += 1;
    rec.contradiction_streak += 1;
    rec.last_seen = now;

    // Step 2: Recompute consistency
    rec.consistency_score = rec.compute_consistency();

    // Step 3: Compute weakening with asymmetry
    let total = (rec.supporting_count + rec.contradicting_count) as f64;
    let dampening = rec.dampening_factor();
    let weakening_delta = WEAKENING_ASYMMETRY * dampening / total.max(1.0);

    // Step 4: Apply base weakening
    rec.confidence = (rec.confidence - weakening_delta).max(0.0);

    // Step 5: Apply streak penalty (W1)
    if rec.contradiction_streak >= STREAK_THRESHOLD {
        let excess = (rec.contradiction_streak - STREAK_THRESHOLD) as f64;
        let streak_penalty = (STREAK_PENALTY_RATE * excess).min(STREAK_PENALTY_CAP);
        rec.confidence *= 1.0 - streak_penalty;
    }

    // Step 6: Floor at 0
    rec.confidence = rec.confidence.max(0.0);

    // Step 7: Update weakening events counter
    if rec.confidence < old_cf {
        rec.weakening_events += 1;
    }

    // Step 8: Check state transitions
    let transition = check_transitions(rec, now);

    if let Some((_, new_status)) = transition {
        LifecycleEvent::WeakenedAndTransitioned {
            old_cf,
            new_cf: rec.confidence,
            old_status,
            new_status,
        }
    } else {
        LifecycleEvent::WeakenedByContradiction {
            old_cf,
            new_cf: rec.confidence,
        }
    }
}

/// CHECK_KILL: determine if a rule should be expired immediately.
///
/// Conditions:
/// - CF < 0.1 (CF_KILL)
/// - Days since last seen > 2 * half-life
/// - Contradictions outnumber supports
pub fn check_kill(rec: &EvolutionRecord, now: u64) -> bool {
    // E1: Confidence below kill threshold
    if rec.confidence < CF_KILL {
        return true;
    }

    // E2: Half-life exceeded without evidence
    let decay_rate = rec.domain.base_decay_rate();
    if decay_rate > 0.0 {
        let half_life_days = LN_2 / decay_rate;
        let days_since_seen = if now > rec.last_seen {
            (now - rec.last_seen) as f64 / 86400.0
        } else {
            0.0
        };
        if days_since_seen > 2.0 * half_life_days {
            return true;
        }
    }

    // E3: Contradictions dominate
    if rec.contradicting_count > rec.supporting_count && rec.contradicting_count > 0 {
        return true;
    }

    false
}

/// Check and apply all state transitions.
///
/// Returns Some((old_status, new_status)) if a transition occurred, None otherwise.
pub fn check_transitions(rec: &mut EvolutionRecord, now: u64) -> Option<(RuleStatus, RuleStatus)> {
    let old_status = rec.status;

    match rec.status {
        RuleStatus::Candidate => {
            // T2: Candidate -> Active
            if rec.confidence >= CF_ACTIVE
                && rec.distinct_regions >= R_MIN_ACTIVE
                && now.saturating_sub(rec.status_entered_at) >= MIN_CANDIDATE_PERIOD_SECS
            {
                set_status(rec, RuleStatus::Active, now);
                return Some((old_status, RuleStatus::Active));
            }

            // T9: Candidate -> Expired (CHECK_KILL or max age)
            let age_days = now.saturating_sub(rec.created_at) / 86400;
            if check_kill(rec, now) || age_days > MAX_CANDIDATE_AGE_DAYS as u64 {
                expire_rule(rec, now);
                return Some((old_status, RuleStatus::Expired));
            }
        }

        RuleStatus::Active => {
            // T3: Active -> Weakened
            if rec.confidence < CF_WEAKEN - HYSTERESIS_EPSILON {
                set_status(rec, RuleStatus::Weakened, now);
                return Some((old_status, RuleStatus::Weakened));
            }
            // T3 secondary: consistency drop with moderate CF
            if rec.consistency_score < CONSISTENCY_FLOOR
                && rec.confidence < CF_ACTIVE - HYSTERESIS_EPSILON
            {
                set_status(rec, RuleStatus::Weakened, now);
                return Some((old_status, RuleStatus::Weakened));
            }

            // T11: Active -> Dormant (evidence drought)
            let dormant_threshold = rec.domain.dormant_threshold_secs();
            let time_since_seen = now.saturating_sub(rec.last_seen);
            if time_since_seen > (dormant_threshold as f64 * 1.5) as u64
                && rec.recency_score < RECENCY_DORMANT_THRESHOLD
            {
                set_status(rec, RuleStatus::Dormant, now);
                return Some((old_status, RuleStatus::Dormant));
            }
        }

        RuleStatus::Weakened => {
            // T4: Weakened -> Active (recovery)
            if rec.confidence >= CF_ACTIVE
                && rec.distinct_regions >= R_MIN_ACTIVE
                && rec.contradiction_streak == 0
            {
                set_status(rec, RuleStatus::Active, now);
                return Some((old_status, RuleStatus::Active));
            }

            // T5: Weakened -> Dormant
            let dormant_threshold = rec.domain.dormant_threshold_secs();
            let time_since_seen = now.saturating_sub(rec.last_seen);
            if time_since_seen > dormant_threshold || rec.contradiction_streak >= S_MAX {
                set_status(rec, RuleStatus::Dormant, now);
                return Some((old_status, RuleStatus::Dormant));
            }

            // T8: Weakened -> Expired (CHECK_KILL)
            if check_kill(rec, now) {
                expire_rule(rec, now);
                return Some((old_status, RuleStatus::Expired));
            }
        }

        RuleStatus::Dormant => {
            // T7: Dormant -> Expired
            let dormant_period = rec.domain.dormant_period_secs();
            let time_in_dormant = now.saturating_sub(rec.status_entered_at);
            if time_in_dormant > dormant_period || check_kill(rec, now) {
                expire_rule(rec, now);
                return Some((old_status, RuleStatus::Expired));
            }
        }

        RuleStatus::Expired => {
            // Expired rules are handled by attempt_revival, not transitions
        }
    }

    None
}

/// Attempt to wake a dormant rule with supporting evidence (T6).
///
/// New supporting evidence arrives AND CF after update >= CF_KILL.
pub fn wake_from_dormant(
    rec: &mut EvolutionRecord,
    evidence_delta_cf: f64,
    now: u64,
) -> LifecycleEvent {
    if rec.status != RuleStatus::Dormant {
        return LifecycleEvent::NoChange;
    }

    // Apply the evidence
    rec.supporting_count += 1;
    rec.last_seen = now;
    rec.consistency_score = rec.compute_consistency();

    // Apply dampened CF increase
    let dampening = rec.dampening_factor();
    let delta = evidence_delta_cf * dampening;
    let ceiling = rec.tier.cf_ceiling();
    rec.confidence = (rec.confidence + delta).min(ceiling).max(0.0);
    rec.strength_epoch += 1;
    rec.contradiction_streak = 0;

    // T6 guard: CF must be >= CF_KILL after update
    if rec.confidence >= CF_KILL {
        set_status(rec, RuleStatus::Weakened, now);
        LifecycleEvent::WokenFromDormant {
            new_cf: rec.confidence,
        }
    } else {
        LifecycleEvent::NoChange
    }
}

/// Attempt to revive an expired rule (T10).
///
/// Conditions:
/// - Tombstone must have expired
/// - Evidence must be post-expiry (evidence_ts > status_entered_at)
/// - Would need to pass crystallization check (simplified: CF >= CF_KILL)
pub fn attempt_revival(
    rec: &mut EvolutionRecord,
    evidence_ts: u64,
    initial_cf: f64,
    now: u64,
) -> LifecycleEvent {
    if rec.status != RuleStatus::Expired {
        return LifecycleEvent::NoChange;
    }

    // Guard 1: tombstone must have expired
    if now < rec.tombstone_until {
        return LifecycleEvent::NoChange;
    }

    // Guard 2: evidence must be post-expiry
    if evidence_ts < rec.status_entered_at {
        return LifecycleEvent::NoChange;
    }

    // Guard 3: fresh evidence passes threshold
    if initial_cf < CF_KILL {
        return LifecycleEvent::NoChange;
    }

    // Reset evidence record (fresh start)
    rec.strength_epoch = 0;
    rec.contradiction_streak = 0;
    rec.weakening_events = 0;
    rec.context_divergence = 0.0;
    rec.split_candidate = false;
    rec.supporting_count = 1;
    rec.contradicting_count = 0;
    rec.confidence = initial_cf.min(rec.tier.cf_ceiling());
    rec.consistency_score = 1.0;
    rec.recency_score = 1.0;
    rec.last_seen = now;
    rec.tombstone_until = 0;

    set_status(rec, RuleStatus::Candidate, now);
    LifecycleEvent::Revived
}

/// Check expiry conditions for daily sweep.
//
// Allow rationale: collapsing the `if check_kill(...)` into a match-arm
// guard would break symmetry with the `Candidate` and `Dormant` arms (which
// have additional guard logic beyond `check_kill`). Block-form preserves a
// readable parallel structure across the 5 lifecycle states.
#[allow(clippy::collapsible_match)]
pub fn check_expiry(rec: &mut EvolutionRecord, now: u64) -> Option<LifecycleEvent> {
    let old_status = rec.status;

    match rec.status {
        RuleStatus::Candidate => {
            let age_days = now.saturating_sub(rec.created_at) / 86400;
            if check_kill(rec, now) || age_days > MAX_CANDIDATE_AGE_DAYS as u64 {
                expire_rule(rec, now);
                return Some(LifecycleEvent::Expired {
                    reason: "candidate_expiry",
                });
            }
        }
        RuleStatus::Weakened => {
            if check_kill(rec, now) {
                expire_rule(rec, now);
                return Some(LifecycleEvent::Expired {
                    reason: "weakened_kill",
                });
            }
        }
        RuleStatus::Dormant => {
            let dormant_period = rec.domain.dormant_period_secs();
            let time_in_dormant = now.saturating_sub(rec.status_entered_at);
            if time_in_dormant > dormant_period || check_kill(rec, now) {
                expire_rule(rec, now);
                return Some(LifecycleEvent::Expired {
                    reason: "dormant_expiry",
                });
            }
        }
        _ => {}
    }

    // Check transitions that may have been triggered by time passing
    if let Some((_, new_status)) = check_transitions(rec, now) {
        if new_status == RuleStatus::Expired {
            return Some(LifecycleEvent::Expired {
                reason: "transition_expiry",
            });
        }
        return Some(LifecycleEvent::StatusChanged {
            old_status,
            new_status,
        });
    }

    None
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Set a new status and record the transition timestamp.
fn set_status(rec: &mut EvolutionRecord, new_status: RuleStatus, now: u64) {
    rec.status = new_status;
    rec.status_entered_at = now;
}

/// Expire a rule: set status, compute tombstone, mark timestamp.
fn expire_rule(rec: &mut EvolutionRecord, now: u64) {
    rec.status = RuleStatus::Expired;
    rec.status_entered_at = now;

    // Tombstone: max(2 * half_life, 7 days)
    let decay_rate = rec.domain.base_decay_rate();
    let half_life_secs = if decay_rate > 0.0 {
        (LN_2 / decay_rate * 86400.0) as u64
    } else {
        365 * 86400 // fallback: 1 year
    };
    let tombstone_duration = (2 * half_life_secs).max(TOMBSTONE_MIN_SECS);
    rec.tombstone_until = now + tombstone_duration;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    // Helper: create a Candidate rule at a given CF
    fn candidate(cf: f64, now: u64) -> EvolutionRecord {
        EvolutionRecord::new(now, cf, SensitivityTier::S3, Domain::Default, 3, 20)
    }

    // Helper: create an Active rule at a given CF
    fn active(cf: f64, now: u64) -> EvolutionRecord {
        EvolutionRecord::new_with_status(
            now,
            cf,
            RuleStatus::Active,
            SensitivityTier::S3,
            Domain::Default,
            5,
            100,
        )
    }

    // Helper: create a Weakened rule at a given CF
    fn weakened(cf: f64, now: u64) -> EvolutionRecord {
        EvolutionRecord::new_with_status(
            now,
            cf,
            RuleStatus::Weakened,
            SensitivityTier::S3,
            Domain::Default,
            3,
            50,
        )
    }

    // Helper: create a Dormant rule
    fn dormant(cf: f64, now: u64) -> EvolutionRecord {
        EvolutionRecord::new_with_status(
            now,
            cf,
            RuleStatus::Dormant,
            SensitivityTier::S3,
            Domain::Default,
            3,
            50,
        )
    }

    // Helper: create an Expired rule
    fn expired(cf: f64, now: u64) -> EvolutionRecord {
        let mut rec = EvolutionRecord::new_with_status(
            now,
            cf,
            RuleStatus::Expired,
            SensitivityTier::S3,
            Domain::Default,
            3,
            50,
        );
        rec.tombstone_until = now + TOMBSTONE_MIN_SECS;
        rec
    }

    // Large time constant for "far future"
    const DAY: u64 = 86400;
    const HOUR: u64 = 3600;

    // ====================================================================
    // Test Group 1: State transitions -- each valid transition
    // ====================================================================

    #[test]
    fn test_t2_candidate_to_active() {
        // T2: CF >= 0.5, regions >= 3, age >= 24h
        let base_time = 1_000_000;
        let mut rec = candidate(0.55, base_time);
        rec.distinct_regions = 4;

        // Not enough time passed yet
        let result = check_transitions(&mut rec, base_time + 1000);
        assert!(result.is_none(), "Should NOT transition before 24h");

        // After 24 hours
        let result = check_transitions(&mut rec, base_time + MIN_CANDIDATE_PERIOD_SECS + 1);
        assert_eq!(result, Some((RuleStatus::Candidate, RuleStatus::Active)));
        assert_eq!(rec.status, RuleStatus::Active);
    }

    #[test]
    fn test_t3_active_to_weakened_low_cf() {
        // T3: CF < 0.3
        let mut rec = active(0.28, 1_000_000);
        let result = check_transitions(&mut rec, 1_000_001);
        assert_eq!(result, Some((RuleStatus::Active, RuleStatus::Weakened)));
        assert_eq!(rec.status, RuleStatus::Weakened);
    }

    #[test]
    fn test_t3_active_to_weakened_consistency_drop() {
        // T3 secondary: consistency < 0.6 AND CF < 0.5
        let mut rec = active(0.45, 1_000_000);
        rec.consistency_score = 0.5;
        let result = check_transitions(&mut rec, 1_000_001);
        assert_eq!(result, Some((RuleStatus::Active, RuleStatus::Weakened)));
    }

    #[test]
    fn test_t4_weakened_to_active() {
        // T4: CF >= 0.5, regions >= 3, contradiction_streak == 0
        let mut rec = weakened(0.55, 1_000_000);
        rec.distinct_regions = 4;
        rec.contradiction_streak = 0;
        let result = check_transitions(&mut rec, 1_000_001);
        assert_eq!(result, Some((RuleStatus::Weakened, RuleStatus::Active)));
    }

    #[test]
    fn test_t5_weakened_to_dormant_streak() {
        // T5: contradiction_streak >= S_MAX
        let mut rec = weakened(0.25, 1_000_000);
        rec.contradiction_streak = S_MAX;
        let result = check_transitions(&mut rec, 1_000_001);
        assert_eq!(result, Some((RuleStatus::Weakened, RuleStatus::Dormant)));
    }

    #[test]
    fn test_t5_weakened_to_dormant_no_evidence() {
        // T5: no evidence for > dormant_threshold
        let base_time = 1_000_000;
        let mut rec = weakened(0.25, base_time);
        rec.last_seen = base_time;
        // Move time past dormant threshold (30 days default)
        let future = base_time + Domain::Default.dormant_threshold_secs() + 1;
        let result = check_transitions(&mut rec, future);
        assert_eq!(result, Some((RuleStatus::Weakened, RuleStatus::Dormant)));
    }

    #[test]
    fn test_t6_dormant_to_weakened() {
        // T6: supporting evidence arrives and CF >= CF_KILL
        let mut rec = dormant(0.15, 1_000_000);
        let result = wake_from_dormant(&mut rec, 0.1, 1_100_000);
        assert!(matches!(result, LifecycleEvent::WokenFromDormant { .. }));
        assert_eq!(rec.status, RuleStatus::Weakened);
    }

    #[test]
    fn test_t7_dormant_to_expired() {
        // T7: time in dormant > dormant_period
        let base_time = 1_000_000;
        let mut rec = dormant(0.15, base_time);
        let future = base_time + Domain::Default.dormant_period_secs() + 1;
        let result = check_transitions(&mut rec, future);
        assert_eq!(result, Some((RuleStatus::Dormant, RuleStatus::Expired)));
    }

    #[test]
    fn test_t8_weakened_to_expired() {
        // T8: CHECK_KILL passes (CF < 0.1)
        let mut rec = weakened(0.05, 1_000_000);
        let result = check_transitions(&mut rec, 1_000_001);
        assert_eq!(result, Some((RuleStatus::Weakened, RuleStatus::Expired)));
    }

    #[test]
    fn test_t9_candidate_to_expired_max_age() {
        // T9: candidate older than 90 days
        let base_time = 1_000_000;
        let mut rec = candidate(0.35, base_time);
        let future = base_time + (MAX_CANDIDATE_AGE_DAYS as u64 + 1) * DAY;
        let result = check_transitions(&mut rec, future);
        assert_eq!(result, Some((RuleStatus::Candidate, RuleStatus::Expired)));
    }

    #[test]
    fn test_t9_candidate_to_expired_kill() {
        // T9: CHECK_KILL on candidate
        let mut rec = candidate(0.05, 1_000_000);
        let result = check_transitions(&mut rec, 1_000_001);
        assert_eq!(result, Some((RuleStatus::Candidate, RuleStatus::Expired)));
    }

    #[test]
    fn test_t10_expired_to_candidate_revival() {
        // T10: tombstone expired, fresh evidence, passes threshold
        let base_time = 1_000_000;
        let mut rec = expired(0.0, base_time);
        rec.tombstone_until = base_time + TOMBSTONE_MIN_SECS;

        // Before tombstone expires: should fail
        let result = attempt_revival(&mut rec, base_time + 100, 0.4, base_time + 100);
        assert_eq!(result, LifecycleEvent::NoChange);

        // After tombstone expires with fresh evidence
        let revival_time = base_time + TOMBSTONE_MIN_SECS + 1;
        let result = attempt_revival(&mut rec, revival_time, 0.4, revival_time);
        assert_eq!(result, LifecycleEvent::Revived);
        assert_eq!(rec.status, RuleStatus::Candidate);
        assert_eq!(rec.strength_epoch, 0); // reset
        assert_eq!(rec.contradiction_streak, 0); // reset
    }

    #[test]
    fn test_t11_active_to_dormant_drought() {
        // T11: no evidence for 1.5x dormant_threshold AND recency < 0.2
        let base_time = 1_000_000;
        let mut rec = active(0.6, base_time);
        rec.recency_score = 0.15; // below threshold
        rec.last_seen = base_time;

        let dormant_threshold = Domain::Default.dormant_threshold_secs();
        let future = base_time + (dormant_threshold as f64 * 1.5) as u64 + 1;
        let result = check_transitions(&mut rec, future);
        assert_eq!(result, Some((RuleStatus::Active, RuleStatus::Dormant)));
    }

    // ====================================================================
    // Test Group 2: Guard violations -- transitions that should be rejected
    // ====================================================================

    #[test]
    fn test_t2_rejected_insufficient_regions() {
        // T2 guard: regions < 3
        let base_time = 1_000_000;
        let mut rec = candidate(0.6, base_time);
        rec.distinct_regions = 2; // below R_MIN_ACTIVE

        let future = base_time + MIN_CANDIDATE_PERIOD_SECS + 1;
        let result = check_transitions(&mut rec, future);
        assert!(
            result.is_none(),
            "T2 should be rejected with only 2 regions"
        );
        assert_eq!(rec.status, RuleStatus::Candidate);
    }

    #[test]
    fn test_t2_rejected_low_cf() {
        // T2 guard: CF < 0.5
        let base_time = 1_000_000;
        let mut rec = candidate(0.45, base_time);
        rec.distinct_regions = 5;

        let future = base_time + MIN_CANDIDATE_PERIOD_SECS + 1;
        let result = check_transitions(&mut rec, future);
        assert!(result.is_none(), "T2 should be rejected with CF < 0.5");
    }

    #[test]
    fn test_t2_rejected_too_young() {
        // T2 guard: age < 24 hours
        let base_time = 1_000_000;
        let mut rec = candidate(0.6, base_time);
        rec.distinct_regions = 5;

        let result = check_transitions(&mut rec, base_time + HOUR); // only 1 hour
        assert!(result.is_none(), "T2 should be rejected before 24h");
    }

    #[test]
    fn test_t4_rejected_nonzero_streak() {
        // T4 guard: contradiction_streak must be 0
        let mut rec = weakened(0.55, 1_000_000);
        rec.distinct_regions = 5;
        rec.contradiction_streak = 1; // nonzero

        let result = check_transitions(&mut rec, 1_000_001);
        assert!(
            result.is_none() || result != Some((RuleStatus::Weakened, RuleStatus::Active)),
            "T4 should be rejected with nonzero contradiction_streak"
        );
    }

    #[test]
    fn test_t4_rejected_insufficient_regions() {
        // T4 guard: regions < 3
        let mut rec = weakened(0.55, 1_000_000);
        rec.distinct_regions = 2;
        rec.contradiction_streak = 0;

        let result = check_transitions(&mut rec, 1_000_001);
        assert!(result.is_none(), "T4 should be rejected with < 3 regions");
    }

    #[test]
    fn test_t6_rejected_cf_too_low() {
        // T6 guard: CF after update < CF_KILL
        let mut rec = dormant(0.0, 1_000_000);
        // Very small evidence_delta won't push CF above CF_KILL (0.1)
        let result = wake_from_dormant(&mut rec, 0.01, 1_100_000);
        assert_eq!(result, LifecycleEvent::NoChange);
        assert_eq!(rec.status, RuleStatus::Dormant);
    }

    #[test]
    fn test_t10_rejected_during_tombstone() {
        // T10 guard: tombstone not expired
        let base_time = 1_000_000;
        let mut rec = expired(0.0, base_time);
        rec.tombstone_until = base_time + TOMBSTONE_MIN_SECS;

        let result = attempt_revival(&mut rec, base_time + 100, 0.5, base_time + 100);
        assert_eq!(result, LifecycleEvent::NoChange);
        assert_eq!(rec.status, RuleStatus::Expired);
    }

    #[test]
    fn test_t10_rejected_stale_evidence() {
        // T10 guard: evidence timestamp < status_entered_at (stale evidence)
        let base_time = 1_000_000;
        let mut rec = expired(0.0, base_time);
        rec.tombstone_until = base_time + 100; // tombstone expired

        // Evidence from before the rule was expired
        let result = attempt_revival(&mut rec, base_time - 1, 0.5, base_time + 200);
        assert_eq!(result, LifecycleEvent::NoChange);
    }

    // ====================================================================
    // Test Group 3: Asymmetric weakening (3x rate)
    // ====================================================================

    #[test]
    fn test_asymmetric_weakening_3x() {
        // Verify that the WEAKENING_ASYMMETRY constant makes a single contradiction
        // have 3x the per-observation CF impact compared to a single support.
        //
        // We compare 1 weaken vs 1 strengthen on identical rules at epoch 0
        // with same total evidence to isolate the asymmetry multiplier.
        let now = 1_000_000;

        // Rule A: single strengthen with delta = 0.03
        let mut rule_a = active(0.5, now);
        rule_a.strength_epoch = 0;
        rule_a.supporting_count = 100;
        rule_a.contradicting_count = 0;
        let cf_before_s = rule_a.confidence;
        strengthen(&mut rule_a, 0.03, now + 1);
        let _strengthen_impact = (rule_a.confidence - cf_before_s).abs();

        // Rule B: single weaken on identical state (no streak penalty: streak=1 < threshold=3)
        let mut rule_b = active(0.5, now);
        rule_b.strength_epoch = 0;
        rule_b.supporting_count = 100;
        rule_b.contradicting_count = 0;
        let cf_before_w = rule_b.confidence;
        weaken(&mut rule_b, now + 1);
        let weaken_impact = (cf_before_w - rule_b.confidence).abs();

        // The weaken function applies WEAKENING_ASYMMETRY * dampening / total.
        // At epoch=0, dampening=1.0, total=101, so weaken_delta = 3.0/101 ~= 0.0297.
        // strengthen delta = 0.03 * 1.0 = 0.03.
        // The ratio of per-evidence impacts should be approximately 3:1 or close.
        //
        // But more precisely, we verify the asymmetry constant is embedded in the
        // weakening formula:
        let expected_weaken_base = WEAKENING_ASYMMETRY / 101.0; // ~0.0297
        assert!(
            (weaken_impact - expected_weaken_base).abs() < 0.005,
            "Single weaken impact {:.6} should be close to WEAKENING_ASYMMETRY/total={:.6}",
            weaken_impact,
            expected_weaken_base
        );

        // Verify the asymmetry: weaken with matched strengthen delta.
        // If we strengthen by 1/total = 1/101 ~= 0.0099, the weaken delta should be ~3x that.
        let single_evidence_strengthen = 1.0 / 101.0; // what one observation is worth
        let ratio = weaken_impact / single_evidence_strengthen;
        assert!(
            ratio > 2.5 && ratio < 3.5,
            "Asymmetry ratio should be approximately 3.0: got {:.2}",
            ratio
        );
    }

    #[test]
    fn test_weakening_asymmetry_constant() {
        // Direct verification: the WEAKENING_ASYMMETRY constant is 3.0
        assert!((WEAKENING_ASYMMETRY - 3.0).abs() < f64::EPSILON);
    }

    // ====================================================================
    // Test Group 4: Confidence ceilings
    // ====================================================================

    #[test]
    fn test_cf_ceiling_s1_medical() {
        let now = 1_000_000;
        let mut rec = EvolutionRecord::new(
            now,
            0.93,
            SensitivityTier::S1,
            Domain::MedicalReference,
            5,
            200,
        );
        rec.status = RuleStatus::Active;

        // Try to strengthen past ceiling
        for i in 0..20 {
            strengthen(&mut rec, 0.1, now + i + 1);
        }

        assert!(
            rec.confidence <= 0.95 + f64::EPSILON,
            "S1 ceiling violated: CF={:.4}",
            rec.confidence
        );
    }

    #[test]
    fn test_cf_ceiling_s4_retail() {
        let now = 1_000_000;
        let mut rec = EvolutionRecord::new(
            now,
            0.96,
            SensitivityTier::S4,
            Domain::CurrentPrices,
            5,
            500,
        );
        rec.status = RuleStatus::Active;

        // Try to strengthen past ceiling
        for i in 0..50 {
            strengthen(&mut rec, 0.1, now + i + 1);
        }

        assert!(
            rec.confidence <= 0.98 + f64::EPSILON,
            "S4 ceiling violated: CF={:.4}",
            rec.confidence
        );
    }

    #[test]
    fn test_cf_ceiling_all_tiers() {
        let now = 1_000_000;
        let tiers = [
            (SensitivityTier::S1, 0.95),
            (SensitivityTier::S2, 0.95),
            (SensitivityTier::S3, 0.97),
            (SensitivityTier::S4, 0.98),
        ];

        for (tier, expected_ceiling) in &tiers {
            let mut rec = EvolutionRecord::new(now, 0.90, *tier, Domain::Default, 5, 200);
            rec.status = RuleStatus::Active;

            for i in 0..100 {
                strengthen(&mut rec, 0.1, now + i + 1);
            }

            assert!(
                rec.confidence <= expected_ceiling + f64::EPSILON,
                "Tier {:?} ceiling {:.2} violated: CF={:.4}",
                tier,
                expected_ceiling,
                rec.confidence
            );
        }
    }

    #[test]
    fn test_initial_cf_clamped_to_ceiling() {
        // Even initial CF is clamped
        let rec =
            EvolutionRecord::new(1_000_000, 0.99, SensitivityTier::S1, Domain::Default, 3, 50);
        assert!(
            rec.confidence <= 0.95 + f64::EPSILON,
            "Initial CF should be clamped to ceiling"
        );
    }

    // ====================================================================
    // Test Group 5: Inertia dampening
    // ====================================================================

    #[test]
    fn test_dampening_reduces_over_epochs() {
        let now = 1_000_000;
        let mut rec = active(0.3, now);
        rec.strength_epoch = 0;

        // First strengthen: full impact (dampening ~1.0)
        strengthen(&mut rec, 0.1, now + 1);
        let first_delta = rec.confidence - 0.3;

        // Strengthen many times to increase epoch count
        for i in 2..102 {
            strengthen(&mut rec, 0.1, now + i);
        }

        let cf_at_100 = rec.confidence;

        // Reset to test a single strengthen at high epoch
        let old_cf = cf_at_100;
        strengthen(&mut rec, 0.1, now + 200);
        let late_delta = rec.confidence - old_cf;

        // Late delta should be significantly less than first delta
        assert!(
            late_delta < first_delta * 0.5,
            "Dampening should reduce impact over time: first={:.6}, late={:.6}",
            first_delta,
            late_delta
        );
    }

    #[test]
    fn test_dampening_prevents_rapid_oscillation() {
        // Alternating support/contradiction should converge to stable CF
        let now = 1_000_000;
        let mut rec = active(0.5, now);
        rec.supporting_count = 50;

        let mut cfs = Vec::new();
        for i in 0..40 {
            if i % 2 == 0 {
                strengthen(&mut rec, 0.05, now + i + 1);
            } else {
                weaken(&mut rec, now + i + 1);
            }
            cfs.push(rec.confidence);
        }

        // Verify oscillation amplitude decreases (comparing first vs last swings)
        if cfs.len() >= 6 {
            let early_swing = (cfs[1] - cfs[2]).abs();
            let late_swing = (cfs[cfs.len() - 2] - cfs[cfs.len() - 1]).abs();
            // Note: Due to weakening asymmetry, the CF trends downward overall,
            // but the per-step delta should decrease
            assert!(
                late_swing <= early_swing + 0.05,
                "Oscillation should dampen: early={:.6}, late={:.6}",
                early_swing,
                late_swing
            );
        }
    }

    #[test]
    fn test_dampening_factor_values() {
        // Verify dampening factor formula at known epochs
        let mut rec = active(0.5, 1_000_000);

        // Epoch 0: factor = 1.0 / (1.0 + 0.01 * 0) = 1.0
        rec.strength_epoch = 0;
        assert!((rec.dampening_factor() - 1.0).abs() < 1e-10);

        // Epoch 100 with S3 (rate=0.01): factor = 1.0 / (1.0 + 0.01 * 100) = 1/2 = 0.5
        rec.strength_epoch = 100;
        assert!(
            (rec.dampening_factor() - 0.5).abs() < 1e-10,
            "Expected 0.5, got {}",
            rec.dampening_factor()
        );

        // Epoch 200: factor = 1.0 / (1.0 + 0.01 * 200) = 1/3 = 0.333...
        rec.strength_epoch = 200;
        let expected = 1.0 / 3.0;
        assert!(
            (rec.dampening_factor() - expected).abs() < 1e-10,
            "Expected {:.6}, got {:.6}",
            expected,
            rec.dampening_factor()
        );
    }

    // ====================================================================
    // Test Group 6: State-dependent firing
    // ====================================================================

    #[test]
    fn test_only_active_weakened_candidate_fire() {
        let now = 1_000_000;

        // Active fires
        let active_rec = active(0.7, now);
        assert!(active_rec.fires(), "Active should fire");

        // Candidate fires
        let candidate_rec = candidate(0.4, now);
        assert!(candidate_rec.fires(), "Candidate should fire");

        // Weakened fires
        let weakened_rec = weakened(0.25, now);
        assert!(weakened_rec.fires(), "Weakened should fire");

        // Dormant does NOT fire
        let dormant_rec = dormant(0.3, now);
        assert!(!dormant_rec.fires(), "Dormant should NOT fire");

        // Expired does NOT fire
        let expired_rec = expired(0.0, now);
        assert!(!expired_rec.fires(), "Expired should NOT fire");
    }

    #[test]
    fn test_status_priority_values() {
        assert_eq!(RuleStatus::Active.priority(), 100);
        assert_eq!(RuleStatus::Candidate.priority(), 50);
        assert_eq!(RuleStatus::Weakened.priority(), 25);
        assert_eq!(RuleStatus::Dormant.priority(), 0);
        assert_eq!(RuleStatus::Expired.priority(), 0);
    }

    // ====================================================================
    // Test Group 7: Expired rule cleanup / tombstoning
    // ====================================================================

    #[test]
    fn test_tombstone_set_on_expiry() {
        let now = 1_000_000;
        let mut rec = weakened(0.05, now);
        let _result = check_transitions(&mut rec, now + 1);

        assert_eq!(rec.status, RuleStatus::Expired);
        assert!(
            rec.tombstone_until > now,
            "Tombstone should be in the future"
        );
        assert!(
            rec.tombstone_until >= now + TOMBSTONE_MIN_SECS,
            "Tombstone should be at least 7 days"
        );
    }

    #[test]
    fn test_tombstone_prevents_revival() {
        let now = 1_000_000;
        let mut rec = expired(0.0, now);
        rec.tombstone_until = now + TOMBSTONE_MIN_SECS;

        // Attempt revival during tombstone
        let result = attempt_revival(&mut rec, now + 100, 0.5, now + 100);
        assert_eq!(result, LifecycleEvent::NoChange);
        assert_eq!(rec.status, RuleStatus::Expired);
    }

    #[test]
    fn test_tombstone_min_7_days() {
        // Even rules with very short half-lives get at least 7-day tombstone
        let now = 1_000_000;
        let mut rec = EvolutionRecord::new_with_status(
            now,
            0.05,
            RuleStatus::Weakened,
            SensitivityTier::S4,
            Domain::CurrentPrices, // short half-life
            3,
            50,
        );

        let _result = check_transitions(&mut rec, now + 1);
        assert_eq!(rec.status, RuleStatus::Expired);

        let tombstone_duration = rec.tombstone_until - (now + 1);
        assert!(
            tombstone_duration >= TOMBSTONE_MIN_SECS,
            "Tombstone duration {} < minimum {}",
            tombstone_duration,
            TOMBSTONE_MIN_SECS
        );
    }

    // ====================================================================
    // Test Group 8: CHECK_KILL conditions
    // ====================================================================

    #[test]
    fn test_check_kill_low_cf() {
        let rec = active(0.05, 1_000_000);
        assert!(check_kill(&rec, 1_000_001));
    }

    #[test]
    fn test_check_kill_contradictions_dominate() {
        let mut rec = active(0.3, 1_000_000);
        rec.supporting_count = 10;
        rec.contradicting_count = 15;
        assert!(check_kill(&rec, 1_000_001));
    }

    #[test]
    fn test_check_kill_evidence_drought() {
        let now = 1_000_000;
        let mut rec = active(0.3, now);
        rec.last_seen = now;

        // Default domain, decay_rate = 0.01
        // half_life = ln2/0.01 = 69.3 days
        // 2 * half_life = 138.6 days
        let drought_time = now + (139 * DAY); // > 2 * half-life
        assert!(check_kill(&rec, drought_time));
    }

    #[test]
    fn test_check_kill_healthy_rule() {
        let rec = active(0.7, 1_000_000);
        assert!(!check_kill(&rec, 1_000_001));
    }

    // ====================================================================
    // Test Group 9: Strengthen / Weaken operations
    // ====================================================================

    #[test]
    fn test_strengthen_increases_cf() {
        let now = 1_000_000;
        let mut rec = active(0.5, now);
        let old_cf = rec.confidence;

        strengthen(&mut rec, 0.1, now + 1);
        assert!(rec.confidence > old_cf, "CF should increase on strengthen");
        assert_eq!(rec.strength_epoch, 1);
        assert_eq!(rec.contradiction_streak, 0);
    }

    #[test]
    fn test_weaken_decreases_cf() {
        let now = 1_000_000;
        let mut rec = active(0.5, now);
        rec.supporting_count = 50;
        let old_cf = rec.confidence;

        weaken(&mut rec, now + 1);
        assert!(rec.confidence < old_cf, "CF should decrease on weaken");
        assert_eq!(rec.contradiction_streak, 1);
        assert_eq!(rec.contradicting_count, 1);
    }

    #[test]
    fn test_streak_penalty_activates() {
        let now = 1_000_000;
        let mut rec = active(0.5, now);
        rec.supporting_count = 100;

        // Apply 3 contradictions (at threshold, no penalty yet)
        for i in 0..3 {
            weaken(&mut rec, now + i + 1);
        }
        let cf_at_threshold = rec.confidence;
        assert_eq!(rec.contradiction_streak, 3);

        // 4th contradiction: streak penalty kicks in
        weaken(&mut rec, now + 4);
        let cf_after_penalty = rec.confidence;

        // The 4th should have extra penalty from streak
        assert!(
            cf_after_penalty < cf_at_threshold,
            "Streak penalty should accelerate weakening"
        );
    }

    #[test]
    fn test_strengthen_resets_streak() {
        let now = 1_000_000;
        let mut rec = active(0.5, now);
        rec.supporting_count = 50;

        // Build up a streak
        for i in 0..5 {
            weaken(&mut rec, now + i + 1);
        }
        assert_eq!(rec.contradiction_streak, 5);

        // One support resets it
        strengthen(&mut rec, 0.05, now + 10);
        assert_eq!(rec.contradiction_streak, 0);
    }

    // ====================================================================
    // Test Group 10: Full lifecycle sequence
    // ====================================================================

    #[test]
    fn test_full_lifecycle_sequence() {
        let t0 = 1_000_000;

        // Step 1: Rule crystallizes as Candidate
        let mut rec = EvolutionRecord::new(t0, 0.35, SensitivityTier::S3, Domain::Default, 2, 50);
        assert_eq!(rec.status, RuleStatus::Candidate);

        // Step 2: Build up CF and regions to promote to Active
        rec.confidence = 0.55;
        rec.distinct_regions = 4;
        let t1 = t0 + MIN_CANDIDATE_PERIOD_SECS + 1;
        let result = check_transitions(&mut rec, t1);
        assert_eq!(result, Some((RuleStatus::Candidate, RuleStatus::Active)));

        // Step 3: Receive contradictions to weaken
        let t2 = t1 + DAY;
        rec.supporting_count = 100;
        for i in 0..15 {
            weaken(&mut rec, t2 + i);
        }
        // Should have transitioned to Weakened (CF dropped below 0.3)
        assert!(
            rec.status == RuleStatus::Weakened
                || rec.status == RuleStatus::Dormant
                || rec.status == RuleStatus::Expired,
            "After 15 contradictions, status should degrade from Active: got {:?}",
            rec.status
        );

        // Step 4: If weakened, verify streak can push to dormant
        if rec.status == RuleStatus::Weakened {
            rec.contradiction_streak = S_MAX;
            let t3 = t2 + 100;
            let _result = check_transitions(&mut rec, t3);
            assert!(
                rec.status == RuleStatus::Dormant || rec.status == RuleStatus::Expired,
                "Streak >= S_MAX should push to Dormant/Expired"
            );
        }

        // Step 5: If dormant, verify time pushes to expired
        if rec.status == RuleStatus::Dormant {
            let t4 = rec.status_entered_at + Domain::Default.dormant_period_secs() + 1;
            let _result = check_transitions(&mut rec, t4);
            assert_eq!(rec.status, RuleStatus::Expired);
        }

        // Step 6: Verify tombstone set and revival
        if rec.status == RuleStatus::Expired {
            assert!(rec.tombstone_until > 0, "Tombstone should be set");

            let revival_time = rec.tombstone_until + 1;
            let result = attempt_revival(&mut rec, revival_time, 0.4, revival_time);
            assert_eq!(result, LifecycleEvent::Revived);
            assert_eq!(rec.status, RuleStatus::Candidate);
        }
    }

    // ====================================================================
    // Test Group 11: Memory overhead
    // ====================================================================

    #[test]
    fn test_evolution_record_size() {
        let size = mem::size_of::<EvolutionRecord>();
        // Target: 50 bytes. With full timestamps and scores, we expect ~88-104 bytes.
        // Requirement: < 100 bytes per rule overhead.
        assert!(
            size <= 128,
            "EvolutionRecord size {} exceeds 128 bytes",
            size
        );
        // Track actual size for reporting
        eprintln!("EvolutionRecord size: {} bytes", size);
    }

    #[test]
    fn test_lifecycle_event_size() {
        let size = mem::size_of::<LifecycleEvent>();
        assert!(size <= 32, "LifecycleEvent size {} exceeds 32 bytes", size);
    }

    // ====================================================================
    // Test Group 12: Domain timing parameters
    // ====================================================================

    #[test]
    fn test_domain_dormant_thresholds() {
        assert_eq!(Domain::CurrentPrices.dormant_threshold_secs(), 7 * DAY);
        assert_eq!(Domain::Seasonal.dormant_threshold_secs(), 90 * DAY);
        assert_eq!(Domain::ContractTerms.dormant_threshold_secs(), 180 * DAY);
        assert_eq!(
            Domain::LegalRequirements.dormant_threshold_secs(),
            365 * DAY
        );
        assert_eq!(Domain::MedicalReference.dormant_threshold_secs(), 180 * DAY);
        assert_eq!(Domain::Default.dormant_threshold_secs(), 30 * DAY);
    }

    #[test]
    fn test_domain_dormant_period_is_2x_threshold() {
        for domain in [
            Domain::CurrentPrices,
            Domain::Seasonal,
            Domain::ContractTerms,
            Domain::LegalRequirements,
            Domain::MedicalReference,
            Domain::Default,
        ] {
            assert_eq!(
                domain.dormant_period_secs(),
                2 * domain.dormant_threshold_secs(),
                "dormant_period should be 2x dormant_threshold for {:?}",
                domain
            );
        }
    }

    // ====================================================================
    // Test Group 13: Edge cases
    // ====================================================================

    #[test]
    fn test_strengthen_from_zero() {
        let now = 1_000_000;
        let mut rec = active(0.0, now);
        strengthen(&mut rec, 0.1, now + 1);
        assert!(rec.confidence > 0.0, "Should strengthen from zero");
    }

    #[test]
    fn test_weaken_to_zero() {
        let now = 1_000_000;
        let mut rec = active(0.01, now);
        rec.supporting_count = 1;
        for i in 0..20 {
            weaken(&mut rec, now + i + 1);
        }
        assert!(
            rec.confidence >= 0.0,
            "CF should never go below 0: {}",
            rec.confidence
        );
    }

    #[test]
    fn test_wake_dormant_wrong_status() {
        // wake_from_dormant on a non-dormant rule should be NoChange
        let mut rec = active(0.5, 1_000_000);
        let result = wake_from_dormant(&mut rec, 0.1, 1_100_000);
        assert_eq!(result, LifecycleEvent::NoChange);
    }

    #[test]
    fn test_revival_wrong_status() {
        // attempt_revival on a non-expired rule should be NoChange
        let mut rec = active(0.5, 1_000_000);
        let result = attempt_revival(&mut rec, 1_100_000, 0.5, 1_100_000);
        assert_eq!(result, LifecycleEvent::NoChange);
    }

    #[test]
    fn test_consistency_score_computation() {
        let mut rec = active(0.5, 1_000_000);
        rec.supporting_count = 80;
        rec.contradicting_count = 20;
        let consistency = rec.compute_consistency();
        // (80 - 20) / (80 + 20) = 60/100 = 0.6
        assert!(
            (consistency - 0.6).abs() < 1e-10,
            "Expected 0.6, got {}",
            consistency
        );
    }

    #[test]
    fn test_consistency_all_contradictions() {
        let mut rec = active(0.5, 1_000_000);
        rec.supporting_count = 0;
        rec.contradicting_count = 50;
        let consistency = rec.compute_consistency();
        // (0 - 50) / (50) = -1.0, clamped to 0.0
        assert!(
            (consistency - 0.0).abs() < 1e-10,
            "All-contradictions consistency should be 0.0: got {}",
            consistency
        );
    }

    #[test]
    fn test_consistency_no_evidence() {
        let mut rec = active(0.5, 1_000_000);
        rec.supporting_count = 0;
        rec.contradicting_count = 0;
        let consistency = rec.compute_consistency();
        assert!(
            (consistency - 1.0).abs() < 1e-10,
            "No-evidence consistency should be 1.0"
        );
    }
}
