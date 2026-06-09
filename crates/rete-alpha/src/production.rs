//! Production node struct.
//! Each production represents a compiled rule's terminal node.

/// Rule lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum RuleStatus {
    Candidate = 0,
    Active = 1,
    Weakened = 2,
    Dormant = 3,
    Expired = 4,
}

impl RuleStatus {
    /// Priority for conflict resolution.
    pub fn priority(self) -> u16 {
        match self {
            RuleStatus::Active => 100,
            RuleStatus::Candidate => 50,
            RuleStatus::Weakened => 25,
            RuleStatus::Dormant | RuleStatus::Expired => 0,
        }
    }

    /// Whether this status allows rule firing.
    pub fn fires(self) -> bool {
        matches!(
            self,
            RuleStatus::Active | RuleStatus::Candidate | RuleStatus::Weakened
        )
    }
}

/// A production (compiled rule terminal node).
///
/// Compact: 24 bytes. 10K productions = 240 KB.
/// Uses a conjunction bitmask to track required conditions.
#[derive(Debug, Clone)]
pub struct Production {
    pub rule_id: u32,
    /// Bitmask of required conditions. Bit i = 1 means condition i must match.
    /// Max ~10 conditions per rule, so u64 is ample.
    pub condition_mask: u64,
    /// Number of conditions (popcount of condition_mask).
    pub condition_count: u8,
    pub status: RuleStatus,
    /// Current rule confidence [0.0, 1.0].
    pub confidence: f32,
}

impl Production {
    pub fn new(rule_id: u32, condition_count: u8, status: RuleStatus, confidence: f32) -> Self {
        // Build a mask with the lowest condition_count bits set
        let condition_mask = if condition_count >= 64 {
            u64::MAX
        } else {
            (1u64 << condition_count) - 1
        };
        Self {
            rule_id,
            condition_mask,
            condition_count,
            status,
            confidence,
        }
    }

    /// Check if all conditions are satisfied given a matched bitmask.
    #[inline(always)]
    pub fn all_conditions_met(&self, matched: u64) -> bool {
        (matched & self.condition_mask) == self.condition_mask
    }
}

/// Result of a production firing.
#[derive(Debug, Clone)]
pub struct FiredProduction {
    pub rule_id: u32,
    pub confidence: f32,
    pub extraction_cf: f32,
    /// Chained CF = rule_cf * extraction_cf (MYCIN chain formula).
    pub chained_cf: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_mask() {
        let prod = Production::new(1, 4, RuleStatus::Active, 0.72);
        assert_eq!(prod.condition_mask, 0b1111);
        assert!(prod.all_conditions_met(0b1111));
        assert!(prod.all_conditions_met(0b11111)); // extra bits ok
        assert!(!prod.all_conditions_met(0b0111)); // missing bit 3
    }

    #[test]
    fn test_status_priority() {
        assert_eq!(RuleStatus::Active.priority(), 100);
        assert_eq!(RuleStatus::Candidate.priority(), 50);
        assert_eq!(RuleStatus::Weakened.priority(), 25);
        assert_eq!(RuleStatus::Dormant.priority(), 0);
        assert!(RuleStatus::Active.fires());
        assert!(!RuleStatus::Dormant.fires());
    }
}
