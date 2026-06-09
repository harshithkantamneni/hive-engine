//! Cold-start network phase detection and tier-specific sharing gates.
//!
//! At small network sizes, sharing sensitive tiers (S1/S2) is disabled
//! because the anonymity set is too small for meaningful DP protection.
//!
//! Phase detection from estimated peer count, with per-tier sharing
//! enablement rules.

use crate::privacy::config::ColdStartConfig;
use crate::privacy::types::{NetworkPhase, SensitivityTier};

// ─── ColdStartGate ──────────────────────────────────────────────────────────

/// Network phase detection and tier-specific sharing gates.
///
/// The gate decides whether a tuple at a given sensitivity tier may enter
/// the sharing pipeline based on the current estimated network size.
pub struct ColdStartGate {
    /// Current estimated number of peers in the network.
    estimated_peers: u64,
    /// Phase thresholds from config: [Bootstrap->Growth, Growth->Maturity, Maturity->Scale].
    phase_thresholds: Vec<u64>,
    /// Minimum medical contributors required to enable S1 sharing.
    s1_enable_medical_contributors: u64,
    /// Minimum domain contributors required to enable S2 sharing.
    s2_enable_domain_contributors: u64,
    /// Minimum total users required to enable S3 sharing.
    s3_enable_total_users: u64,
    /// Minimum total users required to enable S4 sharing.
    s4_enable_total_users: u64,
}

impl ColdStartGate {
    /// Create a new cold-start gate from configuration.
    pub fn new(config: &ColdStartConfig) -> Self {
        Self {
            estimated_peers: 0,
            phase_thresholds: config.phase_thresholds.clone(),
            s1_enable_medical_contributors: config.s1_enable_medical_contributors,
            s2_enable_domain_contributors: config.s2_enable_domain_contributors,
            s3_enable_total_users: config.s3_enable_total_users,
            s4_enable_total_users: config.s4_enable_total_users,
        }
    }

    /// Create a cold-start gate with an initial peer count estimate.
    pub fn with_peers(config: &ColdStartConfig, estimated_peers: u64) -> Self {
        let mut gate = Self::new(config);
        gate.estimated_peers = estimated_peers;
        gate
    }

    /// Check if sharing is enabled for the given sensitivity tier at the
    /// current network phase.
    ///
    /// Per-tier enablement rules:
    /// - S1: requires >= s1_enable_medical_contributors (approximated by total peers)
    /// - S2: requires >= s2_enable_domain_contributors (approximated by total peers)
    /// - S3: requires >= s3_enable_total_users
    /// - S4: requires >= s4_enable_total_users
    ///
    /// Note: In V1, domain-specific contributor counts are approximated by
    /// total peer count. Accurate per-domain counts require gossip traffic
    /// analysis.
    pub fn is_sharing_enabled(&self, tier: SensitivityTier) -> bool {
        match tier {
            SensitivityTier::S1Critical => {
                // S1 needs enough medical contributors; we approximate
                // with total peers since domain-specific counts aren't
                // available yet.
                self.estimated_peers >= self.s1_enable_medical_contributors
            }
            SensitivityTier::S2High => self.estimated_peers >= self.s2_enable_domain_contributors,
            SensitivityTier::S3Medium => self.estimated_peers >= self.s3_enable_total_users,
            SensitivityTier::S4Low => self.estimated_peers >= self.s4_enable_total_users,
        }
    }

    /// Get the current estimated network phase based on total peers.
    pub fn current_phase(&self) -> NetworkPhase {
        Self::phase_from_peers(self.estimated_peers, &self.phase_thresholds)
    }

    /// Update the network size estimate (called hourly from DHT).
    pub fn update_network_size(&mut self, estimated_peers: u64) {
        self.estimated_peers = estimated_peers;
    }

    /// Get the current estimated peer count.
    pub fn estimated_peers(&self) -> u64 {
        self.estimated_peers
    }

    /// Determine the network phase from a peer count and thresholds.
    fn phase_from_peers(peers: u64, thresholds: &[u64]) -> NetworkPhase {
        if thresholds.len() >= 3 {
            if peers >= thresholds[2] {
                NetworkPhase::Scale
            } else if peers >= thresholds[1] {
                NetworkPhase::Maturity
            } else if peers >= thresholds[0] {
                NetworkPhase::Growth
            } else {
                NetworkPhase::Bootstrap
            }
        } else {
            // Fallback with hardcoded defaults
            if peers >= 1_000_000 {
                NetworkPhase::Scale
            } else if peers >= 100_000 {
                NetworkPhase::Maturity
            } else if peers >= 10_000 {
                NetworkPhase::Growth
            } else {
                NetworkPhase::Bootstrap
            }
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> ColdStartConfig {
        ColdStartConfig {
            phase_thresholds: vec![10_000, 100_000, 1_000_000],
            s1_enable_medical_contributors: 10_000,
            s2_enable_domain_contributors: 5_000,
            s3_enable_total_users: 1_000,
            s4_enable_total_users: 500,
        }
    }

    // --- Phase detection tests ---

    #[test]
    fn phase_bootstrap_below_10k() {
        let gate = ColdStartGate::with_peers(&default_config(), 0);
        assert_eq!(gate.current_phase(), NetworkPhase::Bootstrap);

        let gate = ColdStartGate::with_peers(&default_config(), 9_999);
        assert_eq!(gate.current_phase(), NetworkPhase::Bootstrap);
    }

    #[test]
    fn phase_growth_at_10k() {
        let gate = ColdStartGate::with_peers(&default_config(), 10_000);
        assert_eq!(gate.current_phase(), NetworkPhase::Growth);
    }

    #[test]
    fn phase_growth_below_100k() {
        let gate = ColdStartGate::with_peers(&default_config(), 99_999);
        assert_eq!(gate.current_phase(), NetworkPhase::Growth);
    }

    #[test]
    fn phase_maturity_at_100k() {
        let gate = ColdStartGate::with_peers(&default_config(), 100_000);
        assert_eq!(gate.current_phase(), NetworkPhase::Maturity);
    }

    #[test]
    fn phase_maturity_below_1m() {
        let gate = ColdStartGate::with_peers(&default_config(), 999_999);
        assert_eq!(gate.current_phase(), NetworkPhase::Maturity);
    }

    #[test]
    fn phase_scale_at_1m() {
        let gate = ColdStartGate::with_peers(&default_config(), 1_000_000);
        assert_eq!(gate.current_phase(), NetworkPhase::Scale);
    }

    #[test]
    fn phase_scale_above_1m() {
        let gate = ColdStartGate::with_peers(&default_config(), 5_000_000);
        assert_eq!(gate.current_phase(), NetworkPhase::Scale);
    }

    // --- Tier enablement tests ---

    #[test]
    fn s4_enabled_at_500_peers() {
        let gate = ColdStartGate::with_peers(&default_config(), 500);
        assert!(gate.is_sharing_enabled(SensitivityTier::S4Low));
    }

    #[test]
    fn s4_disabled_below_500_peers() {
        let gate = ColdStartGate::with_peers(&default_config(), 499);
        assert!(!gate.is_sharing_enabled(SensitivityTier::S4Low));
    }

    #[test]
    fn s3_enabled_at_1000_peers() {
        let gate = ColdStartGate::with_peers(&default_config(), 1_000);
        assert!(gate.is_sharing_enabled(SensitivityTier::S3Medium));
    }

    #[test]
    fn s3_disabled_below_1000_peers() {
        let gate = ColdStartGate::with_peers(&default_config(), 999);
        assert!(!gate.is_sharing_enabled(SensitivityTier::S3Medium));
    }

    #[test]
    fn s2_enabled_at_5000_peers() {
        let gate = ColdStartGate::with_peers(&default_config(), 5_000);
        assert!(gate.is_sharing_enabled(SensitivityTier::S2High));
    }

    #[test]
    fn s2_disabled_below_5000_peers() {
        let gate = ColdStartGate::with_peers(&default_config(), 4_999);
        assert!(!gate.is_sharing_enabled(SensitivityTier::S2High));
    }

    #[test]
    fn s1_enabled_at_10000_peers() {
        let gate = ColdStartGate::with_peers(&default_config(), 10_000);
        assert!(gate.is_sharing_enabled(SensitivityTier::S1Critical));
    }

    #[test]
    fn s1_disabled_below_10000_peers() {
        let gate = ColdStartGate::with_peers(&default_config(), 9_999);
        assert!(!gate.is_sharing_enabled(SensitivityTier::S1Critical));
    }

    #[test]
    fn bootstrap_only_s3_s4_enabled() {
        // At bootstrap (<10K), only S3 and S4 should be shareable
        // if enough users for those tiers
        let gate = ColdStartGate::with_peers(&default_config(), 2_000);

        assert!(!gate.is_sharing_enabled(SensitivityTier::S1Critical));
        assert!(!gate.is_sharing_enabled(SensitivityTier::S2High));
        assert!(gate.is_sharing_enabled(SensitivityTier::S3Medium));
        assert!(gate.is_sharing_enabled(SensitivityTier::S4Low));
    }

    #[test]
    fn all_tiers_enabled_at_scale() {
        let gate = ColdStartGate::with_peers(&default_config(), 2_000_000);

        assert!(gate.is_sharing_enabled(SensitivityTier::S1Critical));
        assert!(gate.is_sharing_enabled(SensitivityTier::S2High));
        assert!(gate.is_sharing_enabled(SensitivityTier::S3Medium));
        assert!(gate.is_sharing_enabled(SensitivityTier::S4Low));
    }

    #[test]
    fn zero_peers_nothing_enabled() {
        let gate = ColdStartGate::with_peers(&default_config(), 0);

        assert!(!gate.is_sharing_enabled(SensitivityTier::S1Critical));
        assert!(!gate.is_sharing_enabled(SensitivityTier::S2High));
        assert!(!gate.is_sharing_enabled(SensitivityTier::S3Medium));
        assert!(!gate.is_sharing_enabled(SensitivityTier::S4Low));
    }

    // --- Update tests ---

    #[test]
    fn update_network_size_changes_phase() {
        let mut gate = ColdStartGate::new(&default_config());
        assert_eq!(gate.current_phase(), NetworkPhase::Bootstrap);

        gate.update_network_size(50_000);
        assert_eq!(gate.current_phase(), NetworkPhase::Growth);

        gate.update_network_size(500_000);
        assert_eq!(gate.current_phase(), NetworkPhase::Maturity);
    }

    #[test]
    fn update_network_size_changes_enablement() {
        let mut gate = ColdStartGate::new(&default_config());
        assert!(!gate.is_sharing_enabled(SensitivityTier::S2High));

        gate.update_network_size(5_000);
        assert!(gate.is_sharing_enabled(SensitivityTier::S2High));
    }

    #[test]
    fn estimated_peers_accessor() {
        let gate = ColdStartGate::with_peers(&default_config(), 42_000);
        assert_eq!(gate.estimated_peers(), 42_000);
    }
}
