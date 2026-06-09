//! Privacy pipeline for HIVE P2P tuple sharing.
//!
//! This module implements the 10-stage privacy pipeline.
//! It transforms raw extracted tuples into anonymized, DP-encoded tuples
//! safe for P2P sharing. This is a PARALLEL fork from the existing
//! pipeline -- it does NOT modify local reasoning.
//!
//! Architecture: `RawTuple` forks after extraction:
//!   - One copy goes to WmeFactory -> Rete engine (unchanged, no privacy overhead)
//!   - Another enters this pipeline for potential P2P sharing
//!
//! ## Module Map
//!
//! | Module | Pipeline Stage |
//! |--------|---------------|
//! | `types` | All (type-state enforcement) |
//! | `config` | All (parameter loading) |
//! | `audit_log` | Stages 5/6/8 (suppression logging) |
//! | `cold_start` | Gate (network phase detection) |
//! | `pii_stripper` | Stage 1 (PII removal) |
//! | `amount_bucketer` | Stage 2 (amount bucketing) |
//! | `oue` | Stage 7 (OUE DP encoding) |
//! | `budget_manager` | Stage 8 (Renyi DP budget) |

pub mod audit_log;
pub mod cold_start;
pub mod config;
pub mod types;

// Stage 1: PII removal (deny-by-default allowlist)
pub mod pii_stripper;
// Stage 2: Amount bucketing (logarithmic boundaries)
pub mod amount_bucketer;

// Supporting: Frequency data for k-estimation, l-diversity, generalization
pub mod frequency_tables;
// Stage 3: Context generalization (multi-level hierarchies, greedy algorithm)
pub mod generalizer;
// Stage 4: Pattern hashing (HMAC-BLAKE3 with device key)
pub mod pattern_hasher;
// Stage 5: k-Anonymity check (12-field multiplicative selectivity)
pub mod k_anonymity;
// Stage 6: l-Diversity check (entropy-based SA diversity)
pub mod l_diversity;
// Stage 7: OUE encoding (Optimized Unary Encoding, epsilon-LDP)
pub mod oue;
// Stage 8: Privacy budget manager (Renyi DP composition, daily/weekly/lifetime ceilings)
pub mod budget_manager;
// Stage 9: Jitter queue (temporal decorrelation, cross-document batching)
pub mod jitter_queue;
// Pipeline orchestrator (wires all 9 stages together)
pub mod pipeline;

// Re-exports for convenience
pub use audit_log::{AuditLog, SuppressionEvent};
pub use budget_manager::{
    compute_rdp_oue, compute_rdp_oue_exact, BudgetError, BudgetManagerImpl, BudgetState,
    ExhaustionLevel,
};
pub use cold_start::ColdStartGate;
pub use config::PrivacyConfig;
pub use frequency_tables::FrequencyTables;
pub use generalizer::{DefaultFrequencyProvider, FrequencyProvider, Generalizer};
pub use jitter_queue::{JitterQueue, JitterQueueOps};
pub use k_anonymity::{KAnonymityCheck, KAnonymityChecker};
pub use l_diversity::{LDiversityCheck, LDiversityChecker};
pub use oue::{OueEncoder, OueEncoderImpl};
pub use pattern_hasher::{DeviceKey, PatternHasher};
pub use pipeline::{PrivacyPipeline, SimpleJitterQueue};
pub use types::{
    BucketedTuple, BudgetApprovedTuple, BudgetSnapshot, EncodedTuple, GeneralizedTuple,
    HashedTuple, KCheckedTuple, LCheckedTuple, NetworkPhase, OueFieldVector, PatternKey,
    PiiStrippedTuple, PrivacyPipelineResult, QueuedTuple, RawTuple, SensitivityTier,
};
