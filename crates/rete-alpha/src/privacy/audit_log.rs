//! Suppression event logging for the privacy pipeline.
//!
//! Every suppression decision (Stages 5, 6, 8) is logged locally so users
//! can understand why some documents are local-only.
//!
//! In-memory buffer with optional disk persistence. Production persistence
//! will use SQLite.

use crate::privacy::types::SensitivityTier;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Types ──────────────────────────────────────────────────────────────────

/// A single suppression event record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionEvent {
    /// Unix timestamp of the suppression.
    pub timestamp: u64,
    /// The document category that produced the suppressed tuple.
    pub document_category: String,
    /// The sensitivity tier of the suppressed tuple.
    pub sensitivity_tier: SensitivityTier,
    /// The pipeline stage that caused suppression.
    pub stage: String,
    /// Human-readable reason for suppression.
    pub reason: String,
    /// Optional BLAKE3 hash of the tuple (NOT content). For dedup tracking.
    pub tuple_hash: Option<String>,
}

impl SuppressionEvent {
    /// Create a new suppression event with the current timestamp.
    pub fn new(
        document_category: &str,
        sensitivity_tier: SensitivityTier,
        stage: &str,
        reason: &str,
        tuple_hash: Option<String>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            timestamp,
            document_category: document_category.to_string(),
            sensitivity_tier,
            stage: stage.to_string(),
            reason: reason.to_string(),
            tuple_hash,
        }
    }
}

// ─── AuditLog ───────────────────────────────────────────────────────────────

/// In-memory audit log for suppression events. Provides buffered storage
/// with eventual disk persistence (wired up via SQLite in a later cycle).
#[derive(Debug)]
pub struct AuditLog {
    events: Vec<SuppressionEvent>,
    /// Maximum number of events to retain in memory. Oldest are evicted
    /// when this limit is reached (circular buffer behavior).
    max_capacity: usize,
}

impl AuditLog {
    /// Create a new audit log with the specified maximum in-memory capacity.
    pub fn new(max_capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(max_capacity.min(1024)),
            max_capacity,
        }
    }

    /// Log a suppression event. If the buffer is at capacity, the oldest
    /// event is evicted.
    pub fn log_suppression(&mut self, event: SuppressionEvent) {
        if self.events.len() >= self.max_capacity {
            self.events.remove(0);
        }
        self.events.push(event);
    }

    /// Log a suppression event by constructing it from field values.
    pub fn log(
        &mut self,
        document_category: &str,
        sensitivity_tier: SensitivityTier,
        stage: &str,
        reason: &str,
        tuple_hash: Option<String>,
    ) {
        let event = SuppressionEvent::new(
            document_category,
            sensitivity_tier,
            stage,
            reason,
            tuple_hash,
        );
        self.log_suppression(event);
    }

    /// Get the most recent `n` events, newest first.
    pub fn get_recent(&self, n: usize) -> Vec<&SuppressionEvent> {
        self.events.iter().rev().take(n).collect()
    }

    /// Get all events (oldest first).
    pub fn get_all(&self) -> &[SuppressionEvent] {
        &self.events
    }

    /// Get the total number of logged events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Clear all events from the in-memory buffer.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Count events matching a specific stage.
    pub fn count_by_stage(&self, stage: &str) -> usize {
        self.events.iter().filter(|e| e.stage == stage).count()
    }

    /// Count events matching a specific sensitivity tier.
    pub fn count_by_tier(&self, tier: SensitivityTier) -> usize {
        self.events
            .iter()
            .filter(|e| e.sensitivity_tier == tier)
            .count()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(stage: &str, tier: SensitivityTier) -> SuppressionEvent {
        SuppressionEvent::new("medical_bill", tier, stage, "test reason", None)
    }

    #[test]
    fn log_single_event() {
        let mut log = AuditLog::new(100);
        log.log_suppression(make_event("k_anonymity", SensitivityTier::S1Critical));
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }

    #[test]
    fn log_multiple_events() {
        let mut log = AuditLog::new(100);
        log.log_suppression(make_event("k_anonymity", SensitivityTier::S1Critical));
        log.log_suppression(make_event("l_diversity", SensitivityTier::S2High));
        log.log_suppression(make_event("budget", SensitivityTier::S3Medium));
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn get_recent_returns_newest_first() {
        let mut log = AuditLog::new(100);
        log.log(
            "medical_bill",
            SensitivityTier::S1Critical,
            "k_anonymity",
            "first",
            None,
        );
        log.log("receipt", SensitivityTier::S4Low, "budget", "second", None);
        log.log(
            "lease",
            SensitivityTier::S2High,
            "l_diversity",
            "third",
            None,
        );

        let recent = log.get_recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].reason, "third");
        assert_eq!(recent[1].reason, "second");
    }

    #[test]
    fn get_recent_more_than_available() {
        let mut log = AuditLog::new(100);
        log.log_suppression(make_event("k_anonymity", SensitivityTier::S1Critical));
        let recent = log.get_recent(10);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn clear_empties_log() {
        let mut log = AuditLog::new(100);
        log.log_suppression(make_event("k_anonymity", SensitivityTier::S1Critical));
        log.log_suppression(make_event("budget", SensitivityTier::S2High));
        assert_eq!(log.len(), 2);

        log.clear();
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
    }

    #[test]
    fn capacity_evicts_oldest() {
        let mut log = AuditLog::new(3);
        log.log(
            "cat1",
            SensitivityTier::S1Critical,
            "stage_a",
            "first",
            None,
        );
        log.log("cat2", SensitivityTier::S2High, "stage_b", "second", None);
        log.log("cat3", SensitivityTier::S3Medium, "stage_c", "third", None);
        log.log("cat4", SensitivityTier::S4Low, "stage_d", "fourth", None);

        assert_eq!(log.len(), 3);
        // The oldest ("first") should have been evicted
        let all = log.get_all();
        assert_eq!(all[0].reason, "second");
        assert_eq!(all[2].reason, "fourth");
    }

    #[test]
    fn count_by_stage() {
        let mut log = AuditLog::new(100);
        log.log_suppression(make_event("k_anonymity", SensitivityTier::S1Critical));
        log.log_suppression(make_event("k_anonymity", SensitivityTier::S2High));
        log.log_suppression(make_event("budget", SensitivityTier::S3Medium));

        assert_eq!(log.count_by_stage("k_anonymity"), 2);
        assert_eq!(log.count_by_stage("budget"), 1);
        assert_eq!(log.count_by_stage("l_diversity"), 0);
    }

    #[test]
    fn count_by_tier() {
        let mut log = AuditLog::new(100);
        log.log_suppression(make_event("k_anonymity", SensitivityTier::S1Critical));
        log.log_suppression(make_event("budget", SensitivityTier::S1Critical));
        log.log_suppression(make_event("l_diversity", SensitivityTier::S4Low));

        assert_eq!(log.count_by_tier(SensitivityTier::S1Critical), 2);
        assert_eq!(log.count_by_tier(SensitivityTier::S4Low), 1);
        assert_eq!(log.count_by_tier(SensitivityTier::S3Medium), 0);
    }

    #[test]
    fn event_has_timestamp() {
        let event = SuppressionEvent::new(
            "medical_bill",
            SensitivityTier::S1Critical,
            "k_anonymity",
            "too specific",
            Some("abc123".into()),
        );
        assert!(event.timestamp > 0);
        assert_eq!(event.tuple_hash, Some("abc123".into()));
    }

    #[test]
    fn event_serde_roundtrip() {
        let event = SuppressionEvent::new(
            "lease",
            SensitivityTier::S2High,
            "l_diversity",
            "entropy too low",
            None,
        );
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: SuppressionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.document_category, "lease");
        assert_eq!(deserialized.sensitivity_tier, SensitivityTier::S2High);
        assert_eq!(deserialized.stage, "l_diversity");
    }
}
