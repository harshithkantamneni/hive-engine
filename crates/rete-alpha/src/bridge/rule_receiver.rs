//! Async receiver trait + implementation for inbound rule events.
//!
//! Bridges the P2P layer's Gossipsub rule events to the Rete engine.
//! The `RuleReceiver` trait allows mocking in tests.

use super::InboundRuleEvent;
use std::collections::VecDeque;
use tokio::sync::mpsc;

// ============================================================================
// RuleReceiver trait
// ============================================================================

/// Trait for receiving validated rule events from the P2P layer.
///
/// Implementations may use tokio::mpsc, mock pre-loaded queues, or test stubs.
/// The trait uses synchronous try_recv for polling (non-blocking) patterns.
pub trait RuleReceiver: Send {
    /// Try to receive the next rule event without blocking.
    ///
    /// Returns `Some(event)` if an event is available, `None` if the
    /// channel is empty or closed.
    fn try_recv(&mut self) -> Option<InboundRuleEvent>;

    /// Check if the receiver is closed (sender half dropped).
    fn is_closed(&self) -> bool;
}

// ============================================================================
// MpscRuleReceiver -- production implementation
// ============================================================================

/// Production implementation wrapping a `tokio::mpsc::Receiver<InboundRuleEvent>`.
///
/// Uses `try_recv` internally for non-blocking polling from the engine thread.
pub struct MpscRuleReceiver {
    inner: mpsc::Receiver<InboundRuleEvent>,
}

impl MpscRuleReceiver {
    /// Create a new receiver wrapping the given mpsc receiver half.
    pub fn new(receiver: mpsc::Receiver<InboundRuleEvent>) -> Self {
        Self { inner: receiver }
    }
}

impl RuleReceiver for MpscRuleReceiver {
    fn try_recv(&mut self) -> Option<InboundRuleEvent> {
        self.inner.try_recv().ok()
    }

    fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }
}

// ============================================================================
// MockRuleReceiver -- test implementation
// ============================================================================

/// Mock implementation that returns pre-loaded events in order.
///
/// Useful for testing engine-side rule ingestion logic without a P2P layer.
pub struct MockRuleReceiver {
    events: VecDeque<InboundRuleEvent>,
    closed: bool,
}

impl MockRuleReceiver {
    /// Create a mock receiver pre-loaded with the given events.
    pub fn new(events: Vec<InboundRuleEvent>) -> Self {
        Self {
            events: VecDeque::from(events),
            closed: false,
        }
    }

    /// Create an empty mock receiver.
    pub fn empty() -> Self {
        Self {
            events: VecDeque::new(),
            closed: false,
        }
    }

    /// Push an additional event to the back of the queue.
    pub fn push_event(&mut self, event: InboundRuleEvent) {
        self.events.push_back(event);
    }

    /// Get the number of remaining events.
    pub fn remaining(&self) -> usize {
        self.events.len()
    }

    /// Mark the receiver as closed.
    pub fn close(&mut self) {
        self.closed = true;
    }
}

impl RuleReceiver for MockRuleReceiver {
    fn try_recv(&mut self) -> Option<InboundRuleEvent> {
        self.events.pop_front()
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

// ============================================================================
// DrainableRuleReceiver -- helper for batch processing
// ============================================================================

/// Extension for draining all available events in one call.
/// Useful for the engine thread's periodic poll.
pub fn drain_available(receiver: &mut dyn RuleReceiver) -> Vec<InboundRuleEvent> {
    let mut events = Vec::new();
    while let Some(event) = receiver.try_recv() {
        events.push(event);
    }
    events
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::EvidenceSummary;

    fn make_new_rule_event(id: u8) -> InboundRuleEvent {
        InboundRuleEvent::NewRule {
            envelope_bytes: vec![id; 10],
            source_peer: vec![id; 32],
            received_at: 1700000000 + id as u64,
        }
    }

    fn make_confidence_event(rule_id: u32) -> InboundRuleEvent {
        InboundRuleEvent::ConfidenceUpdate {
            rule_id,
            new_cf_x10k: 7500,
            new_version: 2,
            evidence: EvidenceSummary {
                supporting_count: 100,
                contradicting_count: 5,
                distinct_regions: 8,
                recency_score_x10k: 9200,
            },
        }
    }

    fn make_tombstone_event(rule_id: u32) -> InboundRuleEvent {
        InboundRuleEvent::Tombstone {
            rule_id,
            tombstone_until: 1700086400,
            version: 10,
        }
    }

    // ── MockRuleReceiver tests ──────────────────────────────────────────

    #[test]
    fn mock_receiver_returns_preloaded_events_in_order() {
        let mut receiver = MockRuleReceiver::new(vec![
            make_new_rule_event(1),
            make_new_rule_event(2),
            make_new_rule_event(3),
        ]);

        assert_eq!(receiver.remaining(), 3);

        let e1 = receiver.try_recv().unwrap();
        match e1 {
            InboundRuleEvent::NewRule { envelope_bytes, .. } => {
                assert_eq!(envelope_bytes, vec![1; 10]);
            }
            _ => panic!("Wrong variant"),
        }

        let e2 = receiver.try_recv().unwrap();
        match e2 {
            InboundRuleEvent::NewRule { envelope_bytes, .. } => {
                assert_eq!(envelope_bytes, vec![2; 10]);
            }
            _ => panic!("Wrong variant"),
        }

        assert_eq!(receiver.remaining(), 1);
    }

    #[test]
    fn mock_receiver_returns_none_when_empty() {
        let mut receiver = MockRuleReceiver::empty();
        assert!(receiver.try_recv().is_none());
    }

    #[test]
    fn mock_receiver_push_event() {
        let mut receiver = MockRuleReceiver::empty();
        assert_eq!(receiver.remaining(), 0);

        receiver.push_event(make_new_rule_event(1));
        assert_eq!(receiver.remaining(), 1);

        let event = receiver.try_recv().unwrap();
        match event {
            InboundRuleEvent::NewRule { .. } => {}
            _ => panic!("Wrong variant"),
        }
        assert_eq!(receiver.remaining(), 0);
    }

    #[test]
    fn mock_receiver_is_closed() {
        let mut receiver = MockRuleReceiver::empty();
        assert!(!receiver.is_closed());
        receiver.close();
        assert!(receiver.is_closed());
    }

    #[test]
    fn mock_receiver_mixed_event_types() {
        let mut receiver = MockRuleReceiver::new(vec![
            make_new_rule_event(1),
            make_confidence_event(42),
            make_tombstone_event(99),
        ]);

        match receiver.try_recv().unwrap() {
            InboundRuleEvent::NewRule { .. } => {}
            _ => panic!("Expected NewRule"),
        }
        match receiver.try_recv().unwrap() {
            InboundRuleEvent::ConfidenceUpdate { rule_id, .. } => assert_eq!(rule_id, 42),
            _ => panic!("Expected ConfidenceUpdate"),
        }
        match receiver.try_recv().unwrap() {
            InboundRuleEvent::Tombstone { rule_id, .. } => assert_eq!(rule_id, 99),
            _ => panic!("Expected Tombstone"),
        }
        assert!(receiver.try_recv().is_none());
    }

    // ── MpscRuleReceiver tests ──────────────────────────────────────────

    #[test]
    fn mpsc_receiver_receives_sent_event() {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let mut receiver = MpscRuleReceiver::new(rx);

        tx.try_send(make_new_rule_event(1)).unwrap();

        let event = receiver.try_recv().unwrap();
        match event {
            InboundRuleEvent::NewRule { envelope_bytes, .. } => {
                assert_eq!(envelope_bytes, vec![1; 10]);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn mpsc_receiver_returns_none_when_empty() {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let mut receiver = MpscRuleReceiver::new(rx);

        // Channel exists but no messages sent
        assert!(receiver.try_recv().is_none());

        // Send one, recv it, then should be none again
        tx.try_send(make_new_rule_event(1)).unwrap();
        assert!(receiver.try_recv().is_some());
        assert!(receiver.try_recv().is_none());
    }

    #[test]
    fn mpsc_receiver_is_closed_when_sender_dropped() {
        let (tx, rx) = tokio::sync::mpsc::channel::<InboundRuleEvent>(16);
        let receiver = MpscRuleReceiver::new(rx);

        assert!(!receiver.is_closed());
        drop(tx);
        assert!(receiver.is_closed());
    }

    // ── drain_available tests ───────────────────────────────────────────

    #[test]
    fn drain_available_collects_all_events() {
        let mut receiver = MockRuleReceiver::new(vec![
            make_new_rule_event(1),
            make_new_rule_event(2),
            make_confidence_event(42),
        ]);

        let events = drain_available(&mut receiver);
        assert_eq!(events.len(), 3);
        assert_eq!(receiver.remaining(), 0);
    }

    #[test]
    fn drain_available_empty_returns_empty_vec() {
        let mut receiver = MockRuleReceiver::empty();
        let events = drain_available(&mut receiver);
        assert!(events.is_empty());
    }

    // ── Trait object safety ─────────────────────────────────────────────

    #[test]
    fn rule_receiver_is_object_safe() {
        let mut receiver: Box<dyn RuleReceiver> =
            Box::new(MockRuleReceiver::new(vec![make_new_rule_event(1)]));
        let event = receiver.try_recv();
        assert!(event.is_some());
    }
}
