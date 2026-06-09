//! Async sender trait + implementation for outbound tuples.
//!
//! Bridges the privacy pipeline's jitter queue drain to the P2P layer's
//! Dandelion++ behaviour. The `TupleSender` trait allows mocking in tests.

use super::ShareablePayload;
use std::sync::Mutex;
use tokio::sync::mpsc;

// ============================================================================
// Error type
// ============================================================================

/// Error returned when sending a tuple payload fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// Channel is closed (receiver dropped).
    ChannelClosed,
    /// Channel is full (backpressure).
    ChannelFull,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::ChannelClosed => write!(f, "tuple send channel closed"),
            SendError::ChannelFull => write!(f, "tuple send channel full (backpressure)"),
        }
    }
}

impl std::error::Error for SendError {}

// ============================================================================
// TupleSender trait
// ============================================================================

/// Async trait for sending tuples from the privacy pipeline to the P2P layer.
///
/// Implementations may use tokio::mpsc, mock recorders, or test stubs.
/// The trait is object-safe and Send+Sync for use in async contexts.
pub trait TupleSender: Send + Sync {
    /// Send a shareable payload to the P2P layer.
    ///
    /// Returns `Ok(())` on success, or `Err(SendError)` if the channel
    /// is closed or full.
    fn send(&self, payload: ShareablePayload) -> Result<(), SendError>;

    /// Try to send without blocking. Returns immediately.
    fn try_send(&self, payload: ShareablePayload) -> Result<(), SendError>;
}

// ============================================================================
// MpscTupleSender -- production implementation
// ============================================================================

/// Production implementation wrapping a `tokio::mpsc::Sender<ShareablePayload>`.
///
/// Uses `try_send` internally to avoid blocking the pipeline thread.
/// If the channel is full, returns `SendError::ChannelFull` so the caller
/// can hold the tuple in the jitter queue for the next drain cycle.
pub struct MpscTupleSender {
    inner: mpsc::Sender<ShareablePayload>,
}

impl MpscTupleSender {
    /// Create a new sender wrapping the given mpsc sender half.
    pub fn new(sender: mpsc::Sender<ShareablePayload>) -> Self {
        Self { inner: sender }
    }
}

impl TupleSender for MpscTupleSender {
    fn send(&self, payload: ShareablePayload) -> Result<(), SendError> {
        self.inner.try_send(payload).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => SendError::ChannelFull,
            mpsc::error::TrySendError::Closed(_) => SendError::ChannelClosed,
        })
    }

    fn try_send(&self, payload: ShareablePayload) -> Result<(), SendError> {
        self.send(payload)
    }
}

// ============================================================================
// MockTupleSender -- test implementation
// ============================================================================

/// Mock implementation that records sent payloads for test assertions.
///
/// Thread-safe via internal Mutex. Not intended for production use.
pub struct MockTupleSender {
    sent: Mutex<Vec<ShareablePayload>>,
    /// If set, all sends will return this error.
    force_error: Mutex<Option<SendError>>,
}

impl MockTupleSender {
    /// Create a new mock sender.
    pub fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            force_error: Mutex::new(None),
        }
    }

    /// Get a copy of all sent payloads.
    pub fn sent_payloads(&self) -> Vec<ShareablePayload> {
        self.sent.lock().unwrap().clone()
    }

    /// Get the count of sent payloads.
    pub fn sent_count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    /// Configure the mock to return an error on all subsequent sends.
    pub fn set_error(&self, error: SendError) {
        *self.force_error.lock().unwrap() = Some(error);
    }

    /// Clear any forced error.
    pub fn clear_error(&self) {
        *self.force_error.lock().unwrap() = None;
    }
}

impl Default for MockTupleSender {
    fn default() -> Self {
        Self::new()
    }
}

impl TupleSender for MockTupleSender {
    fn send(&self, payload: ShareablePayload) -> Result<(), SendError> {
        if let Some(err) = self.force_error.lock().unwrap().clone() {
            return Err(err);
        }
        self.sent.lock().unwrap().push(payload);
        Ok(())
    }

    fn try_send(&self, payload: ShareablePayload) -> Result<(), SendError> {
        self.send(payload)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_payload(id_byte: u8) -> ShareablePayload {
        ShareablePayload::new(vec![id_byte; 10], 2, 10, [id_byte; 20])
    }

    // ── MockTupleSender tests ───────────────────────────────────────────

    #[test]
    fn mock_sender_records_payloads() {
        let sender = MockTupleSender::new();
        assert_eq!(sender.sent_count(), 0);

        sender.send(make_test_payload(1)).unwrap();
        sender.send(make_test_payload(2)).unwrap();

        assert_eq!(sender.sent_count(), 2);
        let payloads = sender.sent_payloads();
        assert_eq!(payloads[0].wire_bytes, vec![1; 10]);
        assert_eq!(payloads[1].wire_bytes, vec![2; 10]);
    }

    #[test]
    fn mock_sender_forced_error_channel_closed() {
        let sender = MockTupleSender::new();
        sender.set_error(SendError::ChannelClosed);

        let result = sender.send(make_test_payload(1));
        assert_eq!(result, Err(SendError::ChannelClosed));
        assert_eq!(sender.sent_count(), 0);
    }

    #[test]
    fn mock_sender_forced_error_channel_full() {
        let sender = MockTupleSender::new();
        sender.set_error(SendError::ChannelFull);

        let result = sender.send(make_test_payload(1));
        assert_eq!(result, Err(SendError::ChannelFull));
    }

    #[test]
    fn mock_sender_clear_error_resumes_recording() {
        let sender = MockTupleSender::new();
        sender.set_error(SendError::ChannelFull);
        assert!(sender.send(make_test_payload(1)).is_err());

        sender.clear_error();
        sender.send(make_test_payload(2)).unwrap();
        assert_eq!(sender.sent_count(), 1);
    }

    #[test]
    fn mock_sender_try_send_same_as_send() {
        let sender = MockTupleSender::new();
        sender.try_send(make_test_payload(1)).unwrap();
        assert_eq!(sender.sent_count(), 1);
    }

    // ── MpscTupleSender tests ───────────────────────────────────────────

    #[test]
    fn mpsc_sender_send_succeeds() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let sender = MpscTupleSender::new(tx);

        sender.send(make_test_payload(1)).unwrap();

        let received = rx.try_recv().unwrap();
        assert_eq!(received.wire_bytes, vec![1; 10]);
    }

    #[test]
    fn mpsc_sender_closed_channel_returns_error() {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let sender = MpscTupleSender::new(tx);
        drop(rx); // close the receiver

        let result = sender.send(make_test_payload(1));
        assert_eq!(result, Err(SendError::ChannelClosed));
    }

    #[test]
    fn mpsc_sender_full_channel_returns_error() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let sender = MpscTupleSender::new(tx);

        // Fill the channel
        sender.send(make_test_payload(1)).unwrap();
        // Second send should fail with ChannelFull
        let result = sender.send(make_test_payload(2));
        assert_eq!(result, Err(SendError::ChannelFull));
    }

    // ── SendError display tests ─────────────────────────────────────────

    #[test]
    fn send_error_display() {
        assert_eq!(
            format!("{}", SendError::ChannelClosed),
            "tuple send channel closed"
        );
        assert_eq!(
            format!("{}", SendError::ChannelFull),
            "tuple send channel full (backpressure)"
        );
    }

    // ── Trait object safety ─────────────────────────────────────────────

    #[test]
    fn tuple_sender_is_object_safe() {
        let sender: Box<dyn TupleSender> = Box::new(MockTupleSender::new());
        sender.send(make_test_payload(1)).unwrap();
        // If this compiles and runs, TupleSender is object-safe.
    }
}
