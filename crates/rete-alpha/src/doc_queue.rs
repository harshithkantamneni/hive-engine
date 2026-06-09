//! Bounded FIFO document queue with backpressure signaling.
//!
//! Provides a simple bounded queue (capacity 8) for document paths awaiting
//! extraction. The orchestrator enqueues document paths from the UI and
//! dequeues them one at a time for the extraction subprocess.
//!
//! Document queue: bounded FIFO (capacity 8), with backpressure signaling
//! to the UI.

use std::collections::VecDeque;
use std::path::PathBuf;

/// Default queue capacity.
pub const DEFAULT_CAPACITY: usize = 8;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Error returned when the queue is full and cannot accept a new document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueFull {
    /// The path that was rejected.
    pub path: PathBuf,
    /// Current queue length (equal to capacity).
    pub current_len: usize,
}

impl std::fmt::Display for QueueFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Document queue full ({}/{}): {}",
            self.current_len,
            self.current_len,
            self.path.display()
        )
    }
}

impl std::error::Error for QueueFull {}

// ---------------------------------------------------------------------------
// DocQueue
// ---------------------------------------------------------------------------

/// Bounded FIFO queue for document file paths awaiting extraction.
///
/// - Capacity is fixed at construction time (default: 8).
/// - `try_enqueue` returns `Err(QueueFull)` when full (backpressure signal).
/// - `dequeue` returns `None` when empty.
/// - Documents are processed FIFO; the orchestrator dequeues one at a time.
///
/// Memory: 8 PathBufs ~ a few hundred bytes. Well under 0.01 MB.
pub struct DocQueue {
    inner: VecDeque<PathBuf>,
    capacity: usize,
}

impl DocQueue {
    /// Create a new queue with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "DocQueue capacity must be > 0");
        Self {
            inner: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Create a new queue with the default capacity (8).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Attempt to enqueue a document path.
    ///
    /// Returns `Ok(())` if the path was added, or `Err(QueueFull)` if the
    /// queue is at capacity. This is the backpressure signal -- the caller
    /// (orchestrator) should notify the UI that the queue is full.
    pub fn try_enqueue(&mut self, path: PathBuf) -> Result<(), QueueFull> {
        if self.inner.len() >= self.capacity {
            return Err(QueueFull {
                path,
                current_len: self.inner.len(),
            });
        }
        self.inner.push_back(path);
        Ok(())
    }

    /// Dequeue the next document path (FIFO order).
    ///
    /// Returns `None` if the queue is empty.
    pub fn dequeue(&mut self) -> Option<PathBuf> {
        self.inner.pop_front()
    }

    /// Peek at the next document without removing it.
    pub fn peek(&self) -> Option<&PathBuf> {
        self.inner.front()
    }

    /// Current number of queued documents.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Whether the queue is at capacity (backpressure signal).
    pub fn is_full(&self) -> bool {
        self.inner.len() >= self.capacity
    }

    /// Maximum number of items the queue can hold.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Drain all items from the queue, returning them as a Vec.
    /// Used during shutdown to flush pending documents.
    pub fn drain_all(&mut self) -> Vec<PathBuf> {
        self.inner.drain(..).collect()
    }
}

impl Default for DocQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_queue_is_empty() {
        let q = DocQueue::new();
        assert!(q.is_empty());
        assert!(!q.is_full());
        assert_eq!(q.len(), 0);
        assert_eq!(q.capacity(), DEFAULT_CAPACITY);
    }

    #[test]
    fn test_enqueue_and_dequeue_fifo() {
        let mut q = DocQueue::new();
        q.try_enqueue(PathBuf::from("/doc/a.pdf")).unwrap();
        q.try_enqueue(PathBuf::from("/doc/b.pdf")).unwrap();
        q.try_enqueue(PathBuf::from("/doc/c.pdf")).unwrap();

        assert_eq!(q.len(), 3);
        assert_eq!(q.dequeue(), Some(PathBuf::from("/doc/a.pdf")));
        assert_eq!(q.dequeue(), Some(PathBuf::from("/doc/b.pdf")));
        assert_eq!(q.dequeue(), Some(PathBuf::from("/doc/c.pdf")));
        assert_eq!(q.dequeue(), None);
    }

    #[test]
    fn test_backpressure_when_full() {
        let mut q = DocQueue::with_capacity(3);
        q.try_enqueue(PathBuf::from("/a")).unwrap();
        q.try_enqueue(PathBuf::from("/b")).unwrap();
        q.try_enqueue(PathBuf::from("/c")).unwrap();

        assert!(q.is_full());
        let err = q.try_enqueue(PathBuf::from("/d")).unwrap_err();
        assert_eq!(err.path, PathBuf::from("/d"));
        assert_eq!(err.current_len, 3);

        // After dequeue, space opens up
        q.dequeue();
        assert!(!q.is_full());
        q.try_enqueue(PathBuf::from("/d")).unwrap();
        assert!(q.is_full());
    }

    #[test]
    fn test_peek_does_not_remove() {
        let mut q = DocQueue::new();
        q.try_enqueue(PathBuf::from("/peek_test")).unwrap();
        assert_eq!(q.peek(), Some(&PathBuf::from("/peek_test")));
        assert_eq!(q.len(), 1);
        assert_eq!(q.peek(), Some(&PathBuf::from("/peek_test")));
    }

    #[test]
    fn test_dequeue_empty_returns_none() {
        let mut q = DocQueue::new();
        assert_eq!(q.dequeue(), None);
    }

    #[test]
    fn test_drain_all() {
        let mut q = DocQueue::new();
        q.try_enqueue(PathBuf::from("/x")).unwrap();
        q.try_enqueue(PathBuf::from("/y")).unwrap();
        q.try_enqueue(PathBuf::from("/z")).unwrap();

        let drained = q.drain_all();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0], PathBuf::from("/x"));
        assert_eq!(drained[1], PathBuf::from("/y"));
        assert_eq!(drained[2], PathBuf::from("/z"));
        assert!(q.is_empty());
    }

    #[test]
    fn test_fill_to_exact_capacity() {
        let mut q = DocQueue::with_capacity(DEFAULT_CAPACITY);
        for i in 0..DEFAULT_CAPACITY {
            q.try_enqueue(PathBuf::from(format!("/doc/{}", i))).unwrap();
        }
        assert!(q.is_full());
        assert_eq!(q.len(), DEFAULT_CAPACITY);

        // One more should fail
        assert!(q.try_enqueue(PathBuf::from("/overflow")).is_err());
    }

    #[test]
    fn test_interleaved_enqueue_dequeue() {
        let mut q = DocQueue::with_capacity(2);
        q.try_enqueue(PathBuf::from("/1")).unwrap();
        q.try_enqueue(PathBuf::from("/2")).unwrap();
        assert!(q.is_full());

        assert_eq!(q.dequeue(), Some(PathBuf::from("/1")));
        q.try_enqueue(PathBuf::from("/3")).unwrap();

        assert_eq!(q.dequeue(), Some(PathBuf::from("/2")));
        assert_eq!(q.dequeue(), Some(PathBuf::from("/3")));
        assert!(q.is_empty());
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn test_zero_capacity_panics() {
        DocQueue::with_capacity(0);
    }

    #[test]
    fn test_queue_full_error_display() {
        let err = QueueFull {
            path: PathBuf::from("/test/doc.pdf"),
            current_len: 8,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Document queue full"));
        assert!(msg.contains("doc.pdf"));
    }

    #[test]
    fn test_default_trait() {
        let q = DocQueue::default();
        assert_eq!(q.capacity(), DEFAULT_CAPACITY);
        assert!(q.is_empty());
    }
}
