//! Watch Folder: automatic document processing for files dropped into a directory.
//!
//! Uses the `notify` crate (v6) for cross-platform filesystem watching.
//! Detected files are queued for processing via the orchestrator's document queue.
//!
//! ## Design
//!
//! - Watches a configurable directory (default: `~/.hive/watch/`).
//! - Creates the watch directory on startup if it doesn't exist.
//! - Detects new files with supported extensions: .pdf, .txt, .json, .png, .jpg, .jpeg.
//! - Debounces events (500ms) to handle partial writes / multi-event file drops.
//! - Tracks processed files via a HashSet of canonical paths (no re-processing).
//! - Moves processed files to `<watch_dir>/processed/`.
//! - Moves failed files to `<watch_dir>/failed/` with a `.error` sidecar.
//! - Communicates with the main event loop via `tokio::sync::mpsc`.
//! - Graceful shutdown via a `tokio::sync::watch` channel.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use log::warn;

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default debounce duration in milliseconds.
pub const DEBOUNCE_MS: u64 = 500;

/// Supported file extensions for automatic processing.
pub const SUPPORTED_EXTENSIONS: &[&str] = &["pdf", "txt", "json", "png", "jpg", "jpeg"];

/// Default watch directory relative to home: `~/.hive/watch/`.
pub const DEFAULT_WATCH_SUBDIR: &str = ".hive/watch";

/// Maximum number of entries in the processed_files HashSet before pruning.
pub const PROCESSED_FILES_CAPACITY: usize = 10_000;

// ---------------------------------------------------------------------------
// WatchEvent: messages from the watcher to the main loop
// ---------------------------------------------------------------------------

/// Events emitted by the watch folder to the orchestrator integration layer.
#[derive(Debug, Clone)]
pub enum WatchEvent {
    /// A new file was detected and is ready for processing.
    NewFile(PathBuf),
    /// The watcher encountered an error.
    Error(String),
}

// ---------------------------------------------------------------------------
// WatchFolderConfig
// ---------------------------------------------------------------------------

/// Configuration for the watch folder.
#[derive(Debug, Clone)]
pub struct WatchFolderConfig {
    /// Directory to watch for new files.
    pub watch_dir: PathBuf,
    /// Debounce duration in milliseconds.
    pub debounce_ms: u64,
}

impl WatchFolderConfig {
    /// Create a config with the default watch directory (`~/.hive/watch/`).
    pub fn default_dir() -> Option<Self> {
        default_watch_dir().map(|dir| Self {
            watch_dir: dir,
            debounce_ms: DEBOUNCE_MS,
        })
    }

    /// Create a config with a custom watch directory.
    pub fn with_dir(dir: PathBuf) -> Self {
        Self {
            watch_dir: dir,
            debounce_ms: DEBOUNCE_MS,
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Resolve the default watch directory: `~/.hive/watch/`.
pub fn default_watch_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(DEFAULT_WATCH_SUBDIR))
}

/// Check if a file extension is supported for processing.
pub fn is_supported_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| SUPPORTED_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
        .unwrap_or(false)
}

/// Ensure the watch directory and its subdirectories exist.
pub fn ensure_watch_dirs(watch_dir: &Path) -> Result<(), String> {
    let processed_dir = watch_dir.join("processed");
    let failed_dir = watch_dir.join("failed");

    fs::create_dir_all(watch_dir)
        .map_err(|e| format!("Failed to create watch dir {}: {}", watch_dir.display(), e))?;
    fs::create_dir_all(&processed_dir)
        .map_err(|e| format!("Failed to create processed dir: {}", e))?;
    fs::create_dir_all(&failed_dir).map_err(|e| format!("Failed to create failed dir: {}", e))?;

    Ok(())
}

/// Move a processed file to the `processed/` subdirectory.
pub fn move_to_processed(file_path: &Path, watch_dir: &Path) -> Result<PathBuf, String> {
    let file_name = file_path
        .file_name()
        .ok_or_else(|| "File has no name".to_string())?;
    let dest = watch_dir.join("processed").join(file_name);

    // Handle case where destination already exists (add numeric suffix).
    let final_dest = unique_path(&dest);

    fs::rename(file_path, &final_dest).map_err(|e| {
        format!(
            "Failed to move {} to {}: {}",
            file_path.display(),
            final_dest.display(),
            e
        )
    })?;

    Ok(final_dest)
}

/// Move a failed file to the `failed/` subdirectory and write an error sidecar.
pub fn move_to_failed(
    file_path: &Path,
    watch_dir: &Path,
    error_message: &str,
) -> Result<PathBuf, String> {
    let file_name = file_path
        .file_name()
        .ok_or_else(|| "File has no name".to_string())?;
    let dest = watch_dir.join("failed").join(file_name);

    // Handle case where destination already exists.
    let final_dest = unique_path(&dest);

    // Move the file.
    fs::rename(file_path, &final_dest).map_err(|e| {
        format!(
            "Failed to move {} to {}: {}",
            file_path.display(),
            final_dest.display(),
            e
        )
    })?;

    // Write the error sidecar (.error file).
    let error_path = final_dest.with_extension(
        final_dest
            .extension()
            .map(|ext| format!("{}.error", ext.to_string_lossy()))
            .unwrap_or_else(|| "error".to_string()),
    );
    fs::write(&error_path, error_message).map_err(|e| {
        format!(
            "Failed to write error sidecar {}: {}",
            error_path.display(),
            e
        )
    })?;

    Ok(final_dest)
}

/// Generate a unique file path by appending a numeric suffix if the path exists.
fn unique_path(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }

    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let parent = path.parent().unwrap_or(Path::new("."));

    for i in 1..1000 {
        let new_name = if ext.is_empty() {
            format!("{}_{}", stem, i)
        } else {
            format!("{}_{}.{}", stem, i, ext)
        };
        let candidate = parent.join(new_name);
        if !candidate.exists() {
            return candidate;
        }
    }

    // Fallback: use timestamp.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    if ext.is_empty() {
        parent.join(format!("{}_{}", stem, ts))
    } else {
        parent.join(format!("{}_{}.{}", stem, ts, ext))
    }
}

// ---------------------------------------------------------------------------
// WatchFolder: the core watcher
// ---------------------------------------------------------------------------

/// The watch folder manager. Starts a filesystem watcher and emits events
/// for new files that match supported extensions.
pub struct WatchFolder {
    /// Configuration.
    config: WatchFolderConfig,
    /// Set of canonical paths already processed (prevents re-processing).
    processed_files: HashSet<PathBuf>,
    /// The underlying filesystem watcher (kept alive as long as WatchFolder lives).
    _watcher: Option<RecommendedWatcher>,
}

impl WatchFolder {
    /// Create a new watch folder (does not start watching yet).
    pub fn new(config: WatchFolderConfig) -> Self {
        Self {
            config,
            processed_files: HashSet::new(),
            _watcher: None,
        }
    }

    /// The watch directory path.
    pub fn watch_dir(&self) -> &Path {
        &self.config.watch_dir
    }

    /// Number of files tracked as processed.
    pub fn processed_count(&self) -> usize {
        self.processed_files.len()
    }

    /// Check if a file has already been processed.
    pub fn is_processed(&self, path: &Path) -> bool {
        if let Ok(canonical) = fs::canonicalize(path) {
            self.processed_files.contains(&canonical)
        } else {
            // If we cannot canonicalize, check the raw path.
            self.processed_files.contains(path)
        }
    }

    /// Mark a file as processed.
    ///
    /// When the set exceeds `PROCESSED_FILES_CAPACITY`, it is cleared entirely.
    /// Since processed files are moved to `processed/` or `failed/`, they will
    /// not be re-detected by the watcher, so clearing is safe.
    pub fn mark_processed(&mut self, path: &Path) {
        if self.processed_files.len() >= PROCESSED_FILES_CAPACITY {
            self.processed_files.clear();
        }
        if let Ok(canonical) = fs::canonicalize(path) {
            self.processed_files.insert(canonical);
        } else {
            self.processed_files.insert(path.to_path_buf());
        }
    }

    /// Validate that a file path is contained within the watch directory.
    ///
    /// Returns `Err` if the canonical path escapes the watch directory (e.g.,
    /// via a symlink pointing outside it). This prevents symlink-based attacks
    /// where a malicious symlink could cause the watcher to process or move
    /// files outside its designated directory.
    pub fn validate_path(&self, path: &Path) -> Result<(), String> {
        let canonical_path = fs::canonicalize(path)
            .map_err(|e| format!("Failed to canonicalize {}: {}", path.display(), e))?;
        let canonical_watch_dir = fs::canonicalize(&self.config.watch_dir).map_err(|e| {
            format!(
                "Failed to canonicalize watch dir {}: {}",
                self.config.watch_dir.display(),
                e
            )
        })?;
        if !canonical_path.starts_with(&canonical_watch_dir) {
            let msg = format!(
                "Path {} escapes watch directory {} (possible symlink attack), skipping",
                canonical_path.display(),
                canonical_watch_dir.display()
            );
            warn!("{}", msg);
            return Err(msg);
        }
        Ok(())
    }

    /// Start watching. Returns a receiver for watch events.
    ///
    /// The watcher runs in a background thread (via `notify`). Events are
    /// debounced and filtered, then sent on the returned mpsc channel.
    ///
    /// Call `stop()` or drop the WatchFolder to stop watching.
    pub fn start(
        &mut self,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Result<mpsc::Receiver<WatchEvent>, String> {
        // Ensure directories exist.
        ensure_watch_dirs(&self.config.watch_dir)?;

        let (event_tx, event_rx) = mpsc::channel::<WatchEvent>(64);
        let (notify_tx, mut notify_rx) = mpsc::channel::<Result<Event, notify::Error>>(256);

        // Create the notify watcher. It sends raw events to notify_tx.
        let tx_clone = notify_tx.clone();
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                let _ = tx_clone.blocking_send(res);
            },
            Config::default(),
        )
        .map_err(|e| format!("Failed to create filesystem watcher: {}", e))?;

        watcher
            .watch(&self.config.watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| {
                format!(
                    "Failed to watch directory {}: {}",
                    self.config.watch_dir.display(),
                    e
                )
            })?;

        self._watcher = Some(watcher);

        // Spawn a tokio task that debounces and filters events.
        let debounce_ms = self.config.debounce_ms;
        let watch_dir = self.config.watch_dir.clone();
        let mut shutdown = shutdown_rx;

        tokio::spawn(async move {
            let mut pending: HashMap<PathBuf, Instant> = HashMap::new();

            loop {
                tokio::select! {
                    // Check for shutdown.
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            break;
                        }
                    }
                    // Check for new filesystem events.
                    Some(result) = notify_rx.recv() => {
                        match result {
                            Ok(event) => {
                                // Only process Create events.
                                if matches!(event.kind, EventKind::Create(_)) {
                                    for path in event.paths {
                                        // Skip directories, subdirectories (processed/failed).
                                        if path.is_dir() {
                                            continue;
                                        }
                                        if let Some(parent) = path.parent() {
                                            if parent != watch_dir {
                                                continue;
                                            }
                                        }
                                        if is_supported_extension(&path) {
                                            pending.insert(path, Instant::now());
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = event_tx
                                    .send(WatchEvent::Error(format!("Watcher error: {}", e)))
                                    .await;
                            }
                        }
                    }
                    // Debounce timer: check pending events every 100ms.
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                        let debounce_threshold =
                            std::time::Duration::from_millis(debounce_ms);
                        let now = Instant::now();

                        let ready: Vec<PathBuf> = pending
                            .iter()
                            .filter(|(_, ts)| now.duration_since(**ts) >= debounce_threshold)
                            .map(|(path, _)| path.clone())
                            .collect();

                        for path in ready {
                            pending.remove(&path);
                            // Verify the file still exists (might have been deleted).
                            if path.exists() {
                                let _ = event_tx.send(WatchEvent::NewFile(path)).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(event_rx)
    }

    /// Stop watching (drops the watcher).
    pub fn stop(&mut self) {
        self._watcher = None;
    }

    /// Handle a successfully processed file: validate, mark as processed, and move.
    pub fn handle_success(&mut self, file_path: &Path) -> Result<PathBuf, String> {
        self.validate_path(file_path)?;
        self.mark_processed(file_path);
        move_to_processed(file_path, &self.config.watch_dir)
    }

    /// Handle a failed file: validate, mark as processed (to prevent retry loop), and move.
    pub fn handle_failure(&mut self, file_path: &Path, error: &str) -> Result<PathBuf, String> {
        self.validate_path(file_path)?;
        self.mark_processed(file_path);
        move_to_failed(file_path, &self.config.watch_dir, error)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    /// Helper: create a temporary watch directory with the required subdirs.
    fn setup_temp_watch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("hive_watch_test").join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(dir.join("processed")).unwrap();
        fs::create_dir_all(dir.join("failed")).unwrap();
        dir
    }

    /// Helper: create a file with content in the given directory.
    fn create_test_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        let mut f = File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.sync_all().unwrap();
        path
    }

    // -----------------------------------------------------------------------
    // Test 1: File extension filtering (accept .pdf, reject .exe)
    // -----------------------------------------------------------------------
    #[test]
    fn test_supported_extensions_accept() {
        assert!(is_supported_extension(Path::new("doc.pdf")));
        assert!(is_supported_extension(Path::new("notes.txt")));
        assert!(is_supported_extension(Path::new("data.json")));
        assert!(is_supported_extension(Path::new("photo.png")));
        assert!(is_supported_extension(Path::new("image.jpg")));
        assert!(is_supported_extension(Path::new("scan.jpeg")));
    }

    #[test]
    fn test_supported_extensions_reject() {
        assert!(!is_supported_extension(Path::new("malware.exe")));
        assert!(!is_supported_extension(Path::new("script.sh")));
        assert!(!is_supported_extension(Path::new("archive.zip")));
        assert!(!is_supported_extension(Path::new("binary.bin")));
        assert!(!is_supported_extension(Path::new("noext")));
    }

    #[test]
    fn test_supported_extensions_case_insensitive() {
        assert!(is_supported_extension(Path::new("DOC.PDF")));
        assert!(is_supported_extension(Path::new("Image.JPG")));
        assert!(is_supported_extension(Path::new("data.Json")));
    }

    // -----------------------------------------------------------------------
    // Test 2: Debounce logic -- pending map insert and expiry
    // -----------------------------------------------------------------------
    #[test]
    fn test_debounce_pending_insert_and_ready() {
        let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
        let path = PathBuf::from("/tmp/test.pdf");

        // Insert with a timestamp in the past (simulating elapsed debounce).
        let past = Instant::now() - std::time::Duration::from_millis(600);
        pending.insert(path.clone(), past);

        let debounce = std::time::Duration::from_millis(DEBOUNCE_MS);
        let now = Instant::now();

        let ready: Vec<PathBuf> = pending
            .iter()
            .filter(|(_, ts)| now.duration_since(**ts) >= debounce)
            .map(|(p, _)| p.clone())
            .collect();

        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], PathBuf::from("/tmp/test.pdf"));
    }

    #[test]
    fn test_debounce_pending_not_ready() {
        let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
        let path = PathBuf::from("/tmp/test.pdf");

        // Insert with current timestamp (not yet debounced).
        pending.insert(path.clone(), Instant::now());

        let debounce = std::time::Duration::from_millis(DEBOUNCE_MS);
        let now = Instant::now();

        let ready: Vec<PathBuf> = pending
            .iter()
            .filter(|(_, ts)| now.duration_since(**ts) >= debounce)
            .map(|(p, _)| p.clone())
            .collect();

        assert_eq!(
            ready.len(),
            0,
            "Event should not be ready yet (within debounce window)"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3: Processed file tracking (no reprocessing)
    // -----------------------------------------------------------------------
    #[test]
    fn test_processed_file_tracking() {
        let dir = setup_temp_watch_dir("tracking");
        let config = WatchFolderConfig::with_dir(dir.clone());
        let mut wf = WatchFolder::new(config);

        let file = create_test_file(&dir, "doc.pdf", "hello");

        assert!(!wf.is_processed(&file));
        assert_eq!(wf.processed_count(), 0);

        wf.mark_processed(&file);

        assert!(wf.is_processed(&file));
        assert_eq!(wf.processed_count(), 1);

        // Mark again: should not duplicate.
        wf.mark_processed(&file);
        assert_eq!(wf.processed_count(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Test 4: File move to processed/ directory
    // -----------------------------------------------------------------------
    #[test]
    fn test_move_to_processed() {
        let dir = setup_temp_watch_dir("move_proc");
        let file = create_test_file(&dir, "invoice.pdf", "invoice content");

        let result = move_to_processed(&file, &dir);
        assert!(result.is_ok());

        let dest = result.unwrap();
        assert!(dest.exists());
        assert!(!file.exists());
        assert!(dest.starts_with(dir.join("processed")));
        assert_eq!(fs::read_to_string(&dest).unwrap(), "invoice content");

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Test 5: File move to failed/ directory with error sidecar
    // -----------------------------------------------------------------------
    #[test]
    fn test_move_to_failed_with_sidecar() {
        let dir = setup_temp_watch_dir("move_fail");
        let file = create_test_file(&dir, "bad.txt", "bad content");

        let result = move_to_failed(&file, &dir, "Extraction failed: corrupt PDF");
        assert!(result.is_ok());

        let dest = result.unwrap();
        assert!(dest.exists());
        assert!(!file.exists());
        assert!(dest.starts_with(dir.join("failed")));

        // Check error sidecar exists.
        let error_path = dest.with_extension("txt.error");
        assert!(
            error_path.exists(),
            "Error sidecar should exist at {}",
            error_path.display()
        );
        let error_content = fs::read_to_string(&error_path).unwrap();
        assert!(error_content.contains("Extraction failed"));

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Test 6: Watch directory creation
    // -----------------------------------------------------------------------
    #[test]
    fn test_ensure_watch_dirs_creates_all() {
        let dir = std::env::temp_dir()
            .join("hive_watch_test")
            .join("create_dirs");
        let _ = fs::remove_dir_all(&dir);

        // Directory should not exist yet.
        assert!(!dir.exists());

        let result = ensure_watch_dirs(&dir);
        assert!(result.is_ok());

        assert!(dir.exists());
        assert!(dir.join("processed").exists());
        assert!(dir.join("failed").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_ensure_watch_dirs_idempotent() {
        let dir = setup_temp_watch_dir("idempotent");

        // Call twice: should not error.
        assert!(ensure_watch_dirs(&dir).is_ok());
        assert!(ensure_watch_dirs(&dir).is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Test 7: Graceful shutdown (watcher stops on drop)
    // -----------------------------------------------------------------------
    #[test]
    fn test_graceful_shutdown_stop() {
        let dir = setup_temp_watch_dir("shutdown");
        let config = WatchFolderConfig::with_dir(dir.clone());
        let mut wf = WatchFolder::new(config);

        // Stop without starting: should be safe.
        wf.stop();
        assert!(wf._watcher.is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_graceful_shutdown_drop() {
        let dir = setup_temp_watch_dir("shutdown_drop");
        let config = WatchFolderConfig::with_dir(dir.clone());
        let wf = WatchFolder::new(config);

        // Drop should not panic.
        drop(wf);

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Test 8: Configuration persistence (watch fields in HiveConfig)
    // -----------------------------------------------------------------------
    #[test]
    fn test_config_watch_fields_roundtrip() {
        use crate::hive_config::HiveConfig;

        let dir = std::env::temp_dir()
            .join("hive_watch_test")
            .join("config_rt");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");

        let config = HiveConfig {
            watch_enabled: true,
            watch_dir: Some("/custom/watch/path".to_string()),
            ..HiveConfig::default()
        };
        config.save_to(&path).unwrap();

        let loaded = HiveConfig::load_from(&path);
        assert!(loaded.watch_enabled);
        assert_eq!(loaded.watch_dir, Some("/custom/watch/path".to_string()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_config_watch_fields_default() {
        use crate::hive_config::HiveConfig;

        let config = HiveConfig::default();
        assert!(!config.watch_enabled);
        assert_eq!(config.watch_dir, None);
    }

    // -----------------------------------------------------------------------
    // Test 9: Custom watch directory path
    // -----------------------------------------------------------------------
    #[test]
    fn test_custom_watch_dir() {
        let custom_dir = std::env::temp_dir()
            .join("hive_watch_test")
            .join("custom_path");
        let _ = fs::remove_dir_all(&custom_dir);

        let config = WatchFolderConfig::with_dir(custom_dir.clone());
        let wf = WatchFolder::new(config);

        assert_eq!(wf.watch_dir(), custom_dir);

        let _ = fs::remove_dir_all(&custom_dir);
    }

    #[test]
    fn test_default_watch_dir_resolution() {
        // On systems with $HOME, this should resolve.
        if std::env::var("HOME").is_ok() {
            let dir = default_watch_dir();
            assert!(dir.is_some());
            let d = dir.unwrap();
            assert!(d.to_string_lossy().contains(".hive/watch"));
        }
    }

    // -----------------------------------------------------------------------
    // Test 10: Concurrent file drops (multiple files at once)
    // -----------------------------------------------------------------------
    #[test]
    fn test_concurrent_file_drops() {
        let dir = setup_temp_watch_dir("concurrent");
        let config = WatchFolderConfig::with_dir(dir.clone());
        let mut wf = WatchFolder::new(config);

        // Simulate 10 files dropped simultaneously.
        let mut files = Vec::new();
        for i in 0..10 {
            let file = create_test_file(&dir, &format!("doc_{}.pdf", i), &format!("content {}", i));
            files.push(file);
        }

        // Process all: mark each as processed and move.
        for file in &files {
            let result = wf.handle_success(file);
            assert!(result.is_ok(), "Failed to handle file: {}", file.display());
        }

        assert_eq!(wf.processed_count(), 10);

        // Verify all files moved to processed/.
        let processed_dir = dir.join("processed");
        let processed_files: Vec<_> = fs::read_dir(&processed_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(processed_files.len(), 10);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_concurrent_mixed_success_and_failure() {
        let dir = setup_temp_watch_dir("concurrent_mixed");
        let config = WatchFolderConfig::with_dir(dir.clone());
        let mut wf = WatchFolder::new(config);

        // Create files.
        let good_file = create_test_file(&dir, "good.pdf", "good content");
        let bad_file = create_test_file(&dir, "bad.txt", "bad content");

        // Process good file.
        let result = wf.handle_success(&good_file);
        assert!(result.is_ok());

        // Process bad file.
        let result = wf.handle_failure(&bad_file, "parse error");
        assert!(result.is_ok());

        assert_eq!(wf.processed_count(), 2);

        // Verify good is in processed/, bad is in failed/.
        assert!(dir.join("processed").join("good.pdf").exists());
        assert!(dir.join("failed").join("bad.txt").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Edge case: file deleted before processing
    // -----------------------------------------------------------------------
    #[test]
    fn test_file_deleted_before_move() {
        let dir = setup_temp_watch_dir("deleted");
        let file = create_test_file(&dir, "ephemeral.pdf", "content");

        // Delete the file before attempting to move.
        fs::remove_file(&file).unwrap();

        let result = move_to_processed(&file, &dir);
        assert!(result.is_err(), "Should fail when file doesn't exist");
    }

    // -----------------------------------------------------------------------
    // Edge case: symlinks
    // -----------------------------------------------------------------------
    #[test]
    fn test_symlink_extension_check() {
        // Symlinks are checked by their path extension, not target.
        let symlink_path = Path::new("/tmp/linked_doc.pdf");
        assert!(is_supported_extension(symlink_path));

        let symlink_no_ext = Path::new("/tmp/linked_doc");
        assert!(!is_supported_extension(symlink_no_ext));
    }

    // -----------------------------------------------------------------------
    // Edge case: unique path generation
    // -----------------------------------------------------------------------
    #[test]
    fn test_unique_path_no_conflict() {
        let path = PathBuf::from("/tmp/hive_watch_test_nonexistent/doc.pdf");
        let result = unique_path(&path);
        assert_eq!(result, path, "No conflict: should return original path");
    }

    #[test]
    fn test_unique_path_with_conflict() {
        let dir = setup_temp_watch_dir("unique_path");
        let original = create_test_file(&dir, "doc.pdf", "content");

        let result = unique_path(&original);
        assert_ne!(
            result, original,
            "Should generate a new path when conflict exists"
        );
        assert!(result.to_string_lossy().contains("doc_1.pdf"));

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // WatchFolder handle_success / handle_failure integration
    // -----------------------------------------------------------------------
    #[test]
    fn test_handle_success_marks_processed_and_moves() {
        let dir = setup_temp_watch_dir("handle_success");
        let config = WatchFolderConfig::with_dir(dir.clone());
        let mut wf = WatchFolder::new(config);

        let file = create_test_file(&dir, "report.pdf", "report data");
        let result = wf.handle_success(&file);
        assert!(result.is_ok());
        // The original canonical path should be marked processed.
        // Note: file no longer exists, so is_processed may use the raw path.
        assert_eq!(wf.processed_count(), 1);
        assert!(!file.exists());
        assert!(dir.join("processed").join("report.pdf").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_handle_failure_marks_processed_and_moves_with_sidecar() {
        let dir = setup_temp_watch_dir("handle_failure");
        let config = WatchFolderConfig::with_dir(dir.clone());
        let mut wf = WatchFolder::new(config);

        let file = create_test_file(&dir, "corrupt.json", "{bad json");
        let result = wf.handle_failure(&file, "JSON parse error at line 1");
        assert!(result.is_ok());
        assert_eq!(wf.processed_count(), 1);
        assert!(!file.exists());
        assert!(dir.join("failed").join("corrupt.json").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // BLOCKING-2 fix: symlink escape is rejected
    // -----------------------------------------------------------------------
    #[test]
    fn test_symlink_escape_rejected() {
        let dir = setup_temp_watch_dir("symlink_escape");
        let config = WatchFolderConfig::with_dir(dir.clone());
        let mut wf = WatchFolder::new(config);

        // Create a file OUTSIDE the watch directory.
        let outside_dir = setup_temp_watch_dir("symlink_escape_outside");
        let outside_file = create_test_file(&outside_dir, "secret.txt", "secret data");

        // Create a symlink inside the watch directory pointing to the outside file.
        let symlink_path = dir.join("linked_secret.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_file, &symlink_path).unwrap();

        // Attempting to handle the symlinked file should fail validation.
        let result = wf.handle_success(&symlink_path);
        assert!(
            result.is_err(),
            "Symlink escaping watch dir should be rejected"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("escapes watch directory"),
            "Error should mention escape: {}",
            err_msg
        );

        // The outside file should NOT have been moved or deleted.
        assert!(
            outside_file.exists(),
            "Outside file should remain untouched"
        );

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside_dir);
    }

    // -----------------------------------------------------------------------
    // processed_files capacity limit
    // -----------------------------------------------------------------------
    #[test]
    fn test_processed_files_capacity_pruning() {
        let dir = setup_temp_watch_dir("capacity");
        let config = WatchFolderConfig::with_dir(dir.clone());
        let mut wf = WatchFolder::new(config);

        // Fill the processed_files set to capacity.
        for i in 0..PROCESSED_FILES_CAPACITY {
            wf.processed_files
                .insert(PathBuf::from(format!("/fake/path/{}.pdf", i)));
        }
        assert_eq!(wf.processed_count(), PROCESSED_FILES_CAPACITY);

        // The next mark_processed should trigger a clear.
        let overflow_file = create_test_file(&dir, "overflow.pdf", "data");
        wf.mark_processed(&overflow_file);

        // After clearing + inserting the new one, count should be 1.
        assert_eq!(
            wf.processed_count(),
            1,
            "Set should have been pruned and contain only the new entry"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
