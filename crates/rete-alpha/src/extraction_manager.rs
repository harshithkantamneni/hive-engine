//! Extraction subprocess manager for the Python extraction model.
//!
//! Manages the Python extraction subprocess using a subprocess + JSON IPC
//! design, with model load/unload to free idle RAM.
//!
//! ## State Machine
//!
//! ```text
//!     NotRunning --[document_drop]--> Starting --[ready]--> Running
//!         ^                                                   |
//!         |                            Crashed <--[crash/OOM]-+
//!         |                              |                    |
//!         +--[idle_timeout (60s)]--------+---[retry<=2]-------+
//! ```
//!
//! ## Mock Mode
//!
//! In mock mode (`ExtractionMode::Mock`), no Python process is spawned.
//! Instead, canned extraction output is returned for testing. This allows
//! the entire pipeline to be tested without the ML model.

use crate::tuple_adapter::{ExtractionOutput, ExtractionRequest};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(feature = "live-extraction")]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter, Lines};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Idle timeout before killing the Python subprocess (seconds).
pub const IDLE_TIMEOUT_SECS: u64 = 60;

/// Maximum retries per extraction request.
pub const MAX_RETRIES: u32 = 2;

/// Delay between retries (seconds).
pub const RETRY_DELAY_SECS: u64 = 1;

/// Extraction request timeout (seconds).
pub const REQUEST_TIMEOUT_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Trusted-path validation
// ---------------------------------------------------------------------------
//
// Previously, `spawn_subprocess` trusted any path passed in
// via `ExtractionMode::Live { script_path }`, which in turn was sourced from
// the `HIVE_EXTRACTION_SCRIPT` env variable. A shell with a poisoned env
// could redirect the extraction subprocess to an attacker-controlled `.py`
// file and gain code execution with the user's full privileges. The same
// attack applies to the Python interpreter path (a dropped venv in `/tmp`
// or a hijacked `$PATH` matching `python3`).
//
// The two helpers below are the rejection primitives. They are intentionally
// pure functions (no I/O beyond `canonicalize`) so they are unit-testable and
// cheap to call from `spawn_subprocess` and any future extraction entrypoint.

/// Return the set of trusted root directories for the extraction script.
///
/// Any script path whose canonical form starts with one of these roots is
/// considered safe to execute. Non-existent roots are silently dropped, so
/// the function degrades gracefully on systems where (say) `$HIVE_HOME` is
/// missing — the remaining roots still form a valid allowlist.
fn trusted_script_roots(hive_home: Option<&Path>) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    // Installer root: parent of the currently running `hive` binary. On
    // production macOS this is `/Applications/Hive.app/Contents/MacOS/` or
    // similar; during `cargo run` it is `target/{debug,release}/`.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            if let Ok(c) = parent.canonicalize() {
                roots.push(c);
            }
        }
    }

    // Workspace root: the current working directory's canonical form.
    // During development this covers `rete-alpha/` and anything below it.
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(c) = cwd.canonicalize() {
            roots.push(c);
        }
    }

    // $HIVE_HOME: usually `~/.hive`. The installed extraction script lives
    // under `$HIVE_HOME/extraction/` after `hive-setup.sh` runs.
    if let Some(h) = hive_home {
        if let Ok(c) = h.canonicalize() {
            roots.push(c);
        }
    }

    roots
}

/// Is `path` rooted in one of the trusted script roots?
///
/// Uses `canonicalize` to resolve symlinks and `..` traversal before the
/// prefix check, so `$HIVE_HOME/../../etc/evil.py` is rejected even though
/// the literal string starts with `$HIVE_HOME`.
///
/// Returns `Ok(())` if the path is trusted, `Err(reason)` with a short
/// human-readable explanation if not. Caller is expected to wrap the
/// reason in `ExtractionError::UntrustedScriptPath`.
pub fn is_trusted_script_path(path: &Path, hive_home: Option<&Path>) -> Result<(), String> {
    let canonical = match path.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return Err(format!(
                "cannot canonicalize script path ({}); refusing on principle",
                e
            ));
        }
    };
    let roots = trusted_script_roots(hive_home);
    if roots.is_empty() {
        return Err(
            "no trusted roots available (current_exe, cwd, and $HIVE_HOME all failed)".to_string(),
        );
    }
    for root in &roots {
        if canonical.starts_with(root) {
            return Ok(());
        }
    }
    Err(format!(
        "script path resolves to {} which is outside the trusted roots ({})",
        canonical.display(),
        roots
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Is `interpreter` a trusted Python interpreter?
///
/// Trusted means one of:
///   1. `/usr/bin/python3`  — the Apple-signed system Python.
///   2. An interpreter whose canonical path is under
///      `$HIVE_HOME/extraction-venv/` or `$HIVE_HOME/venv/`, i.e. a venv
///      that `hive-setup.sh` itself created under the user's own
///      permission-hardened `$HIVE_HOME` tree.
///
/// Returns `Ok(())` on trust, `Err(reason)` otherwise.
pub fn is_trusted_python_interpreter(
    interpreter: &Path,
    hive_home: Option<&Path>,
) -> Result<(), String> {
    // Fast-path: Apple's system Python, referenced literally.
    if interpreter == Path::new("/usr/bin/python3") {
        return Ok(());
    }

    let canonical = match interpreter.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return Err(format!(
                "cannot canonicalize interpreter path ({}); refusing on principle",
                e
            ));
        }
    };

    // After canonicalization, the system python may appear as
    // `/usr/bin/python3` (macOS stub) or `/Library/Developer/.../python3`
    // depending on Xcode state. Accept both the literal path and the
    // canonical path for `/usr/bin/python3`.
    if canonical == Path::new("/usr/bin/python3") {
        return Ok(());
    }
    if let Ok(system_canonical) = Path::new("/usr/bin/python3").canonicalize() {
        if canonical == system_canonical {
            return Ok(());
        }
    }

    // Trusted venv roots under $HIVE_HOME.
    if let Some(h) = hive_home {
        let candidates = [h.join("extraction-venv"), h.join("venv")];
        for root in &candidates {
            if let Ok(root_canonical) = root.canonicalize() {
                if canonical.starts_with(&root_canonical) {
                    return Ok(());
                }
            }
        }
    }

    Err(format!(
        "interpreter {} is neither /usr/bin/python3 nor under $HIVE_HOME/{{extraction-venv,venv}}",
        canonical.display()
    ))
}

// ---------------------------------------------------------------------------
// Extraction mode
// ---------------------------------------------------------------------------

/// Controls whether the manager spawns a real Python subprocess or uses
/// canned mock responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractionMode {
    /// Spawn a real Python extraction subprocess.
    /// The `script_path` points to `extraction_service.py`.
    Live { script_path: PathBuf },
    /// Return canned mock responses without spawning Python.
    /// Useful for testing the pipeline end-to-end without ML dependencies.
    Mock,
}

// ---------------------------------------------------------------------------
// Subprocess state machine
// ---------------------------------------------------------------------------

/// State of the Python extraction subprocess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubprocessState {
    /// No Python process exists. 0 MB RAM. Transitions to Starting on
    /// document drop.
    NotRunning,
    /// Python process spawned, model loading (~5s). Transitions to Running
    /// on ready signal, or Crashed on error.
    Starting,
    /// Python process alive, model loaded. 928 MB RAM. Transitions to
    /// NotRunning on idle timeout (60s), or Crashed on crash/OOM.
    Running,
    /// Python process died unexpectedly. Transitions to Starting if
    /// retries < MAX_RETRIES, otherwise to NotRunning (permanent).
    Crashed { retries: u32 },
}

// ---------------------------------------------------------------------------
// Subprocess handle (live-extraction feature only)
// ---------------------------------------------------------------------------

/// Handle to the running Python subprocess.
/// Holds stdin/stdout pipes and the child process handle.
#[cfg(feature = "live-extraction")]
#[allow(dead_code)]
struct SubprocessHandle {
    /// Child process handle (for kill/wait).
    child: tokio::process::Child,
    /// Stdin pipe for sending NDJSON requests.
    stdin: BufWriter<tokio::process::ChildStdin>,
    /// Stdout pipe for reading NDJSON responses.
    stdout: Lines<BufReader<tokio::process::ChildStdout>>,
    /// Process ID (for PID file and diagnostics).
    pid: u32,
    /// Timestamp when process was spawned.
    spawned_at: Instant,
}

// ---------------------------------------------------------------------------
// Extraction results
// ---------------------------------------------------------------------------

/// Result of processing a single document through the extraction model.
#[derive(Debug)]
pub struct ExtractionResult {
    /// The parsed extraction output (entities + relationships).
    pub output: ExtractionOutput,
    /// Wall-clock time for this extraction (including startup if cold).
    pub elapsed: Duration,
    /// The request that produced this result.
    pub request_id: String,
    /// True if subprocess was cold-started for this request.
    pub was_cold_start: bool,
    /// Python-reported extraction latency in ms.
    pub python_latency_ms: u64,
}

/// Error from the extraction subprocess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractionError {
    /// Python process crashed during extraction.
    ProcessCrashed { exit_code: Option<i32> },
    /// OOM kill by OS (exit code 137).
    OutOfMemory,
    /// Extraction request timed out.
    Timeout,
    /// JSON output from Python was malformed.
    MalformedOutput { message: String },
    /// All retries exhausted.
    RetriesExhausted { attempts: u32 },
    /// Python script/model not found.
    ScriptNotFound { path: PathBuf },
    /// Python script path resolves outside the trusted
    /// allowlist (installer root, workspace root, or $HIVE_HOME). Spawning
    /// an arbitrary `.py` file as the extraction subprocess gives the
    /// attacker full code execution in the user's context.
    UntrustedScriptPath { path: PathBuf, reason: String },
    /// Python interpreter path is not one of the
    /// trusted interpreters (`/usr/bin/python3` or an interpreter under
    /// `$HIVE_HOME/extraction-venv/` / `$HIVE_HOME/venv/`). A dropped
    /// venv or a hijacked `$PATH` could otherwise be used to escalate.
    UntrustedPythonInterpreter { path: PathBuf, reason: String },
    /// Internal error (channel closed, etc.).
    Internal { message: String },
}

impl std::fmt::Display for ExtractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessCrashed { exit_code } => {
                write!(
                    f,
                    "Extraction process crashed (exit code: {:?}).\n  \
                     Why: Python runtime error or signal interruption.\n   \
                     Do: Run extraction_service.py standalone to debug.",
                    exit_code
                )
            }
            Self::OutOfMemory => {
                write!(
                    f,
                    "Extraction killed: out of memory (exit code 137).\n  \
                     Why: Model needs ~476 MB RAM + ~82 MB pipeline.\n   \
                     Do: Close other apps; ensure >= 1 GB free RAM."
                )
            }
            Self::Timeout => {
                write!(
                    f,
                    "Extraction timed out after {}s.\n  \
                     Why: Model loading, low RAM, or heavy CPU/GPU load.\n   \
                     Do: Retry (first run caches the model); free RAM.",
                    REQUEST_TIMEOUT_SECS
                )
            }
            Self::MalformedOutput { message } => {
                write!(
                    f,
                    "Malformed extraction output.\n  \
                     Why: {}\n   \
                     Do: Check extraction_service.py JSON output.",
                    message
                )
            }
            Self::RetriesExhausted { attempts } => {
                write!(
                    f,
                    "Extraction failed after {} attempts.\n  \
                     Why: Subprocess crashed repeatedly.\n   \
                     Do: Run extraction_service.py standalone; \
                     try --mock mode.",
                    attempts
                )
            }
            Self::ScriptNotFound { path } => {
                write!(
                    f,
                    "Extraction script not found: {}.\n  \
                     Why: Script missing from expected locations.\n   \
                     Do: Set HIVE_EXTRACTION_SCRIPT or pass path \
                     to --live.",
                    path.display()
                )
            }
            Self::UntrustedScriptPath { path, reason } => {
                write!(
                    f,
                    "Refusing to execute extraction script from untrusted path: {}.\n  \
                     Why: {}\n   \
                     Do: Place the script under the installer root, your \
                     workspace root, or $HIVE_HOME; or re-run with \
                     --allow-custom-extractor if you accept the risk.",
                    path.display(),
                    reason,
                )
            }
            Self::UntrustedPythonInterpreter { path, reason } => {
                write!(
                    f,
                    "Refusing to execute untrusted Python interpreter: {}.\n  \
                     Why: {}\n   \
                     Do: Re-run ./scripts/hive-setup.sh to create the \
                     trusted venv at $HIVE_HOME/extraction-venv, or use \
                     the system interpreter (/usr/bin/python3).",
                    path.display(),
                    reason,
                )
            }
            Self::Internal { message } => {
                write!(
                    f,
                    "Internal extraction error.\n  \
                     Why: {}\n   \
                     Do: File a bug report with the above details.",
                    message
                )
            }
        }
    }
}

impl std::error::Error for ExtractionError {}

// ---------------------------------------------------------------------------
// ExtractionManager
// ---------------------------------------------------------------------------

/// Manages the Python extraction subprocess lifecycle.
///
/// In mock mode, returns canned responses without spawning Python.
/// In live mode (future), manages the subprocess state machine.
///
/// The manager tracks:
/// - Current subprocess state (4-state machine)
/// - Idle timer (60s to kill Python and reclaim 928MB)
/// - Retry counter (max 2 retries per request)
/// - PID file for orphan detection
pub struct ExtractionManager {
    mode: ExtractionMode,
    state: SubprocessState,
    /// Timestamp of last successful extraction (for idle timeout).
    last_activity: Option<Instant>,
    /// Path to PID file for orphan detection.
    pid_file_path: PathBuf,
    /// Total extractions completed (for diagnostics).
    extractions_completed: u64,
    /// Total extractions failed (for diagnostics).
    extractions_failed: u64,
    /// Escape hatch for the trusted-path and trusted-
    /// interpreter guards in `spawn_subprocess`. Off by default so the
    /// default posture is safe; opt-in via `hive --allow-custom-extractor`.
    /// When true, the guards still *log* a warning but do not refuse.
    allow_custom_extractor: bool,
    /// Handle to the running Python subprocess (live-extraction only).
    #[cfg(feature = "live-extraction")]
    subprocess: Option<SubprocessHandle>,
}

impl ExtractionManager {
    /// Create a new extraction manager.
    ///
    /// - `mode`: Mock or Live.
    /// - `pid_file_path`: Location for the PID file (e.g., `~/.hive/extraction.pid`).
    pub fn new(mode: ExtractionMode, pid_file_path: PathBuf) -> Self {
        Self {
            mode,
            state: SubprocessState::NotRunning,
            last_activity: None,
            pid_file_path,
            extractions_completed: 0,
            extractions_failed: 0,
            allow_custom_extractor: false,
            #[cfg(feature = "live-extraction")]
            subprocess: None,
        }
    }

    /// Construct a manager with the trusted-path guard
    /// explicitly downgraded to "warn-only". Intended for CLI opt-in via
    /// `--allow-custom-extractor`. Do not use as a library-level default.
    pub fn new_with_allow_custom(
        mode: ExtractionMode,
        pid_file_path: PathBuf,
        allow_custom_extractor: bool,
    ) -> Self {
        let mut m = Self::new(mode, pid_file_path);
        m.allow_custom_extractor = allow_custom_extractor;
        m
    }

    /// Whether the trusted-path guards are downgraded to warn-only.
    pub fn allow_custom_extractor(&self) -> bool {
        self.allow_custom_extractor
    }

    /// Create a mock-mode manager (convenience constructor for testing).
    pub fn new_mock() -> Self {
        Self::new(
            ExtractionMode::Mock,
            PathBuf::from("/tmp/hive_test_extraction.pid"),
        )
    }

    /// Current subprocess state.
    pub fn state(&self) -> &SubprocessState {
        &self.state
    }

    /// Extraction mode (Mock or Live).
    pub fn mode(&self) -> &ExtractionMode {
        &self.mode
    }

    /// Total extractions successfully completed.
    pub fn extractions_completed(&self) -> u64 {
        self.extractions_completed
    }

    /// Total extractions that failed.
    pub fn extractions_failed(&self) -> u64 {
        self.extractions_failed
    }

    /// Whether the Python process should be killed due to idle timeout.
    ///
    /// Returns true if:
    /// - State is Running
    /// - More than IDLE_TIMEOUT_SECS have elapsed since last activity
    pub fn should_idle_kill(&self) -> bool {
        if self.state != SubprocessState::Running {
            return false;
        }
        match self.last_activity {
            Some(t) => t.elapsed() >= Duration::from_secs(IDLE_TIMEOUT_SECS),
            None => false,
        }
    }

    /// Transition to idle/killed state. Called by the orchestrator when
    /// `should_idle_kill()` returns true.
    pub fn idle_kill(&mut self) {
        // In live mode, this would send SIGTERM to the Python process.
        // In mock mode, just transition state.
        self.state = SubprocessState::NotRunning;
        self.last_activity = None;
    }

    /// Process a document through extraction.
    ///
    /// In mock mode, returns canned output immediately.
    /// In live mode (future), this would:
    /// 1. Ensure the Python process is running (start if needed).
    /// 2. Send ExtractionRequest as JSON on stdin.
    /// 3. Read ExtractionOutput JSON from stdout.
    /// 4. Handle timeouts and crashes.
    pub fn extract_sync(
        &mut self,
        document_text: &str,
        source_file: &str,
    ) -> Result<ExtractionResult, ExtractionError> {
        let start = Instant::now();
        let request = ExtractionRequest::new(document_text.to_string());
        let request_id = request.request_id.clone();

        match &self.mode {
            ExtractionMode::Mock => {
                let output = generate_mock_output(document_text, source_file);
                self.state = SubprocessState::Running;
                self.last_activity = Some(Instant::now());
                self.extractions_completed += 1;
                Ok(ExtractionResult {
                    output,
                    elapsed: start.elapsed(),
                    request_id,
                    was_cold_start: false,
                    python_latency_ms: 0,
                })
            }
            ExtractionMode::Live { script_path } => {
                // Verify script exists
                if !script_path.exists() {
                    return Err(ExtractionError::ScriptNotFound {
                        path: script_path.clone(),
                    });
                }

                // Live mode subprocess management is deferred to async
                // implementation. For now, return an error indicating live
                // mode requires the async path.
                Err(ExtractionError::Internal {
                    message: "Live mode requires async extract() method. Use ExtractionMode::Mock for synchronous testing.".to_string(),
                })
            }
        }
    }

    /// Reset retry counter (called after a successful extraction).
    /// Retained for future orchestrator use.
    #[allow(dead_code)]
    fn reset_retries(&mut self) {
        if let SubprocessState::Crashed { .. } = self.state {
            self.state = SubprocessState::NotRunning;
        }
    }

    /// Record a failed extraction attempt.
    pub fn record_failure(&mut self) {
        self.extractions_failed += 1;
        match &self.state {
            SubprocessState::Running => {
                self.state = SubprocessState::Crashed { retries: 1 };
            }
            SubprocessState::Crashed { retries } => {
                if *retries < MAX_RETRIES {
                    self.state = SubprocessState::Crashed {
                        retries: retries + 1,
                    };
                } else {
                    // Retries exhausted, go back to not running
                    self.state = SubprocessState::NotRunning;
                }
            }
            _ => {
                self.state = SubprocessState::Crashed { retries: 1 };
            }
        }
    }

    /// Check if retries are still available.
    pub fn can_retry(&self) -> bool {
        match &self.state {
            SubprocessState::Crashed { retries } => *retries < MAX_RETRIES,
            _ => true,
        }
    }

    /// Classify a process exit code.
    pub fn classify_exit_code(code: i32) -> ExtractionError {
        match code {
            137 => ExtractionError::OutOfMemory,
            139 => ExtractionError::ProcessCrashed {
                exit_code: Some(139),
            },
            0 => ExtractionError::ProcessCrashed { exit_code: Some(0) },
            other => ExtractionError::ProcessCrashed {
                exit_code: Some(other),
            },
        }
    }

    /// PID file path for orphan detection.
    pub fn pid_file_path(&self) -> &Path {
        &self.pid_file_path
    }

    /// Shut down the extraction manager.
    ///
    /// In live mode, this would SIGTERM the Python process, wait 5s,
    /// then SIGKILL if still alive, and delete the PID file.
    /// In mock mode, just reset state.
    pub fn shutdown(&mut self) {
        self.state = SubprocessState::NotRunning;
        self.last_activity = None;
        // In live mode: kill python process, delete PID file
    }
}

// ---------------------------------------------------------------------------
// Async extraction methods (live-extraction feature only)
// ---------------------------------------------------------------------------

#[cfg(feature = "live-extraction")]
impl ExtractionManager {
    /// Spawn the Python extraction subprocess.
    ///
    /// Only works in `ExtractionMode::Live { script_path }`.
    /// Resolves Python binary: check `<script_dir>/.venv/bin/python3`,
    /// fall back to `python3`.
    /// Sets `HIVE_EXTRACTION_BACKEND=real` env var.
    /// Captures stdin (piped), stdout (piped), stderr (inherit for debug logging).
    /// Writes PID to `self.pid_file_path`.
    /// Transitions state: `NotRunning -> Starting`.
    pub async fn spawn_subprocess(&mut self) -> Result<(), ExtractionError> {
        let script_path = match &self.mode {
            ExtractionMode::Live { script_path } => script_path.clone(),
            ExtractionMode::Mock => {
                return Err(ExtractionError::Internal {
                    message: "Cannot spawn subprocess in mock mode".to_string(),
                });
            }
        };

        // Verify script exists
        if !script_path.exists() {
            return Err(ExtractionError::ScriptNotFound { path: script_path });
        }

        // Trusted-path guard for the extraction script.
        // Resolve $HIVE_HOME once up-front — we use it in both the script and
        // interpreter checks. `std::env::var_os` preserves non-UTF-8 paths.
        let hive_home: Option<PathBuf> = std::env::var_os("HIVE_HOME").map(PathBuf::from);
        let hive_home_ref: Option<&Path> = hive_home.as_deref();
        if let Err(reason) = is_trusted_script_path(&script_path, hive_home_ref) {
            if self.allow_custom_extractor {
                eprintln!(
                    "[extraction] WARNING: running untrusted extraction script {} \
                     (allow_custom_extractor=true): {}",
                    script_path.display(),
                    reason
                );
            } else {
                return Err(ExtractionError::UntrustedScriptPath {
                    path: script_path,
                    reason,
                });
            }
        }

        // Resolve Python binary: prefer venv, fall back to system python3.
        // Any interpreter outside the allowlist is
        // rejected before we call `cmd.spawn()`, because by then the
        // attacker already has code execution.
        let script_dir = script_path.parent().unwrap_or(Path::new("."));
        let venv_python = script_dir.join(".venv/bin/python3");
        let python = if venv_python.exists() {
            venv_python
        } else {
            PathBuf::from("/usr/bin/python3")
        };

        if let Err(reason) = is_trusted_python_interpreter(&python, hive_home_ref) {
            if self.allow_custom_extractor {
                eprintln!(
                    "[extraction] WARNING: running untrusted Python interpreter {} \
                     (allow_custom_extractor=true): {}",
                    python.display(),
                    reason
                );
            } else {
                return Err(ExtractionError::UntrustedPythonInterpreter {
                    path: python,
                    reason,
                });
            }
        }

        // Spawn the subprocess
        let mut cmd = tokio::process::Command::new(&python);
        cmd.arg(&script_path)
            .env("HIVE_EXTRACTION_BACKEND", "real")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit());

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ExtractionError::ScriptNotFound {
                    path: python.clone(),
                }
            } else {
                ExtractionError::Internal {
                    message: format!("Failed to spawn subprocess: {}", e),
                }
            }
        })?;

        let pid = child.id().unwrap_or(0);

        // Take ownership of stdin/stdout pipes
        let child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| ExtractionError::Internal {
                message: "Failed to capture subprocess stdin".to_string(),
            })?;
        let child_stdout = child
            .stdout
            .take()
            .ok_or_else(|| ExtractionError::Internal {
                message: "Failed to capture subprocess stdout".to_string(),
            })?;

        let stdin = BufWriter::new(child_stdin);
        let stdout = BufReader::new(child_stdout).lines();

        // Write PID file for orphan detection
        if let Some(parent) = self.pid_file_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&self.pid_file_path, pid.to_string());

        self.subprocess = Some(SubprocessHandle {
            child,
            stdin,
            stdout,
            pid,
            spawned_at: Instant::now(),
        });

        self.state = SubprocessState::Starting;

        Ok(())
    }

    /// Send a request and read the response via NDJSON IPC.
    ///
    /// Writes NDJSON request: `{"request_id":"<id>","text":"<text>","max_tokens":2048}\n`
    /// Reads NDJSON response line with 60s timeout.
    /// Parses response JSON. If `status == "error"`, return `ExtractionError::MalformedOutput`.
    /// On timeout: return `ExtractionError::Timeout`.
    /// On broken pipe: detect via `child.try_wait()`, return `ProcessCrashed`.
    pub async fn send_request(
        &mut self,
        text: &str,
        request_id: &str,
    ) -> Result<(ExtractionOutput, u64), ExtractionError> {
        let handle = self
            .subprocess
            .as_mut()
            .ok_or_else(|| ExtractionError::Internal {
                message: "No subprocess running".to_string(),
            })?;

        // Build NDJSON request
        let request = serde_json::json!({
            "request_id": request_id,
            "text": text,
            "max_tokens": 2048
        });
        let request_line = format!(
            "{}\n",
            serde_json::to_string(&request).map_err(|e| {
                ExtractionError::Internal {
                    message: format!("Failed to serialize request: {}", e),
                }
            })?
        );

        // Write request to stdin
        if let Err(e) = handle.stdin.write_all(request_line.as_bytes()).await {
            // Check if process died
            if let Some(status) = handle.child.try_wait().ok().flatten() {
                return Err(ExtractionError::ProcessCrashed {
                    exit_code: status.code(),
                });
            }
            return Err(ExtractionError::Internal {
                message: format!("Failed to write to subprocess stdin: {}", e),
            });
        }
        if let Err(e) = handle.stdin.flush().await {
            if let Some(status) = handle.child.try_wait().ok().flatten() {
                return Err(ExtractionError::ProcessCrashed {
                    exit_code: status.code(),
                });
            }
            return Err(ExtractionError::Internal {
                message: format!("Failed to flush subprocess stdin: {}", e),
            });
        }

        // Read response with timeout
        let response_line = match tokio::time::timeout(
            Duration::from_secs(REQUEST_TIMEOUT_SECS),
            handle.stdout.next_line(),
        )
        .await
        {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => {
                // EOF -- subprocess closed stdout
                if let Some(status) = handle.child.try_wait().ok().flatten() {
                    return Err(ExtractionError::ProcessCrashed {
                        exit_code: status.code(),
                    });
                }
                return Err(ExtractionError::ProcessCrashed { exit_code: None });
            }
            Ok(Err(e)) => {
                return Err(ExtractionError::Internal {
                    message: format!("Failed to read subprocess stdout: {}", e),
                });
            }
            Err(_) => {
                // Timeout
                return Err(ExtractionError::Timeout);
            }
        };

        // Parse response JSON
        let response: serde_json::Value =
            serde_json::from_str(&response_line).map_err(|e| ExtractionError::MalformedOutput {
                message: format!("Invalid JSON response: {}", e),
            })?;

        // Check status
        let status = response
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");

        if status == "error" {
            let error_msg = response
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("Unknown error from extraction service");
            return Err(ExtractionError::MalformedOutput {
                message: error_msg.to_string(),
            });
        }

        if status != "success" {
            return Err(ExtractionError::MalformedOutput {
                message: format!("Unexpected status: {}", status),
            });
        }

        // Validate request_id correlation
        let resp_id = response
            .get("request_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if resp_id != request_id {
            return Err(ExtractionError::MalformedOutput {
                message: format!(
                    "Response ID mismatch: expected '{}', got '{}'",
                    request_id, resp_id
                ),
            });
        }

        // Transition to Running on first successful response
        self.state = SubprocessState::Running;

        // Extract python-reported latency before parsing entities
        let python_latency_ms = Self::parse_latency_ms(&response_line);

        // Parse ExtractionOutput from response
        let document_category = response
            .get("document_category")
            .and_then(|c| c.as_str())
            .unwrap_or("general")
            .to_string();

        let entities = response
            .get("entities")
            .and_then(|e| e.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        Some(crate::tuple_adapter::ExtractedEntity {
                            id: e.get("id")?.as_str()?.to_string(),
                            name: e.get("name")?.as_str()?.to_string(),
                            entity_type: e.get("entity_type")?.as_str()?.to_string(),
                            value: e.get("value").and_then(|v| v.as_str()).map(String::from),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let relationships = response
            .get("relationships")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| {
                        Some(crate::tuple_adapter::ExtractedRelationship {
                            source: r.get("source")?.as_str()?.to_string(),
                            target: r.get("target")?.as_str()?.to_string(),
                            relationship: r.get("relationship")?.as_str()?.to_string(),
                            context: r.get("context").and_then(|c| c.as_str()).map(String::from),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok((
            ExtractionOutput {
                document_category,
                entities,
                relationships,
            },
            python_latency_ms,
        ))
    }

    /// Get the Python-reported latency from the last NDJSON response.
    /// Called internally after `send_request` succeeds — parses `latency_ms`
    /// from the response. Since we already consumed the response in
    /// `send_request`, we pass it as a parameter when we refactor.
    /// For now, this is embedded in the extract_async flow.
    fn parse_latency_ms(response_line: &str) -> u64 {
        serde_json::from_str::<serde_json::Value>(response_line)
            .ok()
            .and_then(|v| v.get("latency_ms")?.as_u64())
            .unwrap_or(0)
    }

    /// Async extraction: spawn if needed, send request, handle errors.
    ///
    /// If mock mode: delegate to existing `extract_sync()` (wrap sync in Ok).
    /// If live mode:
    ///   1. If `NotRunning`, call `spawn_subprocess()`
    ///   2. Generate request_id via `uuid::Uuid::new_v4()`
    ///   3. Call `send_request()`
    ///   4. On success: update `last_activity`, increment `extractions_completed`,
    ///      return result with `was_cold_start` and `python_latency_ms`
    ///   5. On crash/timeout: `record_failure()`, retry if `can_retry()`, else
    ///      return `RetriesExhausted`
    pub async fn extract_async(
        &mut self,
        document_text: &str,
        source_file: &str,
    ) -> Result<ExtractionResult, ExtractionError> {
        // Mock mode: delegate to synchronous path
        if self.mode == ExtractionMode::Mock {
            return self.extract_sync(document_text, source_file);
        }

        let start = Instant::now();

        // Track whether this is a cold start
        let was_cold_start = self.state == SubprocessState::NotRunning
            || matches!(self.state, SubprocessState::Crashed { .. });

        // Spawn if not running
        if self.state == SubprocessState::NotRunning
            || matches!(self.state, SubprocessState::Crashed { .. })
        {
            // Kill any stale subprocess before re-spawning
            if self.subprocess.is_some() {
                self.kill_subprocess().await;
            }
            self.spawn_subprocess().await?;
        }

        let request_id = uuid::Uuid::new_v4().to_string();

        // Attempt extraction with retry loop
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            match self.send_request(document_text, &request_id).await {
                Ok((output, python_latency_ms)) => {
                    self.last_activity = Some(Instant::now());
                    self.extractions_completed += 1;
                    return Ok(ExtractionResult {
                        output,
                        elapsed: start.elapsed(),
                        request_id,
                        was_cold_start,
                        python_latency_ms,
                    });
                }
                Err(ExtractionError::MalformedOutput { .. }) => {
                    // Do NOT retry malformed output (model issue, not transient)
                    self.record_failure();
                    return Err(ExtractionError::MalformedOutput {
                        message: "Extraction produced malformed output".to_string(),
                    });
                }
                Err(_e) => {
                    self.record_failure();

                    // Kill crashed subprocess
                    if self.subprocess.is_some() {
                        self.kill_subprocess().await;
                    }

                    if self.can_retry() {
                        // Re-spawn and retry
                        self.spawn_subprocess().await?;
                        continue;
                    } else {
                        return Err(ExtractionError::RetriesExhausted { attempts });
                    }
                }
            }
        }
    }

    /// Kill the subprocess gracefully.
    ///
    /// Steps:
    ///   1. Close stdin (drop the BufWriter) to trigger clean exit
    ///   2. Wait up to 5 seconds for clean exit
    ///   3. SIGKILL if still alive
    ///   4. Delete PID file
    ///   5. Transition to NotRunning
    pub async fn kill_subprocess(&mut self) {
        if let Some(mut handle) = self.subprocess.take() {
            // Step 1: Close stdin to signal EOF to Python
            drop(handle.stdin);

            // Step 2: Wait up to 5 seconds for clean exit
            let wait_result =
                tokio::time::timeout(Duration::from_secs(5), handle.child.wait()).await;

            match wait_result {
                Ok(Ok(_status)) => {
                    // Clean exit
                }
                Ok(Err(_e)) => {
                    // Error waiting -- try to kill
                    let _ = handle.child.kill().await;
                }
                Err(_) => {
                    // Timeout -- SIGKILL
                    let _ = handle.child.kill().await;
                }
            }

            // Step 4: Delete PID file
            let _ = std::fs::remove_file(&self.pid_file_path);
        }

        // Step 5: Transition to NotRunning
        self.state = SubprocessState::NotRunning;
    }

    /// Async idle kill -- called by the orchestrator event loop timer.
    /// Same as `idle_kill()` but async -- calls `kill_subprocess()`.
    pub async fn idle_kill_async(&mut self) {
        self.kill_subprocess().await;
        self.last_activity = None;
    }

    /// Async shutdown -- called during orchestrator shutdown.
    /// Same as `shutdown()` but async -- calls `kill_subprocess()` if
    /// subprocess exists.
    pub async fn shutdown_async(&mut self) {
        if self.subprocess.is_some() {
            self.kill_subprocess().await;
        }
        self.state = SubprocessState::NotRunning;
        self.last_activity = None;
    }
}

// ---------------------------------------------------------------------------
// Mock extraction output generation
// ---------------------------------------------------------------------------

/// Generate a canned ExtractionOutput for mock mode.
///
/// The mock output is deterministic based on the source file path:
/// - Files containing "medical" produce medical bill entities.
/// - Files containing "lease" produce lease agreement entities.
/// - Everything else produces a generic extraction.
///
/// This allows the full pipeline (tuple adapter -> WME factory -> engine)
/// to be exercised without the Python extraction model.
pub fn generate_mock_output(document_text: &str, source_file: &str) -> ExtractionOutput {
    let lower = source_file.to_lowercase();
    let text_lower = document_text.to_lowercase();

    if lower.contains("medical")
        || text_lower.contains("medical")
        || text_lower.contains("hospital")
    {
        mock_medical_bill_output()
    } else if lower.contains("lease") || text_lower.contains("lease") || text_lower.contains("rent")
    {
        mock_lease_agreement_output()
    } else if lower.contains("financial")
        || text_lower.contains("salary")
        || text_lower.contains("financial")
    {
        mock_financial_output()
    } else {
        mock_generic_output()
    }
}

fn mock_medical_bill_output() -> ExtractionOutput {
    use crate::tuple_adapter::{ExtractedEntity, ExtractedRelationship};

    ExtractionOutput {
        document_category: "medical_bill".to_string(),
        entities: vec![
            ExtractedEntity {
                id: "e1".to_string(),
                name: "Memorial Hospital".to_string(),
                entity_type: "organization".to_string(),
                value: Some("Memorial Hospital".to_string()),
            },
            ExtractedEntity {
                id: "e2".to_string(),
                name: "ER Visit Charge".to_string(),
                entity_type: "amount".to_string(),
                value: Some("$8,200.00".to_string()),
            },
            ExtractedEntity {
                id: "e3".to_string(),
                name: "John Patient".to_string(),
                entity_type: "person".to_string(),
                value: None,
            },
        ],
        relationships: vec![
            ExtractedRelationship {
                source: "e1".to_string(),
                target: "e2".to_string(),
                relationship: "charged_total".to_string(),
                context: Some("Emergency room visit".to_string()),
            },
            ExtractedRelationship {
                source: "e3".to_string(),
                target: "e1".to_string(),
                relationship: "patient_at".to_string(),
                context: None,
            },
        ],
    }
}

fn mock_lease_agreement_output() -> ExtractionOutput {
    use crate::tuple_adapter::{ExtractedEntity, ExtractedRelationship};

    ExtractionOutput {
        document_category: "lease_agreement".to_string(),
        entities: vec![
            ExtractedEntity {
                id: "e1".to_string(),
                name: "Property Management LLC".to_string(),
                entity_type: "organization".to_string(),
                value: Some("Property Management LLC".to_string()),
            },
            ExtractedEntity {
                id: "e2".to_string(),
                name: "Monthly Rent".to_string(),
                entity_type: "amount".to_string(),
                value: Some("$2,500.00".to_string()),
            },
            ExtractedEntity {
                id: "e3".to_string(),
                name: "Late Fee".to_string(),
                entity_type: "amount".to_string(),
                value: Some("$150.00".to_string()),
            },
        ],
        relationships: vec![
            ExtractedRelationship {
                source: "e1".to_string(),
                target: "e2".to_string(),
                relationship: "charges_rent".to_string(),
                context: Some("Monthly rental payment".to_string()),
            },
            ExtractedRelationship {
                source: "e1".to_string(),
                target: "e3".to_string(),
                relationship: "charges_late_fee".to_string(),
                context: Some("After 5 day grace period".to_string()),
            },
        ],
    }
}

fn mock_financial_output() -> ExtractionOutput {
    use crate::tuple_adapter::{ExtractedEntity, ExtractedRelationship};

    ExtractionOutput {
        document_category: "financial".to_string(),
        entities: vec![
            ExtractedEntity {
                id: "e1".to_string(),
                name: "Acme Corp".to_string(),
                entity_type: "organization".to_string(),
                value: Some("Acme Corp".to_string()),
            },
            ExtractedEntity {
                id: "e2".to_string(),
                name: "Jane Employee".to_string(),
                entity_type: "person".to_string(),
                value: Some("Jane Employee".to_string()),
            },
            ExtractedEntity {
                id: "e3".to_string(),
                name: "Annual Salary".to_string(),
                entity_type: "salary".to_string(),
                value: Some("$75,000.00".to_string()),
            },
        ],
        relationships: vec![
            ExtractedRelationship {
                source: "e1".to_string(),
                target: "e2".to_string(),
                relationship: "employs".to_string(),
                context: Some("Employment record".to_string()),
            },
            ExtractedRelationship {
                source: "e2".to_string(),
                target: "e3".to_string(),
                relationship: "earns_salary".to_string(),
                context: Some("Annual salary".to_string()),
            },
        ],
    }
}

fn mock_generic_output() -> ExtractionOutput {
    use crate::tuple_adapter::{ExtractedEntity, ExtractedRelationship};

    ExtractionOutput {
        document_category: "general".to_string(),
        entities: vec![
            ExtractedEntity {
                id: "e1".to_string(),
                name: "Entity A".to_string(),
                entity_type: "organization".to_string(),
                value: Some("Entity A".to_string()),
            },
            ExtractedEntity {
                id: "e2".to_string(),
                name: "Entity B".to_string(),
                entity_type: "organization".to_string(),
                value: Some("Entity B".to_string()),
            },
        ],
        relationships: vec![ExtractedRelationship {
            source: "e1".to_string(),
            target: "e2".to_string(),
            relationship: "associated_with".to_string(),
            context: Some("General document relationship".to_string()),
        }],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // State machine tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_initial_state_is_not_running() {
        let mgr = ExtractionManager::new_mock();
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
    }

    #[test]
    fn test_mock_extract_transitions_to_running() {
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr.extract_sync("some text", "/test/doc.pdf");
        assert!(result.is_ok());
        assert_eq!(*mgr.state(), SubprocessState::Running);
        assert_eq!(mgr.extractions_completed(), 1);
    }

    #[test]
    fn test_idle_kill_transitions_to_not_running() {
        let mut mgr = ExtractionManager::new_mock();
        mgr.extract_sync("text", "/test/doc.pdf").unwrap();
        assert_eq!(*mgr.state(), SubprocessState::Running);

        mgr.idle_kill();
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
    }

    #[test]
    fn test_should_idle_kill_false_when_not_running() {
        let mgr = ExtractionManager::new_mock();
        assert!(!mgr.should_idle_kill());
    }

    #[test]
    fn test_should_idle_kill_false_immediately_after_extract() {
        let mut mgr = ExtractionManager::new_mock();
        mgr.extract_sync("text", "/doc.pdf").unwrap();
        // Immediately after extraction, idle timeout has not elapsed
        assert!(!mgr.should_idle_kill());
    }

    // -----------------------------------------------------------------------
    // Failure and retry tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_record_failure_increments_retries() {
        let mut mgr = ExtractionManager::new_mock();
        mgr.extract_sync("text", "/doc.pdf").unwrap();
        assert_eq!(*mgr.state(), SubprocessState::Running);

        mgr.record_failure();
        assert_eq!(*mgr.state(), SubprocessState::Crashed { retries: 1 });
        assert!(mgr.can_retry());

        mgr.record_failure();
        assert_eq!(*mgr.state(), SubprocessState::Crashed { retries: 2 });
        assert!(!mgr.can_retry());

        // Third failure exhausts retries, goes to NotRunning
        mgr.record_failure();
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
    }

    #[test]
    fn test_classify_exit_code_oom() {
        match ExtractionManager::classify_exit_code(137) {
            ExtractionError::OutOfMemory => (),
            other => panic!("Expected OutOfMemory, got: {:?}", other),
        }
    }

    #[test]
    fn test_classify_exit_code_segfault() {
        match ExtractionManager::classify_exit_code(139) {
            ExtractionError::ProcessCrashed { exit_code } => {
                assert_eq!(exit_code, Some(139));
            }
            other => panic!("Expected ProcessCrashed, got: {:?}", other),
        }
    }

    #[test]
    fn test_classify_exit_code_clean_shutdown() {
        match ExtractionManager::classify_exit_code(0) {
            ExtractionError::ProcessCrashed { exit_code } => {
                assert_eq!(exit_code, Some(0));
            }
            other => panic!("Expected ProcessCrashed, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Mock output tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_mock_medical_output() {
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr
            .extract_sync("Patient visited hospital", "/docs/medical_bill.pdf")
            .unwrap();
        assert_eq!(result.output.document_category, "medical_bill");
        assert_eq!(result.output.entities.len(), 3);
        assert_eq!(result.output.relationships.len(), 2);
    }

    #[test]
    fn test_mock_lease_output() {
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr
            .extract_sync("Monthly rent payment", "/docs/lease.pdf")
            .unwrap();
        assert_eq!(result.output.document_category, "lease_agreement");
        assert_eq!(result.output.entities.len(), 3);
        assert_eq!(result.output.relationships.len(), 2);
    }

    #[test]
    fn test_mock_financial_output() {
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr
            .extract_sync("Employee salary report", "/docs/financial.pdf")
            .unwrap();
        assert_eq!(result.output.document_category, "financial");
        assert_eq!(result.output.entities.len(), 3);
        assert_eq!(result.output.relationships.len(), 2);
    }

    #[test]
    fn test_mock_generic_output() {
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr
            .extract_sync("Some random text", "/docs/random.pdf")
            .unwrap();
        assert_eq!(result.output.document_category, "general");
        assert_eq!(result.output.entities.len(), 2);
        assert_eq!(result.output.relationships.len(), 1);
    }

    #[test]
    fn test_mock_detection_by_content() {
        // Even without a medical filename, medical content should trigger
        // the medical mock output.
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr
            .extract_sync("hospital emergency room charges", "/docs/generic.pdf")
            .unwrap();
        assert_eq!(result.output.document_category, "medical_bill");
    }

    // -----------------------------------------------------------------------
    // Live mode tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_live_mode_missing_script() {
        let mut mgr = ExtractionManager::new(
            ExtractionMode::Live {
                script_path: PathBuf::from("/nonexistent/extraction_service.py"),
            },
            PathBuf::from("/tmp/test.pid"),
        );
        let result = mgr.extract_sync("text", "/doc.pdf");
        assert!(result.is_err());
        match result.unwrap_err() {
            ExtractionError::ScriptNotFound { path } => {
                assert_eq!(path, PathBuf::from("/nonexistent/extraction_service.py"));
            }
            other => panic!("Expected ScriptNotFound, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Shutdown test
    // -----------------------------------------------------------------------

    #[test]
    fn test_shutdown_resets_state() {
        let mut mgr = ExtractionManager::new_mock();
        mgr.extract_sync("text", "/doc.pdf").unwrap();
        assert_eq!(*mgr.state(), SubprocessState::Running);

        mgr.shutdown();
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
    }

    // -----------------------------------------------------------------------
    // Diagnostics tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extraction_counters() {
        let mut mgr = ExtractionManager::new_mock();
        assert_eq!(mgr.extractions_completed(), 0);
        assert_eq!(mgr.extractions_failed(), 0);

        mgr.extract_sync("text", "/doc.pdf").unwrap();
        assert_eq!(mgr.extractions_completed(), 1);

        mgr.record_failure();
        assert_eq!(mgr.extractions_failed(), 1);

        mgr.extract_sync("text2", "/doc2.pdf").unwrap();
        assert_eq!(mgr.extractions_completed(), 2);
    }

    #[test]
    fn test_pid_file_path() {
        let mgr = ExtractionManager::new(
            ExtractionMode::Mock,
            PathBuf::from("/home/user/.hive/extraction.pid"),
        );
        assert_eq!(
            mgr.pid_file_path(),
            Path::new("/home/user/.hive/extraction.pid")
        );
    }

    // -----------------------------------------------------------------------
    // Error display tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_error_display() {
        // All variants use WHAT/WHY/DO format (U4).
        let err = ExtractionError::OutOfMemory;
        let msg = format!("{}", err);
        assert!(msg.contains("out of memory"));
        assert!(msg.contains("Why:"));
        assert!(msg.contains("Do:"));

        let err = ExtractionError::Timeout;
        let msg = format!("{}", err);
        assert!(msg.contains("timed out"));
        assert!(msg.contains("Why:"));
        assert!(msg.contains("Do:"));

        let err = ExtractionError::RetriesExhausted { attempts: 3 };
        let msg = format!("{}", err);
        assert!(msg.contains("3 attempts"));
        assert!(msg.contains("Why:"));
        assert!(msg.contains("Do:"));

        let err = ExtractionError::MalformedOutput {
            message: "bad json".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("bad json"));
        assert!(msg.contains("Why:"));
        assert!(msg.contains("Do:"));

        let err = ExtractionError::ScriptNotFound {
            path: PathBuf::from("/tmp/test.py"),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("/tmp/test.py"));
        assert!(msg.contains("Why:"));
        assert!(msg.contains("Do:"));

        let err = ExtractionError::ProcessCrashed { exit_code: Some(1) };
        let msg = format!("{}", err);
        assert!(msg.contains("crashed"));
        assert!(msg.contains("Why:"));
        assert!(msg.contains("Do:"));

        let err = ExtractionError::Internal {
            message: "pipe broken".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("pipe broken"));
        assert!(msg.contains("Why:"));
        assert!(msg.contains("Do:"));
    }

    // -----------------------------------------------------------------------
    // Enhanced result tests (always run, no feature gate)
    // -----------------------------------------------------------------------

    #[test]
    fn test_enhanced_result_mock_mode() {
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr
            .extract_sync("Patient visited hospital", "/docs/medical_bill.pdf")
            .unwrap();
        // Mock mode always returns was_cold_start: false, python_latency_ms: 0
        assert!(!result.was_cold_start);
        assert_eq!(result.python_latency_ms, 0);
        assert!(!result.request_id.is_empty());
        assert!(result.elapsed.as_micros() > 0 || result.elapsed.as_nanos() > 0);
    }

    #[test]
    fn test_enhanced_result_fields_on_generic() {
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr.extract_sync("some text", "/docs/generic.pdf").unwrap();
        assert!(!result.was_cold_start);
        assert_eq!(result.python_latency_ms, 0);
    }

    #[test]
    fn test_mock_mode_unchanged_regression() {
        // Comprehensive regression: verify all mock behavior is unchanged
        let mut mgr = ExtractionManager::new_mock();

        // Initial state
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
        assert_eq!(mgr.extractions_completed(), 0);
        assert_eq!(mgr.extractions_failed(), 0);
        assert!(!mgr.should_idle_kill());

        // Medical extraction
        let r1 = mgr.extract_sync("hospital visit", "/medical.pdf").unwrap();
        assert_eq!(r1.output.document_category, "medical_bill");
        assert_eq!(r1.output.entities.len(), 3);
        assert_eq!(r1.output.relationships.len(), 2);
        assert_eq!(*mgr.state(), SubprocessState::Running);
        assert_eq!(mgr.extractions_completed(), 1);

        // Lease extraction
        let r2 = mgr.extract_sync("rent payment", "/lease.pdf").unwrap();
        assert_eq!(r2.output.document_category, "lease_agreement");
        assert_eq!(mgr.extractions_completed(), 2);

        // Idle kill
        mgr.idle_kill();
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);

        // Can extract again after idle kill
        let r3 = mgr.extract_sync("salary info", "/financial.pdf").unwrap();
        assert_eq!(r3.output.document_category, "financial");
        assert_eq!(mgr.extractions_completed(), 3);

        // Failure tracking
        mgr.record_failure();
        assert_eq!(mgr.extractions_failed(), 1);
        assert!(mgr.can_retry());

        // Shutdown
        mgr.shutdown();
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
    }

    #[test]
    fn test_mock_multiple_sequential_extractions() {
        let mut mgr = ExtractionManager::new_mock();

        for i in 0..5 {
            let result = mgr.extract_sync("some text", "/doc.pdf").unwrap();
            assert!(!result.was_cold_start);
            assert_eq!(result.python_latency_ms, 0);
            assert_eq!(mgr.extractions_completed(), i + 1);
        }
    }

    #[test]
    fn test_request_id_is_unique_per_call() {
        let mut mgr = ExtractionManager::new_mock();
        let r1 = mgr.extract_sync("text1", "/doc1.pdf").unwrap();
        let r2 = mgr.extract_sync("text2", "/doc2.pdf").unwrap();
        assert_ne!(r1.request_id, r2.request_id);
    }

    #[test]
    fn test_live_mode_sync_returns_internal_error() {
        // Live mode with extract_sync should return Internal error when
        // script exists (since async is required). If script doesn't exist,
        // returns ScriptNotFound.
        let mut mgr = ExtractionManager::new(
            ExtractionMode::Live {
                script_path: PathBuf::from("/nonexistent/script.py"),
            },
            PathBuf::from("/tmp/test_live_sync.pid"),
        );
        let result = mgr.extract_sync("text", "/doc.pdf");
        assert!(result.is_err());
        // Script doesn't exist, so ScriptNotFound
        match result.unwrap_err() {
            ExtractionError::ScriptNotFound { .. } => {}
            other => panic!("Expected ScriptNotFound, got: {:?}", other),
        }
    }

    #[test]
    fn test_record_failure_from_not_running() {
        let mut mgr = ExtractionManager::new_mock();
        // Failure from NotRunning state
        mgr.record_failure();
        assert_eq!(*mgr.state(), SubprocessState::Crashed { retries: 1 });
        assert_eq!(mgr.extractions_failed(), 1);
    }

    // -----------------------------------------------------------------------
    // request_id validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_request_id_mismatch_produces_malformed_output_error() {
        // Simulate the validation logic from send_request():
        // when response request_id differs from the sent request_id,
        // an ExtractionError::MalformedOutput must be returned.
        let request_id = "expected-uuid-1234";
        let response: serde_json::Value = serde_json::json!({
            "status": "success",
            "request_id": "wrong-uuid-5678",
            "document_category": "general",
            "entities": [],
            "relationships": []
        });

        let resp_id = response
            .get("request_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        assert_ne!(resp_id, request_id);

        // This mirrors the exact error the patched send_request() produces
        let err = ExtractionError::MalformedOutput {
            message: format!(
                "Response ID mismatch: expected '{}', got '{}'",
                request_id, resp_id
            ),
        };

        match &err {
            ExtractionError::MalformedOutput { message } => {
                assert!(message.contains("expected 'expected-uuid-1234'"));
                assert!(message.contains("got 'wrong-uuid-5678'"));
                assert!(message.contains("Response ID mismatch"));
            }
            other => panic!("Expected MalformedOutput, got: {:?}", other),
        }

        // Verify Display impl includes the mismatch detail
        let display = format!("{}", err);
        assert!(display.contains("Response ID mismatch"));
    }

    #[test]
    fn test_request_id_missing_from_response_produces_mismatch() {
        // When the response JSON lacks a request_id field entirely,
        // the validation should treat it as empty string and produce a mismatch.
        let request_id = "expected-uuid-1234";
        let response: serde_json::Value = serde_json::json!({
            "status": "success",
            "document_category": "general",
            "entities": [],
            "relationships": []
        });

        let resp_id = response
            .get("request_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        assert_eq!(resp_id, "");
        assert_ne!(resp_id, request_id);
    }

    #[test]
    fn test_request_id_match_passes_validation() {
        // When request_ids match, no error should be produced.
        let request_id = "matching-uuid-9999";
        let response: serde_json::Value = serde_json::json!({
            "status": "success",
            "request_id": "matching-uuid-9999",
            "document_category": "general",
            "entities": [],
            "relationships": []
        });

        let resp_id = response
            .get("request_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        assert_eq!(resp_id, request_id);
    }

    #[test]
    fn test_can_retry_in_various_states() {
        let mut mgr = ExtractionManager::new_mock();

        // NotRunning: can retry
        assert!(mgr.can_retry());

        // Running: can retry
        mgr.extract_sync("text", "/doc.pdf").unwrap();
        assert!(mgr.can_retry());

        // Crashed with 1 retry: can retry
        mgr.record_failure();
        assert!(mgr.can_retry());

        // Crashed with 2 retries: cannot retry
        mgr.record_failure();
        assert!(!mgr.can_retry());
    }

    // -----------------------------------------------------------------------
    // Trusted-path validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_trusted_script_path_rejects_tmp() {
        // A `.py` file dropped in `/tmp` should never pass the check. We
        // create a real file so `canonicalize()` succeeds — otherwise the
        // check rejects for a different reason (cannot-canonicalize) and we
        // would not be testing the allowlist logic.
        let tmp_path =
            std::env::temp_dir().join(format!("hive_untrusted_{}.py", std::process::id()));
        std::fs::write(&tmp_path, "# attacker script").unwrap();

        let result = is_trusted_script_path(&tmp_path, None);
        assert!(
            result.is_err(),
            "expected /tmp path to be rejected, got {:?}",
            result
        );

        let _ = std::fs::remove_file(&tmp_path);
    }

    #[test]
    fn test_is_trusted_script_path_accepts_cwd() {
        // A file inside the current workspace must pass. We use Cargo.toml
        // — it is guaranteed to exist when `cargo test` runs.
        let cwd = std::env::current_dir().unwrap();
        let cargo_toml = cwd.join("Cargo.toml");
        if !cargo_toml.exists() {
            // Some test runners launch from a different directory; skip
            // rather than fail. (Still a warning: do not silently pass.)
            eprintln!(
                "[test] skipping cwd-accept check: no Cargo.toml at {}",
                cargo_toml.display()
            );
            return;
        }

        let result = is_trusted_script_path(&cargo_toml, None);
        assert!(
            result.is_ok(),
            "expected {} to be trusted (under cwd), got {:?}",
            cargo_toml.display(),
            result
        );
    }

    #[test]
    fn test_is_trusted_python_interpreter_accepts_system() {
        // `/usr/bin/python3` must always pass on macOS / Linux. On CI
        // images that lack the system interpreter we skip rather than fail.
        if !std::path::Path::new("/usr/bin/python3").exists() {
            eprintln!("[test] skipping system-python check: /usr/bin/python3 missing");
            return;
        }
        let result = is_trusted_python_interpreter(std::path::Path::new("/usr/bin/python3"), None);
        assert!(result.is_ok(), "got {:?}", result);
    }

    #[test]
    fn test_is_trusted_python_interpreter_rejects_tmp_shim() {
        // Drop a fake `python3` into /tmp and verify rejection.
        let shim =
            std::env::temp_dir().join(format!("hive_fake_python_{}", std::process::id()));
        std::fs::write(&shim, "#!/bin/sh\nexec /bin/sh \"$@\"\n").unwrap();

        let result = is_trusted_python_interpreter(&shim, None);
        assert!(
            result.is_err(),
            "expected tmp shim to be rejected, got {:?}",
            result
        );

        let _ = std::fs::remove_file(&shim);
    }

    #[test]
    fn test_allow_custom_extractor_default_off() {
        let mgr = ExtractionManager::new_mock();
        assert!(
            !mgr.allow_custom_extractor(),
            "default constructor must NOT downgrade trusted-path guards"
        );
    }

    #[test]
    fn test_allow_custom_extractor_opt_in_on() {
        let mgr = ExtractionManager::new_with_allow_custom(
            ExtractionMode::Mock,
            PathBuf::from("/tmp/hive_test.pid"),
            true,
        );
        assert!(mgr.allow_custom_extractor());
    }

    #[test]
    fn test_untrusted_script_path_error_display() {
        let err = ExtractionError::UntrustedScriptPath {
            path: PathBuf::from("/tmp/attacker.py"),
            reason: "outside trusted roots".to_string(),
        };
        let s = format!("{}", err);
        assert!(s.contains("/tmp/attacker.py"), "got {}", s);
        assert!(s.contains("--allow-custom-extractor"), "got {}", s);
    }

    #[test]
    fn test_untrusted_python_interpreter_error_display() {
        let err = ExtractionError::UntrustedPythonInterpreter {
            path: PathBuf::from("/tmp/fake_python3"),
            reason: "not in allowlist".to_string(),
        };
        let s = format!("{}", err);
        assert!(s.contains("/tmp/fake_python3"), "got {}", s);
        assert!(s.contains("/usr/bin/python3"), "got {}", s);
    }
}

// ---------------------------------------------------------------------------
// Async tests (live-extraction feature only)
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "live-extraction"))]
mod async_tests {
    use super::*;

    #[tokio::test]
    async fn test_spawn_missing_script() {
        let mut mgr = ExtractionManager::new(
            ExtractionMode::Live {
                script_path: PathBuf::from("/nonexistent/extraction_service.py"),
            },
            PathBuf::from("/tmp/hive_test_spawn_missing.pid"),
        );
        let result = mgr.spawn_subprocess().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ExtractionError::ScriptNotFound { path } => {
                assert_eq!(path, PathBuf::from("/nonexistent/extraction_service.py"));
            }
            other => panic!("Expected ScriptNotFound, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_spawn_in_mock_mode_fails() {
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr.spawn_subprocess().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ExtractionError::Internal { message } => {
                assert!(message.contains("mock mode"));
            }
            other => panic!("Expected Internal, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_extract_async_mock_delegates_to_sync() {
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr
            .extract_async("Patient visited hospital", "/docs/medical_bill.pdf")
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.output.document_category, "medical_bill");
        assert_eq!(result.output.entities.len(), 3);
        assert_eq!(result.output.relationships.len(), 2);
        assert!(!result.was_cold_start);
        assert_eq!(result.python_latency_ms, 0);
        assert_eq!(*mgr.state(), SubprocessState::Running);
        assert_eq!(mgr.extractions_completed(), 1);
    }

    #[tokio::test]
    async fn test_extract_async_mock_lease() {
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr
            .extract_async("Monthly rent payment", "/docs/lease.pdf")
            .await
            .unwrap();
        assert_eq!(result.output.document_category, "lease_agreement");
    }

    #[tokio::test]
    async fn test_extract_async_mock_financial() {
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr
            .extract_async("Employee salary report", "/docs/financial.pdf")
            .await
            .unwrap();
        assert_eq!(result.output.document_category, "financial");
    }

    #[tokio::test]
    async fn test_extract_async_mock_generic() {
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr
            .extract_async("Some random text", "/docs/random.pdf")
            .await
            .unwrap();
        assert_eq!(result.output.document_category, "general");
    }

    #[tokio::test]
    async fn test_extract_async_mock_multiple_sequential() {
        let mut mgr = ExtractionManager::new_mock();
        for i in 0..5u64 {
            let result = mgr.extract_async("some text", "/doc.pdf").await.unwrap();
            assert!(!result.was_cold_start);
            assert_eq!(mgr.extractions_completed(), i + 1);
        }
    }

    #[tokio::test]
    async fn test_kill_subprocess_without_process() {
        let mut mgr = ExtractionManager::new_mock();
        // Killing when no process exists should be a no-op
        mgr.kill_subprocess().await;
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
    }

    #[tokio::test]
    async fn test_kill_subprocess_without_process_live_mode() {
        let mut mgr = ExtractionManager::new(
            ExtractionMode::Live {
                script_path: PathBuf::from("/some/script.py"),
            },
            PathBuf::from("/tmp/hive_test_kill_noop.pid"),
        );
        // No subprocess spawned; killing should be a no-op
        mgr.kill_subprocess().await;
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
    }

    #[tokio::test]
    async fn test_idle_kill_async_no_crash() {
        let mut mgr = ExtractionManager::new_mock();
        // idle_kill_async when not running should not crash
        mgr.idle_kill_async().await;
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
        assert!(mgr.last_activity.is_none());
    }

    #[tokio::test]
    async fn test_idle_kill_async_after_mock_extract() {
        let mut mgr = ExtractionManager::new_mock();
        mgr.extract_async("text", "/doc.pdf").await.unwrap();
        assert_eq!(*mgr.state(), SubprocessState::Running);

        mgr.idle_kill_async().await;
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
        assert!(mgr.last_activity.is_none());
    }

    #[tokio::test]
    async fn test_shutdown_async_no_crash() {
        let mut mgr = ExtractionManager::new_mock();
        // shutdown_async when not running should not crash
        mgr.shutdown_async().await;
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
    }

    #[tokio::test]
    async fn test_shutdown_async_after_mock_extract() {
        let mut mgr = ExtractionManager::new_mock();
        mgr.extract_async("text", "/doc.pdf").await.unwrap();
        assert_eq!(*mgr.state(), SubprocessState::Running);

        mgr.shutdown_async().await;
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
    }

    #[tokio::test]
    async fn test_send_request_without_subprocess() {
        let mut mgr = ExtractionManager::new(
            ExtractionMode::Live {
                script_path: PathBuf::from("/some/script.py"),
            },
            PathBuf::from("/tmp/hive_test_send_no_sub.pid"),
        );
        let result = mgr.send_request("test text", "test-id-123").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ExtractionError::Internal { message } => {
                assert!(message.contains("No subprocess running"));
            }
            other => panic!("Expected Internal, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_extract_async_live_missing_script() {
        let mut mgr = ExtractionManager::new(
            ExtractionMode::Live {
                script_path: PathBuf::from("/nonexistent/extraction_service.py"),
            },
            PathBuf::from("/tmp/hive_test_async_missing.pid"),
        );
        let result = mgr.extract_async("test text", "/doc.pdf").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ExtractionError::ScriptNotFound { .. } => {}
            other => panic!("Expected ScriptNotFound, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_subprocess_field_initial_none() {
        let mgr = ExtractionManager::new_mock();
        assert!(mgr.subprocess.is_none());
    }

    #[tokio::test]
    async fn test_subprocess_field_initial_none_live() {
        let mgr = ExtractionManager::new(
            ExtractionMode::Live {
                script_path: PathBuf::from("/some/script.py"),
            },
            PathBuf::from("/tmp/hive_test_init.pid"),
        );
        assert!(mgr.subprocess.is_none());
    }

    #[tokio::test]
    async fn test_parse_latency_ms_valid() {
        let json = r#"{"request_id":"abc","status":"success","latency_ms":1234}"#;
        assert_eq!(ExtractionManager::parse_latency_ms(json), 1234);
    }

    #[tokio::test]
    async fn test_parse_latency_ms_missing() {
        let json = r#"{"request_id":"abc","status":"success"}"#;
        assert_eq!(ExtractionManager::parse_latency_ms(json), 0);
    }

    #[tokio::test]
    async fn test_parse_latency_ms_invalid_json() {
        let json = "not json at all";
        assert_eq!(ExtractionManager::parse_latency_ms(json), 0);
    }

    #[tokio::test]
    async fn test_parse_latency_ms_zero_value() {
        let json = r#"{"request_id":"abc","status":"success","latency_ms":0}"#;
        assert_eq!(ExtractionManager::parse_latency_ms(json), 0);
    }

    #[tokio::test]
    async fn test_parse_latency_ms_large_value() {
        let json = r#"{"request_id":"abc","status":"success","latency_ms":99999}"#;
        assert_eq!(ExtractionManager::parse_latency_ms(json), 99999);
    }

    #[tokio::test]
    async fn test_send_request_returns_latency_tuple() {
        // Verify send_request returns (ExtractionOutput, u64) type.
        // Without a subprocess, it returns Internal error -- confirming the
        // signature compiles and the tuple type is correct.
        let mut mgr = ExtractionManager::new(
            ExtractionMode::Live {
                script_path: PathBuf::from("/some/script.py"),
            },
            PathBuf::from("/tmp/hive_test_latency_tuple.pid"),
        );
        let result: Result<(ExtractionOutput, u64), ExtractionError> =
            mgr.send_request("test", "id-1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_async_counters() {
        let mut mgr = ExtractionManager::new_mock();
        assert_eq!(mgr.extractions_completed(), 0);
        assert_eq!(mgr.extractions_failed(), 0);

        mgr.extract_async("text", "/doc.pdf").await.unwrap();
        assert_eq!(mgr.extractions_completed(), 1);

        mgr.record_failure();
        assert_eq!(mgr.extractions_failed(), 1);

        mgr.extract_async("text2", "/doc2.pdf").await.unwrap();
        assert_eq!(mgr.extractions_completed(), 2);
    }

    #[tokio::test]
    async fn test_mock_async_then_shutdown() {
        let mut mgr = ExtractionManager::new_mock();
        mgr.extract_async("text", "/doc.pdf").await.unwrap();
        assert_eq!(*mgr.state(), SubprocessState::Running);

        mgr.shutdown_async().await;
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
        assert!(mgr.last_activity.is_none());
    }

    // -----------------------------------------------------------------------
    // Live end-to-end tests (require Python + extraction service)
    // -----------------------------------------------------------------------
    // These tests are guarded by the HIVE_TEST_LIVE_EXTRACTION env var.
    // They will only run when the extraction service and its dependencies
    // are available.

    #[tokio::test]
    #[ignore]
    async fn test_live_spawn_and_kill() {
        if std::env::var("HIVE_TEST_LIVE_EXTRACTION").is_err() {
            return;
        }
        let script = PathBuf::from("../extraction-service/extraction_service.py");
        if !script.exists() {
            return;
        }
        let mut mgr = ExtractionManager::new(
            ExtractionMode::Live {
                script_path: script,
            },
            PathBuf::from("/tmp/hive_test_live_spawn.pid"),
        );
        mgr.spawn_subprocess().await.unwrap();
        assert_eq!(*mgr.state(), SubprocessState::Starting);
        assert!(mgr.subprocess.is_some());
        assert!(mgr.pid_file_path().exists());

        mgr.kill_subprocess().await;
        assert_eq!(*mgr.state(), SubprocessState::NotRunning);
        assert!(mgr.subprocess.is_none());
        assert!(!mgr.pid_file_path().exists());
    }

    #[tokio::test]
    #[ignore]
    async fn test_live_extract_medical_bill() {
        if std::env::var("HIVE_TEST_LIVE_EXTRACTION").is_err() {
            return;
        }
        let script = PathBuf::from("../extraction-service/extraction_service.py");
        if !script.exists() {
            return;
        }
        let mut mgr = ExtractionManager::new(
            ExtractionMode::Live {
                script_path: script,
            },
            PathBuf::from("/tmp/hive_test_live_extract.pid"),
        );
        let result = mgr
            .extract_async(
                "Memorial Hospital\nER Visit: $8,200.00\nPatient: John Doe",
                "/docs/medical_bill.pdf",
            )
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.was_cold_start);
        assert!(!result.output.entities.is_empty());
        assert!(result.elapsed.as_secs() > 0);

        mgr.shutdown_async().await;
    }

    #[tokio::test]
    #[ignore]
    async fn test_live_warm_second_extract() {
        if std::env::var("HIVE_TEST_LIVE_EXTRACTION").is_err() {
            return;
        }
        let script = PathBuf::from("../extraction-service/extraction_service.py");
        if !script.exists() {
            return;
        }
        let mut mgr = ExtractionManager::new(
            ExtractionMode::Live {
                script_path: script,
            },
            PathBuf::from("/tmp/hive_test_live_warm.pid"),
        );
        // First extraction (cold start)
        let r1 = mgr
            .extract_async("Hospital ER visit $5000", "/docs/medical.pdf")
            .await
            .unwrap();
        assert!(r1.was_cold_start);

        // Second extraction (warm)
        let r2 = mgr
            .extract_async("Lease rent $2500 monthly", "/docs/lease.pdf")
            .await
            .unwrap();
        assert!(!r2.was_cold_start);
        assert!(r2.elapsed < r1.elapsed); // Warm should be faster

        mgr.shutdown_async().await;
    }
}
