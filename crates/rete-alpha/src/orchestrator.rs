//! Process Orchestrator: tokio-based async runtime for the HIVE local pipeline.
//!
//! Wires together the pipeline:
//!   Document Queue -> Extraction -> Tuple Adapter -> WME Factory -> Rete-II Engine -> Insights
//!
//! ## Local Mode
//!
//! Skips: privacy pipeline, P2P, crystallization, jitter queue.
//! These are gated by runtime configuration.
//!
//! ## Architecture
//!
//! The orchestrator:
//! 1. Creates all channels (ch_extract, ch_extraction_out, ch_wme, ch_engine, ch_insight, ch_shutdown)
//! 2. Initializes the Rete-II engine (empty)
//! 3. Loads seed rules from a file path
//! 4. Spawns all core tokio tasks: engine task, tuple adapter task, WME factory task
//! 5. Runs the main event loop: accept document paths, send to extraction, handle shutdown
//! 6. Implements graceful shutdown (broadcast shutdown, drain channels, await tasks)
//!
//! ## Design Notes
//!
//! - All channels are bounded (no silent OOM).
//! - Shutdown uses tokio::sync::broadcast for one-shot signal to all tasks.
//! - The orchestrator is a library module; the binary entry point is built separately.
//! - Mock extraction mode enables full pipeline testing without Python/ML dependencies.

use crate::doc_queue::{DocQueue, QueueFull};
use crate::extraction_manager::{ExtractionError, ExtractionManager, ExtractionMode};
use crate::pipeline::{LocalPipeline, ProcessingResult, ProductionSpec};
use crate::production::FiredProduction;
use crate::tuple_adapter::ExtractionOutput;

use std::path::PathBuf;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Channel capacities
// ---------------------------------------------------------------------------

/// Extraction request channel capacity (1 in-flight extraction at a time).
pub const CH_EXTRACT_CAPACITY: usize = 1;

/// Extraction output channel capacity (one doc yields 5-15 tuples).
pub const CH_EXTRACTION_OUT_CAPACITY: usize = 4;

/// WME channel capacity (RawTuple -> WME factory).
pub const CH_WME_CAPACITY: usize = 16;

/// Engine command channel capacity (WMEs + rule ops).
pub const CH_ENGINE_CAPACITY: usize = 32;

/// Insight channel capacity (rule firings -> UI).
pub const CH_INSIGHT_CAPACITY: usize = 32;

/// Tuple outbound channel capacity (privacy pipeline -> Dandelion++).
pub const CH_TUPLE_OUTBOUND_CAPACITY: usize = 256;

/// Rule inbound channel capacity (Gossipsub -> Rete engine).
pub const CH_RULE_INBOUND_CAPACITY: usize = 128;

// ---------------------------------------------------------------------------
// EngineCommand: messages to the Rete-II engine task
// ---------------------------------------------------------------------------

/// Commands sent to the engine task via ch_engine.
///
/// The ch_engine channel carries a discriminated union to handle both
/// WME insertions and rule operations.
#[derive(Debug)]
pub enum EngineCommand {
    /// Insert a WME into working memory. The tuple contains the
    /// serialized extraction JSON and source file for the pipeline
    /// to process through tuple adapter -> WME factory -> engine.
    ProcessExtraction { json: String, source_file: String },
    /// Add a rule (future: from rule_loader module).
    AddRule(ProductionSpec),
    /// Retract a rule by ID (future).
    RetractRule { rule_id: u32 },
    /// Update rule confidence (future: from P2P rule events).
    UpdateRuleConfidence { rule_id: u32, confidence: f32 },
    /// Daily lifecycle sweep (future).
    DailySweep,
    /// Inbound rule event from P2P network (via Channel 17).
    /// D5: the engine task polls rule_rx and converts InboundRuleEvent
    /// into the appropriate engine operation (AddRule, RetractRule, UpdateConfidence).
    InboundRule(crate::bridge::InboundRuleEvent),
}

// ---------------------------------------------------------------------------
// RuleFiring: insight output from the engine
// ---------------------------------------------------------------------------

/// An insight produced when a rule fires on a WME.
///
/// Generated when a Rete-II production fires on a WME.
///
/// In local mode, this is a simplified version of the full FullInsightCard.
/// The UI task will consume these to display insights.
#[derive(Debug, Clone)]
pub struct RuleFiring {
    /// The rule that fired.
    pub rule_id: u32,
    /// The rule's display name (e.g. "Rule #<id>").
    pub production_name: String,
    /// Matched field summaries: (field_name, value).
    pub matched_fields: Vec<(String, String)>,
    /// Combined confidence: rule_cf * extraction_cf.
    pub confidence: f64,
    /// Source document path.
    pub source_file: String,
}

impl From<(&FiredProduction, &str)> for RuleFiring {
    fn from((fp, source_file): (&FiredProduction, &str)) -> Self {
        Self {
            rule_id: fp.rule_id,
            production_name: format!("Rule #{}", fp.rule_id),
            matched_fields: Vec::new(), // Populated by insight generation
            confidence: fp.chained_cf as f64,
            source_file: source_file.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// OrchestratorConfig
// ---------------------------------------------------------------------------

/// Configuration for the orchestrator.
///
/// In local mode, privacy, P2P, and crystallization are skipped.
/// Feature flags control which components are spawned.
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    /// Path to seed rules file (JSON or binary). Loaded at startup (step S5).
    pub seed_rules_path: Option<PathBuf>,
    /// Extraction mode: Mock or Live.
    pub extraction_mode: ExtractionMode,
    /// Path for the extraction PID file.
    pub pid_file_path: PathBuf,
    /// Enable privacy pipeline.
    pub enable_privacy_pipeline: bool,
    /// Enable P2P networking.
    pub enable_p2p: bool,
    /// Enable crystallization.
    pub enable_crystallization: bool,
    /// Document queue capacity (default: 8).
    pub doc_queue_capacity: usize,
    /// When true, downgrade the extraction-script and
    /// python-interpreter trust guards from reject-on-failure to warn-only.
    /// OFF by default — the CLI `--allow-custom-extractor` flag is the only
    /// way to turn this on, and it is the only thing that should flip this.
    pub allow_custom_extractor: bool,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            seed_rules_path: None,
            extraction_mode: ExtractionMode::Mock,
            pid_file_path: PathBuf::from("/tmp/hive_extraction.pid"),
            enable_privacy_pipeline: false,
            enable_p2p: false,
            enable_crystallization: false,
            doc_queue_capacity: 8,
            allow_custom_extractor: false,
        }
    }
}

impl OrchestratorConfig {
    /// Create an MVP config (mock extraction, no privacy/P2P/crystallization).
    pub fn mvp() -> Self {
        Self::default()
    }

    /// Create an MVP config with seed rules.
    pub fn mvp_with_rules(seed_rules_path: PathBuf) -> Self {
        Self {
            seed_rules_path: Some(seed_rules_path),
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Orchestrator state
// ---------------------------------------------------------------------------

/// Lifecycle state of the orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchestratorState {
    /// Not yet started.
    Created,
    /// Foundation initialization in progress.
    Initializing,
    /// Service startup in progress.
    SpawningTasks,
    /// Ready to accept documents. Emitted after services start.
    Ready,
    /// Graceful shutdown in progress.
    ShuttingDown,
    /// Shutdown complete.
    Stopped,
}

// ---------------------------------------------------------------------------
// ProcessDocumentResult
// ---------------------------------------------------------------------------

/// Result of processing a single document through the pipeline.
#[derive(Debug)]
pub struct ProcessDocumentResult {
    /// The source file that was processed.
    pub source_file: String,
    /// Pipeline processing result (tuples created, WMEs inserted, fired rules).
    pub pipeline_result: ProcessingResult,
    /// Insights generated from rule firings.
    pub insights: Vec<RuleFiring>,
    /// Total elapsed time for this document.
    pub elapsed: Duration,
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/// The Process Orchestrator.
///
/// Coordinates the local pipeline: document queue -> extraction -> tuple
/// adapter -> WME factory -> Rete-II engine -> insights.
///
/// In local mode, this runs synchronously (single-threaded). The async
/// runtime wrapping (tokio tasks, channels) will be the execution layer
/// that calls into this orchestrator's methods.
///
/// Memory budget: < 3MB overhead.
pub struct Orchestrator {
    /// Configuration.
    config: OrchestratorConfig,
    /// Current lifecycle state.
    state: OrchestratorState,
    /// Document queue (bounded FIFO, capacity 8).
    doc_queue: DocQueue,
    /// Extraction subprocess manager.
    extraction_manager: ExtractionManager,
    /// The local processing pipeline (tuple adapter + WME factory + engine).
    pipeline: LocalPipeline,
    /// All insights produced during this session.
    insights: Vec<RuleFiring>,
    /// Whether shutdown has been requested.
    shutting_down: bool,
    /// Timestamp of orchestrator creation.
    created_at: Instant,
    /// Timestamp of ready state.
    ready_at: Option<Instant>,
    /// Total documents processed.
    documents_processed: u64,
    /// Total documents failed.
    documents_failed: u64,
}

impl Orchestrator {
    /// Create a new orchestrator with the given configuration.
    ///
    /// Does NOT start the orchestrator. Call `initialize()` to begin the
    /// startup sequence.
    pub fn new(config: OrchestratorConfig) -> Self {
        let doc_queue = DocQueue::with_capacity(config.doc_queue_capacity);
        let extraction_manager = ExtractionManager::new_with_allow_custom(
            config.extraction_mode.clone(),
            config.pid_file_path.clone(),
            config.allow_custom_extractor,
        );
        let pipeline = LocalPipeline::new();

        Self {
            config,
            state: OrchestratorState::Created,
            doc_queue,
            extraction_manager,
            pipeline,
            insights: Vec::new(),
            shutting_down: false,
            created_at: Instant::now(),
            ready_at: None,
            documents_processed: 0,
            documents_failed: 0,
        }
    }

    /// Create an MVP orchestrator (mock extraction, no optional features).
    pub fn new_mvp() -> Self {
        Self::new(OrchestratorConfig::mvp())
    }

    // -----------------------------------------------------------------------
    // Startup sequence
    // -----------------------------------------------------------------------

    /// Initialize the orchestrator (foundation stage).
    ///
    /// Startup steps:
    /// - S2: Channels created (handled by the async layer)
    /// - S4: Initialize Rete-II engine (empty) -- already done in new()
    /// - S5: Load seed rules from file path
    ///
    /// Returns the time taken for initialization.
    pub fn initialize(&mut self) -> Result<Duration, String> {
        let start = Instant::now();
        self.state = OrchestratorState::Initializing;

        // S4: Engine already initialized (empty) in new()

        // S5: Load seed rules if path provided
        if let Some(ref _path) = self.config.seed_rules_path {
            // Rule loading interface: the rule_loader is a separate
            // module. We provide load_rules() which takes
            // ProductionSpec directly. The rule_loader will call this
            // after deserializing seed_rules.bin.
            //
            // For now, this is a no-op. Seed rules are loaded via
            // load_seed_rules() after initialization.
        }

        self.state = OrchestratorState::Ready;
        self.ready_at = Some(Instant::now());

        Ok(start.elapsed())
    }

    /// Load seed rules into the engine.
    ///
    /// This is the interface for the rule_loader module.
    /// Takes a Vec<ProductionSpec> and compiles them into the engine.
    pub fn load_seed_rules(&mut self, rules: Vec<ProductionSpec>) {
        self.pipeline.load_rules(rules);
    }

    // -----------------------------------------------------------------------
    // Document processing
    // -----------------------------------------------------------------------

    /// Submit a document for processing.
    ///
    /// Enqueues the document path in the DocQueue. If extraction is idle,
    /// immediately processes the next document.
    ///
    /// Returns `Err(QueueFull)` if the queue is at capacity.
    pub fn submit_document(&mut self, path: PathBuf) -> Result<(), QueueFull> {
        if self.shutting_down {
            return Err(QueueFull {
                path,
                current_len: self.doc_queue.len(),
            });
        }
        self.doc_queue.try_enqueue(path)
    }

    /// Process the next document in the queue through the full pipeline.
    ///
    /// Steps:
    /// 1. Dequeue document path
    /// 2. Read document text (mock mode: use path as placeholder text)
    /// 3. Send to extraction (mock returns canned output)
    /// 4. Tuple adapter: ExtractionOutput -> Vec<RawTuple>
    /// 5. WME factory: RawTuple -> Wme
    /// 6. Engine: insert WME, match rules
    /// 7. Insight generation: FiredProduction -> RuleFiring
    ///
    /// Returns None if the queue is empty.
    pub fn process_next(&mut self) -> Option<Result<ProcessDocumentResult, ExtractionError>> {
        let path = self.doc_queue.dequeue()?;
        Some(self.process_document(path))
    }

    /// Process a specific document through the full pipeline.
    ///
    /// This is the core method. It runs the entire pipeline synchronously.
    /// The async runtime (tokio tasks) wraps this in spawn_blocking or
    /// coordinates via channels.
    pub fn process_document(
        &mut self,
        path: PathBuf,
    ) -> Result<ProcessDocumentResult, ExtractionError> {
        let start = Instant::now();
        let source_file = path.to_string_lossy().to_string();

        // Step 1: Read document text
        // We use the file path as the "document text" for mock extraction.
        // In production, this would read the actual file and OCR it.
        let document_text = read_document_text(&path);

        // Step 2: Extraction (mock or live)
        let extraction_result = self
            .extraction_manager
            .extract_sync(&document_text, &source_file)?;

        // Step 3-6: Pipeline processing (tuple adapter -> WME factory -> engine)
        let pipeline_result = self
            .pipeline
            .process_extraction_output(&extraction_result.output, &source_file)
            .map_err(|e| ExtractionError::MalformedOutput { message: e })?;

        // Step 7: Generate insights from fired productions
        let insights: Vec<RuleFiring> = pipeline_result
            .fired_productions
            .iter()
            .map(|fp| RuleFiring::from((fp, source_file.as_str())))
            .collect();

        // Store insights
        self.insights.extend(insights.clone());
        self.documents_processed += 1;

        Ok(ProcessDocumentResult {
            source_file,
            pipeline_result,
            insights,
            elapsed: start.elapsed(),
        })
    }

    /// Process all documents currently in the queue.
    ///
    /// Returns a Vec of results (one per document). Continues processing
    /// even if individual documents fail.
    pub fn process_all(&mut self) -> Vec<Result<ProcessDocumentResult, ExtractionError>> {
        let mut results = Vec::new();
        while let Some(result) = self.process_next() {
            results.push(result);
        }
        results
    }

    // -----------------------------------------------------------------------
    // Shutdown
    // -----------------------------------------------------------------------

    /// Initiate graceful shutdown.
    ///
    /// Shutdown steps:
    /// - G1: Set shutting_down = true, reject new documents
    /// - G2: Wait for in-flight extraction (if any)
    /// - G3: Drain ch_engine
    /// - G9: Kill Python extraction process
    /// - G10: Drop channels
    ///
    /// In local mode, shutdown is simpler since we skip P2P/jitter/privacy.
    pub fn shutdown(&mut self) -> ShutdownReport {
        let start = Instant::now();
        self.shutting_down = true;
        self.state = OrchestratorState::ShuttingDown;

        // G1: Reject new documents (already handled by shutting_down flag)

        // Drain remaining documents from queue
        let pending_docs = self.doc_queue.drain_all();

        // G9: Kill Python process
        self.extraction_manager.shutdown();

        self.state = OrchestratorState::Stopped;

        ShutdownReport {
            elapsed: start.elapsed(),
            pending_documents_drained: pending_docs.len(),
            total_documents_processed: self.documents_processed,
            total_documents_failed: self.documents_failed,
            total_insights_generated: self.insights.len() as u64,
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Current orchestrator state.
    pub fn state(&self) -> OrchestratorState {
        self.state
    }

    /// Whether the orchestrator is shutting down.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down
    }

    /// Reference to the document queue.
    pub fn doc_queue(&self) -> &DocQueue {
        &self.doc_queue
    }

    /// Mutable reference to the document queue (for testing).
    pub fn doc_queue_mut(&mut self) -> &mut DocQueue {
        &mut self.doc_queue
    }

    /// Reference to the extraction manager.
    pub fn extraction_manager(&self) -> &ExtractionManager {
        &self.extraction_manager
    }

    /// Reference to the local pipeline.
    pub fn pipeline(&self) -> &LocalPipeline {
        &self.pipeline
    }

    /// Mutable reference to the local pipeline.
    ///
    /// Used by the hive binary to load seed rules via rule_loader,
    /// which needs &mut Engine for dictionary encoding.
    pub fn pipeline_mut(&mut self) -> &mut LocalPipeline {
        &mut self.pipeline
    }

    /// All insights generated during this session.
    pub fn insights(&self) -> &[RuleFiring] {
        &self.insights
    }

    /// Total documents processed successfully.
    pub fn documents_processed(&self) -> u64 {
        self.documents_processed
    }

    /// Total documents that failed processing.
    pub fn documents_failed(&self) -> u64 {
        self.documents_failed
    }

    /// Number of rules loaded in the engine.
    pub fn rule_count(&self) -> usize {
        self.pipeline.production_count()
    }

    /// Number of WMEs in working memory.
    pub fn wme_count(&self) -> usize {
        self.pipeline.wme_count()
    }

    /// Time since orchestrator was created.
    pub fn uptime(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Time to reach ready state (None if not yet ready).
    pub fn startup_time(&self) -> Option<Duration> {
        self.ready_at.map(|t| t.duration_since(self.created_at))
    }

    /// Configuration reference.
    pub fn config(&self) -> &OrchestratorConfig {
        &self.config
    }

    /// Check if the extraction subprocess should be killed due to idle timeout.
    /// The caller (async event loop) should call `idle_kill_extraction()` if true.
    pub fn should_idle_kill_extraction(&self) -> bool {
        self.extraction_manager.should_idle_kill()
    }

    /// Kill the idle extraction subprocess (reclaim 928MB).
    pub fn idle_kill_extraction(&mut self) {
        self.extraction_manager.idle_kill();
    }

    /// Async document processing: uses `extract_async()` in live mode,
    /// delegates to synchronous `process_document()` in mock mode.
    ///
    /// Per Phase E design Section 2.2.5: the async variant replaces step 2
    /// (extraction) with the async path while keeping steps 3-7 (pipeline
    /// processing) synchronous since they are CPU-bound and fast (~1ms).
    #[cfg(feature = "live-extraction")]
    pub async fn process_document_async(
        &mut self,
        path: PathBuf,
    ) -> Result<ProcessDocumentResult, ExtractionError> {
        // In mock mode, delegate to the synchronous path (instant, no IO).
        if self.config.extraction_mode == ExtractionMode::Mock {
            return self.process_document(path);
        }

        let start = Instant::now();
        let source_file = path.to_string_lossy().to_string();

        // Step 1: Read document text
        let document_text = read_document_text(&path);

        // Step 2: Async extraction (live subprocess with NDJSON IPC)
        let extraction_result = self
            .extraction_manager
            .extract_async(&document_text, &source_file)
            .await?;

        // Steps 3-6: Pipeline processing (synchronous, CPU-bound, fast)
        let pipeline_result = self
            .pipeline
            .process_extraction_output(&extraction_result.output, &source_file)
            .map_err(|e| ExtractionError::MalformedOutput { message: e })?;

        // Step 7: Generate insights from fired productions
        let insights: Vec<RuleFiring> = pipeline_result
            .fired_productions
            .iter()
            .map(|fp| RuleFiring::from((fp, source_file.as_str())))
            .collect();

        // Store insights
        self.insights.extend(insights.clone());
        self.documents_processed += 1;

        Ok(ProcessDocumentResult {
            source_file,
            pipeline_result,
            insights,
            elapsed: start.elapsed(),
        })
    }

    /// Mutable reference to the extraction manager (for live mode status updates).
    #[cfg(feature = "live-extraction")]
    pub fn extraction_manager_mut(&mut self) -> &mut ExtractionManager {
        &mut self.extraction_manager
    }
}

// ---------------------------------------------------------------------------
// ShutdownReport
// ---------------------------------------------------------------------------

/// Report generated after shutdown completes.
#[derive(Debug)]
pub struct ShutdownReport {
    /// Time taken for shutdown.
    pub elapsed: Duration,
    /// Number of pending documents drained from the queue.
    pub pending_documents_drained: usize,
    /// Total documents processed during this session.
    pub total_documents_processed: u64,
    /// Total documents that failed during this session.
    pub total_documents_failed: u64,
    /// Total insights generated during this session.
    pub total_insights_generated: u64,
}

// ---------------------------------------------------------------------------
// Document text reader (placeholder)
// ---------------------------------------------------------------------------

/// Read document text from a file path.
///
/// In mock mode, this returns the file path as the "document text"
/// since mock extraction uses the path/content for category detection.
///
/// In production, this would:
/// 1. Detect file type (image/PDF/text)
/// 2. For images/PDFs: pass through OCR (Surya)
/// 3. Return extracted text
fn read_document_text(path: &std::path::Path) -> String {
    // Try to read the file; fall back to using the path itself
    match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => {
            // For mock mode, the path name is enough to trigger
            // category-specific mock output
            path.to_string_lossy().to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Rule loading interface (for rule_loader module)
// ---------------------------------------------------------------------------

/// Trait for loading rules into the orchestrator.
///
/// This is the interface contract between the orchestrator and the
/// rule_loader module. The rule_loader deserializes seed_rules.bin
/// (or wire format rules from P2P) and produces Vec<ProductionSpec>.
///
/// The rule_loader module implements this trait.
pub trait RuleLoader {
    /// Load rules from a file path.
    fn load_from_file(&self, path: &std::path::Path) -> Result<Vec<ProductionSpec>, String>;
}

// ---------------------------------------------------------------------------
// Async channel types (for the tokio runtime layer)
// ---------------------------------------------------------------------------

/// Channel payload types used by the async runtime layer.
///
/// These types define what flows through each tokio::mpsc channel.
/// The actual channel creation happens in the async entry point
/// (binary crate), not in this library module.
pub mod channel_types {
    use super::*;
    use std::path::PathBuf;

    /// Sent on ch_extract: document path to extract.
    #[derive(Debug)]
    pub struct ExtractRequest {
        pub path: PathBuf,
    }

    /// Sent on ch_extraction_out: raw extraction JSON output.
    #[derive(Debug)]
    pub struct ExtractResponse {
        pub output: ExtractionOutput,
        pub source_file: String,
    }

    /// Sent on ch_insight: a rule firing/insight for the UI.
    pub type InsightMessage = RuleFiring;

    /// Shutdown signal broadcast to all tasks.
    #[derive(Debug, Clone)]
    pub struct ShutdownSignal {
        /// Whether this is a forced shutdown (second SIGINT).
        pub forced: bool,
    }
}

// ---------------------------------------------------------------------------
// Async orchestrator skeleton (tokio task spawning)
// ---------------------------------------------------------------------------

/// Async orchestrator that wraps the synchronous Orchestrator in tokio tasks.
///
/// This module provides the async entry point that:
/// 1. Creates all tokio::mpsc channels
/// 2. Spawns engine, adapter, and factory tasks
/// 3. Runs the main select! event loop
/// 4. Handles graceful shutdown via broadcast
///
/// The actual implementation requires tokio in Cargo.toml. The types and
/// function signatures are defined here; the caller (binary crate) provides
/// the tokio runtime.
pub mod async_runtime {
    use super::*;

    /// Channel handles created by the async orchestrator.
    ///
    /// All channels are bounded.
    /// The orchestrator distributes sender/receiver halves to tasks.
    pub struct ChannelTopology {
        /// ch_extract: Orchestrator -> ExtractionManager.
        /// Capacity: 1 (only 1 in-flight extraction).
        pub ch_extract_capacity: usize,

        /// ch_extraction_out: ExtractionManager -> TupleAdapter.
        /// Capacity: 4.
        pub ch_extraction_out_capacity: usize,

        /// ch_wme: TupleAdapter -> WmeFactory.
        /// Capacity: 16.
        pub ch_wme_capacity: usize,

        /// ch_engine: WmeFactory -> Engine.
        /// Capacity: 32.
        pub ch_engine_capacity: usize,

        /// ch_insight: Engine -> UI.
        /// Capacity: 32.
        pub ch_insight_capacity: usize,

        /// ch_tuple_outbound: Privacy pipeline -> Dandelion++ (Channel 16).
        /// Capacity: 256.
        pub ch_tuple_outbound_capacity: usize,

        /// ch_rule_inbound: Gossipsub -> Rete engine (Channel 17).
        /// Capacity: 128.
        pub ch_rule_inbound_capacity: usize,
    }

    impl Default for ChannelTopology {
        fn default() -> Self {
            Self {
                ch_extract_capacity: CH_EXTRACT_CAPACITY,
                ch_extraction_out_capacity: CH_EXTRACTION_OUT_CAPACITY,
                ch_wme_capacity: CH_WME_CAPACITY,
                ch_engine_capacity: CH_ENGINE_CAPACITY,
                ch_insight_capacity: CH_INSIGHT_CAPACITY,
                ch_tuple_outbound_capacity: CH_TUPLE_OUTBOUND_CAPACITY,
                ch_rule_inbound_capacity: CH_RULE_INBOUND_CAPACITY,
            }
        }
    }

    /// Configuration for spawning async tasks.
    #[derive(Default)]
    pub struct AsyncOrchestratorConfig {
        /// Channel topology (capacities).
        pub channels: ChannelTopology,
        /// Base orchestrator configuration.
        pub base: OrchestratorConfig,
    }

    /// Task handle registry for shutdown coordination.
    ///
    /// Awaits all spawned tasks (with 5s timeout per task).
    pub struct TaskRegistry {
        /// Names and handles for spawned tasks.
        task_names: Vec<String>,
        task_count: usize,
    }

    impl TaskRegistry {
        pub fn new() -> Self {
            Self {
                task_names: Vec::new(),
                task_count: 0,
            }
        }

        /// Register a new task.
        pub fn register(&mut self, name: &str) {
            self.task_names.push(name.to_string());
            self.task_count += 1;
        }

        /// Number of registered tasks.
        pub fn count(&self) -> usize {
            self.task_count
        }

        /// Names of registered tasks.
        pub fn names(&self) -> &[String] {
            &self.task_names
        }
    }

    impl Default for TaskRegistry {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Start the async orchestrator.
    ///
    /// This function is called from the binary entry point with a tokio runtime.
    /// It creates channels, spawns tasks, and enters the main event loop.
    ///
    /// ## Example (requires tokio runtime):
    ///
    /// ```ignore
    /// use rete_alpha::orchestrator::async_runtime;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let config = async_runtime::AsyncOrchestratorConfig::default();
    ///     // Create channels, spawn tasks, run event loop...
    /// }
    /// ```
    ///
    /// Returns the channel topology configuration for external reference.
    pub fn create_channel_topology() -> ChannelTopology {
        ChannelTopology::default()
    }
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

/// Health status of the orchestrator and its components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    /// All components functioning normally.
    Healthy,
    /// Some components degraded but system operational.
    Degraded { reason: String },
    /// System not operational.
    Unhealthy { reason: String },
}

/// Health report for the orchestrator.
#[derive(Debug)]
pub struct HealthReport {
    /// Overall status.
    pub status: HealthStatus,
    /// Orchestrator state.
    pub orchestrator_state: OrchestratorState,
    /// Extraction subprocess state name.
    pub extraction_state: String,
    /// Number of rules loaded.
    pub rules_loaded: usize,
    /// Number of WMEs in working memory.
    pub wme_count: usize,
    /// Document queue depth.
    pub queue_depth: usize,
    /// Total documents processed.
    pub documents_processed: u64,
    /// Total insights generated.
    pub insights_generated: usize,
}

impl Orchestrator {
    /// Generate a health report.
    ///
    /// Polls component health every 10 seconds.
    pub fn health_check(&self) -> HealthReport {
        let extraction_state = format!("{:?}", self.extraction_manager.state());

        let status = match self.state {
            OrchestratorState::Ready => {
                if self.pipeline.production_count() == 0 {
                    HealthStatus::Degraded {
                        reason: "No rules loaded. Insights unavailable.".to_string(),
                    }
                } else {
                    HealthStatus::Healthy
                }
            }
            OrchestratorState::ShuttingDown | OrchestratorState::Stopped => {
                HealthStatus::Unhealthy {
                    reason: "Orchestrator is shutting down.".to_string(),
                }
            }
            _ => HealthStatus::Degraded {
                reason: format!("Orchestrator not ready: {:?}", self.state),
            },
        };

        HealthReport {
            status,
            orchestrator_state: self.state,
            extraction_state,
            rules_loaded: self.pipeline.production_count(),
            wme_count: self.pipeline.wme_count(),
            queue_depth: self.doc_queue.len(),
            documents_processed: self.documents_processed,
            insights_generated: self.insights.len(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{all_test_rules, lease_agreement_rules, medical_bill_rules};

    // -----------------------------------------------------------------------
    // Orchestrator lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_orchestrator_state() {
        let orch = Orchestrator::new_mvp();
        assert_eq!(orch.state(), OrchestratorState::Created);
        assert!(!orch.is_shutting_down());
        assert_eq!(orch.documents_processed(), 0);
        assert_eq!(orch.documents_failed(), 0);
        assert_eq!(orch.rule_count(), 0);
        assert_eq!(orch.wme_count(), 0);
        assert!(orch.insights().is_empty());
    }

    #[test]
    fn test_initialize() {
        let mut orch = Orchestrator::new_mvp();
        let elapsed = orch.initialize().unwrap();
        assert_eq!(orch.state(), OrchestratorState::Ready);
        assert!(elapsed.as_millis() < 100, "Init should be < 100ms");
        assert!(orch.startup_time().is_some());
    }

    #[test]
    fn test_load_seed_rules() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();
        orch.load_seed_rules(medical_bill_rules());
        assert_eq!(orch.rule_count(), 2);
    }

    #[test]
    fn test_shutdown() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();

        let report = orch.shutdown();
        assert_eq!(orch.state(), OrchestratorState::Stopped);
        assert!(orch.is_shutting_down());
        assert_eq!(report.pending_documents_drained, 0);
    }

    // -----------------------------------------------------------------------
    // Document submission tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_submit_document() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();

        orch.submit_document(PathBuf::from("/test/doc.pdf"))
            .unwrap();
        assert_eq!(orch.doc_queue().len(), 1);
    }

    #[test]
    fn test_submit_document_rejected_when_shutting_down() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();
        orch.shutdown();

        let result = orch.submit_document(PathBuf::from("/test/doc.pdf"));
        assert!(result.is_err());
    }

    #[test]
    fn test_submit_document_backpressure() {
        let config = OrchestratorConfig {
            doc_queue_capacity: 2,
            ..OrchestratorConfig::mvp()
        };
        let mut orch = Orchestrator::new(config);
        orch.initialize().unwrap();

        orch.submit_document(PathBuf::from("/a")).unwrap();
        orch.submit_document(PathBuf::from("/b")).unwrap();
        let result = orch.submit_document(PathBuf::from("/c"));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Full pipeline processing tests (mock extraction)
    // -----------------------------------------------------------------------

    #[test]
    fn test_process_medical_bill_end_to_end() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();
        orch.load_seed_rules(medical_bill_rules());

        let result = orch
            .process_document(PathBuf::from("/test/medical_bill.pdf"))
            .unwrap();

        // Mock medical output has 2 relationships -> 2 tuples -> 2 WMEs
        assert_eq!(result.pipeline_result.tuples_created, 2);
        assert_eq!(result.pipeline_result.wmes_inserted, 2);

        // Both medical rules should fire
        assert_eq!(
            result.pipeline_result.fired_productions.len(),
            2,
            "Both medical_bill rules should fire"
        );

        // Insights should be generated
        assert_eq!(result.insights.len(), 2);
        assert_eq!(orch.documents_processed(), 1);
        assert_eq!(orch.wme_count(), 2);
    }

    #[test]
    fn test_process_lease_end_to_end() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();
        orch.load_seed_rules(lease_agreement_rules());

        let result = orch
            .process_document(PathBuf::from("/test/lease.pdf"))
            .unwrap();

        assert_eq!(result.pipeline_result.tuples_created, 2);
        assert_eq!(result.pipeline_result.wmes_inserted, 2);
        assert_eq!(result.pipeline_result.fired_productions.len(), 2);
        assert_eq!(result.insights.len(), 2);
    }

    #[test]
    fn test_process_no_matching_rules() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();
        // Load medical rules but process a lease document
        orch.load_seed_rules(medical_bill_rules());

        let result = orch
            .process_document(PathBuf::from("/test/lease.pdf"))
            .unwrap();

        // WMEs created but no rules fire (wrong category/relations)
        assert_eq!(result.pipeline_result.tuples_created, 2);
        assert_eq!(result.pipeline_result.wmes_inserted, 2);
        assert_eq!(result.pipeline_result.fired_productions.len(), 0);
        assert_eq!(result.insights.len(), 0);
    }

    #[test]
    fn test_process_queue_then_process_all() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();
        orch.load_seed_rules(all_test_rules());

        orch.submit_document(PathBuf::from("/test/medical_bill.pdf"))
            .unwrap();
        orch.submit_document(PathBuf::from("/test/lease.pdf"))
            .unwrap();
        assert_eq!(orch.doc_queue().len(), 2);

        let results = orch.process_all();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert_eq!(orch.documents_processed(), 2);
        assert!(orch.doc_queue().is_empty());
    }

    #[test]
    fn test_process_multiple_sequential_documents() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();
        orch.load_seed_rules(all_test_rules());

        // Process 3 medical bills sequentially
        for i in 0..3 {
            let result = orch
                .process_document(PathBuf::from(format!("/test/medical_{}.pdf", i)))
                .unwrap();
            assert_eq!(result.pipeline_result.fired_productions.len(), 2);
        }

        assert_eq!(orch.documents_processed(), 3);
        assert_eq!(orch.wme_count(), 6); // 3 docs * 2 WMEs each
        assert_eq!(orch.insights().len(), 6); // 3 docs * 2 insights each
    }

    #[test]
    fn test_process_empty_queue_returns_none() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();
        assert!(orch.process_next().is_none());
    }

    // -----------------------------------------------------------------------
    // RuleFiring tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule_firing_from_fired_production() {
        let fp = FiredProduction {
            rule_id: 1001,
            confidence: 0.85,
            extraction_cf: 0.9,
            chained_cf: 0.765,
        };
        let rf = RuleFiring::from((&fp, "/test/doc.pdf"));
        assert_eq!(rf.rule_id, 1001);
        assert_eq!(rf.production_name, "Rule #1001");
        assert!((rf.confidence - 0.765).abs() < 1e-3);
        assert_eq!(rf.source_file, "/test/doc.pdf");
    }

    // -----------------------------------------------------------------------
    // Health check tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_health_check_degraded_no_rules() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();
        let report = orch.health_check();
        match report.status {
            HealthStatus::Degraded { reason } => {
                assert!(reason.contains("No rules loaded"));
            }
            other => panic!("Expected Degraded, got: {:?}", other),
        }
    }

    #[test]
    fn test_health_check_healthy_with_rules() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();
        orch.load_seed_rules(medical_bill_rules());
        let report = orch.health_check();
        assert_eq!(report.status, HealthStatus::Healthy);
        assert_eq!(report.rules_loaded, 2);
    }

    #[test]
    fn test_health_check_unhealthy_when_stopped() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();
        orch.shutdown();
        let report = orch.health_check();
        match report.status {
            HealthStatus::Unhealthy { .. } => (),
            other => panic!("Expected Unhealthy, got: {:?}", other),
        }
    }

    #[test]
    fn test_health_report_fields() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();
        orch.load_seed_rules(medical_bill_rules());
        orch.process_document(PathBuf::from("/test/medical_bill.pdf"))
            .unwrap();

        let report = orch.health_check();
        assert_eq!(report.orchestrator_state, OrchestratorState::Ready);
        assert_eq!(report.rules_loaded, 2);
        assert_eq!(report.wme_count, 2);
        assert_eq!(report.documents_processed, 1);
        assert_eq!(report.insights_generated, 2);
        assert_eq!(report.queue_depth, 0);
    }

    // -----------------------------------------------------------------------
    // EngineCommand tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_engine_command_variants() {
        // Verify all variants construct correctly (compile-time check)
        let _cmd1 = EngineCommand::ProcessExtraction {
            json: "{}".to_string(),
            source_file: "/test".to_string(),
        };
        let _cmd2 = EngineCommand::AddRule(ProductionSpec {
            rule_id: 1,
            conditions: vec![],
            confidence: 0.5,
        });
        let _cmd3 = EngineCommand::RetractRule { rule_id: 1 };
        let _cmd4 = EngineCommand::UpdateRuleConfidence {
            rule_id: 1,
            confidence: 0.8,
        };
        let _cmd5 = EngineCommand::DailySweep;
        let _cmd6 = EngineCommand::InboundRule(crate::bridge::InboundRuleEvent::Tombstone {
            rule_id: 42,
            tombstone_until: 1700000000,
            version: 1,
        });
    }

    // -----------------------------------------------------------------------
    // D5 Step 2: P2P channel topology and InboundRule tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ch_tuple_outbound_capacity_is_256() {
        assert_eq!(CH_TUPLE_OUTBOUND_CAPACITY, 256);
    }

    #[test]
    fn test_ch_rule_inbound_capacity_is_128() {
        assert_eq!(CH_RULE_INBOUND_CAPACITY, 128);
    }

    #[test]
    fn test_channel_topology_p2p_fields_match_constants() {
        let topo = async_runtime::ChannelTopology::default();
        assert_eq!(topo.ch_tuple_outbound_capacity, 256);
        assert_eq!(topo.ch_rule_inbound_capacity, 128);
    }

    #[test]
    fn test_engine_command_inbound_rule_new_rule() {
        let cmd = EngineCommand::InboundRule(crate::bridge::InboundRuleEvent::NewRule {
            envelope_bytes: vec![1, 2, 3],
            source_peer: vec![0xAB; 32],
            received_at: 1700000000,
        });
        match cmd {
            EngineCommand::InboundRule(crate::bridge::InboundRuleEvent::NewRule {
                envelope_bytes,
                source_peer,
                received_at,
            }) => {
                assert_eq!(envelope_bytes, vec![1, 2, 3]);
                assert_eq!(source_peer.len(), 32);
                assert_eq!(received_at, 1700000000);
            }
            _ => panic!("Expected InboundRule(NewRule)"),
        }
    }

    #[test]
    fn test_engine_command_inbound_rule_confidence_update() {
        let cmd = EngineCommand::InboundRule(crate::bridge::InboundRuleEvent::ConfidenceUpdate {
            rule_id: 99,
            new_cf_x10k: 8500,
            new_version: 3,
            evidence: crate::bridge::EvidenceSummary {
                supporting_count: 50,
                contradicting_count: 2,
                distinct_regions: 4,
                recency_score_x10k: 9000,
            },
        });
        match cmd {
            EngineCommand::InboundRule(crate::bridge::InboundRuleEvent::ConfidenceUpdate {
                rule_id,
                new_cf_x10k,
                ..
            }) => {
                assert_eq!(rule_id, 99);
                assert_eq!(new_cf_x10k, 8500);
            }
            _ => panic!("Expected InboundRule(ConfidenceUpdate)"),
        }
    }

    #[test]
    fn test_engine_command_inbound_rule_tombstone() {
        let cmd = EngineCommand::InboundRule(crate::bridge::InboundRuleEvent::Tombstone {
            rule_id: 200,
            tombstone_until: 1700086400,
            version: 15,
        });
        match cmd {
            EngineCommand::InboundRule(crate::bridge::InboundRuleEvent::Tombstone {
                rule_id,
                ..
            }) => {
                assert_eq!(rule_id, 200);
            }
            _ => panic!("Expected InboundRule(Tombstone)"),
        }
    }

    // -----------------------------------------------------------------------
    // Config tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_mvp_config() {
        let config = OrchestratorConfig::mvp();
        assert_eq!(config.extraction_mode, ExtractionMode::Mock);
        assert!(!config.enable_privacy_pipeline);
        assert!(!config.enable_p2p);
        assert!(!config.enable_crystallization);
        assert_eq!(config.doc_queue_capacity, 8);
    }

    #[test]
    fn test_mvp_config_with_rules() {
        let config = OrchestratorConfig::mvp_with_rules(PathBuf::from("/rules/seed.bin"));
        assert_eq!(
            config.seed_rules_path,
            Some(PathBuf::from("/rules/seed.bin"))
        );
    }

    // -----------------------------------------------------------------------
    // Async runtime types tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_channel_topology_defaults() {
        let topo = async_runtime::ChannelTopology::default();
        assert_eq!(topo.ch_extract_capacity, CH_EXTRACT_CAPACITY);
        assert_eq!(topo.ch_extraction_out_capacity, CH_EXTRACTION_OUT_CAPACITY);
        assert_eq!(topo.ch_wme_capacity, CH_WME_CAPACITY);
        assert_eq!(topo.ch_engine_capacity, CH_ENGINE_CAPACITY);
        assert_eq!(topo.ch_insight_capacity, CH_INSIGHT_CAPACITY);
        assert_eq!(topo.ch_tuple_outbound_capacity, CH_TUPLE_OUTBOUND_CAPACITY);
        assert_eq!(topo.ch_rule_inbound_capacity, CH_RULE_INBOUND_CAPACITY);
    }

    #[test]
    fn test_task_registry() {
        let mut registry = async_runtime::TaskRegistry::new();
        assert_eq!(registry.count(), 0);

        registry.register("engine_task");
        registry.register("adapter_task");
        registry.register("factory_task");
        assert_eq!(registry.count(), 3);
        assert_eq!(
            registry.names(),
            &["engine_task", "adapter_task", "factory_task"]
        );
    }

    // -----------------------------------------------------------------------
    // Channel types tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_shutdown_signal() {
        let signal = channel_types::ShutdownSignal { forced: false };
        assert!(!signal.forced);

        let forced = channel_types::ShutdownSignal { forced: true };
        assert!(forced.forced);

        // Clone should work (for broadcast)
        let cloned = signal.clone();
        assert!(!cloned.forced);
    }

    #[test]
    fn test_extract_request() {
        let req = channel_types::ExtractRequest {
            path: PathBuf::from("/test/doc.pdf"),
        };
        assert_eq!(req.path, PathBuf::from("/test/doc.pdf"));
    }

    // -----------------------------------------------------------------------
    // Shutdown with pending documents
    // -----------------------------------------------------------------------

    #[test]
    fn test_shutdown_drains_pending_documents() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();

        orch.submit_document(PathBuf::from("/a")).unwrap();
        orch.submit_document(PathBuf::from("/b")).unwrap();
        orch.submit_document(PathBuf::from("/c")).unwrap();

        let report = orch.shutdown();
        assert_eq!(report.pending_documents_drained, 3);
        assert!(orch.doc_queue().is_empty());
    }

    // -----------------------------------------------------------------------
    // Idle kill extraction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_idle_kill_extraction() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();

        // Process a document so extraction becomes Running
        orch.load_seed_rules(medical_bill_rules());
        orch.process_document(PathBuf::from("/test/medical_bill.pdf"))
            .unwrap();

        // Immediately after, idle kill should not trigger
        assert!(!orch.should_idle_kill_extraction());

        // Manually kill (simulates timeout)
        orch.idle_kill_extraction();
        assert!(!orch.should_idle_kill_extraction());
    }

    // -----------------------------------------------------------------------
    // ProcessDocumentResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_process_document_result_fields() {
        let mut orch = Orchestrator::new_mvp();
        orch.initialize().unwrap();
        orch.load_seed_rules(medical_bill_rules());

        let result = orch
            .process_document(PathBuf::from("/test/medical_bill.pdf"))
            .unwrap();

        assert_eq!(result.source_file, "/test/medical_bill.pdf");
        assert!(result.elapsed.as_secs() < 1);
        assert!(!result.insights.is_empty());

        // Check insight confidence is reasonable
        for insight in &result.insights {
            assert!(insight.confidence > 0.0);
            assert!(insight.confidence <= 1.0);
        }
    }

    // -----------------------------------------------------------------------
    // Uptime tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_uptime() {
        let orch = Orchestrator::new_mvp();
        let uptime = orch.uptime();
        // Should be very small (just created)
        assert!(uptime.as_millis() < 100);
    }

    // -----------------------------------------------------------------------
    // Async document processing tests (feature-gated)
    // -----------------------------------------------------------------------

    #[cfg(feature = "live-extraction")]
    mod async_tests {
        use super::*;

        #[tokio::test]
        async fn test_process_document_async_mock_delegates_to_sync() {
            let mut orch = Orchestrator::new_mvp();
            orch.initialize().unwrap();
            orch.load_seed_rules(medical_bill_rules());

            let result = orch
                .process_document_async(PathBuf::from("/test/medical_bill.pdf"))
                .await
                .unwrap();

            // Should produce the same results as synchronous path
            assert_eq!(result.pipeline_result.tuples_created, 2);
            assert_eq!(result.pipeline_result.wmes_inserted, 2);
            assert_eq!(result.insights.len(), 2);
            assert_eq!(orch.documents_processed(), 1);
        }

        #[tokio::test]
        async fn test_process_document_async_mock_no_matching_rules() {
            let mut orch = Orchestrator::new_mvp();
            orch.initialize().unwrap();
            orch.load_seed_rules(medical_bill_rules());

            let result = orch
                .process_document_async(PathBuf::from("/test/lease.pdf"))
                .await
                .unwrap();

            // WMEs created but no rules fire (wrong category)
            assert_eq!(result.pipeline_result.tuples_created, 2);
            assert_eq!(result.insights.len(), 0);
        }
    }
}
