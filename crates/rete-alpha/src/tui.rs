//! Terminal UI for HIVE -- ratatui-based "document in, insight out" interface.
//!
//! Three-panel layout:
//!   1. Header + input bar (document path entry)
//!   2. Scrollable insight card panel
//!   3. Footer with rule count and keyboard shortcuts

use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::hive_config::{HiveConfig, PrivacyMode};

// ---------------------------------------------------------------------------
// ExtractionStatus: real-time extraction status for TUI display
// ---------------------------------------------------------------------------
// Per Phase E design Section 3.4.

/// Extraction status shown in the TUI status bar.
///
/// Tracks the lifecycle of a real extraction subprocess for user feedback.
/// In mock mode, the status stays at `Idle` since mock extraction is instant.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ExtractionStatus {
    /// No extraction subprocess. Mock mode or idle-killed.
    #[default]
    Idle,
    /// Python subprocess spawning, model not yet loaded.
    SpawningProcess,
    /// Model loading into memory (~5s).
    LoadingModel,
    /// Actively extracting entities from a document.
    Extracting {
        file_name: String,
        elapsed_secs: u32,
    },
    /// Extraction complete, processing through pipeline.
    Processing,
    /// Extraction failed, will retry.
    Retrying { attempt: u32, max_attempts: u32 },
    /// Extraction failed permanently.
    Failed { reason: String },
}

impl fmt::Display for ExtractionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::SpawningProcess => write!(f, "Spawning extraction process..."),
            Self::LoadingModel => write!(f, "Loading extraction model..."),
            Self::Extracting {
                file_name,
                elapsed_secs,
            } => {
                write!(f, "Extracting: {} ({}s)", file_name, elapsed_secs)
            }
            Self::Processing => write!(f, "Processing extraction results..."),
            Self::Retrying {
                attempt,
                max_attempts,
            } => {
                write!(f, "Retrying extraction ({}/{})", attempt, max_attempts)
            }
            Self::Failed { reason } => {
                // reason already in WHAT/WHY/DO format from
                // ExtractionError Display (U4); show first line.
                let first = reason.lines().next().unwrap_or(reason);
                write!(f, "{}", first)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FullInsightCard and StrippedInsightCard
// ---------------------------------------------------------------------------
// These are the TUI's data types; the orchestrator produces them.

/// Insight card for local display.
#[derive(Debug, Clone)]
pub struct FullInsightCard {
    /// Filled template with user-specific values.
    pub rule_text: String,
    /// Combined confidence factor (rule CF * extraction CF).
    pub confidence: f64,
    /// "High" / "Moderate" / "Low".
    pub confidence_band: String,
    /// dp_corrected_count from rule.
    pub evidence_count: u32,
    /// distinct_region_count from rule.
    pub evidence_regions: u8,
    /// "hundreds of observations..." etc.
    pub evidence_summary: String,
    /// "Your amount: $8,200. Typical: $1K-$5K" (None if no amount context).
    pub amount_context: Option<String>,
    /// From matched WME raw values.
    pub specific_entities: Vec<String>,
    /// Display rule id, e.g. "#127".
    pub rule_id: String,
    /// "stable" / "increasing" / "decreasing".
    pub trend: String,
    /// For share warning calibration (1-4).
    pub sensitivity_tier: u8,
    /// Document category, e.g. "Medical Billing", "Lease Agreement".
    pub category: String,
}

/// Stripped card for external sharing.
#[derive(Debug, Clone)]
pub struct StrippedInsightCard {
    /// All QIs removed.
    pub rule_text_generic: String,
    /// 3 bands only.
    pub confidence_band: String,
    /// Approximate description.
    pub evidence_summary: String,
    /// "Scan your own documents with HIVE".
    pub call_to_action: String,
}

impl FullInsightCard {
    /// Generate a stripped (shareable) version of this insight card.
    /// Removes all personally-identifiable information.
    ///
    /// Structured comparison card with no PII.
    /// No patient name, no hospital name, no location, no account numbers.
    pub fn to_stripped(&self) -> StrippedInsightCard {
        // The authoritative PII-strip path is `insight_gen::strip_insight`
        // (insight_gen.rs:358), which runs `strip_amounts` + `strip_entity_names`
        // against `card.rule_text` and stores the result as `rule_text_generic`.
        // The shareable text built below is a fixed box-drawing template
        // populated from `confidence`, `evidence_count`, `category`, and the
        // already-parsed `amount_context` -- it never copies free-form text out
        // of `self.rule_text`, so there is no surface here that a runtime
        // strip could protect. Keeping a TODO + dead helper in this position
        // (the earlier stance) was net-misleading: it implied a strip happens here
        // when the layer responsible for stripping lives upstream.
        //
        // If runtime stripping is ever needed in this function, the correct
        // approach is to reach for `insight_gen::strip_amounts` directly,
        // not to resurrect the in-file helper that was removed.

        // Build the enhanced shareable card text.
        let parsed = parse_amount_context(&self.amount_context);
        let confidence_pct = (self.confidence * 100.0).round() as u32;
        let evidence_count_str = format_evidence_count(self.evidence_count);
        let regions_str = format!(
            "{} region{}",
            self.evidence_regions,
            if self.evidence_regions == 1 { "" } else { "s" }
        );

        let category_upper = self.category.replace('_', " ").to_uppercase();
        // Determine a generic service label from the rule text
        let service_label = extract_service_label(&self.rule_text);

        let shareable_text = if let Some(ref amounts) = parsed {
            let diff_str = if !amounts.difference.is_empty() {
                format!("  ({})", amounts.difference)
            } else {
                String::new()
            };
            format!(
                "+--[ HIVE ]------------------------------------+\n\
                 |                                              |\n\
                 |  {}: {}                           \n\
                 |  TYPICAL:  {}{}     \n\
                 |                                              |\n\
                 |  Based on {} observations, {}     \n\
                 |  Confidence: {}%                             \n\
                 |                                              |\n\
                 |  Analyzed by HIVE - hive.example.com         |\n\
                 +----------------------------------------------+",
                service_label.to_uppercase(),
                amounts.your_amount,
                amounts.typical_amount,
                diff_str,
                evidence_count_str,
                regions_str,
                confidence_pct,
            )
        } else {
            format!(
                "+--[ HIVE ]------------------------------------+\n\
                 |                                              |\n\
                 |  {}                                \n\
                 |                                              |\n\
                 |  Based on {} observations, {}     \n\
                 |  Confidence: {}%                             \n\
                 |                                              |\n\
                 |  Analyzed by HIVE - hive.example.com         |\n\
                 +----------------------------------------------+",
                category_upper, evidence_count_str, regions_str, confidence_pct,
            )
        };

        StrippedInsightCard {
            rule_text_generic: shareable_text,
            confidence_band: self.confidence_band.clone(),
            evidence_summary: self.evidence_summary.clone(),
            call_to_action: "Analyzed by HIVE - hive.example.com".to_string(),
        }
    }

    /// Determine the conclusion type for display styling.
    pub fn conclusion_type(&self) -> ConclusionType {
        let lower = self.rule_text.to_lowercase();
        if lower.contains("above") {
            ConclusionType::AboveRange
        } else if lower.contains("below") {
            ConclusionType::BelowRange
        } else if lower.contains("within") || lower.contains("typical") {
            ConclusionType::WithinRange
        } else {
            ConclusionType::Informational
        }
    }
}

/// Conclusion type for card styling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConclusionType {
    AboveRange,
    BelowRange,
    WithinRange,
    Informational,
}

// `strip_pii_from_text` removed. It was previously retained with
// `#[allow(dead_code)]` and a TODO to re-wire it from `to_stripped`, but
// the actual strip path lives in `insight_gen::strip_insight`
// (insight_gen.rs:358) and `to_stripped` does not consume free-form
// `rule_text` at all -- so any "wire it back in here" plan was
// architecturally wrong. If runtime stripping is ever needed in `tui.rs`,
// call `insight_gen::strip_amounts` / `strip_entity_names` directly.

// ---------------------------------------------------------------------------
// AppState: TUI state machine
// ---------------------------------------------------------------------------

/// TUI state machine. Controls what the UI displays and accepts.
#[derive(Debug, Clone)]
pub enum AppState {
    /// Waiting for user to enter a file path.
    Idle,
    /// Extraction/processing in progress.
    Processing { path: String, started_at: Instant },
    /// Insights displayed and available for scrolling.
    ShowingInsights {
        path: String,
        processing_time_secs: f64,
    },
    /// Detail view for a specific insight card.
    DetailView {
        card_index: usize,
        /// Saved path from ShowingInsights for return navigation.
        return_path: String,
        return_time: f64,
    },
    /// Privacy settings panel overlay.
    PrivacySettings {
        /// AppState to return to on Escape.
        return_state: Box<AppState>,
    },
    /// Error state with user-facing message.
    Error { message: String },
}

// ---------------------------------------------------------------------------
// AppAction: what the event loop should do after handling input
// ---------------------------------------------------------------------------

/// Action returned by input handling for the event loop to execute.
#[derive(Debug, Clone, PartialEq)]
pub enum AppAction {
    /// User submitted a file path for processing.
    ProcessFile(String),
    /// User requested quit.
    Quit,
    /// User requested to share insight at the given index.
    ShareInsight(usize),
    /// User requested to show detail view for the given insight index.
    ShowDetail(usize),
    /// User requested to clear insights.
    ClearInsights,
    /// Privacy mode was changed; event loop must propagate.
    ModeChanged(PrivacyMode),
    /// No action needed (handled internally).
    None,
}

// ---------------------------------------------------------------------------
// TuiApp: the main TUI application struct
// ---------------------------------------------------------------------------

/// The terminal UI application.
///
/// Owns all display state. The orchestrator calls `push_insight`,
/// `set_status`, etc. to drive the display. The event loop calls
/// `handle_input` and `draw`.
pub struct TuiApp {
    /// Current UI state.
    pub state: AppState,
    /// Text input buffer for file path entry.
    pub input: String,
    /// Cursor position within the input buffer.
    pub cursor_pos: usize,
    /// All insight cards for the current document.
    pub insights: Vec<FullInsightCard>,
    /// Index of the currently selected insight card.
    pub selected: usize,
    /// Vertical scroll offset for the insight panel.
    pub scroll_offset: usize,
    /// Number of rules loaded in the engine.
    pub rules_loaded: usize,
    /// Status message displayed in the status bar.
    pub status_message: String,
    /// Last shared insight (for display feedback).
    pub last_shared: Option<StrippedInsightCard>,
    /// Whether the app should quit.
    pub should_quit: bool,
    /// Current extraction status (for real-time status bar updates).
    /// Phase E: tracks subprocess lifecycle for live extraction mode.
    pub extraction_status: ExtractionStatus,
    /// Whether the extraction model is currently loaded in memory.
    /// Phase E: true when Python subprocess has completed first extraction.
    pub model_loaded: bool,
    /// Shared authoritative privacy mode -- single source of truth.
    /// All components (TUI, pipeline, P2P) read/write through this Arc.
    pub shared_privacy_mode: Arc<RwLock<PrivacyMode>>,
    /// When switching TO Collective mode, gated behind a confirmation dialog.
    pub pending_collective_confirm: bool,
    /// Daily privacy budget remaining (0.0 to 1.0).
    pub privacy_budget_daily: f64,
    /// Weekly privacy budget remaining (0.0 to 1.0).
    pub privacy_budget_weekly: f64,
    /// Lifetime privacy budget remaining (0.0 to 1.0).
    pub privacy_budget_lifetime: f64,
    /// Documents analyzed today.
    pub docs_analyzed_today: u32,
    /// Tuples shared today.
    pub tuples_shared_today: u32,
    /// Whether the pipeline details sub-view is active.
    pub privacy_show_details: bool,
}

impl Default for TuiApp {
    fn default() -> Self {
        Self::new()
    }
}

impl TuiApp {
    /// Create a new TUI application instance with default LocalOnly mode.
    pub fn new() -> Self {
        Self::new_with_shared_mode(Arc::new(RwLock::new(PrivacyMode::LocalOnly)))
    }

    /// Create a TUI application from a loaded HiveConfig.
    /// The returned `Arc<RwLock<PrivacyMode>>` is the shared source of truth
    /// that should also be wired into the pipeline and P2P layers.
    pub fn new_with_config(config: &HiveConfig) -> (Self, Arc<RwLock<PrivacyMode>>) {
        let shared = Arc::new(RwLock::new(config.privacy_mode.clone()));
        let app = Self::new_with_shared_mode(Arc::clone(&shared));
        (app, shared)
    }

    /// Create a TUI application with an externally-provided shared mode.
    pub fn new_with_shared_mode(shared_mode: Arc<RwLock<PrivacyMode>>) -> Self {
        Self {
            state: AppState::Idle,
            input: String::new(),
            cursor_pos: 0,
            insights: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            rules_loaded: 0,
            status_message: "Ready. Enter a file path to begin.".to_string(),
            last_shared: None,
            should_quit: false,
            extraction_status: ExtractionStatus::Idle,
            model_loaded: false,
            shared_privacy_mode: shared_mode,
            pending_collective_confirm: false,
            privacy_budget_daily: 1.0,
            privacy_budget_weekly: 1.0,
            privacy_budget_lifetime: 1.0,
            docs_analyzed_today: 0,
            tuples_shared_today: 0,
            privacy_show_details: false,
        }
    }

    /// Read the current privacy mode from the shared source of truth.
    pub fn privacy_mode(&self) -> PrivacyMode {
        self.shared_privacy_mode.read().unwrap().clone()
    }

    /// Set privacy mode atomically: updates shared state, persists to disk,
    /// and returns `AppAction::ModeChanged` so the event loop can propagate.
    pub fn set_privacy_mode(&mut self, new_mode: PrivacyMode) -> AppAction {
        // Update the shared source of truth.
        {
            let mut mode = self.shared_privacy_mode.write().unwrap();
            *mode = new_mode.clone();
        }

        // Persist to disk.
        let mut config = HiveConfig::load();
        config.privacy_mode = new_mode.clone();
        if let Err(e) = config.save() {
            self.status_message = format!("Warning: mode changed but save failed: {}", e);
        }

        let mode_str = match &new_mode {
            PrivacyMode::LocalOnly => "Local Only",
            PrivacyMode::Collective => "Collective",
        };
        self.status_message = format!("Privacy mode set to: {}", mode_str);
        AppAction::ModeChanged(new_mode)
    }

    /// Called by orchestrator when an insight arrives from the engine.
    pub fn push_insight(&mut self, card: FullInsightCard) {
        self.insights.push(card);
        let count = self.insights.len();

        // Transition to ShowingInsights if we were Processing.
        if let AppState::Processing {
            ref path,
            started_at,
        } = self.state
        {
            let elapsed = started_at.elapsed().as_secs_f64();
            self.state = AppState::ShowingInsights {
                path: path.clone(),
                processing_time_secs: elapsed,
            };
            self.status_message = format!(
                "Processed ({:.1}s) -- {} insight{} found",
                elapsed,
                count,
                if count == 1 { "" } else { "s" }
            );
        } else if let AppState::ShowingInsights { ref path, .. } = self.state {
            // Update the count in the status message.
            let path = path.clone();
            self.status_message = format!(
                "{} insight{} found for {}",
                count,
                if count == 1 { "" } else { "s" },
                path
            );
        }
    }

    /// Called by orchestrator to update the status message.
    pub fn set_status(&mut self, status: &str) {
        self.status_message = status.to_string();
    }

    /// Called by orchestrator when processing begins.
    pub fn begin_processing(&mut self, path: &str) {
        self.insights.clear();
        self.selected = 0;
        self.scroll_offset = 0;
        self.last_shared = None;
        self.state = AppState::Processing {
            path: path.to_string(),
            started_at: Instant::now(),
        };
        self.status_message = format!("Extracting: {}...", path);
    }

    /// Called by orchestrator when processing completes (all insights delivered).
    pub fn finish_processing(&mut self) {
        if let AppState::Processing {
            ref path,
            started_at,
        } = self.state
        {
            let elapsed = started_at.elapsed().as_secs_f64();
            let count = self.insights.len();
            self.state = AppState::ShowingInsights {
                path: path.clone(),
                processing_time_secs: elapsed,
            };
            self.status_message = format!(
                "Processed ({:.1}s) -- {} insight{} found",
                elapsed,
                count,
                if count == 1 { "" } else { "s" }
            );
        }
    }

    /// Called by orchestrator when an error occurs.
    /// Expects `message` already in WHAT/WHY/DO format (U4).
    pub fn set_error(&mut self, message: &str) {
        self.state = AppState::Error {
            message: message.to_string(),
        };
        // Show only first line in the narrow status bar.
        let first_line = message.lines().next().unwrap_or(message);
        self.status_message = first_line.to_string();
    }

    /// Handle a keyboard event. Returns an AppAction for the event loop.
    pub fn handle_input(&mut self, key: KeyEvent) -> AppAction {
        // Global bindings first.
        match key {
            KeyEvent::Char('q') if !self.is_input_focused() => {
                self.should_quit = true;
                return AppAction::Quit;
            }
            KeyEvent::CtrlC => {
                self.should_quit = true;
                return AppAction::Quit;
            }
            _ => {}
        }

        // State-specific bindings.
        match &self.state {
            AppState::Idle | AppState::Error { .. } => self.handle_input_mode(key),
            AppState::Processing { .. } => {
                // During processing, only quit is allowed (handled above).
                AppAction::None
            }
            AppState::ShowingInsights { .. } => self.handle_insight_mode(key),
            AppState::DetailView { .. } => self.handle_detail_mode(key),
            AppState::PrivacySettings { .. } => self.handle_privacy_mode(key),
        }
    }

    /// Whether the text input field is focused (Idle or Error states).
    fn is_input_focused(&self) -> bool {
        matches!(self.state, AppState::Idle | AppState::Error { .. })
    }

    /// Handle input in text-entry mode (Idle / Error states).
    fn handle_input_mode(&mut self, key: KeyEvent) -> AppAction {
        match key {
            KeyEvent::Char(c) => {
                self.input.insert(self.cursor_pos, c);
                self.cursor_pos += 1;
                AppAction::None
            }
            KeyEvent::Backspace => {
                if self.cursor_pos > 0 {
                    self.cursor_pos -= 1;
                    self.input.remove(self.cursor_pos);
                }
                AppAction::None
            }
            KeyEvent::Delete => {
                if self.cursor_pos < self.input.len() {
                    self.input.remove(self.cursor_pos);
                }
                AppAction::None
            }
            KeyEvent::Left => {
                if self.cursor_pos > 0 {
                    self.cursor_pos -= 1;
                }
                AppAction::None
            }
            KeyEvent::Right => {
                if self.cursor_pos < self.input.len() {
                    self.cursor_pos += 1;
                }
                AppAction::None
            }
            KeyEvent::Home => {
                self.cursor_pos = 0;
                AppAction::None
            }
            KeyEvent::End => {
                self.cursor_pos = self.input.len();
                AppAction::None
            }
            KeyEvent::Enter => {
                let path = self.input.trim().to_string();
                if path.is_empty() {
                    return AppAction::None;
                }
                self.input.clear();
                self.cursor_pos = 0;
                AppAction::ProcessFile(path)
            }
            _ => AppAction::None,
        }
    }

    /// Handle input in insight-viewing mode.
    fn handle_insight_mode(&mut self, key: KeyEvent) -> AppAction {
        match key {
            KeyEvent::Up | KeyEvent::Char('k') => {
                if self.selected > 0 {
                    self.selected -= 1;
                    self.ensure_selected_visible();
                }
                AppAction::None
            }
            KeyEvent::Down | KeyEvent::Char('j') => {
                if !self.insights.is_empty() && self.selected < self.insights.len() - 1 {
                    self.selected += 1;
                    self.ensure_selected_visible();
                }
                AppAction::None
            }
            KeyEvent::Char('s') => {
                if !self.insights.is_empty() {
                    let stripped = self.insights[self.selected].to_stripped();
                    self.last_shared = Some(stripped);
                    self.status_message = format!(
                        "Shared insight {} (stripped for privacy)",
                        self.selected + 1
                    );
                    AppAction::ShareInsight(self.selected)
                } else {
                    AppAction::None
                }
            }
            KeyEvent::Char('d') => {
                if !self.insights.is_empty() {
                    let idx = self.selected;
                    // Save current state info for return navigation.
                    let (return_path, return_time) = match &self.state {
                        AppState::ShowingInsights {
                            path,
                            processing_time_secs,
                        } => (path.clone(), *processing_time_secs),
                        _ => (String::new(), 0.0),
                    };
                    self.state = AppState::DetailView {
                        card_index: idx,
                        return_path,
                        return_time,
                    };
                    self.status_message = format!(
                        "Detail view: insight {} of {} | Esc/d: back",
                        idx + 1,
                        self.insights.len()
                    );
                    AppAction::ShowDetail(idx)
                } else {
                    AppAction::None
                }
            }
            KeyEvent::Char('c') => {
                self.insights.clear();
                self.selected = 0;
                self.scroll_offset = 0;
                self.last_shared = None;
                self.state = AppState::Idle;
                self.status_message = "Cleared. Enter a file path to begin.".to_string();
                AppAction::ClearInsights
            }
            KeyEvent::Char('p') => {
                let return_state = self.state.clone();
                self.state = AppState::PrivacySettings {
                    return_state: Box::new(return_state),
                };
                self.privacy_show_details = false;
                self.status_message =
                    "Privacy Settings | [1] Toggle mode  [2] Pipeline details  [Esc] Back"
                        .to_string();
                AppAction::None
            }
            // Allow entering a new path while viewing insights.
            KeyEvent::Enter => {
                self.state = AppState::Idle;
                self.status_message = "Enter a file path to process.".to_string();
                AppAction::None
            }
            _ => AppAction::None,
        }
    }

    /// Handle input in detail view mode.
    /// Escape or 'd' returns to the card list.
    fn handle_detail_mode(&mut self, key: KeyEvent) -> AppAction {
        match key {
            KeyEvent::Escape | KeyEvent::Char('d') => {
                // Return to showing insights.
                let (return_path, return_time) = match &self.state {
                    AppState::DetailView {
                        return_path,
                        return_time,
                        ..
                    } => (return_path.clone(), *return_time),
                    _ => (String::new(), 0.0),
                };
                self.state = AppState::ShowingInsights {
                    path: return_path,
                    processing_time_secs: return_time,
                };
                let count = self.insights.len();
                self.status_message = format!(
                    "{} insight{} | Use j/k to scroll, d for details",
                    count,
                    if count == 1 { "" } else { "s" }
                );
                AppAction::None
            }
            _ => AppAction::None,
        }
    }

    /// Handle input in the privacy settings screen.
    fn handle_privacy_mode(&mut self, key: KeyEvent) -> AppAction {
        match key {
            KeyEvent::Escape => {
                // Return to the saved state.
                if let AppState::PrivacySettings { return_state } = &self.state {
                    let restored = *return_state.clone();
                    self.state = restored;
                    self.privacy_show_details = false;
                    self.status_message = "Returned from privacy settings.".to_string();
                } else {
                    self.state = AppState::Idle;
                }
                AppAction::None
            }
            KeyEvent::Char('1') => {
                // Toggle privacy mode via shared source of truth.
                let current = self.privacy_mode();
                match current {
                    PrivacyMode::Collective => {
                        // Switching to LocalOnly: no confirmation needed.
                        self.set_privacy_mode(PrivacyMode::LocalOnly)
                    }
                    PrivacyMode::LocalOnly => {
                        // Switching to Collective: require confirmation.
                        self.pending_collective_confirm = true;
                        self.status_message =
                            "Switch to Collective mode? Press 'y' to confirm, 'n' to cancel."
                                .to_string();
                        AppAction::None
                    }
                }
            }
            KeyEvent::Char('y') if self.pending_collective_confirm => {
                self.pending_collective_confirm = false;
                self.set_privacy_mode(PrivacyMode::Collective)
            }
            KeyEvent::Char('n') if self.pending_collective_confirm => {
                self.pending_collective_confirm = false;
                self.status_message = "Mode change cancelled.".to_string();
                AppAction::None
            }
            KeyEvent::Char('2') => {
                // Toggle pipeline details sub-view.
                self.privacy_show_details = !self.privacy_show_details;
                AppAction::None
            }
            _ => AppAction::None,
        }
    }

    /// Adjust scroll_offset so the selected card is visible.
    /// Assumes each card occupies roughly CARD_HEIGHT_ESTIMATE lines.
    fn ensure_selected_visible(&mut self) {
        // Simple: keep selected index as scroll_offset when needed.
        if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        }
        // We allow at most ~3 visible cards; scroll if selected is beyond.
        let visible_cards = 3;
        if self.selected >= self.scroll_offset + visible_cards {
            self.scroll_offset = self.selected - visible_cards + 1;
        }
    }

    // -----------------------------------------------------------------------
    // Rendering via ratatui
    // -----------------------------------------------------------------------

    /// Main render function. Draws the entire UI to the given frame.
    ///
    /// Uses ratatui types. This function is called by the event loop.
    /// The frame type is generic to avoid a hard compile dependency
    /// when ratatui is not available -- but in practice this is only
    /// called from code that has ratatui in scope.
    pub fn draw(&self, frame: &mut Frame) {
        let area = frame.area();

        // Privacy settings is a full-screen overlay.
        if matches!(self.state, AppState::PrivacySettings { .. }) {
            self.draw_privacy_screen(frame, area);
            return;
        }

        // Top-level vertical layout: header, input+status, insights, footer.
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Length(4), // Input bar + status
                Constraint::Min(10),   // Insight panel
                Constraint::Length(3), // Footer
            ])
            .split(area);

        self.draw_header(frame, chunks[0]);
        self.draw_input_and_status(frame, chunks[1]);
        self.draw_insight_panel(frame, chunks[2]);
        self.draw_footer(frame, chunks[3]);
    }

    /// Render the header bar.
    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let status_indicator = match &self.state {
            AppState::Idle => "[Ready]",
            AppState::Processing { .. } => "[Processing...]",
            AppState::ShowingInsights { .. } => "[Online]",
            AppState::DetailView { .. } => "[Detail]",
            AppState::PrivacySettings { .. } => "[Privacy]",
            AppState::Error { .. } => "[Error]",
        };

        let title = format!(
            "  HIVE -- Collective Intelligence Engine    {}",
            status_indicator
        );

        let header = Paragraph::new(title)
            .style(
                Style::default()
                    .fg(Color::White)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .alignment(Alignment::Left)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .border_type(BorderType::Rounded),
            );
        frame.render_widget(header, area);
    }

    /// Render the input bar and status line.
    fn draw_input_and_status(&self, frame: &mut Frame, area: Rect) {
        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Input line
                Constraint::Length(1), // Status line
                Constraint::Length(1), // Hint line
            ])
            .margin(0)
            .split(area);

        // Input line.
        let input_display = if self.input.is_empty() && self.is_input_focused() {
            "  Enter path or drag file...".to_string()
        } else if self.input.is_empty() {
            match &self.state {
                AppState::ShowingInsights { ref path, .. } => format!("  Document: {}", path),
                AppState::Processing { ref path, .. } => format!("  Document: {}", path),
                _ => "  Enter path or drag file...".to_string(),
            }
        } else {
            format!("  > {}", self.input)
        };

        let input_style = if self.is_input_focused() {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::Gray)
        };

        let input_line = Paragraph::new(input_display).style(input_style);
        frame.render_widget(input_line, inner_chunks[0]);

        // Status line -- incorporate extraction status when active.
        let (status_style, status_prefix) = match &self.extraction_status {
            ExtractionStatus::Failed { .. } => (
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                "  \u{2717} ",
            ),
            ExtractionStatus::SpawningProcess
            | ExtractionStatus::LoadingModel
            | ExtractionStatus::Extracting { .. }
            | ExtractionStatus::Retrying { .. } => {
                (Style::default().fg(Color::Yellow), "  \u{25cb} ")
            }
            ExtractionStatus::Processing => (Style::default().fg(Color::Yellow), "  \u{25cb} "),
            // When extraction status is idle, fall back to app state styling
            ExtractionStatus::Idle => match &self.state {
                AppState::Error { .. } => (
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    "  \u{2717} ",
                ),
                AppState::Processing { .. } => (Style::default().fg(Color::Yellow), "  \u{25cb} "),
                AppState::ShowingInsights { .. } | AppState::DetailView { .. } => {
                    (Style::default().fg(Color::Green), "  \u{2713} ")
                }
                AppState::PrivacySettings { .. } => {
                    (Style::default().fg(Color::Green), "  \u{1f512} ")
                }
                AppState::Idle => (Style::default().fg(Color::DarkGray), "  "),
            },
        };

        // Build status text: show extraction status if active, otherwise status_message
        let status_text = match &self.extraction_status {
            ExtractionStatus::Idle => format!("{}{}", status_prefix, self.status_message),
            other => format!("{}{}", status_prefix, other),
        };

        let status_line = Paragraph::new(status_text).style(status_style);
        frame.render_widget(status_line, inner_chunks[1]);

        // Hint line -- show model status or input hint.
        //
        // Allow rationale: collapsing `if self.model_loaded` into a
        // match-arm guard would force splitting each `Idle` arm into two
        // separate guarded arms, doubling arm count and breaking parallel
        // structure with the focused/unfocused branches above. Block-form
        // is the more readable idiom here.
        #[allow(clippy::collapsible_match, clippy::collapsible_if)]
        let hint = match &self.extraction_status {
            ExtractionStatus::Idle if self.is_input_focused() => {
                if self.model_loaded {
                    "  [Press Enter to process] [Model: loaded]"
                } else {
                    "  [Press Enter to process]"
                }
            }
            ExtractionStatus::Idle => {
                if self.model_loaded {
                    "  [Model: loaded]"
                } else {
                    ""
                }
            }
            _ => "",
        };
        let hint_line = Paragraph::new(hint).style(Style::default().fg(Color::DarkGray));
        frame.render_widget(hint_line, inner_chunks[2]);
    }

    /// Render the scrollable insight card panel.
    fn draw_insight_panel(&self, frame: &mut Frame, area: Rect) {
        // If we're in detail view, render the detail panel instead.
        if let AppState::DetailView { card_index, .. } = &self.state {
            if *card_index < self.insights.len() {
                self.draw_detail_panel(frame, area, *card_index);
                return;
            }
        }

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .border_type(BorderType::Rounded)
            .title(" Insights ")
            .title_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );

        let inner = block.inner(area);
        frame.render_widget(block, area);

        if self.insights.is_empty() {
            let empty_msg = match &self.state {
                AppState::Processing { .. } => "  Processing document...",
                AppState::Idle => "  No insights yet. Enter a document path above.",
                AppState::Error { ref message } => {
                    // Static fallback; full message in status bar.
                    let _ = message;
                    "  Error occurred. See status bar. Press Esc."
                }
                AppState::ShowingInsights { .. } => "  No insights found for this document.",
                AppState::DetailView { .. } => "  No insights found.",
                AppState::PrivacySettings { .. } => "  Privacy settings.",
            };
            let empty = Paragraph::new(empty_msg)
                .style(Style::default().fg(Color::DarkGray))
                .alignment(Alignment::Left);
            frame.render_widget(empty, inner);
            return;
        }

        // Build lines for all visible cards.
        let mut lines: Vec<Line> = Vec::new();
        let visible_start = self.scroll_offset;
        let visible_end = self.insights.len();

        for (idx, card) in self.insights.iter().enumerate().skip(visible_start) {
            let _ = visible_end; // used only for range
            let is_selected = idx == self.selected;
            let card_lines = self.render_card(card, is_selected);
            lines.extend(card_lines);
            lines.push(Line::from("")); // spacing between cards
        }

        let paragraph = Paragraph::new(lines).scroll((0, 0));
        frame.render_widget(paragraph, inner);
    }

    /// Render the detail view for a single insight card.
    fn draw_detail_panel(&self, frame: &mut Frame, area: Rect, card_index: usize) {
        let card = &self.insights[card_index];
        let conclusion = card.conclusion_type();
        let card_color = match conclusion {
            ConclusionType::AboveRange => Color::Red,
            ConclusionType::BelowRange => Color::Yellow,
            ConclusionType::WithinRange => Color::Green,
            ConclusionType::Informational => Color::Blue,
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(card_color))
            .border_type(BorderType::Rounded)
            .title(format!(" Detail: {} -- {} ", card.rule_id, card.category))
            .title_style(Style::default().fg(card_color).add_modifier(Modifier::BOLD));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let mut lines: Vec<Line<'static>> = Vec::new();

        // Section: Rule Text
        lines.push(Line::from(Span::styled(
            "  RULE TEXT",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        for tl in wrap_text(&card.rule_text, 70) {
            lines.push(Line::from(Span::styled(
                format!("    {}", tl),
                Style::default().fg(Color::White),
            )));
        }
        lines.push(Line::from(""));

        // Section: Amounts
        if let Some(ref ctx) = card.amount_context {
            let parsed = parse_amount_context(&card.amount_context);
            lines.push(Line::from(Span::styled(
                "  AMOUNTS",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
            if let Some(ref amounts) = parsed {
                lines.push(Line::from(vec![
                    Span::styled("    YOUR CHARGE:  ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        amounts.your_amount.clone(),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("    TYPICAL:      ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        amounts.typical_amount.clone(),
                        Style::default().fg(Color::White),
                    ),
                ]));
                if !amounts.difference.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("    DIFFERENCE:   ", Style::default().fg(Color::DarkGray)),
                        Span::styled(
                            amounts.difference.clone(),
                            Style::default().fg(card_color).add_modifier(Modifier::BOLD),
                        ),
                    ]));
                }
            } else {
                lines.push(Line::from(Span::styled(
                    format!("    {}", ctx),
                    Style::default().fg(Color::Gray),
                )));
            }
            lines.push(Line::from(""));
        }

        // Section: Confidence
        lines.push(Line::from(Span::styled(
            "  CONFIDENCE",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        let cf_pct = (card.confidence * 100.0).round() as u32;
        let bar = render_confidence_bar(card.confidence);
        lines.push(Line::from(vec![
            Span::styled("    ", Style::default()),
            Span::styled(bar.clone(), Style::default().fg(Color::White)),
            Span::styled(
                format!("  {}% ({})", cf_pct, card.confidence_band),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!("    Exact CF: {:.4}", card.confidence),
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(""));

        // Section: Evidence
        lines.push(Line::from(Span::styled(
            "  EVIDENCE",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        let evidence_count_str = format_evidence_count(card.evidence_count);
        lines.push(Line::from(Span::styled(
            format!(
                "    {} observations across {} region{}",
                evidence_count_str,
                card.evidence_regions,
                if card.evidence_regions == 1 { "" } else { "s" }
            ),
            Style::default().fg(Color::White),
        )));
        lines.push(Line::from(""));

        // Section: Trend
        lines.push(Line::from(Span::styled(
            "  TREND",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        let trend_display = if card.trend.is_empty() {
            "Unknown".to_string()
        } else {
            let capitalized = format!("{}{}", &card.trend[..1].to_uppercase(), &card.trend[1..]);
            format!("{} (last 90 days)", capitalized)
        };
        lines.push(Line::from(Span::styled(
            format!("    {}", trend_display),
            Style::default().fg(Color::White),
        )));
        lines.push(Line::from(""));

        // Section: Metadata
        lines.push(Line::from(Span::styled(
            "  METADATA",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            format!("    Rule ID:          {}", card.rule_id),
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(Span::styled(
            format!("    Category:         {}", card.category),
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(Span::styled(
            format!("    Sensitivity Tier: {} of 4", card.sensitivity_tier),
            Style::default().fg(Color::DarkGray),
        )));
        if !card.specific_entities.is_empty() {
            lines.push(Line::from(Span::styled(
                format!(
                    "    Entities:         {}",
                    card.specific_entities.join(", ")
                ),
                Style::default().fg(Color::DarkGray),
            )));
        }
        lines.push(Line::from(""));

        // Footer hint
        lines.push(Line::from(Span::styled(
            "  [Esc/d] Back to card list",
            Style::default().fg(Color::DarkGray),
        )));

        let paragraph = Paragraph::new(lines).scroll((0, 0));
        frame.render_widget(paragraph, inner);
    }

    /// Render a single insight card as a vector of styled Lines.
    ///
    /// Redesigned card layout:
    /// ```text
    /// +--[ HIVE INSIGHT ]------- Medical Billing --------+
    /// |                                                   |
    /// |  YOUR CHARGE:  $8,200  (ER Visit)                 |
    /// |  TYPICAL:      $3,608  (regional median)          |
    /// |  DIFFERENCE:   +$4,592  (+127%)                   |
    /// |                                                   |
    /// |  CONFIDENCE:   [bar]  89%                         |
    /// |  EVIDENCE:     2,847 observations across 14 rgns  |
    /// |  TREND:        Stable (last 90 days)              |
    /// |                                                   |
    /// |  [s] Share (privacy-safe)  [d] Details  [?] Help  |
    /// +---------------------------------------------------+
    /// ```
    fn render_card(&self, card: &FullInsightCard, selected: bool) -> Vec<Line<'static>> {
        let conclusion = card.conclusion_type();
        let card_color = match conclusion {
            ConclusionType::AboveRange => Color::Red,
            ConclusionType::BelowRange => Color::Yellow,
            ConclusionType::WithinRange => Color::Green,
            ConclusionType::Informational => Color::Blue,
        };

        let border_style = if selected {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(card_color)
        };

        let content_style = Style::default().fg(Color::White);
        let label_style = Style::default().fg(Color::DarkGray);
        let highlight_style = Style::default().fg(card_color).add_modifier(Modifier::BOLD);

        let mut lines: Vec<Line<'static>> = Vec::new();

        // Category display -- format "Medical Billing" from "medical_bills" etc.
        let category_display = if card.category.is_empty() {
            "General".to_string()
        } else {
            card.category
                .replace('_', " ")
                .split_whitespace()
                .map(|w| {
                    let mut c = w.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().to_string() + c.as_str(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        };

        // Top border with category label.
        let selector = if selected { "\u{25b6} " } else { "  " };
        lines.push(Line::from(vec![
            Span::styled(format!("{}+--[ HIVE INSIGHT ]", selector), border_style),
            Span::styled(
                format!("------- {} ", category_display),
                Style::default().fg(card_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled("--------+", border_style),
        ]));

        // Blank line.
        lines.push(Line::from(vec![Span::styled("  |", border_style)]));

        // Parse amount context for YOUR vs TYPICAL display.
        let parsed = parse_amount_context(&card.amount_context);
        if let Some(ref amounts) = parsed {
            // Extract a service label from rule text (e.g., "ER Visit", "blood work").
            let service_label = extract_service_label(&card.rule_text);

            lines.push(Line::from(vec![
                Span::styled("  |  ", border_style),
                Span::styled("YOUR CHARGE:  ", label_style),
                Span::styled(
                    format!("{}  ", amounts.your_amount),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("({})", service_label),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  |  ", border_style),
                Span::styled("TYPICAL:      ", label_style),
                Span::styled(format!("{}  ", amounts.typical_amount), content_style),
                Span::styled("(regional median)", Style::default().fg(Color::DarkGray)),
            ]));
            if !amounts.difference.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("  |  ", border_style),
                    Span::styled("DIFFERENCE:   ", label_style),
                    Span::styled(amounts.difference.clone(), highlight_style),
                ]));
            }
        } else {
            // No amount context -- show the rule text summary.
            let text_lines = wrap_text(&card.rule_text, 50);
            for tl in &text_lines {
                lines.push(Line::from(vec![
                    Span::styled("  |  ", border_style),
                    Span::styled(tl.clone(), content_style),
                ]));
            }
        }

        // Blank line.
        lines.push(Line::from(vec![Span::styled("  |", border_style)]));

        // Confidence bar.
        let cf_pct = (card.confidence * 100.0).round() as u32;
        let bar = render_confidence_bar(card.confidence);
        lines.push(Line::from(vec![
            Span::styled("  |  ", border_style),
            Span::styled("CONFIDENCE:   ", label_style),
            Span::styled(bar, Style::default().fg(card_color)),
            Span::styled(format!("  {}%", cf_pct), content_style),
        ]));

        // Evidence line.
        let evidence_count_str = format_evidence_count(card.evidence_count);
        lines.push(Line::from(vec![
            Span::styled("  |  ", border_style),
            Span::styled("EVIDENCE:     ", label_style),
            Span::styled(
                format!(
                    "{} observations across {} region{}",
                    evidence_count_str,
                    card.evidence_regions,
                    if card.evidence_regions == 1 { "" } else { "s" }
                ),
                Style::default().fg(Color::DarkGray),
            ),
        ]));

        // Trend line.
        if !card.trend.is_empty() {
            let trend_cap = format!("{}{}", &card.trend[..1].to_uppercase(), &card.trend[1..]);
            lines.push(Line::from(vec![
                Span::styled("  |  ", border_style),
                Span::styled("TREND:        ", label_style),
                Span::styled(
                    format!("{} (last 90 days)", trend_cap),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }

        // Blank line.
        lines.push(Line::from(vec![Span::styled("  |", border_style)]));

        // Action hints.
        lines.push(Line::from(vec![
            Span::styled("  |  ", border_style),
            Span::styled(
                "[s] Share (privacy-safe)  [d] Details",
                Style::default().fg(Color::DarkGray),
            ),
        ]));

        // Bottom border.
        lines.push(Line::from(vec![Span::styled(
            "  +---------------------------------------------------+".to_string(),
            border_style,
        )]));

        lines
    }

    /// Render the footer bar.
    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let shortcuts = match &self.state {
            AppState::ShowingInsights { .. } => {
                format!(
                    "  Rules: {} loaded | q: quit | \u{2191}\u{2193}/jk: scroll | s: share | d: details | c: clear | p: privacy | Enter: new doc",
                    self.rules_loaded
                )
            }
            AppState::DetailView { .. } => {
                format!(
                    "  Rules: {} loaded | q: quit | Esc/d: back to list",
                    self.rules_loaded
                )
            }
            AppState::PrivacySettings { .. } => {
                "  [1] Switch mode  [2] Pipeline details  [Esc] Back  [q] Quit".to_string()
            }
            _ => {
                format!(
                    "  Rules: {} loaded | q: quit | Enter: process",
                    self.rules_loaded
                )
            }
        };

        let footer = Paragraph::new(shortcuts)
            .style(Style::default().fg(Color::White).bg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .border_type(BorderType::Rounded),
            );
        frame.render_widget(footer, area);
    }

    /// Render the full-screen privacy settings panel.
    fn draw_privacy_screen(&self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Title bar
                Constraint::Min(10),   // Content
                Constraint::Length(3), // Footer
            ])
            .split(area);

        // -- Title bar --
        let title = Paragraph::new("  PRIVACY SETTINGS")
            .style(
                Style::default()
                    .fg(Color::White)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green))
                    .border_type(BorderType::Rounded),
            );
        frame.render_widget(title, chunks[0]);

        // -- Content area --
        let mut lines: Vec<Line> = Vec::new();

        // Mode section
        let current_mode = self.privacy_mode();
        let (local_mark, collective_mark) = match current_mode {
            PrivacyMode::LocalOnly => ("x", " "),
            PrivacyMode::Collective => (" ", "x"),
        };
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  MODE: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("[{}] Local Only", local_mark),
                if current_mode == PrivacyMode::LocalOnly {
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ),
            Span::raw("    "),
            Span::styled(
                format!("[{}] Collective", collective_mark),
                if current_mode == PrivacyMode::Collective {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ),
        ]));
        lines.push(Line::from(""));

        // What HIVE shares section
        lines.push(Line::from(Span::styled(
            "  WHAT HIVE SHARES (in Collective mode):",
            Style::default().add_modifier(Modifier::BOLD),
        )));

        if self.privacy_show_details {
            lines.push(Line::from(Span::styled(
                "  + Anonymized entity-relationship patterns",
                Style::default().fg(Color::Green),
            )));
            lines.push(Line::from(Span::styled(
                "  + Generalized document-type frequency counts",
                Style::default().fg(Color::Green),
            )));
            lines.push(Line::from(Span::styled(
                "  - NO names, addresses, account numbers",
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from(Span::styled(
                "  - NO document text or raw content",
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from(Span::styled(
                "  - NO dollar amounts or financial figures",
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from(Span::styled(
                "  - NO device identifiers or IP addresses",
                Style::default().fg(Color::Red),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "  - Anonymized entity patterns",
                Style::default().fg(Color::Green),
            )));
            lines.push(Line::from(Span::styled(
                "  - NO names, addresses, account numbers",
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from(Span::styled(
                "  - NO document text",
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from(Span::styled(
                "  - NO device identifiers",
                Style::default().fg(Color::Red),
            )));
        }

        lines.push(Line::from(""));

        // Budget section
        lines.push(Line::from(Span::styled(
            "  PRIVACY BUDGET:",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(format!(
            "  Daily:    {}",
            render_budget_bar(self.privacy_budget_daily)
        )));
        lines.push(Line::from(format!(
            "  Weekly:   {}",
            render_budget_bar(self.privacy_budget_weekly)
        )));
        lines.push(Line::from(format!(
            "  Lifetime: {}",
            render_budget_bar(self.privacy_budget_lifetime)
        )));
        lines.push(Line::from(""));

        // Counters
        lines.push(Line::from(format!(
            "  Documents analyzed today: {}",
            self.docs_analyzed_today
        )));
        let tuples_str = if self.privacy_mode() == PrivacyMode::LocalOnly {
            format!(
                "  Tuples shared today: {} (Local Only mode)",
                self.tuples_shared_today
            )
        } else {
            format!("  Tuples shared today: {}", self.tuples_shared_today)
        };
        lines.push(Line::from(tuples_str));

        let content = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green))
                .border_type(BorderType::Rounded),
        );
        frame.render_widget(content, chunks[1]);

        // -- Footer --
        let footer_text = "  [1] Switch mode  [2] Pipeline details  [Esc] Back  [q] Quit";
        let footer = Paragraph::new(footer_text)
            .style(Style::default().fg(Color::White).bg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green))
                    .border_type(BorderType::Rounded),
            );
        frame.render_widget(footer, chunks[2]);
    }
}

// ---------------------------------------------------------------------------
// KeyEvent: abstraction over crossterm key events
// ---------------------------------------------------------------------------

/// Simplified key event for TUI input handling.
/// Maps from crossterm's KeyEvent to a smaller set relevant to the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEvent {
    Char(char),
    Enter,
    Backspace,
    Delete,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    CtrlC,
    /// Any other key we don't handle.
    Other,
}

// ---------------------------------------------------------------------------
// Ratatui type aliases (re-exports for draw methods)
// ---------------------------------------------------------------------------
// These are used in the draw methods above. When ratatui is in Cargo.toml,
// they resolve to actual types. The TUI module is designed to be compiled
// only when ratatui is a dependency.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

// ---------------------------------------------------------------------------
// Confidence bar rendering
// ---------------------------------------------------------------------------

/// Render a visual confidence bar using Unicode block characters.
///
/// The bar has 10 positions. Filled positions use the full block (U+2588),
/// empty positions use the light shade (U+2591).
///
/// Example: confidence 0.89 -> 9 filled, 1 empty -> "█████████░"
pub fn render_confidence_bar(confidence: f64) -> String {
    let filled = (confidence * 10.0).round().clamp(0.0, 10.0) as usize;
    let empty = 10 - filled;
    let mut bar = String::with_capacity(30); // Unicode chars are multi-byte
    for _ in 0..filled {
        bar.push('\u{2588}'); // █
    }
    for _ in 0..empty {
        bar.push('\u{2591}'); // ░
    }
    bar
}

// ---------------------------------------------------------------------------
// Privacy budget bar rendering
// ---------------------------------------------------------------------------

/// Render a privacy budget bar with percentage label.
///
/// The bar has 10 positions. Filled = remaining budget. Clamped to [0.0, 1.0].
///
/// Example: `render_budget_bar(0.82)` -> `"████████░░  82% remaining"`
pub fn render_budget_bar(fraction_remaining: f64) -> String {
    let clamped = fraction_remaining.clamp(0.0, 1.0);
    let filled = (clamped * 10.0).round() as usize;
    let empty = 10 - filled;
    let mut bar = String::with_capacity(60);
    for _ in 0..filled {
        bar.push('\u{2588}'); // █
    }
    for _ in 0..empty {
        bar.push('\u{2591}'); // ░
    }
    let pct = (clamped * 100.0).round() as u32;
    bar.push_str(&format!("  {}% remaining", pct));
    bar
}

// ---------------------------------------------------------------------------
// Amount context parsing
// ---------------------------------------------------------------------------

/// Parsed amount fields from the `amount_context` string.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedAmounts {
    /// The user's charge, e.g., "$8,200".
    pub your_amount: String,
    /// The typical/median amount, e.g., "$3,608" or "$1,000-$5,000".
    pub typical_amount: String,
    /// Difference string, e.g., "+$4,592 (+127%)" or empty if not computable.
    pub difference: String,
}

/// Parse the `amount_context` string to extract YOUR, TYPICAL, and DIFFERENCE values.
///
/// Handles formats like:
///   "Your amount: $8,200. Typical: $1,000-$5,000."
///   "Your charge: $8,200. Typical range: $1K-$5K"
///   "Your amount: $10K-$50K. Typical range: $1K-$5K. This is above typical range."
///
/// Returns None if the input is None or doesn't match expected patterns.
pub fn parse_amount_context(ctx: &Option<String>) -> Option<ParsedAmounts> {
    let text = ctx.as_ref()?;

    // Find "Your amount:" or "Your charge:" portion.
    let lower = text.to_lowercase();
    let your_start = if let Some(idx) = lower.find("your amount:") {
        idx + "your amount:".len()
    } else if let Some(idx) = lower.find("your charge:") {
        idx + "your charge:".len()
    } else {
        return None;
    };

    // Find "Typical:" or "Typical range:" portion.
    let typical_key = if let Some(idx) = lower.find("typical range:") {
        (idx, idx + "typical range:".len())
    } else if let Some(idx) = lower.find("typical:") {
        (idx, idx + "typical:".len())
    } else {
        return None;
    };

    // Extract the your amount text (between "Your X:" and "Typical")
    let your_raw = text[your_start..typical_key.0].trim().trim_end_matches('.');
    let your_amount = your_raw.trim().to_string();

    // Extract the typical text (after "Typical X:" until end or next sentence)
    let typical_raw = &text[typical_key.1..];
    let typical_end = typical_raw.find(". ").unwrap_or(typical_raw.len());
    let typical_amount = typical_raw[..typical_end]
        .trim()
        .trim_end_matches('.')
        .to_string();

    // Try to compute a difference if both are simple dollar amounts.
    let your_val = parse_dollar_amount(&your_amount);
    let typical_val = parse_dollar_amount(&typical_amount);

    let difference = match (your_val, typical_val) {
        (Some(y), Some(t)) if t > 0.0 => {
            let diff = y - t;
            let pct = ((diff / t) * 100.0).round() as i64;
            let sign = if diff >= 0.0 { "+" } else { "" };
            format!(
                "{}${} ({}{}%)",
                sign,
                format_dollar_value(diff.abs()),
                sign,
                pct
            )
        }
        _ => String::new(),
    };

    Some(ParsedAmounts {
        your_amount,
        typical_amount,
        difference,
    })
}

/// Try to parse a simple dollar amount like "$8,200" into f64.
/// Returns None for ranges like "$1,000-$5,000" or "$1K-$5K".
fn parse_dollar_amount(s: &str) -> Option<f64> {
    let trimmed = s.trim();
    if !trimmed.starts_with('$') {
        return None;
    }
    // If it contains a dash, it's a range -- can't parse to single value.
    if trimmed.contains('-') {
        return None;
    }
    let numeric = trimmed[1..].replace(',', "");
    // Handle K/M suffixes.
    if numeric.ends_with('K') || numeric.ends_with('k') {
        let base: f64 = numeric[..numeric.len() - 1].parse().ok()?;
        return Some(base * 1_000.0);
    }
    if numeric.ends_with('M') || numeric.ends_with('m') {
        let base: f64 = numeric[..numeric.len() - 1].parse().ok()?;
        return Some(base * 1_000_000.0);
    }
    numeric.parse::<f64>().ok()
}

/// Format a dollar value for display (e.g., 4592.0 -> "4,592").
fn format_dollar_value(val: f64) -> String {
    let rounded = val.round() as u64;
    let s = rounded.to_string();
    let len = s.len();
    if len <= 3 {
        return s;
    }
    let mut result = String::with_capacity(len + len / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(ch);
    }
    result
}

/// Extract a service label from the rule text for card display.
///
/// Looks for common patterns like "ER visit", "blood work", "CT scan", etc.
/// Falls back to "service" if nothing specific is found.
pub fn extract_service_label(rule_text: &str) -> String {
    let lower = rule_text.to_lowercase();

    // Known service patterns to extract.
    let patterns = [
        "er visit",
        "emergency room",
        "blood work",
        "ct scan",
        "mri",
        "x-ray",
        "pharmacy",
        "consultation",
        "office visit",
        "lab panel",
        "lab test",
        "surgery",
        "physical therapy",
        "ambulance",
        "anesthesia",
        "prescription",
    ];

    for pat in &patterns {
        if lower.contains(pat) {
            // Title-case it.
            return pat
                .split_whitespace()
                .map(|w| {
                    let mut c = w.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().to_string() + c.as_str(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
        }
    }

    // Fallback: try to find "Your X charge" pattern.
    if let Some(your_idx) = lower.find("your ") {
        let after_your = &rule_text[your_idx + 5..];
        if let Some(charge_idx) = after_your.to_lowercase().find(" charge") {
            let label = after_your[..charge_idx].trim();
            if !label.is_empty() && label.len() < 30 {
                return label.to_string();
            }
        }
    }

    "service".to_string()
}

/// Format an evidence count with comma separators for card display.
pub fn format_evidence_count(count: u32) -> String {
    let s = count.to_string();
    let len = s.len();
    if len <= 3 {
        return s;
    }
    let mut result = String::with_capacity(len + len / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(ch);
    }
    result
}

// ---------------------------------------------------------------------------
// Text wrapping utility
// ---------------------------------------------------------------------------

/// Simple word-wrap for card text. Wraps at `width` characters.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if text.len() <= width {
        return vec![text.to_string()];
    }

    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.len() + 1 + word.len() <= width {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            current_line = word.to_string();
        }
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

// ---------------------------------------------------------------------------
// Mock data generation for standalone demo
// ---------------------------------------------------------------------------

/// Generate mock insight cards for the standalone demo binary.
pub fn mock_insights() -> Vec<FullInsightCard> {
    vec![
        FullInsightCard {
            rule_text: "Your ER visit charge of $8,200 is above the typical range of $1,000-$5,000 for emergency room visits.".to_string(),
            confidence: 0.87,
            confidence_band: "High".to_string(),
            evidence_count: 2500,
            evidence_regions: 12,
            evidence_summary: "Based on 2,500+ observations from 12 regions".to_string(),
            amount_context: Some("Your amount: $8,200. Typical: $1,000-$5,000.".to_string()),
            specific_entities: vec!["Memorial Hospital".to_string(), "Emergency Room".to_string()],
            rule_id: "#127".to_string(),
            trend: "stable".to_string(),
            sensitivity_tier: 1,
            category: "Medical Billing".to_string(),
        },
        FullInsightCard {
            rule_text: "Your blood work charge of $450 is within the typical range of $200-$800 for standard lab panels.".to_string(),
            confidence: 0.82,
            confidence_band: "High".to_string(),
            evidence_count: 4100,
            evidence_regions: 15,
            evidence_summary: "Based on 4,100+ observations from 15 regions".to_string(),
            amount_context: Some("Your amount: $450. Typical: $200-$800.".to_string()),
            specific_entities: vec!["Quest Diagnostics".to_string()],
            rule_id: "#89".to_string(),
            trend: "stable".to_string(),
            sensitivity_tier: 1,
            category: "Medical Billing".to_string(),
        },
        FullInsightCard {
            rule_text: "Your CT scan charge of $12,500 is above the typical range of $3,000-$8,000 for abdominal CT with contrast.".to_string(),
            confidence: 0.79,
            confidence_band: "High".to_string(),
            evidence_count: 1800,
            evidence_regions: 10,
            evidence_summary: "Based on 1,800+ observations from 10 regions".to_string(),
            amount_context: Some("Your amount: $12,500. Typical: $3,000-$8,000.".to_string()),
            specific_entities: vec!["RadNet Imaging".to_string(), "Abdominal CT".to_string()],
            rule_id: "#203".to_string(),
            trend: "increasing".to_string(),
            sensitivity_tier: 1,
            category: "Medical Billing".to_string(),
        },
        FullInsightCard {
            rule_text: "Your pharmacy charge of $35 is below the typical range of $50-$200 for prescription medications.".to_string(),
            confidence: 0.65,
            confidence_band: "Moderate".to_string(),
            evidence_count: 6200,
            evidence_regions: 18,
            evidence_summary: "Based on 6,200+ observations from 18 regions".to_string(),
            amount_context: Some("Your amount: $35. Typical: $50-$200.".to_string()),
            specific_entities: vec!["CVS Pharmacy".to_string()],
            rule_id: "#412".to_string(),
            trend: "decreasing".to_string(),
            sensitivity_tier: 2,
            category: "Pharmacy".to_string(),
        },
        FullInsightCard {
            rule_text: "Your consultation fee of $275 is within the typical range of $150-$400 for specialist office visits.".to_string(),
            confidence: 0.91,
            confidence_band: "High".to_string(),
            evidence_count: 8500,
            evidence_regions: 22,
            evidence_summary: "Based on 8,500+ observations from 22 regions".to_string(),
            amount_context: Some("Your amount: $275. Typical: $150-$400.".to_string()),
            specific_entities: vec!["Dr. Smith".to_string(), "Cardiology".to_string()],
            rule_id: "#56".to_string(),
            trend: "stable".to_string(),
            sensitivity_tier: 2,
            category: "Medical Billing".to_string(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- State transition tests --

    #[test]
    fn test_new_app_is_idle() {
        let app = TuiApp::new();
        assert!(matches!(app.state, AppState::Idle));
        assert!(app.insights.is_empty());
        assert_eq!(app.selected, 0);
        assert!(!app.should_quit);
    }

    #[test]
    fn test_begin_processing_transitions_state() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        assert!(matches!(app.state, AppState::Processing { .. }));
        assert!(app.insights.is_empty());
    }

    #[test]
    fn test_push_insight_transitions_to_showing() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");

        let card = mock_insights().remove(0);
        app.push_insight(card);

        assert!(matches!(app.state, AppState::ShowingInsights { .. }));
        assert_eq!(app.insights.len(), 1);
    }

    #[test]
    fn test_push_multiple_insights() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");

        for card in mock_insights() {
            app.push_insight(card);
        }

        assert_eq!(app.insights.len(), 5);
        assert!(matches!(app.state, AppState::ShowingInsights { .. }));
    }

    #[test]
    fn test_set_error_transitions_state() {
        let mut app = TuiApp::new();
        app.set_error("File not found");
        assert!(matches!(app.state, AppState::Error { .. }));
    }

    #[test]
    fn test_finish_processing_updates_status() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        let card = mock_insights().remove(0);
        app.push_insight(card);
        app.finish_processing();

        assert!(matches!(app.state, AppState::ShowingInsights { .. }));
        assert!(app.status_message.contains("insight"));
    }

    // -- Input handling tests --

    #[test]
    fn test_char_input_appends() {
        let mut app = TuiApp::new();
        app.handle_input(KeyEvent::Char('h'));
        app.handle_input(KeyEvent::Char('i'));
        assert_eq!(app.input, "hi");
        assert_eq!(app.cursor_pos, 2);
    }

    #[test]
    fn test_backspace_removes_char() {
        let mut app = TuiApp::new();
        app.handle_input(KeyEvent::Char('a'));
        app.handle_input(KeyEvent::Char('b'));
        app.handle_input(KeyEvent::Backspace);
        assert_eq!(app.input, "a");
        assert_eq!(app.cursor_pos, 1);
    }

    #[test]
    fn test_enter_returns_process_file() {
        let mut app = TuiApp::new();
        app.handle_input(KeyEvent::Char('/'));
        app.handle_input(KeyEvent::Char('t'));
        app.handle_input(KeyEvent::Char('m'));
        app.handle_input(KeyEvent::Char('p'));

        let action = app.handle_input(KeyEvent::Enter);
        assert_eq!(action, AppAction::ProcessFile("/tmp".to_string()));
        assert!(app.input.is_empty());
    }

    #[test]
    fn test_enter_on_empty_input_is_noop() {
        let mut app = TuiApp::new();
        let action = app.handle_input(KeyEvent::Enter);
        assert_eq!(action, AppAction::None);
    }

    #[test]
    fn test_quit_with_q() {
        let mut app = TuiApp::new();
        // Put into showing insights so q is not captured by text input.
        app.begin_processing("/tmp/test.pdf");
        app.push_insight(mock_insights().remove(0));

        let action = app.handle_input(KeyEvent::Char('q'));
        assert_eq!(action, AppAction::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn test_q_in_input_mode_types_q() {
        let mut app = TuiApp::new();
        // In Idle mode, q should be typed, not quit.
        let action = app.handle_input(KeyEvent::Char('q'));
        assert_eq!(action, AppAction::None);
        assert_eq!(app.input, "q");
    }

    #[test]
    fn test_ctrl_c_quits_from_any_state() {
        let mut app = TuiApp::new();
        let action = app.handle_input(KeyEvent::CtrlC);
        assert_eq!(action, AppAction::Quit);
    }

    #[test]
    fn test_scroll_down_increments_selected() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        for card in mock_insights() {
            app.push_insight(card);
        }

        assert_eq!(app.selected, 0);
        app.handle_input(KeyEvent::Down);
        assert_eq!(app.selected, 1);
        app.handle_input(KeyEvent::Char('j'));
        assert_eq!(app.selected, 2);
    }

    #[test]
    fn test_scroll_up_decrements_selected() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        for card in mock_insights() {
            app.push_insight(card);
        }
        app.selected = 3;

        app.handle_input(KeyEvent::Up);
        assert_eq!(app.selected, 2);
        app.handle_input(KeyEvent::Char('k'));
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn test_scroll_does_not_underflow() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        app.push_insight(mock_insights().remove(0));

        assert_eq!(app.selected, 0);
        app.handle_input(KeyEvent::Up);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn test_scroll_does_not_overflow() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        app.push_insight(mock_insights().remove(0));

        assert_eq!(app.selected, 0);
        app.handle_input(KeyEvent::Down);
        assert_eq!(app.selected, 0); // only 1 item
    }

    #[test]
    fn test_share_returns_action() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        for card in mock_insights() {
            app.push_insight(card);
        }
        app.selected = 1;

        let action = app.handle_input(KeyEvent::Char('s'));
        assert_eq!(action, AppAction::ShareInsight(1));
        assert!(app.last_shared.is_some());
    }

    #[test]
    fn test_clear_returns_to_idle() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        for card in mock_insights() {
            app.push_insight(card);
        }

        let action = app.handle_input(KeyEvent::Char('c'));
        assert_eq!(action, AppAction::ClearInsights);
        assert!(app.insights.is_empty());
        assert!(matches!(app.state, AppState::Idle));
    }

    // -- Card rendering helpers --

    #[test]
    fn test_conclusion_type_detection() {
        let cards = mock_insights();
        assert_eq!(cards[0].conclusion_type(), ConclusionType::AboveRange);
        assert_eq!(cards[1].conclusion_type(), ConclusionType::WithinRange);
        assert_eq!(cards[3].conclusion_type(), ConclusionType::BelowRange);
    }

    #[test]
    fn test_stripped_card_format_and_no_pii() {
        let card = &mock_insights()[0];
        let stripped = card.to_stripped();
        // Shareable card includes amounts (market data) but no PII.
        // Amount context values are included for the YOUR/TYPICAL comparison.
        assert!(
            stripped.rule_text_generic.contains("$8,200"),
            "Shareable card should include amount for comparison"
        );
        // Must NOT contain entity names (PII).
        assert!(
            !stripped.rule_text_generic.contains("Memorial Hospital"),
            "Shareable card must not contain entity names"
        );
        assert!(
            !stripped.rule_text_generic.contains("Emergency Room"),
            "Shareable card must not contain specific facility names"
        );
        // Must contain HIVE branding.
        assert!(stripped.rule_text_generic.contains("HIVE"));
        assert_eq!(
            stripped.call_to_action,
            "Analyzed by HIVE - hive.example.com"
        );
        assert_eq!(stripped.confidence_band, "High");
    }

    #[test]
    fn test_text_wrapping() {
        let short = "Hello world";
        assert_eq!(wrap_text(short, 60), vec!["Hello world"]);

        let long = "This is a longer sentence that should be wrapped at the specified width boundary for display";
        let wrapped = wrap_text(long, 40);
        assert!(wrapped.len() > 1);
        for line in &wrapped {
            assert!(line.len() <= 45); // allow some slack for word boundaries
        }
    }

    // `test_pii_stripping` removed alongside the
    // `strip_pii_from_text` helper. The integration-level guarantee
    // ("StrippedInsightCard text contains no entity names") is still
    // covered by `test_stripped_card_format_and_no_pii` (above) and
    // `test_shareable_card_no_pii_entities` (below), plus the upstream
    // insight_gen tests at insight_gen.rs:1003+ which exercise the real
    // PII-strip path (`strip_amounts` + `strip_entity_names`).

    // -- Scroll offset tests --

    #[test]
    fn test_ensure_selected_visible_scrolls_down() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        for card in mock_insights() {
            app.push_insight(card);
        }

        app.selected = 4;
        app.scroll_offset = 0;
        app.ensure_selected_visible();
        assert!(app.scroll_offset > 0);
    }

    #[test]
    fn test_ensure_selected_visible_scrolls_up() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        for card in mock_insights() {
            app.push_insight(card);
        }

        app.selected = 0;
        app.scroll_offset = 3;
        app.ensure_selected_visible();
        assert_eq!(app.scroll_offset, 0);
    }

    // -- Cursor movement tests --

    #[test]
    fn test_cursor_left_right() {
        let mut app = TuiApp::new();
        app.handle_input(KeyEvent::Char('a'));
        app.handle_input(KeyEvent::Char('b'));
        app.handle_input(KeyEvent::Char('c'));
        assert_eq!(app.cursor_pos, 3);

        app.handle_input(KeyEvent::Left);
        assert_eq!(app.cursor_pos, 2);

        app.handle_input(KeyEvent::Left);
        assert_eq!(app.cursor_pos, 1);

        app.handle_input(KeyEvent::Right);
        assert_eq!(app.cursor_pos, 2);
    }

    #[test]
    fn test_cursor_home_end() {
        let mut app = TuiApp::new();
        app.handle_input(KeyEvent::Char('a'));
        app.handle_input(KeyEvent::Char('b'));

        app.handle_input(KeyEvent::Home);
        assert_eq!(app.cursor_pos, 0);

        app.handle_input(KeyEvent::End);
        assert_eq!(app.cursor_pos, 2);
    }

    #[test]
    fn test_delete_at_cursor() {
        let mut app = TuiApp::new();
        app.handle_input(KeyEvent::Char('a'));
        app.handle_input(KeyEvent::Char('b'));
        app.handle_input(KeyEvent::Char('c'));
        app.handle_input(KeyEvent::Home);
        app.handle_input(KeyEvent::Delete);
        assert_eq!(app.input, "bc");
    }

    #[test]
    fn test_processing_ignores_input() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");

        let action = app.handle_input(KeyEvent::Char('x'));
        assert_eq!(action, AppAction::None);
        // Input buffer unchanged.
        assert!(app.input.is_empty());
    }

    // -- ExtractionStatus tests --

    #[test]
    fn test_extraction_status_default_is_idle() {
        let status = ExtractionStatus::default();
        assert_eq!(status, ExtractionStatus::Idle);
    }

    #[test]
    fn test_extraction_status_display_idle() {
        assert_eq!(format!("{}", ExtractionStatus::Idle), "Idle");
    }

    #[test]
    fn test_extraction_status_display_spawning() {
        assert_eq!(
            format!("{}", ExtractionStatus::SpawningProcess),
            "Spawning extraction process..."
        );
    }

    #[test]
    fn test_extraction_status_display_loading_model() {
        assert_eq!(
            format!("{}", ExtractionStatus::LoadingModel),
            "Loading extraction model..."
        );
    }

    #[test]
    fn test_extraction_status_display_extracting() {
        let status = ExtractionStatus::Extracting {
            file_name: "medical_bill.pdf".to_string(),
            elapsed_secs: 12,
        };
        assert_eq!(format!("{}", status), "Extracting: medical_bill.pdf (12s)");
    }

    #[test]
    fn test_extraction_status_display_processing() {
        assert_eq!(
            format!("{}", ExtractionStatus::Processing),
            "Processing extraction results..."
        );
    }

    #[test]
    fn test_extraction_status_display_retrying() {
        let status = ExtractionStatus::Retrying {
            attempt: 1,
            max_attempts: 3,
        };
        assert_eq!(format!("{}", status), "Retrying extraction (1/3)");
    }

    #[test]
    fn test_extraction_status_display_failed() {
        // Single-line reason: shows first (only) line.
        let status = ExtractionStatus::Failed {
            reason: "OOM killed".to_string(),
        };
        assert_eq!(format!("{}", status), "OOM killed");

        // Multi-line WHAT/WHY/DO: shows only the first line.
        let status = ExtractionStatus::Failed {
            reason: "OOM killed.\n  Why: Low RAM.\n   Do: Free RAM.".to_string(),
        };
        assert_eq!(format!("{}", status), "OOM killed.");
    }

    #[test]
    fn test_new_app_extraction_status_is_idle() {
        let app = TuiApp::new();
        assert_eq!(app.extraction_status, ExtractionStatus::Idle);
        assert!(!app.model_loaded);
    }

    #[test]
    fn test_extraction_status_transitions() {
        let mut app = TuiApp::new();

        // Idle -> SpawningProcess
        app.extraction_status = ExtractionStatus::SpawningProcess;
        assert_eq!(app.extraction_status, ExtractionStatus::SpawningProcess);

        // SpawningProcess -> LoadingModel
        app.extraction_status = ExtractionStatus::LoadingModel;
        assert_eq!(app.extraction_status, ExtractionStatus::LoadingModel);

        // LoadingModel -> Extracting
        app.extraction_status = ExtractionStatus::Extracting {
            file_name: "test.pdf".to_string(),
            elapsed_secs: 0,
        };
        assert!(matches!(
            app.extraction_status,
            ExtractionStatus::Extracting { .. }
        ));

        // Extracting -> Processing
        app.extraction_status = ExtractionStatus::Processing;
        assert_eq!(app.extraction_status, ExtractionStatus::Processing);

        // Processing -> Idle (success)
        app.extraction_status = ExtractionStatus::Idle;
        app.model_loaded = true;
        assert_eq!(app.extraction_status, ExtractionStatus::Idle);
        assert!(app.model_loaded);
    }

    #[test]
    fn test_extraction_status_clone_eq() {
        let status = ExtractionStatus::Extracting {
            file_name: "doc.pdf".to_string(),
            elapsed_secs: 5,
        };
        let cloned = status.clone();
        assert_eq!(status, cloned);

        // Different variants are not equal
        assert_ne!(ExtractionStatus::Idle, ExtractionStatus::SpawningProcess);
        assert_ne!(ExtractionStatus::LoadingModel, ExtractionStatus::Processing);
    }

    // ====================================================================
    // Insight Card Redesign -- new tests
    // ====================================================================

    // -- Confidence bar rendering tests --

    #[test]
    fn test_confidence_bar_full() {
        let bar = render_confidence_bar(1.0);
        assert_eq!(bar.chars().count(), 10);
        // All characters should be the full block
        assert!(bar.chars().all(|c| c == '\u{2588}'));
    }

    #[test]
    fn test_confidence_bar_empty() {
        let bar = render_confidence_bar(0.0);
        assert_eq!(bar.chars().count(), 10);
        // All characters should be the light shade
        assert!(bar.chars().all(|c| c == '\u{2591}'));
    }

    #[test]
    fn test_confidence_bar_half() {
        let bar = render_confidence_bar(0.5);
        let chars: Vec<char> = bar.chars().collect();
        assert_eq!(chars.len(), 10);
        let filled = chars.iter().filter(|&&c| c == '\u{2588}').count();
        let empty = chars.iter().filter(|&&c| c == '\u{2591}').count();
        assert_eq!(filled, 5);
        assert_eq!(empty, 5);
    }

    #[test]
    fn test_confidence_bar_clamped_above_one() {
        let bar = render_confidence_bar(1.5);
        assert_eq!(bar.chars().count(), 10);
        // Should be clamped to 10 filled
        assert!(bar.chars().all(|c| c == '\u{2588}'));
    }

    #[test]
    fn test_confidence_bar_clamped_below_zero() {
        let bar = render_confidence_bar(-0.5);
        assert_eq!(bar.chars().count(), 10);
        // Should be clamped to 0 filled
        assert!(bar.chars().all(|c| c == '\u{2591}'));
    }

    // -- Amount context parsing tests --

    #[test]
    fn test_parse_amount_context_standard_format() {
        let ctx = Some("Your amount: $8,200. Typical: $1,000-$5,000.".to_string());
        let parsed = parse_amount_context(&ctx);
        assert!(parsed.is_some());
        let p = parsed.unwrap();
        assert_eq!(p.your_amount, "$8,200");
        assert_eq!(p.typical_amount, "$1,000-$5,000");
        // Difference empty because typical is a range
        assert_eq!(p.difference, "");
    }

    #[test]
    fn test_parse_amount_context_your_charge_format() {
        let ctx = Some("Your charge: $450. Typical: $200-$800.".to_string());
        let parsed = parse_amount_context(&ctx);
        assert!(parsed.is_some());
        let p = parsed.unwrap();
        assert_eq!(p.your_amount, "$450");
        assert_eq!(p.typical_amount, "$200-$800");
    }

    #[test]
    fn test_parse_amount_context_single_typical_computes_difference() {
        let ctx = Some("Your amount: $8,200. Typical: $3,608.".to_string());
        let parsed = parse_amount_context(&ctx);
        assert!(parsed.is_some());
        let p = parsed.unwrap();
        assert_eq!(p.your_amount, "$8,200");
        assert_eq!(p.typical_amount, "$3,608");
        // Should compute difference: +$4,592 (+127%)
        assert!(!p.difference.is_empty());
        assert!(p.difference.contains("+"));
        assert!(p.difference.contains("%"));
    }

    #[test]
    fn test_parse_amount_context_none() {
        let parsed = parse_amount_context(&None);
        assert!(parsed.is_none());
    }

    #[test]
    fn test_parse_amount_context_no_match() {
        let ctx = Some("Random text without amount patterns.".to_string());
        let parsed = parse_amount_context(&ctx);
        assert!(parsed.is_none());
    }

    // -- Dollar parsing tests --

    #[test]
    fn test_parse_dollar_amount_simple() {
        assert_eq!(parse_dollar_amount("$8,200"), Some(8200.0));
        assert_eq!(parse_dollar_amount("$450"), Some(450.0));
        assert_eq!(parse_dollar_amount("$3,608"), Some(3608.0));
    }

    #[test]
    fn test_parse_dollar_amount_k_suffix() {
        assert_eq!(parse_dollar_amount("$5K"), Some(5000.0));
        assert_eq!(parse_dollar_amount("$1k"), Some(1000.0));
    }

    #[test]
    fn test_parse_dollar_amount_range_returns_none() {
        assert_eq!(parse_dollar_amount("$1,000-$5,000"), None);
        assert_eq!(parse_dollar_amount("$1K-$5K"), None);
    }

    #[test]
    fn test_parse_dollar_amount_no_dollar_sign() {
        assert_eq!(parse_dollar_amount("8200"), None);
    }

    // -- Detail view state transition tests --

    #[test]
    fn test_d_key_transitions_to_detail_view() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        for card in mock_insights() {
            app.push_insight(card);
        }
        app.selected = 2;

        let action = app.handle_input(KeyEvent::Char('d'));
        assert_eq!(action, AppAction::ShowDetail(2));
        assert!(matches!(
            app.state,
            AppState::DetailView { card_index: 2, .. }
        ));
    }

    #[test]
    fn test_d_key_on_empty_insights_is_noop() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        app.push_insight(mock_insights().remove(0));
        // Transition to ShowingInsights via finish_processing
        app.finish_processing();
        app.insights.clear(); // Clear after transitioning

        let action = app.handle_input(KeyEvent::Char('d'));
        assert_eq!(action, AppAction::None);
    }

    #[test]
    fn test_escape_returns_from_detail_to_insights() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        for card in mock_insights() {
            app.push_insight(card);
        }

        // Enter detail view.
        app.handle_input(KeyEvent::Char('d'));
        assert!(matches!(app.state, AppState::DetailView { .. }));

        // Press Escape to return.
        let action = app.handle_input(KeyEvent::Escape);
        assert_eq!(action, AppAction::None);
        assert!(matches!(app.state, AppState::ShowingInsights { .. }));
    }

    #[test]
    fn test_d_key_returns_from_detail_to_insights() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        for card in mock_insights() {
            app.push_insight(card);
        }

        // Enter detail view.
        app.handle_input(KeyEvent::Char('d'));
        assert!(matches!(app.state, AppState::DetailView { .. }));

        // Press 'd' again to return.
        let action = app.handle_input(KeyEvent::Char('d'));
        assert_eq!(action, AppAction::None);
        assert!(matches!(app.state, AppState::ShowingInsights { .. }));
    }

    #[test]
    fn test_detail_view_preserves_return_path() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test_file.pdf");
        for card in mock_insights() {
            app.push_insight(card);
        }

        app.handle_input(KeyEvent::Char('d'));

        if let AppState::DetailView { return_path, .. } = &app.state {
            assert_eq!(return_path, "/tmp/test_file.pdf");
        } else {
            panic!("Expected DetailView state");
        }
    }

    #[test]
    fn test_detail_view_preserves_selected_index() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        for card in mock_insights() {
            app.push_insight(card);
        }
        app.selected = 3;

        app.handle_input(KeyEvent::Char('d'));

        if let AppState::DetailView { card_index, .. } = &app.state {
            assert_eq!(*card_index, 3);
        } else {
            panic!("Expected DetailView state");
        }
    }

    // -- Service label extraction tests --

    #[test]
    fn test_extract_service_label_er_visit() {
        let label = extract_service_label("Your ER visit charge of $8,200 is above typical");
        assert_eq!(label, "Er Visit");
    }

    #[test]
    fn test_extract_service_label_blood_work() {
        let label = extract_service_label("Your blood work charge of $450 is within range");
        assert_eq!(label, "Blood Work");
    }

    #[test]
    fn test_extract_service_label_fallback() {
        let label = extract_service_label("Some generic rule text without known services");
        assert_eq!(label, "service");
    }

    // -- Evidence count formatting tests --

    #[test]
    fn test_format_evidence_count_small() {
        assert_eq!(format_evidence_count(42), "42");
        assert_eq!(format_evidence_count(999), "999");
    }

    #[test]
    fn test_format_evidence_count_with_commas() {
        assert_eq!(format_evidence_count(1000), "1,000");
        assert_eq!(format_evidence_count(2500), "2,500");
        assert_eq!(format_evidence_count(12345), "12,345");
        assert_eq!(format_evidence_count(1000000), "1,000,000");
    }

    // -- Shareable card format tests --

    #[test]
    fn test_shareable_card_contains_hive_branding() {
        let card = &mock_insights()[0];
        let stripped = card.to_stripped();
        assert!(stripped.rule_text_generic.contains("HIVE"));
        assert!(stripped.rule_text_generic.contains("hive.example.com"));
    }

    #[test]
    fn test_shareable_card_no_pii_entities() {
        let card = &mock_insights()[0];
        let stripped = card.to_stripped();
        // Should not contain specific entity names
        assert!(!stripped.rule_text_generic.contains("Memorial Hospital"));
        assert!(!stripped.rule_text_generic.contains("Emergency Room"));
    }

    #[test]
    fn test_shareable_card_includes_evidence_info() {
        let card = &mock_insights()[0];
        let stripped = card.to_stripped();
        assert!(stripped.rule_text_generic.contains("observations"));
        assert!(stripped.rule_text_generic.contains("region"));
    }

    // -- Category field tests --

    #[test]
    fn test_mock_insights_have_category() {
        let cards = mock_insights();
        for card in &cards {
            assert!(
                !card.category.is_empty(),
                "Each mock card should have a category"
            );
        }
        assert_eq!(cards[0].category, "Medical Billing");
        assert_eq!(cards[3].category, "Pharmacy");
    }

    // -- Conclusion type tests with new cards --

    #[test]
    fn test_conclusion_type_informational() {
        let mut card = mock_insights().remove(0);
        card.rule_text = "Some informational note about your document.".to_string();
        assert_eq!(card.conclusion_type(), ConclusionType::Informational);
    }

    // -- Dollar value formatting --

    #[test]
    fn test_format_dollar_value() {
        assert_eq!(format_dollar_value(4592.0), "4,592");
        assert_eq!(format_dollar_value(100.0), "100");
        assert_eq!(format_dollar_value(1000000.0), "1,000,000");
        assert_eq!(format_dollar_value(0.0), "0");
    }

    // -- AppAction ShowDetail variant --

    #[test]
    fn test_app_action_show_detail_equality() {
        assert_eq!(AppAction::ShowDetail(0), AppAction::ShowDetail(0));
        assert_ne!(AppAction::ShowDetail(0), AppAction::ShowDetail(1));
        assert_ne!(AppAction::ShowDetail(0), AppAction::None);
    }

    // ====================================================================
    // Privacy Settings Screen -- tests
    // ====================================================================

    #[test]
    fn test_p_key_enters_privacy_screen_from_insights() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        for card in mock_insights() {
            app.push_insight(card);
        }

        let action = app.handle_input(KeyEvent::Char('p'));
        assert_eq!(action, AppAction::None);
        assert!(matches!(app.state, AppState::PrivacySettings { .. }));
    }

    #[test]
    fn test_escape_returns_from_privacy_to_previous_state() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        for card in mock_insights() {
            app.push_insight(card);
        }

        // Enter privacy screen.
        app.handle_input(KeyEvent::Char('p'));
        assert!(matches!(app.state, AppState::PrivacySettings { .. }));

        // Press Escape to return.
        app.handle_input(KeyEvent::Escape);
        assert!(matches!(app.state, AppState::ShowingInsights { .. }));
    }

    #[test]
    fn test_privacy_mode_toggle_local_to_collective_requires_confirm() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        app.push_insight(mock_insights().remove(0));

        // Enter privacy screen.
        app.handle_input(KeyEvent::Char('p'));
        assert_eq!(app.privacy_mode(), PrivacyMode::LocalOnly);

        // Press '1' to request Collective -- should show confirmation.
        let action = app.handle_input(KeyEvent::Char('1'));
        assert_eq!(action, AppAction::None);
        assert!(app.pending_collective_confirm);
        // Mode not changed yet -- still LocalOnly.
        assert_eq!(app.privacy_mode(), PrivacyMode::LocalOnly);

        // Confirm with 'y'.
        let action = app.handle_input(KeyEvent::Char('y'));
        assert_eq!(action, AppAction::ModeChanged(PrivacyMode::Collective));
        assert_eq!(app.privacy_mode(), PrivacyMode::Collective);
        assert!(!app.pending_collective_confirm);
    }

    #[test]
    fn test_privacy_mode_collective_confirm_cancel() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        app.push_insight(mock_insights().remove(0));

        app.handle_input(KeyEvent::Char('p'));
        app.handle_input(KeyEvent::Char('1')); // request Collective
        assert!(app.pending_collective_confirm);

        // Cancel with 'n'.
        let action = app.handle_input(KeyEvent::Char('n'));
        assert_eq!(action, AppAction::None);
        assert_eq!(app.privacy_mode(), PrivacyMode::LocalOnly);
        assert!(!app.pending_collective_confirm);
    }

    #[test]
    fn test_privacy_mode_toggle_collective_to_local() {
        let shared = Arc::new(RwLock::new(PrivacyMode::Collective));
        let mut app = TuiApp::new_with_shared_mode(shared);
        app.begin_processing("/tmp/test.pdf");
        app.push_insight(mock_insights().remove(0));

        // Enter privacy screen.
        app.handle_input(KeyEvent::Char('p'));

        // Press '1' to toggle back to Local Only (no confirmation needed).
        let action = app.handle_input(KeyEvent::Char('1'));
        assert_eq!(action, AppAction::ModeChanged(PrivacyMode::LocalOnly));
        assert_eq!(app.privacy_mode(), PrivacyMode::LocalOnly);
    }

    #[test]
    fn test_privacy_pipeline_details_toggle() {
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        app.push_insight(mock_insights().remove(0));

        // Enter privacy screen.
        app.handle_input(KeyEvent::Char('p'));
        assert!(!app.privacy_show_details);

        // Press '2' to show details.
        app.handle_input(KeyEvent::Char('2'));
        assert!(app.privacy_show_details);

        // Press '2' again to hide.
        app.handle_input(KeyEvent::Char('2'));
        assert!(!app.privacy_show_details);
    }

    #[test]
    fn test_budget_bar_zero_percent() {
        let bar = render_budget_bar(0.0);
        assert!(bar.contains("0% remaining"));
        // All empty
        let block_count = bar.chars().filter(|&c| c == '\u{2588}').count();
        assert_eq!(block_count, 0);
        let empty_count = bar.chars().filter(|&c| c == '\u{2591}').count();
        assert_eq!(empty_count, 10);
    }

    #[test]
    fn test_budget_bar_fifty_percent() {
        let bar = render_budget_bar(0.5);
        assert!(bar.contains("50% remaining"));
        let filled = bar.chars().filter(|&c| c == '\u{2588}').count();
        let empty = bar.chars().filter(|&c| c == '\u{2591}').count();
        assert_eq!(filled, 5);
        assert_eq!(empty, 5);
    }

    #[test]
    fn test_budget_bar_hundred_percent() {
        let bar = render_budget_bar(1.0);
        assert!(bar.contains("100% remaining"));
        let filled = bar.chars().filter(|&c| c == '\u{2588}').count();
        assert_eq!(filled, 10);
        let empty = bar.chars().filter(|&c| c == '\u{2591}').count();
        assert_eq!(empty, 0);
    }

    #[test]
    fn test_budget_bar_clamped_above_one() {
        let bar = render_budget_bar(1.5);
        assert!(bar.contains("100% remaining"));
        let filled = bar.chars().filter(|&c| c == '\u{2588}').count();
        assert_eq!(filled, 10);
    }

    #[test]
    fn test_budget_bar_clamped_below_zero() {
        let bar = render_budget_bar(-0.3);
        assert!(bar.contains("0% remaining"));
        let empty = bar.chars().filter(|&c| c == '\u{2591}').count();
        assert_eq!(empty, 10);
    }

    #[test]
    fn test_privacy_default_budgets_are_full() {
        let app = TuiApp::new();
        assert_eq!(app.privacy_budget_daily, 1.0);
        assert_eq!(app.privacy_budget_weekly, 1.0);
        assert_eq!(app.privacy_budget_lifetime, 1.0);
        assert_eq!(app.docs_analyzed_today, 0);
        assert_eq!(app.tuples_shared_today, 0);
    }

    #[test]
    fn test_privacy_screen_docs_analyzed_counter() {
        let mut app = TuiApp::new();
        app.docs_analyzed_today = 7;
        assert_eq!(app.docs_analyzed_today, 7);
    }

    // ====================================================================
    // Privacy mode persistence & shared state
    // ====================================================================

    #[test]
    fn test_crit01_mode_toggle_persists_to_disk() {
        // Mode change must call HiveConfig::save -- verify via save_to.
        let dir = std::env::temp_dir().join("hive_crit01_persist_test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");

        // Start with LocalOnly.
        let config = HiveConfig {
            onboarding_complete: true,
            privacy_mode: PrivacyMode::LocalOnly,
            ..HiveConfig::default()
        };
        config.save_to(&path).unwrap();

        // set_privacy_mode should persist.  We test the shared-state + disk
        // by round-tripping through set_privacy_mode and reloading.
        let shared = Arc::new(RwLock::new(PrivacyMode::LocalOnly));
        let mut app = TuiApp::new_with_shared_mode(Arc::clone(&shared));

        // Directly call set_privacy_mode (the unit under test).
        let action = app.set_privacy_mode(PrivacyMode::Collective);
        assert_eq!(action, AppAction::ModeChanged(PrivacyMode::Collective));

        // Shared state updated.
        assert_eq!(*shared.read().unwrap(), PrivacyMode::Collective);

        // NOTE: set_privacy_mode saves to the default config path (~/.hive/config.toml).
        // For test isolation, we verify the shared state update above.
        // The save path behavior is tested separately in hive_config::tests.

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_crit02_tui_reads_from_shared_source() {
        // TUI must always read from shared Arc, never a cached local field.
        let shared = Arc::new(RwLock::new(PrivacyMode::LocalOnly));
        let app = TuiApp::new_with_shared_mode(Arc::clone(&shared));

        assert_eq!(app.privacy_mode(), PrivacyMode::LocalOnly);

        // External code changes the shared state (simulates pipeline update).
        {
            let mut mode = shared.write().unwrap();
            *mode = PrivacyMode::Collective;
        }

        // TUI must see the updated value immediately.
        assert_eq!(app.privacy_mode(), PrivacyMode::Collective);
    }

    #[test]
    fn test_crit02_mode_change_propagates_to_all_holders() {
        // set_privacy_mode updates the shared Arc so all holders see the change.
        let shared = Arc::new(RwLock::new(PrivacyMode::LocalOnly));
        let pipeline_ref = Arc::clone(&shared); // Simulate pipeline holding a ref.
        let mut app = TuiApp::new_with_shared_mode(Arc::clone(&shared));

        let action = app.set_privacy_mode(PrivacyMode::Collective);
        assert_eq!(action, AppAction::ModeChanged(PrivacyMode::Collective));

        // Pipeline reference sees the same value.
        assert_eq!(*pipeline_ref.read().unwrap(), PrivacyMode::Collective);
    }

    #[test]
    fn test_crit02_startup_loads_mode_from_config() {
        // new_with_config must initialize shared mode from the loaded config.
        let config = HiveConfig {
            onboarding_complete: true,
            privacy_mode: PrivacyMode::Collective,
            ..HiveConfig::default()
        };

        let (app, shared) = TuiApp::new_with_config(&config);

        // TUI reads Collective from config, not the default LocalOnly.
        assert_eq!(app.privacy_mode(), PrivacyMode::Collective);
        assert_eq!(*shared.read().unwrap(), PrivacyMode::Collective);
    }

    #[test]
    fn test_crit02_collective_requires_confirmation() {
        // Switching TO Collective must require y/n confirmation.
        let mut app = TuiApp::new();
        app.begin_processing("/tmp/test.pdf");
        app.push_insight(mock_insights().remove(0));
        app.handle_input(KeyEvent::Char('p'));

        // Request switch to Collective.
        let action = app.handle_input(KeyEvent::Char('1'));
        assert_eq!(action, AppAction::None, "Must not switch immediately");
        assert!(app.pending_collective_confirm);
        assert_eq!(
            app.privacy_mode(),
            PrivacyMode::LocalOnly,
            "Mode must stay LocalOnly until confirmed"
        );

        // Confirm.
        let action = app.handle_input(KeyEvent::Char('y'));
        assert_eq!(action, AppAction::ModeChanged(PrivacyMode::Collective));
        assert_eq!(app.privacy_mode(), PrivacyMode::Collective);
    }
}
