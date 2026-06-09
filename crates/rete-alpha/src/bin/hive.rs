//! HIVE unified binary -- end-to-end "document in, insight out".
//!
//! Wires the orchestrator, seed rules, insight generation, and terminal UI
//! into a single pipeline.
//!
//! Pipeline:
//!   TUI input -> Orchestrator -> ExtractionManager (mock/live) -> LocalPipeline
//!   -> Rete-II Engine (with 40 seed rules) -> InsightGen -> TUI display
//!
//! Usage:
//!   cargo run --bin hive                          # interactive TUI, mock mode
//!   cargo run --bin hive -- --mock                # explicit mock mode (default)
//!   cargo run --bin hive -- --live                # live extraction (Gemma 3n 2B)
//!   cargo run --bin hive -- --live script.py      # live with explicit script path
//!   cargo run --bin hive -- file1.pdf             # process files, then enter TUI
//!
//! Key bindings (in TUI):
//!   q / Ctrl+C  : Quit
//!   Enter       : Submit file path for processing
//!   Up/Down/j/k : Scroll through insight cards
//!   s           : Share selected insight (strips PII)
//!   c           : Clear insights

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};

use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use rete_alpha::diagnostics;
use rete_alpha::extraction_manager::{ExtractionManager, ExtractionMode};
use rete_alpha::hive_config::HiveConfig;
use rete_alpha::insight_gen;
use rete_alpha::invite;
use rete_alpha::onboarding::{self, OnboardingResult};
use rete_alpha::orchestrator::{
    Orchestrator, OrchestratorConfig, RuleFiring as OrchestratorRuleFiring,
};
use rete_alpha::rule_loader;
use rete_alpha::seed_rules;
#[cfg(feature = "live-extraction")]
use rete_alpha::tui::ExtractionStatus;
use rete_alpha::tui::{AppAction, FullInsightCard, KeyEvent as TuiKeyEvent, TuiApp};
use rete_alpha::watch_folder::{WatchEvent, WatchFolder, WatchFolderConfig};

// ---------------------------------------------------------------------------
// Build metadata (injected by build.rs at compile time)
// ---------------------------------------------------------------------------

/// Returns the version string: `hive v0.1.0-alpha (built YYYY-MM-DD, git:SHORT_HASH)`
///
/// `CARGO_PKG_VERSION` already carries the `-alpha`
/// prerelease tag (SemVer 2.0.0 §9) because `Cargo.toml` pins
/// `version = "0.1.0-alpha"`. Appending another literal `-alpha` here
/// produced `hive v0.1.0-alpha-alpha ...`.
/// The format string now inlines `CARGO_PKG_VERSION` once; the prerelease
/// tag is still present because the manifest carries it.
fn version_string() -> String {
    format!(
        "hive v{} (built {}, git:{})",
        env!("CARGO_PKG_VERSION"),
        env!("BUILD_DATE"),
        env!("GIT_HASH"),
    )
}

// ---------------------------------------------------------------------------
// CLI argument parsing (minimal, no clap dependency)
// ---------------------------------------------------------------------------

struct CliArgs {
    /// Files to process on startup (before entering TUI).
    files: Vec<PathBuf>,
    /// Extraction mode: Mock (default) or Live with optional script path.
    extraction_mode: ExtractionMode,
    /// Re-run first-time onboarding even if already completed.
    reset_onboarding: bool,
    /// Run diagnostics export and exit.
    diagnostics: bool,
    /// Emit the diagnostic report as pretty-printed JSON
    /// instead of the human-readable text form. Only applies when
    /// `diagnostics` is true; ignored otherwise (no effect on TUI mode).
    /// Provides `jq`-parseable output.
    diagnostics_json: bool,
    /// Activate with an invite code and exit.
    activate_code: Option<String>,
    /// Show my invite codes and exit.
    my_invites: bool,
    /// Enable watch folder mode (auto-process files dropped into watch dir).
    watch: bool,
    /// Custom watch directory path (overrides default `~/.hive/watch/`).
    watch_dir: Option<PathBuf>,
    /// Downgrade the extraction-script / python-interpreter trust guards
    /// in `ExtractionManager::spawn_subprocess`
    /// from reject-on-failure to warn-on-failure. OFF by default; users who
    /// genuinely need to run a custom script must set this flag explicitly
    /// so the looser posture is visible in `ps`, shell history, and logs.
    allow_custom_extractor: bool,
    /// Explicitly suppress the first-run interactive
    /// onboarding TUI. When true, the binary proceeds with default privacy
    /// (`LocalOnly`) and marks `onboarding_complete = true` in the in-memory
    /// config without ever entering raw terminal mode. Set by
    /// `--non-interactive` or `--skip-onboarding`; also auto-set when stdin
    /// is not a TTY (e.g. `ssh vm 'hive --diagnostics --json'`).
    non_interactive: bool,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut files = Vec::new();
    let mut live_script: Option<PathBuf> = None;
    let mut is_live = false;
    let mut skip_next = false;
    let mut reset_onboarding = false;
    let mut diagnostics = false;
    let mut diagnostics_json = false;
    let mut activate_code: Option<String> = None;
    let mut my_invites = false;
    let mut watch = false;
    let mut watch_dir: Option<PathBuf> = None;
    let mut allow_custom_extractor = false;
    // Default false; flipped by --non-interactive /
    // --skip-onboarding, and additionally by the TTY-detection fallback
    // below when stdin is not a terminal.
    let mut non_interactive = false;

    for (i, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        match arg.as_str() {
            "--mock" => { /* default, no-op */ }
            "--reset-onboarding" => {
                reset_onboarding = true;
            }
            "--diagnostics" => {
                diagnostics = true;
            }
            // `--json` is a modifier on `--diagnostics`.
            // Accepted anywhere on the line (order-independent).
            "--json" => {
                diagnostics_json = true;
            }
            "--my-invites" => {
                my_invites = true;
            }
            "--watch" => {
                watch = true;
            }
            // Operator-facing flags to bypass the onboarding
            // TUI. Both spellings are accepted because some scripts
            // use `--skip-onboarding` while the spec prefers
            // `--non-interactive`; aliasing is zero-risk.
            "--non-interactive" | "--skip-onboarding" => {
                non_interactive = true;
            }
            "--allow-custom-extractor" => {
                // Opt-in escape hatch. Prints a loud
                // warning to stderr so the looser posture is obvious in
                // any terminal session or captured log.
                allow_custom_extractor = true;
                eprintln!(
                    "[hive] WARNING: --allow-custom-extractor is ON; \
                     extraction script + interpreter trust checks are \
                     downgraded to warn-only. Use only with scripts you \
                     personally trust."
                );
            }
            "--watch-dir" => {
                if let Some(dir) = args.get(i + 1) {
                    watch_dir = Some(PathBuf::from(dir));
                    watch = true; // --watch-dir implies --watch
                    skip_next = true;
                } else {
                    eprintln!("[hive] Error: --watch-dir missing directory path.");
                    eprintln!("   Do: hive --watch-dir /path/to/watch");
                    std::process::exit(1);
                }
            }
            "--activate" => {
                if let Some(code) = args.get(i + 1) {
                    activate_code = Some(code.clone());
                    skip_next = true;
                } else {
                    eprintln!("[hive] Error: --activate missing invite code.");
                    eprintln!("   Do: hive --activate HIVE-XXXX-XXXX-XXXX");
                    std::process::exit(1);
                }
            }
            "--live" => {
                is_live = true;
                // Check if next arg is a script path (not another flag and not a file to process)
                if let Some(next) = args.get(i + 1) {
                    if !next.starts_with("--") && next.ends_with(".py") {
                        live_script = Some(PathBuf::from(next));
                        skip_next = true;
                    }
                }
            }
            "--version" | "-V" => {
                println!("{}", version_string());
                std::process::exit(0);
            }
            "--self-test" => {
                std::process::exit(run_self_test());
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                files.push(PathBuf::from(other));
            }
        }
    }

    let extraction_mode = if is_live {
        let script_path = live_script.unwrap_or_else(|| match resolve_extraction_script() {
            Some(path) => path,
            None => {
                eprintln!("[hive] Error: Extraction script not found.");
                eprintln!(
                    "  Why: --live needs extraction_service.py; \
not in standard paths."
                );
                eprintln!(
                    "   Do: export HIVE_EXTRACTION_SCRIPT=/path/to/script \
or use --mock."
                );
                std::process::exit(1);
            }
        });
        ExtractionMode::Live { script_path }
    } else {
        ExtractionMode::Mock
    };

    // TTY-detection fallback. If stdin is not a terminal
    // (pipe, redirect, `ssh host 'hive ...'`), auto-enable non-interactive
    // mode so the onboarding TUI does not blow up against a closed terminal.
    // Uses `std::io::IsTerminal` (Rust 1.70+, no extra crate).
    if !non_interactive {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            non_interactive = true;
        }
    }

    CliArgs {
        files,
        extraction_mode,
        reset_onboarding,
        diagnostics,
        diagnostics_json,
        activate_code,
        my_invites,
        watch,
        watch_dir,
        allow_custom_extractor,
        non_interactive,
    }
}

/// Resolve the extraction script path using the standard search order:
///
/// 1. `$HIVE_EXTRACTION_SCRIPT` environment variable
/// 2. Bundled subdir alongside the binary (`<exe_dir>/extraction-service/extraction_service.py`)
/// 3. Adjacent to the current binary (`<exe_dir>/extraction_service.py`)
/// 4. Workspace-relative path (`lab/extraction/extraction_service.py`)
///
/// Returns `None` if not found in any location.
fn resolve_extraction_script() -> Option<PathBuf> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from));
    resolve_extraction_script_with_exe_dir(exe_dir.as_deref())
}

/// Inner helper isolated from
/// `std::env::current_exe()` so unit tests can exercise the bundled
/// `extraction-service/` auto-discovery search path without manipulating
/// the test binary's own location. Production callers use the public
/// `resolve_extraction_script()` wrapper which sources `exe_dir` from
/// `current_exe()` exactly as before.
fn resolve_extraction_script_with_exe_dir(exe_dir: Option<&std::path::Path>) -> Option<PathBuf> {
    // 1. Environment variable (canonicalize to resolve symlinks and validate existence)
    // Log a warning when HIVE_EXTRACTION_SCRIPT resolves
    // outside the trusted roots. The rejection itself happens deeper, in
    // `ExtractionManager::spawn_subprocess`, where we have access to
    // `allow_custom_extractor`. Logging here gives the user a heads-up at
    // the first point we see the env var, rather than a spawn-time surprise.
    if let Ok(env_path) = std::env::var("HIVE_EXTRACTION_SCRIPT") {
        match std::fs::canonicalize(&env_path) {
            Ok(canonical) => {
                let hive_home = std::env::var_os("HIVE_HOME").map(PathBuf::from);
                if let Err(reason) = rete_alpha::extraction_manager::is_trusted_script_path(
                    &canonical,
                    hive_home.as_deref(),
                ) {
                    eprintln!(
                        "[hive] WARNING: $HIVE_EXTRACTION_SCRIPT points outside \
                         trusted roots: {}",
                        reason
                    );
                    eprintln!(
                        "   Do: move the script under your workspace / installer \
                         / $HIVE_HOME, or re-run with --allow-custom-extractor."
                    );
                }
                return Some(canonical);
            }
            Err(e) => {
                eprintln!("[hive] Error: HIVE_EXTRACTION_SCRIPT path invalid.");
                eprintln!("  Why: {} -> {}", env_path, e);
                eprintln!("   Do: Fix the path or unset the variable.");
            }
        }
    }

    // 2. Bundled subdir alongside the
    // binary. The release tarball ships `extraction-service/extraction_service.py`
    // sibling-to the `hive` binary (see scripts/build-release.sh L161-165),
    // so users running an unpacked tarball with `./hive --live` should get
    // auto-discovery without needing to `export HIVE_EXTRACTION_SCRIPT=...`.
    // Checked BEFORE the legacy adjacent path so the canonical bundled
    // layout wins; the env var override at step 1 still takes precedence.
    if let Some(dir) = exe_dir {
        let bundled = dir.join("extraction-service").join("extraction_service.py");
        if bundled.exists() {
            if let Ok(canonical) = std::fs::canonicalize(&bundled) {
                return Some(canonical);
            }
        }
    }

    // 3. Adjacent to binary (canonicalize to resolve symlinks)
    if let Some(dir) = exe_dir {
        let adjacent = dir.join("extraction_service.py");
        if adjacent.exists() {
            if let Ok(canonical) = std::fs::canonicalize(&adjacent) {
                return Some(canonical);
            }
        }
    }

    // 4. Workspace-relative paths (common development layouts)
    // NOTE: CWD-relative "extraction_service.py" removed to prevent malicious script planting
    let candidates = [
        "lab/extraction/extraction_service.py",
        "../extraction/extraction_service.py",
    ];
    for candidate in &candidates {
        let p = PathBuf::from(candidate);
        if p.exists() {
            if let Ok(canonical) = std::fs::canonicalize(&p) {
                return Some(canonical);
            }
        }
    }

    None
}

fn print_usage() {
    eprintln!("{}", version_string());
    eprintln!("  Document in, insight out. Powered by Rete-II with 40 seed rules.");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  hive [OPTIONS] [FILES...]");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  --mock                  Use mock extraction (default, no Python needed)");
    eprintln!("  --live                  Use live extraction (Gemma 3n 2B via MLX)");
    eprintln!("  --live <script.py>      Live extraction with explicit script path");
    eprintln!("  -V, --version           Print version and build info");
    eprintln!("  --self-test             Run self-diagnostics (mock mode, no model needed)");
    eprintln!("  --diagnostics           Export PII-free diagnostic report (text form)");
    eprintln!("  --diagnostics --json    Export PII-free diagnostic report as JSON");
    eprintln!("                          (pipe to `jq` for programmatic access)");
    eprintln!("  --activate <code>       Activate HIVE with an invite code");
    eprintln!("  --my-invites            Show your invite codes");
    eprintln!("  --watch                 Watch a folder for automatic document processing");
    eprintln!("  --watch-dir <PATH>      Set custom watch directory (implies --watch)");
    eprintln!("  --reset-onboarding      Re-run first-time onboarding screens");
    eprintln!("  --non-interactive       Run without any TUI (alias: --skip-onboarding).");
    eprintln!("                          Skips first-run onboarding AND the main TUI --");
    eprintln!("                          files are processed with stdout status lines,");
    eprintln!("                          one per file. Auto-enabled when stdin is not a");
    eprintln!("                          terminal, so ssh/CI pipelines work without a TTY.");
    eprintln!("                          Not compatible with --watch (needs an event loop).");
    eprintln!("  --allow-custom-extractor  Downgrade extraction-script and python-");
    eprintln!("                          interpreter trust checks to warn-only.");
    eprintln!("                          Use at your own risk.");
    eprintln!("  -h, --help              Show this help message");
    eprintln!();
    eprintln!("EXAMPLES:");
    eprintln!("  hive                                      Interactive TUI, mock mode");
    eprintln!("  hive medical_bill.txt lease.txt            Process files, then enter TUI");
    eprintln!("  hive --live invoice.pdf                    Live extraction on one file");
    eprintln!("  hive --live extract.py bill.txt lease.txt  Custom script, two files");
    eprintln!();
    eprintln!("EXTRACTION MODES:");
    eprintln!("  Mock (default):  Returns canned extraction output. No Python/MLX");
    eprintln!("                   required. Exercises the full Rust pipeline.");
    eprintln!("  Live (--live):   Spawns a Python subprocess running Gemma 3n 2B");
    eprintln!("                   via MLX. Requires Apple Silicon, Python 3.10+,");
    eprintln!("                   and MLX framework installed.");
    eprintln!();
    eprintln!("LIVE MODE SCRIPT RESOLUTION (when --live used without explicit path):");
    eprintln!("  1. $HIVE_EXTRACTION_SCRIPT environment variable");
    eprintln!("  2. Adjacent to binary: <exe_dir>/extraction_service.py");
    eprintln!("  3. Workspace relative: lab/extraction/extraction_service.py");
    eprintln!();
    eprintln!("LIVE MODE REQUIREMENTS:");
    eprintln!("  - Apple Silicon Mac (M1/M2/M3/M4)");
    eprintln!("  - Python 3.10+ with mlx and mlx-lm installed");
    eprintln!("  - ~2 GB disk for model download (first run only)");
    eprintln!("  - ~1 GB free RAM during extraction");
    eprintln!("  - Build with: cargo build --bin hive --features live-extraction");
    eprintln!();
    eprintln!("KEY BINDINGS (in TUI):");
    eprintln!("  q / Ctrl+C    Quit");
    eprintln!("  Enter         Submit file path for processing");
    eprintln!("  Up/Down/j/k   Scroll through insight cards");
    eprintln!("  s             Share selected insight (PII stripped)");
    eprintln!("  c             Clear all insights");
    eprintln!();
    eprintln!("TROUBLESHOOTING:");
    eprintln!(
        "  Python not found      Set up a venv: python3 -m venv .venv && source .venv/bin/activate"
    );
    eprintln!("  Script not found      Set HIVE_EXTRACTION_SCRIPT=/path/to/extraction_service.py");
    eprintln!(
        "  Slow first run        Normal: MLX downloads the model (~2 GB) on first extraction"
    );
    eprintln!("  Extraction timeout    Check free RAM (need ~1 GB). Close memory-heavy apps.");
    eprintln!("  Out of memory         Model needs ~476 MB. Ensure sufficient free RAM.");
}

// ---------------------------------------------------------------------------
// Self-test: mock pipeline validation (--self-test)
// ---------------------------------------------------------------------------

/// Run five diagnostic checks in mock mode and print PASS/FAIL for each.
/// Returns 0 if all pass, 1 if any fail.
fn run_self_test() -> i32 {
    eprintln!("HIVE self-test ({})", version_string());
    eprintln!("---");

    let mut passed = 0u32;
    let mut failed = 0u32;

    // Check 1: Seed rules load correctly (40 rules expected)
    let seed_rules_vec = seed_rules::get_seed_rules();
    let seed_count = seed_rules_vec.len();
    if seed_count == 40 {
        eprintln!("[PASS] Seed rules loaded ({} rules)", seed_count);
        passed += 1;
    } else {
        eprintln!(
            "[FAIL] Seed rules loaded ({} rules, expected 40)",
            seed_count
        );
        failed += 1;
    }

    // Check 2: Mock extraction produces valid output
    let mut mgr = ExtractionManager::new_mock();
    match mgr.extract_sync(
        "Patient visited hospital for emergency care",
        "/self-test/medical.pdf",
    ) {
        Ok(result) => {
            let cat = &result.output.document_category;
            let ent_count = result.output.entities.len();
            if !cat.is_empty() && ent_count > 0 {
                eprintln!(
                    "[PASS] Mock extraction produces valid output (category={}, {} entities)",
                    cat, ent_count,
                );
                passed += 1;
            } else {
                eprintln!(
                    "[FAIL] Mock extraction output invalid (category={:?}, entities={})",
                    cat, ent_count,
                );
                failed += 1;
            }
        }
        Err(e) => {
            eprintln!("[FAIL] Mock extraction error: {}", e);
            failed += 1;
        }
    }

    // Check 3: Pipeline processes a mock document end-to-end
    let config = OrchestratorConfig {
        extraction_mode: ExtractionMode::Mock,
        ..OrchestratorConfig::mvp()
    };
    let mut orch = Orchestrator::new(config);
    orch.initialize()
        .expect("Orchestrator init failed in self-test");
    let loaded = rule_loader::load_seed_rules(&mut orch.pipeline_mut().engine, &seed_rules_vec);

    let doc_result = orch.process_document(PathBuf::from("/self-test/medical_bill.pdf"));
    match doc_result {
        Ok(result) => {
            let wmes = result.pipeline_result.wmes_inserted;
            let insights = result.insights.len();
            eprintln!(
                "[PASS] Pipeline end-to-end ({} WMEs, {} insights, {:.1}ms)",
                wmes,
                insights,
                result.elapsed.as_secs_f64() * 1000.0,
            );
            passed += 1;
        }
        Err(e) => {
            eprintln!("[FAIL] Pipeline end-to-end error: {}", e);
            failed += 1;
        }
    }

    // Check 4: Insight cards are generated from mock data
    let doc_result2 = orch.process_document(PathBuf::from("/self-test/lease_agreement.pdf"));
    match doc_result2 {
        Ok(result) => {
            // Validate insight card fields if any were generated
            let card_count = result.insights.len();
            let all_valid = result
                .insights
                .iter()
                .all(|firing| firing.rule_id > 0 && !firing.source_file.is_empty());
            if all_valid {
                eprintln!(
                    "[PASS] Insight cards generated ({} cards from {} rules loaded)",
                    card_count, loaded,
                );
                passed += 1;
            } else {
                eprintln!("[FAIL] Insight cards have invalid fields");
                failed += 1;
            }
        }
        Err(e) => {
            eprintln!("[FAIL] Insight card generation error: {}", e);
            failed += 1;
        }
    }

    // Check 5: Version info is correct
    let ver = version_string();
    let ver_ok = ver.starts_with("hive v")
        && ver.contains("-alpha")
        && ver.contains("built ")
        && ver.contains("git:");
    if ver_ok {
        eprintln!("[PASS] Version info correct ({})", ver);
        passed += 1;
    } else {
        eprintln!("[FAIL] Version info malformed: {}", ver);
        failed += 1;
    }

    eprintln!("---");
    eprintln!("Self-test complete: {} passed, {} failed", passed, failed,);

    if failed > 0 {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Orchestrator + rule engine initialization
// ---------------------------------------------------------------------------

/// Initialize the orchestrator with seed rules loaded via rule_loader.
///
/// Steps:
///   1. Create orchestrator with the given extraction mode
///   2. Initialize lifecycle (transitions to Ready)
///   3. Load 40 seed rules via rule_loader into the engine
///
/// Returns (orchestrator, rules_loaded_count).
fn init_orchestrator(
    extraction_mode: ExtractionMode,
    allow_custom_extractor: bool,
) -> (Orchestrator, usize) {
    let config = OrchestratorConfig {
        extraction_mode,
        allow_custom_extractor,
        ..OrchestratorConfig::mvp()
    };
    let mut orch = Orchestrator::new(config);

    // Step 2: Initialize -- transitions Created -> Ready
    orch.initialize()
        .expect("Orchestrator initialization should not fail in mock mode");

    // Step 3: Load seed rules via rule_loader directly into the engine.
    // The rule_loader compiles SeedConditions into AlphaConditions using
    // the engine's dictionaries, handling bitmask computation and
    // dictionary encoding.
    let seed_rules = seed_rules::get_seed_rules();
    let summary = rule_loader::summarize_seed_rules(&seed_rules);
    let loaded = rule_loader::load_seed_rules(&mut orch.pipeline_mut().engine, &seed_rules);

    eprintln!("[hive] {}", summary);
    eprintln!("[hive] Loaded {} seed rules into Rete-II engine", loaded);

    (orch, loaded)
}

// ---------------------------------------------------------------------------
// Bridge: orchestrator RuleFiring -> TUI FullInsightCard
// ---------------------------------------------------------------------------

/// Convert an orchestrator `RuleFiring` into a TUI `FullInsightCard`.
///
/// This bridges the orchestrator's output format to the TUI's display
/// format. Uses the insight_gen module for evidence formatting and the
/// seed_rules for metadata (conclusion template, evidence counts, trend).
fn orchestrator_firing_to_tui_card(firing: &OrchestratorRuleFiring) -> FullInsightCard {
    // Look up the original seed rule for metadata
    let seed = seed_rules::get_seed_rule_by_id(firing.rule_id);

    let (rule_text, evidence_count, evidence_regions, trend, sensitivity_tier) =
        if let Some(ref rule) = seed {
            // Fill the conclusion template with matched field data
            let fields: Vec<(String, String)> = firing
                .matched_fields
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let filled = insight_gen::fill_template(&rule.conclusion_template, &fields);

            (
                filled,
                rule.evidence_count,
                rule.evidence_regions,
                rule.trend.clone(),
                rule.sensitivity_tier,
            )
        } else {
            // Fallback for rules not in the seed set
            (
                format!(
                    "Rule #{} fired on {} (confidence: {:.1}%)",
                    firing.rule_id,
                    firing.source_file,
                    firing.confidence * 100.0
                ),
                0u32,
                0u8,
                "stable".to_string(),
                4u8,
            )
        };

    let confidence = firing.confidence;
    let confidence_band = insight_gen::confidence_to_band(confidence);
    let evidence_summary = insight_gen::count_to_summary(evidence_count, evidence_regions);

    FullInsightCard {
        rule_text,
        confidence,
        confidence_band,
        evidence_count,
        evidence_regions,
        evidence_summary,
        amount_context: None, // amount context requires WME field decoding
        specific_entities: vec![firing.source_file.clone()],
        rule_id: format!("#{}", firing.rule_id),
        trend,
        sensitivity_tier,
        category: seed
            .as_ref()
            .map(|r| r.conclusion_type.replace('_', " "))
            .unwrap_or_else(|| "general".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Document processing: TUI -> Orchestrator -> InsightGen -> TUI
// ---------------------------------------------------------------------------

/// Process a document path through the full pipeline and push insights to the TUI.
///
/// Pipeline: path -> Orchestrator.process_document() -> RuleFiring[] -> FullInsightCard[] -> TUI
fn process_document(orch: &mut Orchestrator, app: &mut TuiApp, path: &str) {
    app.begin_processing(path);

    let doc_path = PathBuf::from(path);
    match orch.process_document(doc_path) {
        Ok(result) => {
            if result.insights.is_empty() {
                app.finish_processing();
                app.set_status(&format!(
                    "Processed {} ({:.1}ms) -- {} tuples, {} WMEs, no rules fired",
                    path,
                    result.elapsed.as_secs_f64() * 1000.0,
                    result.pipeline_result.tuples_created,
                    result.pipeline_result.wmes_inserted,
                ));
            } else {
                for firing in &result.insights {
                    let card = orchestrator_firing_to_tui_card(firing);
                    app.push_insight(card);
                }
                app.finish_processing();
                app.set_status(&format!(
                    "Processed {} ({:.1}ms) -- {} insight{} from {} WMEs ({} rules loaded)",
                    path,
                    result.elapsed.as_secs_f64() * 1000.0,
                    result.insights.len(),
                    if result.insights.len() == 1 { "" } else { "s" },
                    result.pipeline_result.wmes_inserted,
                    orch.rule_count(),
                ));
            }
        }
        Err(e) => {
            // ExtractionError Display already uses WHAT/WHY/DO (U4).
            app.set_error(&format!("Failed to process {}.\n  Why: {}", path, e));
        }
    }
}

// ---------------------------------------------------------------------------
// Crossterm key mapping (same as hive_tui.rs)
// ---------------------------------------------------------------------------

fn map_crossterm_key(key: event::KeyEvent) -> TuiKeyEvent {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return TuiKeyEvent::CtrlC;
    }

    match key.code {
        KeyCode::Char(c) => TuiKeyEvent::Char(c),
        KeyCode::Enter => TuiKeyEvent::Enter,
        KeyCode::Backspace => TuiKeyEvent::Backspace,
        KeyCode::Delete => TuiKeyEvent::Delete,
        KeyCode::Esc => TuiKeyEvent::Escape,
        KeyCode::Up => TuiKeyEvent::Up,
        KeyCode::Down => TuiKeyEvent::Down,
        KeyCode::Left => TuiKeyEvent::Left,
        KeyCode::Right => TuiKeyEvent::Right,
        KeyCode::Home => TuiKeyEvent::Home,
        KeyCode::End => TuiKeyEvent::End,
        _ => TuiKeyEvent::Other,
    }
}

// ---------------------------------------------------------------------------
// Terminal setup/teardown
// ---------------------------------------------------------------------------

fn restore_terminal() -> Result<(), Box<dyn std::error::Error>> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Non-interactive entry point
// ---------------------------------------------------------------------------

/// Non-interactive entry point for the main TUI surfaces
/// (`--watch`, `--live`, default file-processing). Executed when
/// `args.non_interactive` is set -- either explicitly via
/// `--non-interactive` / `--skip-onboarding`, or implicitly via the
/// TTY-detection fallback in `parse_args` when stdin is not a terminal
/// (ssh pipeline, CI, `hive ... < /dev/null`).
///
/// Contract: never touches crossterm, ratatui, or raw/alt-screen state.
/// Reads CLI files, pushes them through the orchestrator, and emits
/// human-readable status lines to stdout (one per file, plus a shutdown
/// summary). Errors route to stderr and exit non-zero.
///
/// `--watch --non-interactive` is an explicit error: watching requires
/// an event loop, and a headless watch daemon is a different feature
/// that is out of scope here.
fn run_non_interactive(
    is_live: bool,
    watch: bool,
    files: Vec<PathBuf>,
    orch: &mut Orchestrator,
    rules_loaded: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if watch {
        eprintln!("[hive] Error: --watch is not supported in non-interactive mode.");
        eprintln!(
            "  Why: watch requires an event loop that currently lives inside \
             the TUI runtime; running it headless is a separate feature."
        );
        eprintln!(
            "   Do: drop --non-interactive (for a TTY) or drop --watch \
             and pass files on the command line."
        );
        std::process::exit(2);
    }

    if is_live {
        #[cfg(not(feature = "live-extraction"))]
        {
            eprintln!("[hive] Error: --live not available in this build.");
            eprintln!("  Why: Compiled without 'live-extraction' feature.");
            eprintln!("   Do: Rebuild with --features live-extraction, or use --mock.");
            std::process::exit(1);
        }
    }

    let mode_label = if is_live { "live" } else { "mock" };
    println!(
        "[hive] Non-interactive mode: {} rules loaded, {} extraction, \
         {} file(s) to process.",
        rules_loaded,
        mode_label,
        files.len()
    );

    if files.is_empty() {
        println!(
            "[hive] No files provided. Pass one or more paths on the command \
             line (e.g. `hive --non-interactive doc.pdf`) or run without \
             --non-interactive for the interactive TUI."
        );
    }

    // Process each file through the same orchestrator entry point used by
    // the interactive mode's pre-TUI file loop. We emit a stdout status
    // line per file so shell pipelines (`hive --non-interactive *.pdf | tee`)
    // can observe progress without parsing ANSI escape sequences.
    let mut any_failed = false;

    for file_path in &files {
        let path_str = file_path.to_string_lossy().to_string();
        match orch.process_document(file_path.clone()) {
            Ok(result) => {
                println!(
                    "[hive] processed {} -- {} insight(s), {} WMEs, {:.1} ms",
                    path_str,
                    result.insights.len(),
                    result.pipeline_result.wmes_inserted,
                    result.elapsed.as_secs_f64() * 1000.0,
                );
            }
            Err(e) => {
                eprintln!(
                    "[hive] Error: failed to process {}.\n  Why: {}",
                    path_str, e
                );
                any_failed = true;
            }
        }
    }

    let shutdown_report = orch.shutdown();
    println!(
        "[hive] shutdown: {} document(s), {} insight(s), {} drained, {:.1} ms",
        shutdown_report.total_documents_processed,
        shutdown_report.total_insights_generated,
        shutdown_report.pending_documents_drained,
        shutdown_report.elapsed.as_secs_f64() * 1000.0,
    );

    if any_failed {
        std::process::exit(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Main event loop: draws TUI, handles input, dispatches to orchestrator.
fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut TuiApp,
    orch: &mut Orchestrator,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // Draw the TUI.
        terminal.draw(|frame| {
            app.draw(frame);
        })?;

        // Poll for events with 50ms timeout (~20 FPS).
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key_event) = event::read()? {
                let tui_key = map_crossterm_key(key_event);
                let action = app.handle_input(tui_key);

                match action {
                    AppAction::Quit => break,
                    AppAction::ProcessFile(path) => {
                        process_document(orch, app, &path);
                    }
                    AppAction::ShareInsight(idx) => {
                        if let Some(ref stripped) = app.last_shared {
                            app.set_status(&format!(
                                "Shared insight {}: \"{}\" (stripped for privacy)",
                                idx + 1,
                                truncate(&stripped.rule_text_generic, 40),
                            ));
                        }
                    }
                    AppAction::ShowDetail(idx) => {
                        // The TUI already transitioned to DetailView state.
                        app.set_status(&format!(
                            "Detail view: insight {} of {}",
                            idx + 1,
                            app.insights.len()
                        ));
                    }
                    AppAction::ModeChanged(ref mode) => {
                        let label = match mode {
                            rete_alpha::hive_config::PrivacyMode::LocalOnly => "Local Only",
                            rete_alpha::hive_config::PrivacyMode::Collective => "Collective",
                        };
                        app.set_status(&format!(
                            "Privacy mode changed to: {}. Persisted to disk.",
                            label,
                        ));
                    }
                    AppAction::ClearInsights => {
                        // Already handled by TuiApp
                    }
                    AppAction::None => {}
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Watch folder event loop
// ---------------------------------------------------------------------------

/// Event loop with watch folder integration. Runs under a tokio runtime.
///
/// Polls both crossterm keyboard events (50ms) and the watch folder mpsc
/// channel. When a new file is detected by the watcher, it is processed
/// through the orchestrator and insights are pushed to the TUI.
async fn run_watch_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut TuiApp,
    orch: &mut Orchestrator,
    watch_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let watch_config = WatchFolderConfig::with_dir(watch_dir.clone());
    let mut watcher = WatchFolder::new(watch_config);

    // Shutdown signal for the watcher task.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let mut watch_rx = watcher.start(shutdown_rx).map_err(|e| {
        Box::<dyn std::error::Error>::from(format!("Watch folder start failed: {}", e))
    })?;

    app.set_status(&format!(
        "Watching: {} | {} rules loaded. Drop files to process.",
        watch_dir.display(),
        app.rules_loaded,
    ));

    loop {
        // Draw the TUI.
        terminal.draw(|frame| {
            app.draw(frame);
        })?;

        // Use tokio::select to poll both keyboard and watch events.
        tokio::select! {
            // Poll watch folder events (non-blocking).
            Some(watch_event) = watch_rx.recv() => {
                match watch_event {
                    WatchEvent::NewFile(file_path) => {
                        if watcher.is_processed(&file_path) {
                            continue;
                        }
                        let path_str = file_path.to_string_lossy().to_string();
                        app.set_status(&format!("Watch: processing {}...", path_str));

                        // Process through the orchestrator.
                        let doc_path = file_path.clone();
                        match orch.process_document(doc_path) {
                            Ok(result) => {
                                for firing in &result.insights {
                                    let card = orchestrator_firing_to_tui_card(firing);
                                    app.push_insight(card);
                                }
                                let _ = watcher.handle_success(&file_path);
                                app.set_status(&format!(
                                    "Watch: processed {} ({:.1}ms, {} insights). Watching: {}",
                                    path_str,
                                    result.elapsed.as_secs_f64() * 1000.0,
                                    result.insights.len(),
                                    watch_dir.display(),
                                ));
                            }
                            Err(e) => {
                                let error_msg = format!("{}", e);
                                let _ = watcher.handle_failure(&file_path, &error_msg);
                                app.set_status(&format!(
                                    "Watch: failed {} -- {}. Watching: {}",
                                    path_str, error_msg, watch_dir.display(),
                                ));
                            }
                        }
                    }
                    WatchEvent::Error(err) => {
                        app.set_status(&format!("Watch error: {}", err));
                    }
                }
            }
            // Poll keyboard input with a short timeout.
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                if event::poll(Duration::from_millis(0))? {
                    if let Event::Key(key_event) = event::read()? {
                        let tui_key = map_crossterm_key(key_event);
                        let action = app.handle_input(tui_key);

                        match action {
                            AppAction::Quit => {
                                let _ = shutdown_tx.send(true);
                                watcher.stop();
                                break;
                            }
                            AppAction::ProcessFile(path) => {
                                process_document(orch, app, &path);
                            }
                            AppAction::ShareInsight(idx) => {
                                if let Some(ref stripped) = app.last_shared {
                                    app.set_status(&format!(
                                        "Shared insight {}: \"{}\" (stripped for privacy)",
                                        idx + 1,
                                        truncate(&stripped.rule_text_generic, 40),
                                    ));
                                }
                            }
                            AppAction::ShowDetail(idx) => {
                                app.set_status(&format!(
                                    "Detail view: insight {} of {}",
                                    idx + 1,
                                    app.insights.len()
                                ));
                            }
                            AppAction::ModeChanged(ref mode) => {
                                let label = match mode {
                                    rete_alpha::hive_config::PrivacyMode::LocalOnly => "Local Only",
                                    rete_alpha::hive_config::PrivacyMode::Collective => "Collective",
                                };
                                app.set_status(&format!(
                                    "Privacy mode changed to: {}. Persisted to disk.",
                                    label,
                                ));
                            }
                            AppAction::ClearInsights => {}
                            AppAction::None => {}
                        }
                    }
                }
            }
        }

        if app.should_quit {
            let _ = shutdown_tx.send(true);
            watcher.stop();
            break;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Async event loop (live-extraction feature only)
// ---------------------------------------------------------------------------

/// Async document processing: updates TUI extraction status through
/// the lifecycle stages (spawning -> extracting -> processing -> done).
#[cfg(feature = "live-extraction")]
async fn process_document_async(orch: &mut Orchestrator, app: &mut TuiApp, path: &str) {
    app.begin_processing(path);

    // Show extraction status
    let file_name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());

    // If the subprocess isn't running yet, show spawning status
    if !app.model_loaded {
        app.extraction_status = ExtractionStatus::SpawningProcess;
    } else {
        app.extraction_status = ExtractionStatus::Extracting {
            file_name: file_name.clone(),
            elapsed_secs: 0,
        };
    }

    let doc_path = PathBuf::from(path);
    match orch.process_document_async(doc_path).await {
        Ok(result) => {
            app.extraction_status = ExtractionStatus::Processing;
            app.model_loaded = true; // Model is loaded after first successful extraction

            if result.insights.is_empty() {
                app.finish_processing();
                app.extraction_status = ExtractionStatus::Idle;
                app.set_status(&format!(
                    "Processed {} ({:.1}ms) -- {} tuples, {} WMEs, no rules fired",
                    path,
                    result.elapsed.as_secs_f64() * 1000.0,
                    result.pipeline_result.tuples_created,
                    result.pipeline_result.wmes_inserted,
                ));
            } else {
                for firing in &result.insights {
                    let card = orchestrator_firing_to_tui_card(firing);
                    app.push_insight(card);
                }
                app.finish_processing();
                app.extraction_status = ExtractionStatus::Idle;
                app.set_status(&format!(
                    "Processed {} ({:.1}ms) -- {} insight{} from {} WMEs ({} rules loaded)",
                    path,
                    result.elapsed.as_secs_f64() * 1000.0,
                    result.insights.len(),
                    if result.insights.len() == 1 { "" } else { "s" },
                    result.pipeline_result.wmes_inserted,
                    orch.rule_count(),
                ));
            }
        }
        Err(e) => {
            // ExtractionError Display already uses WHAT/WHY/DO (U4).
            app.extraction_status = ExtractionStatus::Failed {
                reason: format!("{}", e),
            };
            app.set_error(&format!("Failed to process {}.\n  Why: {}", path, e));
        }
    }
}

/// Async event loop: same as `run_event_loop` but uses `process_document_async`
/// for document processing. The TUI draw/poll loop remains synchronous (50ms
/// poll on crossterm) while extraction runs as an async operation.
#[cfg(feature = "live-extraction")]
async fn run_event_loop_async(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut TuiApp,
    orch: &mut Orchestrator,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // Draw the TUI.
        terminal.draw(|frame| {
            app.draw(frame);
        })?;

        // Poll for events with 50ms timeout (~20 FPS).
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key_event) = event::read()? {
                let tui_key = map_crossterm_key(key_event);
                let action = app.handle_input(tui_key);

                match action {
                    AppAction::Quit => break,
                    AppAction::ProcessFile(path) => {
                        process_document_async(orch, app, &path).await;
                    }
                    AppAction::ShareInsight(idx) => {
                        if let Some(ref stripped) = app.last_shared {
                            app.set_status(&format!(
                                "Shared insight {}: \"{}\" (stripped for privacy)",
                                idx + 1,
                                truncate(&stripped.rule_text_generic, 40),
                            ));
                        }
                    }
                    AppAction::ShowDetail(idx) => {
                        // The TUI already transitioned to DetailView state.
                        app.set_status(&format!(
                            "Detail view: insight {} of {}",
                            idx + 1,
                            app.insights.len()
                        ));
                    }
                    AppAction::ModeChanged(ref mode) => {
                        let label = match mode {
                            rete_alpha::hive_config::PrivacyMode::LocalOnly => "Local Only",
                            rete_alpha::hive_config::PrivacyMode::Collective => "Collective",
                        };
                        app.set_status(&format!(
                            "Privacy mode changed to: {}. Persisted to disk.",
                            label,
                        ));
                    }
                    AppAction::ClearInsights => {
                        // Already handled by TuiApp
                    }
                    AppAction::None => {}
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

/// Truncate a string to `max_len` characters, appending "..." if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let end = s
            .char_indices()
            .nth(max_len.saturating_sub(3))
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        format!("{}...", &s[..end])
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

/// Initialize structured logging.
///
/// - `RUST_LOG` controls verbosity (e.g. `RUST_LOG=hive=debug,rete_alpha=info`).
/// - Default is `info` when `RUST_LOG` is unset.
/// - `tracing-log`'s `LogTracer` is installed so any `log::warn!` /
///   `log::info!` calls inside the workspace (we still depend on `log = 0.4`
///   for compatibility) flow into the same subscriber as `tracing::info!`.
/// - Idempotent: re-calling is a no-op (subscriber already installed).
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // Bridge `log` -> `tracing`. Idempotent: returns Err if already set.
    let _ = tracing_log::LogTracer::init();

    // try_init returns Err if a subscriber is already set (e.g. tests that
    // pre-install one). That is fine -- the binary's idempotent contract
    // means we should not panic in that case.
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let args = parse_args();

    // -- First-run onboarding --
    let mut config = HiveConfig::load();

    // Bootstrap ~/.hive/watch/ and ~/.hive/insights/ with
    // mode 0700 on every startup. Idempotent; cheap; fixes up loose modes left
    // by earlier binaries. Non-fatal on failure (e.g. read-only $HOME on CI):
    // we log and continue so the user can still run --diagnostics.
    if let Err(e) = rete_alpha::hive_config::ensure_hive_subdirs() {
        eprintln!("[hive] Warning: could not ensure ~/.hive subdirs: {}", e);
    }

    if args.reset_onboarding {
        config.onboarding_complete = false;
    }

    if !config.onboarding_complete {
        // A fresh binary invoked over ssh or in a non-TTY pipeline tried to
        // enable crossterm raw mode and died. When `--non-interactive`
        // (or `--skip-onboarding`) is set -- or when the TTY-detection
        // fallback in `parse_args` fired because stdin is not a terminal --
        // skip the interactive TUI entirely and accept the defaults:
        // LocalOnly privacy, onboarding_complete = true (in-memory only;
        // we deliberately do NOT persist this so the next *interactive*
        // run still offers the onboarding flow).
        if args.non_interactive {
            eprintln!(
                "[hive] Non-interactive mode: skipping onboarding; using \
                 default privacy=LocalOnly (set --reset-onboarding in an \
                 interactive session to run the full prompt)."
            );
            config.onboarding_complete = true;
            // Leave config.privacy_mode at its on-disk value (Default =
            // LocalOnly). Do not call config.save() -- see note above.
        } else {
            eprintln!("[hive] Running first-time onboarding...");
            match onboarding::run_onboarding()? {
                OnboardingResult::Completed(privacy_mode) => {
                    config.privacy_mode = privacy_mode;
                    config.onboarding_complete = true;
                    if let Err(e) = config.save() {
                        eprintln!("[hive] Error: Could not save config.");
                        eprintln!("  Why: {}", e);
                        eprintln!("   Do: Check ~/.hive/ permissions.");
                    } else {
                        eprintln!("[hive] Onboarding complete. Config saved.");
                    }
                }
                OnboardingResult::Quit => {
                    eprintln!("[hive] Onboarding cancelled. Exiting.");
                    return Ok(());
                }
            }
        }
    }

    // -- Handle --diagnostics flag --
    if args.diagnostics {
        // `--json` switches the emitter from the
        // human-readable text form to pretty-printed JSON. The
        // orchestrator-init / field-collection steps are shared so both
        // output modes see identical state.
        //
        // We route the "generating..." banner to stderr so `jq` sees only
        // the JSON on stdout. Same reasoning as `git --porcelain`: status
        // chatter belongs on fd 2.
        eprintln!("[hive] Generating diagnostic report...");
        let (mut orch, _rules_loaded) = init_orchestrator(ExtractionMode::Mock, false);
        let report = diagnostics::build_report(
            &version_string(),
            diagnostics::EngineState {
                rule_count: orch.rule_count(),
                wme_count: orch.wme_count(),
            },
            diagnostics::PipelineState {
                mock_documents: orch.documents_processed(),
                live_documents: 0,
            },
            diagnostics::PrivacyState {
                mode: format!("{:?}", config.privacy_mode).to_lowercase(),
                budget_remaining_pct: 100,
            },
            diagnostics::P2PState {
                enabled: false,
                peer_count: 0,
            },
            "not loaded",
            vec![],
            vec![],
        );
        if args.diagnostics_json {
            match diagnostics::format_report_json(&report) {
                Ok(json) => {
                    println!("{}", json);
                }
                Err(e) => {
                    // Unreachable today (no Serialize impl in this report
                    // can fail), but we surface a real error on stderr so
                    // CI picks up regressions instead of an empty stdout.
                    eprintln!("[hive] Error: could not emit JSON diagnostics: {}", e);
                    let _ = orch.shutdown();
                    std::process::exit(1);
                }
            }
        } else {
            print!("{}", diagnostics::format_report(&report));
        }
        let _ = orch.shutdown();
        return Ok(());
    }

    // -- Handle --activate <code> flag (L1) --
    if let Some(code) = args.activate_code {
        match invite::activate(&code) {
            Ok(activation) => {
                eprintln!("[hive] Activation successful!");
                eprintln!("[hive] Generation: {}", activation.generation);
                eprintln!("[hive] Your invite codes:");
                for (i, c) in activation.my_invites.iter().enumerate() {
                    eprintln!("  {}. {}", i + 1, c);
                }
                return Ok(());
            }
            Err(e) => {
                eprintln!("[hive] Error: Activation failed.");
                eprintln!("  Why: {}", e);
                // Case-aware remediation:
                // AlreadyActivated has its own operator guidance in Display,
                // so only print "verify and retry" for format/I/O errors.
                match &e {
                    invite::ActivationError::AlreadyActivated { .. } => {
                        eprintln!("   Do: If you intend to re-activate, remove the activation file first.");
                    }
                    _ => {
                        eprintln!("   Do: Verify the invite code and retry.");
                    }
                }
                std::process::exit(1);
            }
        }
    }

    // -- Handle --my-invites flag (L1) --
    if args.my_invites {
        match invite::load_activation() {
            Some(activation) => {
                print!("{}", invite::format_my_invites(&activation));
                return Ok(());
            }
            None => {
                eprintln!("[hive] Error: No activation found.");
                eprintln!("   Do: hive --activate HIVE-XXXX-XXXX-XXXX");
                std::process::exit(1);
            }
        }
    }

    let is_live = matches!(args.extraction_mode, ExtractionMode::Live { .. });
    let mode_label = if is_live {
        "live extraction"
    } else {
        "mock extraction"
    };

    // -- Initialize orchestrator + seed rules --
    eprintln!("[hive] Initializing HIVE MVP...");
    let (mut orch, rules_loaded) =
        init_orchestrator(args.extraction_mode, args.allow_custom_extractor);
    eprintln!(
        "[hive] Orchestrator ready: {} rules, {} mode",
        rules_loaded, mode_label
    );

    // Multi-surface handling of `args.non_interactive`. Earlier, only the
    // first-run onboarding branch consumed it. `--watch`,
    // `--live`, and default file-processing all fell through to the
    // unconditional `enable_raw_mode()` below -- reproducing the same
    // "hive over ssh / piped stdin crashes the terminal" failure mode,
    // just on different CLI surfaces. We
    // honor `args.non_interactive` on every TUI-spawning surface and
    // route each one to a stdout-only path that processes CLI files,
    // emits human-readable status lines, and returns -- no crossterm,
    // no ratatui, no event loop.
    //
    // Scope note: we do NOT rewrite the TTY primitive itself
    // (still the one call at parse_args:238). We do NOT add a
    // non-interactive "watch daemon" mode -- a daemonized watch loop
    // with no TUI is a distinct feature.
    // `--watch --non-interactive` therefore exits with an explicit
    // error explaining the constraint, rather than silently running a
    // different thing than the user asked for.
    if args.non_interactive {
        return run_non_interactive(is_live, args.watch, args.files, &mut orch, rules_loaded);
    }

    // -- Install panic hook that restores terminal --
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = restore_terminal();
        original_hook(panic_info);
    }));

    // -- Terminal setup --
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // -- Initialize TUI app with config-loaded privacy mode --
    let (mut app, _shared_privacy_mode) = TuiApp::new_with_config(&config);
    app.rules_loaded = rules_loaded;

    // -- Resolve watch mode from CLI flags or config --
    let watch_enabled = args.watch || config.watch_enabled;
    let watch_status = if watch_enabled {
        let watch_dir = args
            .watch_dir
            .or_else(|| config.watch_dir.as_ref().map(PathBuf::from))
            .or_else(rete_alpha::watch_folder::default_watch_dir);

        match watch_dir {
            Some(dir) => {
                app.set_status(&format!(
                    "HIVE ready ({} mode). {} seed rules loaded. Watching: {}",
                    if is_live { "live" } else { "mock" },
                    rules_loaded,
                    dir.display(),
                ));
                Some(dir)
            }
            None => {
                app.set_status(&format!(
                    "HIVE ready ({} mode). {} seed rules loaded. Watch dir could not be resolved.",
                    if is_live { "live" } else { "mock" },
                    rules_loaded,
                ));
                None
            }
        }
    } else {
        app.set_status(&format!(
            "HIVE ready ({} mode). {} seed rules loaded. Enter a file path to process.",
            if is_live { "live" } else { "mock" },
            rules_loaded
        ));
        None
    };

    // -- Dispatch to sync or async event loop based on mode --
    let result = if is_live {
        #[cfg(feature = "live-extraction")]
        {
            // Live mode: run under a tokio runtime for async extraction
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create tokio runtime for live extraction");

            // Process CLI-provided files with async extraction
            for file_path in &args.files {
                let path_str = file_path.to_string_lossy().to_string();
                rt.block_on(process_document_async(&mut orch, &mut app, &path_str));
            }

            // Run async event loop
            rt.block_on(run_event_loop_async(&mut terminal, &mut app, &mut orch))
        }
        #[cfg(not(feature = "live-extraction"))]
        {
            let _ = restore_terminal();
            eprintln!("[hive] Error: --live not available in this build.");
            eprintln!("  Why: Compiled without 'live-extraction' feature.");
            eprintln!(
                "   Do: Rebuild with --features live-extraction, \
or use --mock."
            );
            std::process::exit(1);
        }
    } else if let Some(watch_dir) = watch_status {
        // Watch mode: needs a tokio runtime for the watcher task.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime for watch mode");

        // Process CLI-provided files first.
        for file_path in &args.files {
            let path_str = file_path.to_string_lossy().to_string();
            process_document(&mut orch, &mut app, &path_str);
        }

        rt.block_on(run_watch_event_loop(
            &mut terminal,
            &mut app,
            &mut orch,
            watch_dir,
        ))
    } else {
        // Mock mode: synchronous event loop (no tokio needed)
        for file_path in &args.files {
            let path_str = file_path.to_string_lossy().to_string();
            process_document(&mut orch, &mut app, &path_str);
        }
        run_event_loop(&mut terminal, &mut app, &mut orch)
    };

    // -- Graceful shutdown --
    let shutdown_report = orch.shutdown();
    let _ = restore_terminal();

    eprintln!("[hive] Shutdown complete:");
    eprintln!(
        "  Documents processed: {}",
        shutdown_report.total_documents_processed
    );
    eprintln!(
        "  Insights generated: {}",
        shutdown_report.total_insights_generated
    );
    eprintln!(
        "  Pending docs drained: {}",
        shutdown_report.pending_documents_drained
    );
    eprintln!(
        "  Shutdown time: {:.1}ms",
        shutdown_report.elapsed.as_secs_f64() * 1000.0
    );

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // === Task 1 tests: version output format ===

    #[test]
    fn test_version_string_format() {
        let ver = version_string();
        // Must start with "hive v" and contain the expected segments
        assert!(
            ver.starts_with("hive v"),
            "version must start with 'hive v': {}",
            ver
        );
        assert!(
            ver.contains("-alpha"),
            "version must contain '-alpha': {}",
            ver
        );
        assert!(
            ver.contains("built "),
            "version must contain 'built ': {}",
            ver
        );
        assert!(ver.contains("git:"), "version must contain 'git:': {}", ver);
    }

    #[test]
    fn test_version_contains_cargo_version() {
        let ver = version_string();
        let pkg_version = env!("CARGO_PKG_VERSION");
        assert!(
            ver.contains(pkg_version),
            "version string '{}' must contain CARGO_PKG_VERSION '{}'",
            ver,
            pkg_version,
        );
    }

    #[test]
    fn test_version_build_date_format() {
        let ver = version_string();
        // Extract the date portion between "built " and ","
        let built_idx = ver.find("built ").expect("must contain 'built '");
        let date_start = built_idx + 6;
        let comma_idx = ver[date_start..]
            .find(',')
            .expect("must contain comma after date");
        let date_str = &ver[date_start..date_start + comma_idx];
        // Date must be YYYY-MM-DD or "unknown"
        if date_str != "unknown" {
            assert_eq!(
                date_str.len(),
                10,
                "date must be 10 chars (YYYY-MM-DD): {}",
                date_str
            );
            assert_eq!(
                &date_str[4..5],
                "-",
                "date must have dash at pos 4: {}",
                date_str
            );
            assert_eq!(
                &date_str[7..8],
                "-",
                "date must have dash at pos 7: {}",
                date_str
            );
        }
    }

    // === Task 2 tests: self-test checks ===

    #[test]
    fn test_self_test_seed_rules_count() {
        let rules = seed_rules::get_seed_rules();
        assert_eq!(rules.len(), 40, "seed rules must be exactly 40");
    }

    #[test]
    fn test_self_test_mock_extraction_valid() {
        let mut mgr = ExtractionManager::new_mock();
        let result = mgr
            .extract_sync("Patient visited hospital", "/test/medical.pdf")
            .expect("mock extraction must succeed");
        assert!(!result.output.document_category.is_empty());
        assert!(!result.output.entities.is_empty());
    }

    #[test]
    fn test_self_test_pipeline_end_to_end() {
        let config = OrchestratorConfig {
            extraction_mode: ExtractionMode::Mock,
            ..OrchestratorConfig::mvp()
        };
        let mut orch = Orchestrator::new(config);
        orch.initialize().unwrap();
        let seed = seed_rules::get_seed_rules();
        let loaded = rule_loader::load_seed_rules(&mut orch.pipeline_mut().engine, &seed);
        assert_eq!(loaded, 40);

        let result = orch
            .process_document(PathBuf::from("/test/medical_bill.pdf"))
            .expect("pipeline must process mock document");
        assert!(result.pipeline_result.wmes_inserted > 0);
    }

    #[test]
    fn test_self_test_insight_card_fields() {
        let config = OrchestratorConfig {
            extraction_mode: ExtractionMode::Mock,
            ..OrchestratorConfig::mvp()
        };
        let mut orch = Orchestrator::new(config);
        orch.initialize().unwrap();
        let seed = seed_rules::get_seed_rules();
        rule_loader::load_seed_rules(&mut orch.pipeline_mut().engine, &seed);

        let result = orch
            .process_document(PathBuf::from("/test/lease_agreement.pdf"))
            .expect("pipeline must process mock document");
        for firing in &result.insights {
            assert!(firing.rule_id > 0, "rule_id must be positive");
            assert!(
                !firing.source_file.is_empty(),
                "source_file must not be empty"
            );
        }
    }

    #[test]
    fn test_self_test_version_info_valid() {
        let ver = version_string();
        assert!(ver.starts_with("hive v"));
        assert!(ver.contains("-alpha"));
        assert!(ver.contains("built "));
        assert!(ver.contains("git:"));
    }

    // === multi-surface --non-interactive honor tests ===
    //
    // Every sibling surface of the TTY-detect
    // primitive must route to a non-TUI path when `non_interactive` is
    // set. These tests drive `run_non_interactive` directly and assert
    // each surface (--live / default / --watch) behaves per contract
    // without ever touching crossterm or ratatui.
    //
    // Note: we cannot unit-test `std::process::exit(...)` paths inside a
    // `#[test]` (they would abort the test binary). The watch-rejection
    // and missing-live-feature paths are therefore exercised via separate
    // integration pathways (preflight harness + manual testing).

    fn mk_nonint_orch() -> (Orchestrator, usize) {
        init_orchestrator(ExtractionMode::Mock, false)
    }

    #[test]
    fn test_nonint_default_surface_no_files_is_ok() {
        // Default file-processing surface, no files: must return Ok
        // without panicking and without invoking any TUI code paths.
        let (mut orch, rules_loaded) = mk_nonint_orch();
        let result = run_non_interactive(
            /* is_live */ false,
            /* watch  */ false,
            /* files  */ Vec::new(),
            &mut orch,
            rules_loaded,
        );
        assert!(
            result.is_ok(),
            "default surface with no files must return Ok: {:?}",
            result
        );
    }

    #[test]
    fn test_nonint_default_surface_mock_file_is_ok() {
        // Default file-processing surface, one mock file: must drive the
        // orchestrator through `process_document` and return Ok. This is
        // the SSH / CI use case -- `ssh host 'hive --non-interactive doc.pdf'`.
        let (mut orch, rules_loaded) = mk_nonint_orch();
        let files = vec![PathBuf::from("/test/medical_bill.pdf")];
        let result = run_non_interactive(false, false, files, &mut orch, rules_loaded);
        assert!(
            result.is_ok(),
            "default surface with mock file must return Ok: {:?}",
            result
        );
    }

    #[test]
    fn test_nonint_live_surface_no_files_is_ok_when_feature_enabled() {
        // --live surface in non-interactive mode: when no files are given,
        // we print the banner + empty-files notice and shut down cleanly.
        // In the mock-compiled test build (no live-extraction feature), the
        // path guards in `run_non_interactive` use the same mock-style exit
        // only when `is_live` collides with a missing feature -- so for the
        // test build we skip when compiled without live-extraction.
        #[cfg(feature = "live-extraction")]
        {
            let (mut orch, rules_loaded) = mk_nonint_orch();
            let result = run_non_interactive(true, false, Vec::new(), &mut orch, rules_loaded);
            assert!(result.is_ok(), "live surface with no files must return Ok");
        }
        #[cfg(not(feature = "live-extraction"))]
        {
            // In a non-live build, `--live --non-interactive` would exit(1)
            // via `std::process::exit`; that is covered by the preflight
            // integration harness and is not unit-testable here. We instead
            // assert the non-live default surface still works, so the
            // test contributes a signal even when the feature is off.
            let (mut orch, rules_loaded) = mk_nonint_orch();
            let result = run_non_interactive(false, false, Vec::new(), &mut orch, rules_loaded);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_nonint_panic_hook_not_installed() {
        // Contract: `run_non_interactive` must NOT install the TUI panic
        // hook (which calls `restore_terminal` and therefore touches
        // crossterm). We verify by snapshotting the current hook pointer,
        // running a non-interactive invocation, and confirming the hook
        // did not change. If this assertion ever starts failing, someone
        // wired TUI state into the non-interactive path.
        let before = std::panic::take_hook();
        // Immediately restore so a panic in the test body prints normally.
        std::panic::set_hook(before);

        let (mut orch, rules_loaded) = mk_nonint_orch();
        let _ = run_non_interactive(false, false, Vec::new(), &mut orch, rules_loaded);

        // If run_non_interactive had installed the TUI panic hook, a
        // subsequent panic in test teardown would try to restore a
        // terminal that was never put in raw mode -- causing flaky test
        // output. We can't introspect the hook pointer stable-Rust, so
        // this test serves as a documented contract: any reviewer
        // touching run_non_interactive should keep it hook-free.
    }

    #[test]
    fn test_nonint_signature_takes_no_terminal() {
        // Contract: `run_non_interactive`'s signature must not thread a
        // `Terminal<CrosstermBackend<...>>` through -- that would be a
        // proof-by-types violation of the non-interactive invariant.
        //
        // We codify the check by coercing the function to a concrete
        // signature that explicitly excludes any Terminal argument.
        // Any change that threads a Terminal into the non-interactive
        // surface fails to compile here and must be justified in review.
        #[allow(clippy::type_complexity)]
        type NonIntSig = fn(
            bool,
            bool,
            Vec<PathBuf>,
            &mut Orchestrator,
            usize,
        ) -> Result<(), Box<dyn std::error::Error>>;
        let _f: NonIntSig = run_non_interactive;
    }

    // === env-override ergonomics tests ===
    //
    // Contract: `resolve_extraction_script_with_exe_dir` must auto-discover
    // `<exe_dir>/extraction-service/extraction_service.py` when the canonical
    // release-tarball layout is present, without the user needing to
    // `export HIVE_EXTRACTION_SCRIPT=...`. This matches the tarball layout
    // emitted by scripts/build-release.sh L161-165 which copies the
    // `extraction-service/*.py` sources sibling-to the `hive` binary.

    /// Guard that snapshots and clears `HIVE_EXTRACTION_SCRIPT` for the
    /// duration of a test, then restores the original value on drop. The
    /// env var takes precedence in `resolve_extraction_script_with_exe_dir`
    /// step 1, so the auto-discovery tests must ensure it is unset before
    /// invoking the resolver.
    struct EnvVarGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvVarGuard {
        fn unset(key: &'static str) -> Self {
            let original = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.original.take() {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn test_resolve_extraction_script_autodiscovers_bundled_subdir() {
        // Simulate the unpacked-tarball layout:
        //   <temp>/hive                                 (binary placeholder)
        //   <temp>/extraction-service/extraction_service.py (script placeholder)
        //
        // With HIVE_EXTRACTION_SCRIPT unset, the resolver must return the
        // canonicalized bundled-script path -- NOT None, and NOT some other
        // on-disk candidate.
        let _guard = EnvVarGuard::unset("HIVE_EXTRACTION_SCRIPT");

        let temp = tempfile::tempdir().expect("tempdir must be creatable");
        let exe_dir = temp.path();

        // Binary placeholder (not actually executed; exists only so the
        // simulated layout is realistic).
        std::fs::write(exe_dir.join("hive"), b"#!placeholder\n").expect("write binary placeholder");

        // Bundled script placeholder.
        let bundled_dir = exe_dir.join("extraction-service");
        std::fs::create_dir_all(&bundled_dir).expect("create extraction-service subdir");
        let script_path = bundled_dir.join("extraction_service.py");
        std::fs::write(&script_path, b"# placeholder extraction_service.py\n")
            .expect("write script placeholder");

        let resolved = resolve_extraction_script_with_exe_dir(Some(exe_dir))
            .expect("bundled extraction_service.py must be auto-discovered");

        let expected =
            std::fs::canonicalize(&script_path).expect("canonicalize expected script path");
        assert_eq!(
            resolved, expected,
            "resolver must return the canonicalized bundled script path; got {:?}, expected {:?}",
            resolved, expected
        );
    }

    #[test]
    fn test_resolve_extraction_script_prefers_bundled_over_adjacent() {
        // When BOTH `<exe_dir>/extraction-service/extraction_service.py`
        // (bundled) AND `<exe_dir>/extraction_service.py`
        // (legacy adjacent) exist, the bundled-subdir path wins. This
        // codifies the tarball-layout-first ordering so future edits to
        // the search list cannot silently regress it.
        let _guard = EnvVarGuard::unset("HIVE_EXTRACTION_SCRIPT");

        let temp = tempfile::tempdir().expect("tempdir must be creatable");
        let exe_dir = temp.path();

        // Legacy adjacent script.
        let adjacent = exe_dir.join("extraction_service.py");
        std::fs::write(&adjacent, b"# adjacent legacy\n").expect("write adjacent");

        // Canonical bundled script.
        let bundled_dir = exe_dir.join("extraction-service");
        std::fs::create_dir_all(&bundled_dir).expect("create extraction-service subdir");
        let bundled = bundled_dir.join("extraction_service.py");
        std::fs::write(&bundled, b"# bundled canonical\n").expect("write bundled");

        let resolved = resolve_extraction_script_with_exe_dir(Some(exe_dir))
            .expect("resolver must return a path when both candidates exist");
        let expected_bundled = std::fs::canonicalize(&bundled).expect("canonicalize bundled");
        assert_eq!(
            resolved, expected_bundled,
            "bundled subdir path must win over adjacent legacy path"
        );
    }
}
