//! Diagnostic export for HIVE (`hive --diagnostics`).
//!
//! Generates a PII-free diagnostic report
//! covering platform info, engine state, extraction statistics, and error history.
//!
//! Design constraints:
//! - No file paths, document content, or PII in the output
//! - All data sourced from in-process state (no disk reads)
//! - Report is plain text, structured for paste into bug reports

use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Data structures for diagnostic report
// ---------------------------------------------------------------------------
//
// All diagnostic-report structs derive `serde::Serialize`
// so `hive --diagnostics --json` can emit a machine-readable form with a
// stable field set. The text formatter (`format_report`) is unchanged; the
// JSON emitter (`format_report_json`) is additive, providing `jq`-parseable
// diagnostics output.

/// Platform information detected at runtime.
#[derive(Debug, Clone, Serialize)]
pub struct PlatformInfo {
    pub macos_version: String,
    pub chip: String,
    pub ram_gb: u64,
    pub python_version: String,
    pub mlx_version: String,
}

/// Extraction statistics (PII-free).
#[derive(Debug, Clone, Serialize)]
pub struct ExtractionStat {
    /// Document type category (e.g., "medical_bill", "lease_agreement").
    pub doc_type: String,
    /// Whether extraction succeeded.
    pub success: bool,
    /// Latency in seconds.
    pub latency_secs: f64,
    /// Number of entities extracted.
    pub entity_count: usize,
    /// Number of relationships extracted.
    pub relationship_count: usize,
}

/// An error occurrence with category and count.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorStat {
    pub category: String,
    pub count: u64,
    /// Timestamp of most recent occurrence (seconds since UNIX epoch).
    pub last_seen: u64,
}

/// Engine state snapshot for diagnostics.
#[derive(Debug, Clone, Serialize)]
pub struct EngineState {
    pub rule_count: usize,
    pub wme_count: usize,
}

/// Pipeline state snapshot for diagnostics.
#[derive(Debug, Clone, Serialize)]
pub struct PipelineState {
    pub mock_documents: u64,
    pub live_documents: u64,
}

/// Privacy state snapshot for diagnostics.
#[derive(Debug, Clone, Serialize)]
pub struct PrivacyState {
    pub mode: String,
    pub budget_remaining_pct: u32,
}

/// P2P state snapshot for diagnostics.
#[derive(Debug, Clone, Serialize)]
pub struct P2PState {
    pub enabled: bool,
    pub peer_count: usize,
}

/// Complete diagnostic report data.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticReport {
    pub version: String,
    pub platform: PlatformInfo,
    pub model_status: String,
    pub engine: EngineState,
    pub pipeline: PipelineState,
    pub privacy: PrivacyState,
    pub p2p: P2PState,
    pub last_extractions: Vec<ExtractionStat>,
    pub error_history: Vec<ErrorStat>,
}

// ---------------------------------------------------------------------------
// Platform detection (~40 lines)
// ---------------------------------------------------------------------------

/// Detect platform information by running shell commands.
/// Returns best-effort values; fields are "unknown" if detection fails.
pub fn detect_platform() -> PlatformInfo {
    let macos_version =
        run_cmd("sw_vers", &["-productVersion"]).unwrap_or_else(|| "unknown".to_string());

    let chip = run_cmd("sysctl", &["-n", "machdep.cpu.brand_string"]).unwrap_or_else(|| {
        // Fallback for Apple Silicon
        run_cmd("uname", &["-m"]).unwrap_or_else(|| "unknown".to_string())
    });

    let ram_bytes_str = run_cmd("sysctl", &["-n", "hw.memsize"]).unwrap_or_else(|| "0".to_string());
    let ram_gb = ram_bytes_str.trim().parse::<u64>().unwrap_or(0) / (1024 * 1024 * 1024);

    let python_version = run_cmd("python3", &["--version"])
        .map(|v| v.trim().replace("Python ", ""))
        .unwrap_or_else(|| "not found".to_string());

    let mlx_version = run_cmd("python3", &["-c", "import mlx; print(mlx.__version__)"])
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|| "not found".to_string());

    PlatformInfo {
        macos_version,
        chip,
        ram_gb,
        python_version,
        mlx_version,
    }
}

/// Run a command and capture stdout. Returns None on failure.
fn run_cmd(cmd: &str, args: &[&str]) -> Option<String> {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

// ---------------------------------------------------------------------------
// Error history filtering (~40 lines)
// ---------------------------------------------------------------------------

/// Filter error history to only the last 7 days.
pub fn filter_errors_last_7_days(errors: &[ErrorStat]) -> Vec<ErrorStat> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let seven_days_ago = now.saturating_sub(7 * 24 * 3600);
    errors
        .iter()
        .filter(|e| e.last_seen >= seven_days_ago)
        .cloned()
        .collect()
}

/// Aggregate errors by category, summing counts.
pub fn aggregate_errors(errors: &[ErrorStat]) -> Vec<ErrorStat> {
    let mut map: std::collections::HashMap<String, (u64, u64)> = std::collections::HashMap::new();
    for e in errors {
        let entry = map.entry(e.category.clone()).or_insert((0, 0));
        entry.0 += e.count;
        if e.last_seen > entry.1 {
            entry.1 = e.last_seen;
        }
    }
    let mut result: Vec<ErrorStat> = map
        .into_iter()
        .map(|(cat, (count, last_seen))| ErrorStat {
            category: cat,
            count,
            last_seen,
        })
        .collect();
    // sort_by_key with Reverse satisfies clippy::unnecessary_sort_by (1.95+).
    result.sort_by_key(|s| std::cmp::Reverse(s.count));
    result
}

// ---------------------------------------------------------------------------
// Report formatter (~120 lines)
// ---------------------------------------------------------------------------

/// Format the current date as YYYY-MM-DD from SystemTime.
pub fn current_date_string() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    // Simple date calculation (no chrono dependency)
    let days = secs / 86400;
    let (year, month, day) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02}", year, month, day)
}

/// Convert days since UNIX epoch to (year, month, day).
fn days_to_ymd(days_since_epoch: u64) -> (u64, u64, u64) {
    // Algorithm: https://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let z = days_since_epoch as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as u64, m, d)
}

/// Format the full diagnostic report as a string.
pub fn format_report(report: &DiagnosticReport) -> String {
    let mut out = String::with_capacity(2048);
    let date = current_date_string();

    // Header
    out.push_str(&format!("HIVE Diagnostic Report ({})\n", date));
    out.push_str("=====================================\n");

    // Version + Platform
    out.push_str(&format!("Version: {}\n", report.version));
    out.push_str(&format!(
        "Platform: macOS {}, {}, {} GB RAM\n",
        report.platform.macos_version, report.platform.chip, report.platform.ram_gb,
    ));
    out.push_str(&format!(
        "Python: {}, MLX {}\n",
        report.platform.python_version, report.platform.mlx_version,
    ));
    out.push_str(&format!(
        "Model: gemma-3n-E2B-it-lm-4bit ({})\n",
        report.model_status
    ));

    out.push('\n');

    // Engine
    out.push_str(&format!(
        "Engine: {} rules, {} WMEs\n",
        report.engine.rule_count, report.engine.wme_count,
    ));

    // Pipeline
    out.push_str(&format!(
        "Pipeline: mock={}, live={} documents processed\n",
        report.pipeline.mock_documents, report.pipeline.live_documents,
    ));

    // Privacy
    out.push_str(&format!(
        "Privacy: {} mode, budget {}% remaining\n",
        report.privacy.mode, report.privacy.budget_remaining_pct,
    ));

    // P2P
    if report.p2p.enabled {
        out.push_str(&format!("P2P: enabled ({} peers)\n", report.p2p.peer_count,));
    } else {
        out.push_str("P2P: disabled\n");
    }

    out.push('\n');

    // Last extractions
    if report.last_extractions.is_empty() {
        out.push_str("Last 5 extractions: (none)\n");
    } else {
        let count = report.last_extractions.len().min(5);
        out.push_str(&format!("Last {} extractions:\n", count));
        for (i, stat) in report.last_extractions.iter().take(5).enumerate() {
            let status = if stat.success { "OK" } else { "FAIL" };
            out.push_str(&format!(
                "  {}. [{}] [{}] {:.1}s, {} entities, {} relationships\n",
                i + 1,
                stat.doc_type,
                status,
                stat.latency_secs,
                stat.entity_count,
                stat.relationship_count,
            ));
        }
    }

    out.push('\n');

    // Error history (last 7 days)
    let recent_errors = filter_errors_last_7_days(&report.error_history);
    let aggregated = aggregate_errors(&recent_errors);
    if aggregated.is_empty() {
        out.push_str("Errors (last 7 days): (none)\n");
    } else {
        out.push_str("Errors (last 7 days):\n");
        for (i, err) in aggregated.iter().enumerate() {
            out.push_str(&format!(
                "  {}. {}: {} occurrences\n",
                i + 1,
                err.category,
                err.count,
            ));
        }
    }

    out.push('\n');
    out.push_str("No PII, document content, or file paths included in this report.\n");

    out
}

/// Emit the diagnostic report as pretty-printed JSON.
///
/// The schema mirrors `DiagnosticReport` one-for-one -- every field is a
/// direct serde projection of the Rust struct, so consumers can rely on
/// names like `version`, `platform.macos_version`, `engine.rule_count`,
/// and `privacy.mode`. Adding new fields in the future is backwards-
/// compatible for `jq` consumers because unknown keys are simply ignored.
///
/// Why pretty-printed: `hive --diagnostics --json | jq '.version'` should
/// work interactively.
/// Pretty output is still `jq`-parseable and is a better default for a
/// human who just pipes without a filter. Consumers who want compact
/// output can feed through `jq -c .` themselves.
///
/// Why `Result`: `serde_json::to_string_pretty` can only fail if one of
/// the `Serialize` impls returns an error, which none of ours do today;
/// exposing the `Result` keeps us safe against future additions (e.g. a
/// custom serializer that validates bounds).
pub fn format_report_json(report: &DiagnosticReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

/// Build a DiagnosticReport from the current system state.
/// This is the main entry point called by `hive --diagnostics`.
///
/// The eight arguments are the independent diagnostic slices collected by the
/// CLI; bundling them into a struct would merely rename this signature without
/// reducing caller complexity.
#[allow(clippy::too_many_arguments)]
pub fn build_report(
    version: &str,
    engine: EngineState,
    pipeline: PipelineState,
    privacy: PrivacyState,
    p2p: P2PState,
    model_status: &str,
    last_extractions: Vec<ExtractionStat>,
    error_history: Vec<ErrorStat>,
) -> DiagnosticReport {
    let platform = detect_platform();
    DiagnosticReport {
        version: version.to_string(),
        platform,
        model_status: model_status.to_string(),
        engine,
        pipeline,
        privacy,
        p2p,
        last_extractions,
        error_history,
    }
}

/// Validate that a report string contains no PII indicators.
/// Used in tests to ensure diagnostic output is safe.
pub fn check_no_pii(report: &str) -> bool {
    // Check for common PII patterns
    let pii_patterns = [
        "/Users/",
        "/home/",
        "/tmp/",
        "C:\\Users\\",
        "@", // email addresses
    ];
    for pattern in &pii_patterns {
        // Allow the pattern in the footer disclaimer line
        let lines: Vec<&str> = report.lines().collect();
        for line in &lines {
            if line.contains("No PII") {
                continue;
            }
            if line.contains(pattern) {
                return false;
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Tests (~15)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> DiagnosticReport {
        DiagnosticReport {
            version: "v0.1.0-alpha.39".to_string(),
            platform: PlatformInfo {
                macos_version: "15.4".to_string(),
                chip: "Apple M4 Pro".to_string(),
                ram_gb: 48,
                python_version: "3.12.1".to_string(),
                mlx_version: "0.22.0".to_string(),
            },
            model_status: "not loaded".to_string(),
            engine: EngineState {
                rule_count: 40,
                wme_count: 120,
            },
            pipeline: PipelineState {
                mock_documents: 5,
                live_documents: 0,
            },
            privacy: PrivacyState {
                mode: "local_only".to_string(),
                budget_remaining_pct: 100,
            },
            p2p: P2PState {
                enabled: false,
                peer_count: 0,
            },
            last_extractions: vec![
                ExtractionStat {
                    doc_type: "medical_bill".to_string(),
                    success: true,
                    latency_secs: 0.3,
                    entity_count: 3,
                    relationship_count: 2,
                },
                ExtractionStat {
                    doc_type: "lease_agreement".to_string(),
                    success: true,
                    latency_secs: 0.2,
                    entity_count: 3,
                    relationship_count: 2,
                },
                ExtractionStat {
                    doc_type: "general".to_string(),
                    success: false,
                    latency_secs: 60.0,
                    entity_count: 0,
                    relationship_count: 0,
                },
            ],
            error_history: vec![
                ErrorStat {
                    category: "ExtractionTimeout".to_string(),
                    count: 2,
                    last_seen: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                },
                ErrorStat {
                    category: "MalformedOutput".to_string(),
                    count: 1,
                    last_seen: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                },
            ],
        }
    }

    // --- Report format validation ---

    #[test]
    fn test_report_contains_header() {
        let report = format_report(&sample_report());
        assert!(report.contains("HIVE Diagnostic Report ("));
        assert!(report.contains("====================================="));
    }

    #[test]
    fn test_report_contains_version() {
        let report = format_report(&sample_report());
        assert!(report.contains("Version: v0.1.0-alpha.39"));
    }

    #[test]
    fn test_report_contains_platform() {
        let report = format_report(&sample_report());
        assert!(report.contains("macOS 15.4"));
        assert!(report.contains("Apple M4 Pro"));
        assert!(report.contains("48 GB RAM"));
    }

    #[test]
    fn test_report_contains_engine_state() {
        let report = format_report(&sample_report());
        assert!(report.contains("Engine: 40 rules, 120 WMEs"));
    }

    #[test]
    fn test_report_contains_pipeline_state() {
        let report = format_report(&sample_report());
        assert!(report.contains("Pipeline: mock=5, live=0 documents processed"));
    }

    #[test]
    fn test_report_contains_extractions() {
        let report = format_report(&sample_report());
        assert!(report.contains("[medical_bill] [OK]"));
        assert!(report.contains("[lease_agreement] [OK]"));
        assert!(report.contains("[general] [FAIL]"));
    }

    #[test]
    fn test_report_contains_errors() {
        let report = format_report(&sample_report());
        assert!(report.contains("ExtractionTimeout: 2 occurrences"));
        assert!(report.contains("MalformedOutput: 1 occurrences"));
    }

    #[test]
    fn test_report_contains_footer() {
        let report = format_report(&sample_report());
        assert!(report.contains("No PII, document content, or file paths included in this report."));
    }

    // --- Platform detection ---

    #[test]
    fn test_platform_detection_returns_values() {
        let platform = detect_platform();
        // On macOS, at least the version and RAM should be detected
        assert!(!platform.macos_version.is_empty());
        // RAM must be > 0 on any real machine
        // (in CI this might be "unknown", so just check it doesn't panic)
    }

    // --- Statistics aggregation ---

    #[test]
    fn test_empty_extractions() {
        let report = DiagnosticReport {
            last_extractions: vec![],
            ..sample_report()
        };
        let output = format_report(&report);
        assert!(output.contains("Last 5 extractions: (none)"));
    }

    #[test]
    fn test_extractions_capped_at_five() {
        let mut r = sample_report();
        r.last_extractions = (0..10)
            .map(|i| ExtractionStat {
                doc_type: format!("type_{}", i),
                success: true,
                latency_secs: 0.1 * i as f64,
                entity_count: i,
                relationship_count: i,
            })
            .collect();
        let output = format_report(&r);
        // Should show exactly 5, not 10
        assert!(output.contains("Last 5 extractions:"));
        assert!(output.contains("[type_0]"));
        assert!(output.contains("[type_4]"));
        assert!(!output.contains("[type_5]"));
    }

    // --- Error history filters to 7 days ---

    #[test]
    fn test_error_history_filters_old() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let errors = vec![
            ErrorStat {
                category: "Recent".to_string(),
                count: 1,
                last_seen: now,
            },
            ErrorStat {
                category: "Old".to_string(),
                count: 5,
                last_seen: now - 8 * 24 * 3600, // 8 days ago
            },
        ];
        let filtered = filter_errors_last_7_days(&errors);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].category, "Recent");
    }

    #[test]
    fn test_error_aggregation() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let errors = vec![
            ErrorStat {
                category: "Timeout".to_string(),
                count: 2,
                last_seen: now,
            },
            ErrorStat {
                category: "Timeout".to_string(),
                count: 3,
                last_seen: now - 100,
            },
            ErrorStat {
                category: "OOM".to_string(),
                count: 1,
                last_seen: now,
            },
        ];
        let agg = aggregate_errors(&errors);
        assert_eq!(agg.len(), 2);
        // Timeout should have 5 total, OOM should have 1
        let timeout = agg.iter().find(|e| e.category == "Timeout").unwrap();
        assert_eq!(timeout.count, 5);
    }

    // --- No PII leakage ---

    #[test]
    fn test_no_pii_in_report() {
        let report = format_report(&sample_report());
        assert!(
            check_no_pii(&report),
            "Report must not contain PII indicators"
        );
    }

    #[test]
    fn test_check_no_pii_catches_paths() {
        assert!(!check_no_pii("File: /Users/john/documents/tax.pdf"));
        assert!(!check_no_pii("Path: /home/user/data.txt"));
    }

    // --- Date formatting ---

    #[test]
    fn test_current_date_format() {
        let date = current_date_string();
        assert_eq!(date.len(), 10, "Date must be YYYY-MM-DD: {}", date);
        assert_eq!(&date[4..5], "-");
        assert_eq!(&date[7..8], "-");
        let year: u64 = date[0..4].parse().expect("year must be numeric");
        assert!((2024..=2100).contains(&year));
    }

    #[test]
    fn test_days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_date() {
        // 2024-01-01 is day 19723
        let (y, m, d) = days_to_ymd(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    // -----------------------------------------------------------------------
    // JSON emitter contract tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_json_report_parses_as_valid_json() {
        let json = format_report_json(&sample_report())
            .expect("format_report_json must not fail on a clean sample");
        let v: serde_json::Value =
            serde_json::from_str(&json).expect("emitted string must be valid JSON");
        assert!(v.is_object(), "top-level report must be a JSON object");
    }

    #[test]
    fn test_json_report_has_stable_schema() {
        // Schema-contract test: the stable top-level keys consumers
        // will hit with `jq '.version'`, `.engine.rule_count`, etc.
        let json = format_report_json(&sample_report()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["version"], "v0.1.0-alpha.39");
        assert!(v["platform"].is_object());
        assert_eq!(v["platform"]["macos_version"], "15.4");
        assert_eq!(v["platform"]["chip"], "Apple M4 Pro");
        assert_eq!(v["platform"]["ram_gb"], 48);
        assert_eq!(v["engine"]["rule_count"], 40);
        assert_eq!(v["engine"]["wme_count"], 120);
        assert_eq!(v["pipeline"]["mock_documents"], 5);
        assert_eq!(v["pipeline"]["live_documents"], 0);
        assert_eq!(v["privacy"]["mode"], "local_only");
        assert_eq!(v["privacy"]["budget_remaining_pct"], 100);
        assert_eq!(v["p2p"]["enabled"], false);
        assert_eq!(v["p2p"]["peer_count"], 0);
        assert_eq!(v["model_status"], "not loaded");
        assert!(v["last_extractions"].is_array());
        assert!(v["error_history"].is_array());
    }

    #[test]
    fn test_json_report_extraction_entries_preserve_fields() {
        let json = format_report_json(&sample_report()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let first = &v["last_extractions"][0];
        assert_eq!(first["doc_type"], "medical_bill");
        assert_eq!(first["success"], true);
        assert_eq!(first["entity_count"], 3);
        assert_eq!(first["relationship_count"], 2);
    }

    #[test]
    fn test_json_report_is_pretty_printed() {
        // `jq` should pipe cleanly, but a
        // human hitting the command without a filter should see readable
        // output. Pretty printing puts one field per line.
        let json = format_report_json(&sample_report()).unwrap();
        assert!(
            json.contains('\n'),
            "output must be pretty-printed (has newlines)"
        );
        assert!(json.trim_start().starts_with('{'));
    }

    #[test]
    fn test_json_report_roundtrips_via_serde_value() {
        // Defensive: if a future change breaks `Serialize` on any nested
        // struct, this roundtrip will catch it before the `jq` user does.
        let json = format_report_json(&sample_report()).unwrap();
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }
}
