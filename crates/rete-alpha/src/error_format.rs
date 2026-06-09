//! Standardized WHAT/WHY/DO error formatting for HIVE.
//!
//! All user-facing error messages follow a consistent format:
//!   Error: <what went wrong>
//!     Why: <why it happened>
//!      Do: <actionable fix>

/// Format a user-facing error in WHAT/WHY/DO style.
///
/// - `what`: one-line description of what went wrong
/// - `why`:  one-line reason (pass `None` if unknowable)
/// - `do_action`: one-line actionable fix
///
/// Returns a multi-line string. Lines are kept under 80 chars
/// by the caller (this function does not wrap).
pub fn format_error(what: &str, why: Option<&str>, do_action: &str) -> String {
    match why {
        Some(reason) => {
            format!("Error: {}\n  Why: {}\n   Do: {}", what, reason, do_action)
        }
        None => {
            format!("Error: {}\n   Do: {}", what, do_action)
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_with_why() {
        let msg = format_error(
            "Extraction process crashed.",
            Some("Python runtime error or signal."),
            "Run extraction_service.py standalone.",
        );
        assert!(msg.starts_with("Error: "));
        assert!(msg.contains("  Why: "));
        assert!(msg.contains("   Do: "));
        assert!(msg.contains("Extraction process crashed."));
        assert!(msg.contains("Python runtime error or signal."));
        assert!(msg.contains("Run extraction_service.py standalone."));
    }

    #[test]
    fn test_format_without_why() {
        let msg = format_error(
            "Config file not found.",
            None,
            "Run hive to create a default config.",
        );
        assert!(msg.starts_with("Error: Config file not found."));
        assert!(!msg.contains("Why:"));
        assert!(msg.contains("   Do: "));
    }

    #[test]
    fn test_exact_format_with_why() {
        let msg = format_error("A", Some("B"), "C");
        assert_eq!(msg, "Error: A\n  Why: B\n   Do: C");
    }

    #[test]
    fn test_exact_format_without_why() {
        let msg = format_error("A", None, "C");
        assert_eq!(msg, "Error: A\n   Do: C");
    }
}
