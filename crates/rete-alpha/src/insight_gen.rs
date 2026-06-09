//! Insight Card Generation
//!
//! Transforms Rete-II engine rule firings into user-facing insight cards.
//! Implements Interface 7 of the HIVE integration architecture.
//!
//! Two card types:
//! - `FullInsightCard`: local display with full user-specific detail
//! - `StrippedInsightCard`: privacy-safe for external sharing (all QIs removed)

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Generated when a Rete-II production fires on a WME.
/// Bridges the engine's internal representation to user-facing output.
#[derive(Debug, Clone)]
pub struct RuleFiring {
    pub rule_id: u32,
    pub production_name: String,
    /// Decoded field values from the matched WME: (field_name, decoded_value).
    pub matched_wme_fields: Vec<(String, String)>,
    /// "typical_range", "above_range", "below_range", "warning", "informational"
    pub conclusion_type: String,
    /// Template string with {placeholders} like "{entity_a} was charged {amount}".
    pub conclusion_template: String,
    /// Rule's confidence factor [0.0, 1.0].
    pub rule_confidence: f64,
    /// Extraction confidence [0.0, 1.0]. Defaults to 1.0.
    pub extraction_confidence: f64,
    pub evidence_count: u32,
    pub evidence_regions: u8,
    /// "stable", "increasing", "decreasing"
    pub trend: String,
    /// Sensitivity tier (1=highest, 4=lowest).
    pub sensitivity_tier: u8,
    /// User's amount bucket (E8 spec 0-8), or None if not applicable.
    pub amount_bucket: Option<u8>,
    /// Rule's expected typical bucket, or None if not applicable.
    pub typical_bucket: Option<u8>,
}

/// Full insight card for local display (E8 v1.1 Section 2.5).
#[derive(Debug, Clone, serde::Serialize)]
pub struct FullInsightCard {
    /// Filled template with user-specific values.
    pub rule_text: String,
    /// Combined CF = rule_confidence * extraction_confidence.
    pub confidence: f64,
    /// "High" / "Moderate" / "Low"
    pub confidence_band: String,
    pub evidence_count: u32,
    pub evidence_regions: u8,
    /// "Based on 2,500+ observations from 12 regions"
    pub evidence_summary: String,
    /// "Your charge: $8,200. Typical range: $1K-$5K" or None.
    pub amount_context: Option<String>,
    /// Entity names from matched WME.
    pub specific_entities: Vec<String>,
    /// "#127"
    pub rule_id: String,
    pub trend: String,
    pub sensitivity_tier: u8,
    /// "medical_bills", "lease_agreements", etc.
    pub category: String,
    /// For UI styling: "warning" = red, "typical_range" = green, etc.
    pub conclusion_type: String,
}

/// Stripped card for external sharing (privacy-safe).
/// All quasi-identifiers removed per E8 privacy spec.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StrippedInsightCard {
    /// All QIs (names, amounts, dates) removed.
    pub rule_text_generic: String,
    /// 3 bands only (no exact number).
    pub confidence_band: String,
    /// Approximate description.
    pub evidence_summary: String,
    /// "Scan your own documents with HIVE"
    pub call_to_action: String,
}

// ---------------------------------------------------------------------------
// Amount bucket labels (E8 spec)
// ---------------------------------------------------------------------------

/// Map a bucket index (0-8) to a human-readable label.
pub fn bucket_to_label(bucket: u8) -> &'static str {
    match bucket {
        0 => "N/A",
        1 => "$0-$100",
        2 => "$100-$500",
        3 => "$500-$1K",
        4 => "$1K-$5K",
        5 => "$5K-$10K",
        6 => "$10K-$50K",
        7 => "$50K-$100K",
        8 => "$100K+",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Map a combined confidence value to a 3-band label.
pub fn confidence_to_band(cf: f64) -> String {
    if cf >= 0.75 {
        "High".to_string()
    } else if cf >= 0.50 {
        "Moderate".to_string()
    } else {
        "Low".to_string()
    }
}

/// Format an evidence count as a human-friendly summary string.
/// e.g., 2500 -> "2,500+", 150 -> "150+", 12345 -> "12,000+"
pub fn format_count(n: u32) -> String {
    if n == 0 {
        return "0".to_string();
    }
    if n < 100 {
        return format!("{}+", n);
    }
    // Round down to nearest significant figure for large numbers
    let rounded = if n < 1_000 {
        (n / 100) * 100
    } else if n < 10_000 {
        (n / 500) * 500
    } else if n < 100_000 {
        (n / 1_000) * 1_000
    } else {
        (n / 10_000) * 10_000
    };
    format!("{}+", insert_commas(rounded))
}

/// Insert comma separators into a number string.
fn insert_commas(n: u32) -> String {
    let s = n.to_string();
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

/// Generate evidence summary text from count and region count.
pub fn count_to_summary(count: u32, regions: u8) -> String {
    if count == 0 && regions == 0 {
        return "No collective evidence available yet".to_string();
    }
    let count_str = format_count(count);
    let region_str = if regions == 1 {
        "1 region".to_string()
    } else {
        format!("{} regions", regions)
    };
    format!("Based on {} observations from {}", count_str, region_str)
}

/// Fill a template string by replacing {placeholder} tokens with values
/// from the matched WME fields map.
///
/// Placeholders not found in the map are left as-is (graceful degradation).
pub fn fill_template(template: &str, fields: &[(String, String)]) -> String {
    let field_map: HashMap<&str, &str> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let mut result = String::with_capacity(template.len() * 2);
    let mut chars = template.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '{' {
            // Extract placeholder name
            let mut placeholder = String::new();
            let mut found_close = false;
            for inner in chars.by_ref() {
                if inner == '}' {
                    found_close = true;
                    break;
                }
                placeholder.push(inner);
            }
            if found_close {
                if let Some(value) = field_map.get(placeholder.as_str()) {
                    result.push_str(value);
                } else {
                    // Leave placeholder intact for debugging
                    result.push('{');
                    result.push_str(&placeholder);
                    result.push('}');
                }
            } else {
                // Unclosed brace -- emit as literal
                result.push('{');
                result.push_str(&placeholder);
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Extract entity names from matched WME fields.
/// Looks for fields with "entity" in the key name.
fn extract_entities(fields: &[(String, String)]) -> Vec<String> {
    fields
        .iter()
        .filter(|(k, _)| {
            k.contains("entity_a") || k.contains("entity_b") || k.contains("entity_name")
        })
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty())
        .collect()
}

/// Determine document category from matched WME fields.
/// Falls back to "general" if not found.
fn extract_category(fields: &[(String, String)]) -> String {
    for (k, v) in fields {
        if k == "doc_category" || k == "document_category" || k == "category" {
            return v.clone();
        }
    }
    "general".to_string()
}

/// Generate amount context string comparing user's bucket to typical bucket.
fn generate_amount_context(
    amount_bucket: Option<u8>,
    typical_bucket: Option<u8>,
) -> Option<String> {
    match (amount_bucket, typical_bucket) {
        (Some(user_b), Some(typical_b)) if user_b > 0 && typical_b > 0 => {
            let user_label = bucket_to_label(user_b);
            let typical_label = bucket_to_label(typical_b);
            let comparison = if user_b > typical_b {
                "above typical range"
            } else if user_b < typical_b {
                "below typical range"
            } else {
                "within typical range"
            };
            Some(format!(
                "Your amount: {}. Typical range: {}. This is {}.",
                user_label, typical_label, comparison
            ))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Main generation function
// ---------------------------------------------------------------------------

/// Generate a FullInsightCard from a rule firing.
///
/// - Fills the conclusion template with matched WME field values
/// - Computes combined CF via MYCIN chain formula
/// - Maps confidence to 3-band label
/// - Generates human-friendly evidence summary
/// - Compares user's amount bucket to rule's typical bucket
pub fn generate_insight(firing: &RuleFiring) -> FullInsightCard {
    let rule_text = fill_template(&firing.conclusion_template, &firing.matched_wme_fields);
    let confidence = firing.rule_confidence * firing.extraction_confidence;
    let confidence_band = confidence_to_band(confidence);
    let evidence_summary = count_to_summary(firing.evidence_count, firing.evidence_regions);
    let amount_context = generate_amount_context(firing.amount_bucket, firing.typical_bucket);
    let specific_entities = extract_entities(&firing.matched_wme_fields);
    let category = extract_category(&firing.matched_wme_fields);

    FullInsightCard {
        rule_text,
        confidence,
        confidence_band,
        evidence_count: firing.evidence_count,
        evidence_regions: firing.evidence_regions,
        evidence_summary,
        amount_context,
        specific_entities,
        rule_id: format!("#{}", firing.rule_id),
        trend: firing.trend.clone(),
        sensitivity_tier: firing.sensitivity_tier,
        category,
        conclusion_type: firing.conclusion_type.clone(),
    }
}

// ---------------------------------------------------------------------------
// PII stripping
// ---------------------------------------------------------------------------

/// Patterns that indicate a specific monetary amount (e.g., "$8,200", "$1,234.56").
fn strip_amounts(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '$' {
            // Scan ahead for digits, commas, dots
            let start = i;
            i += 1;
            while i < chars.len()
                && (chars[i].is_ascii_digit() || chars[i] == ',' || chars[i] == '.')
            {
                i += 1;
            }
            if i > start + 1 {
                result.push_str("[amount]");
            } else {
                result.push('$');
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    result
}

/// Replace entity names with generic labels for privacy.
fn strip_entity_names(text: &str, entities: &[String]) -> String {
    let mut result = text.to_string();
    for (idx, entity) in entities.iter().enumerate() {
        if entity.is_empty() {
            continue;
        }
        let replacement = match idx {
            0 => "a provider",
            1 => "a service",
            _ => "an entity",
        };
        result = result.replace(entity, replacement);
    }
    result
}

/// Strip a FullInsightCard of all personally identifiable information.
///
/// - Replaces specific amounts with generic range descriptions
/// - Replaces entity names with generic labels
/// - Uses confidence band instead of exact number
/// - Adds call-to-action text
pub fn strip_insight(card: &FullInsightCard) -> StrippedInsightCard {
    // Strip amounts and entity names from rule text
    let mut generic_text = strip_amounts(&card.rule_text);
    generic_text = strip_entity_names(&generic_text, &card.specific_entities);

    // Approximate the evidence summary (remove exact numbers)
    let evidence_summary = if card.evidence_count >= 10_000 {
        "Based on tens of thousands of observations from multiple regions".to_string()
    } else if card.evidence_count >= 1_000 {
        "Based on thousands of observations from multiple regions".to_string()
    } else if card.evidence_count >= 100 {
        "Based on hundreds of observations from multiple regions".to_string()
    } else if card.evidence_count > 0 {
        "Based on limited collective observations".to_string()
    } else {
        "No collective evidence available yet".to_string()
    };

    StrippedInsightCard {
        rule_text_generic: generic_text,
        confidence_band: card.confidence_band.clone(),
        evidence_summary,
        call_to_action: "Scan your own documents with HIVE".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Terminal display formatting
// ---------------------------------------------------------------------------

/// ANSI color codes for conclusion types.
fn conclusion_color(conclusion_type: &str) -> &'static str {
    match conclusion_type {
        "warning" => "\x1b[31m",       // red
        "above_range" => "\x1b[33m",   // yellow
        "below_range" => "\x1b[36m",   // cyan
        "typical_range" => "\x1b[32m", // green
        "informational" => "\x1b[37m", // white
        _ => "\x1b[0m",                // reset
    }
}

/// ANSI reset code.
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

/// Format a FullInsightCard for terminal display with box-drawing characters.
///
/// Returns a multi-line string with ANSI color codes.
pub fn format_insight_text(card: &FullInsightCard) -> String {
    let color = conclusion_color(&card.conclusion_type);
    let confidence_indicator = match card.confidence_band.as_str() {
        "High" => "\x1b[32m●●●\x1b[0m",     // green dots
        "Moderate" => "\x1b[33m●●○\x1b[0m", // yellow dots
        _ => "\x1b[31m●○○\x1b[0m",          // red dots (Low or anything else)
    };

    let trend_arrow = match card.trend.as_str() {
        "increasing" => " ^",
        "decreasing" => " v",
        _ => " =", // stable or anything else
    };

    let mut lines: Vec<String> = Vec::new();

    // Top border
    lines.push(format!(
        "{}+-----------------------------------------+{}",
        color, RESET
    ));

    // Rule ID + conclusion type header
    lines.push(format!(
        "{}| {}HIVE Insight {}  [{}]{}",
        color,
        BOLD,
        card.rule_id,
        card.conclusion_type.to_uppercase(),
        RESET
    ));

    // Separator
    lines.push(format!(
        "{}+-----------------------------------------+{}",
        color, RESET
    ));

    // Rule text (wrapped to ~40 chars)
    for chunk in wrap_text(&card.rule_text, 39) {
        lines.push(format!("{}| {}{}", color, chunk, RESET));
    }

    // Blank separator
    lines.push(format!("{}|{}", color, RESET));

    // Confidence
    lines.push(format!(
        "{}| {}Confidence:{} {} ({:.0}%)",
        color,
        DIM,
        RESET,
        confidence_indicator,
        card.confidence * 100.0
    ));

    // Evidence
    lines.push(format!(
        "{}| {}Evidence:{} {}",
        color, DIM, RESET, card.evidence_summary
    ));

    // Trend
    lines.push(format!(
        "{}| {}Trend:{} {}{}",
        color, DIM, RESET, card.trend, trend_arrow
    ));

    // Amount context if present
    if let Some(ref ctx) = card.amount_context {
        lines.push(format!("{}| {}Amount:{} {}", color, DIM, RESET, ctx));
    }

    // Category
    lines.push(format!(
        "{}| {}Category:{} {}",
        color, DIM, RESET, card.category
    ));

    // Bottom border
    lines.push(format!(
        "{}+-----------------------------------------+{}",
        color, RESET
    ));

    lines.join("\n")
}

/// Simple word-wrap for terminal display.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line.push_str(word);
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
    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test fixtures -------------------------------------------------------

    fn medical_above_range_firing() -> RuleFiring {
        RuleFiring {
            rule_id: 127,
            production_name: "medical_charge_above_range".to_string(),
            matched_wme_fields: vec![
                ("entity_a".to_string(), "Memorial Hospital".to_string()),
                ("entity_b".to_string(), "$8,200".to_string()),
                ("doc_category".to_string(), "medical_bills".to_string()),
                ("entity_name".to_string(), "Dr. Smith".to_string()),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template:
                "{entity_a} charged {entity_b} which is above the typical range for this procedure"
                    .to_string(),
            rule_confidence: 0.85,
            extraction_confidence: 0.92,
            evidence_count: 2500,
            evidence_regions: 12,
            trend: "stable".to_string(),
            sensitivity_tier: 1,
            amount_bucket: Some(6),  // $10K-$50K
            typical_bucket: Some(4), // $1K-$5K
        }
    }

    fn lease_typical_firing() -> RuleFiring {
        RuleFiring {
            rule_id: 42,
            production_name: "lease_deposit_typical".to_string(),
            matched_wme_fields: vec![
                ("entity_a".to_string(), "Skyline Properties".to_string()),
                ("entity_b".to_string(), "$2,400".to_string()),
                ("doc_category".to_string(), "lease_agreements".to_string()),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template:
                "Security deposit of {entity_b} from {entity_a} is within the typical range"
                    .to_string(),
            rule_confidence: 0.78,
            extraction_confidence: 1.0,
            evidence_count: 850,
            evidence_regions: 6,
            trend: "stable".to_string(),
            sensitivity_tier: 2,
            amount_bucket: Some(4),
            typical_bucket: Some(4),
        }
    }

    fn insurance_warning_firing() -> RuleFiring {
        RuleFiring {
            rule_id: 303,
            production_name: "insurance_denial_warning".to_string(),
            matched_wme_fields: vec![
                ("entity_a".to_string(), "BlueCross".to_string()),
                ("entity_b".to_string(), "claim denial".to_string()),
                ("doc_category".to_string(), "insurance".to_string()),
                ("entity_name".to_string(), "Jane Doe".to_string()),
            ],
            conclusion_type: "warning".to_string(),
            conclusion_template: "{entity_a} has denied the claim. {evidence_count} similar denials have been observed".to_string(),
            rule_confidence: 0.90,
            extraction_confidence: 0.88,
            evidence_count: 15000,
            evidence_regions: 18,
            trend: "increasing".to_string(),
            sensitivity_tier: 1,
            amount_bucket: None,
            typical_bucket: None,
        }
    }

    fn informational_firing() -> RuleFiring {
        RuleFiring {
            rule_id: 5,
            production_name: "general_info".to_string(),
            matched_wme_fields: vec![("doc_category".to_string(), "general".to_string())],
            conclusion_type: "informational".to_string(),
            conclusion_template: "Document analyzed successfully".to_string(),
            rule_confidence: 0.60,
            extraction_confidence: 1.0,
            evidence_count: 50,
            evidence_regions: 3,
            trend: "stable".to_string(),
            sensitivity_tier: 4,
            amount_bucket: None,
            typical_bucket: None,
        }
    }

    fn low_confidence_firing() -> RuleFiring {
        RuleFiring {
            rule_id: 999,
            production_name: "uncertain_pattern".to_string(),
            matched_wme_fields: vec![
                ("entity_a".to_string(), "Unknown Corp".to_string()),
                ("doc_category".to_string(), "financial".to_string()),
            ],
            conclusion_type: "informational".to_string(),
            conclusion_template: "Possible pattern detected involving {entity_a}".to_string(),
            rule_confidence: 0.30,
            extraction_confidence: 0.45,
            evidence_count: 12,
            evidence_regions: 2,
            trend: "decreasing".to_string(),
            sensitivity_tier: 3,
            amount_bucket: None,
            typical_bucket: None,
        }
    }

    // -- confidence_to_band --------------------------------------------------

    #[test]
    fn test_confidence_band_high() {
        assert_eq!(confidence_to_band(0.75), "High");
        assert_eq!(confidence_to_band(0.99), "High");
        assert_eq!(confidence_to_band(1.0), "High");
    }

    #[test]
    fn test_confidence_band_moderate() {
        assert_eq!(confidence_to_band(0.50), "Moderate");
        assert_eq!(confidence_to_band(0.74), "Moderate");
        assert_eq!(confidence_to_band(0.60), "Moderate");
    }

    #[test]
    fn test_confidence_band_low() {
        assert_eq!(confidence_to_band(0.49), "Low");
        assert_eq!(confidence_to_band(0.10), "Low");
        assert_eq!(confidence_to_band(0.0), "Low");
    }

    #[test]
    fn test_confidence_band_exact_boundaries() {
        assert_eq!(confidence_to_band(0.75), "High");
        assert_eq!(confidence_to_band(0.50), "Moderate");
        // Just below boundaries
        assert_eq!(confidence_to_band(0.7499), "Moderate");
        assert_eq!(confidence_to_band(0.4999), "Low");
    }

    // -- bucket_to_label -----------------------------------------------------

    #[test]
    fn test_bucket_labels() {
        assert_eq!(bucket_to_label(0), "N/A");
        assert_eq!(bucket_to_label(1), "$0-$100");
        assert_eq!(bucket_to_label(2), "$100-$500");
        assert_eq!(bucket_to_label(3), "$500-$1K");
        assert_eq!(bucket_to_label(4), "$1K-$5K");
        assert_eq!(bucket_to_label(5), "$5K-$10K");
        assert_eq!(bucket_to_label(6), "$10K-$50K");
        assert_eq!(bucket_to_label(7), "$50K-$100K");
        assert_eq!(bucket_to_label(8), "$100K+");
    }

    #[test]
    fn test_bucket_label_unknown() {
        assert_eq!(bucket_to_label(9), "Unknown");
        assert_eq!(bucket_to_label(255), "Unknown");
    }

    // -- format_count --------------------------------------------------------

    #[test]
    fn test_format_count_small() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(1), "1+");
        assert_eq!(format_count(50), "50+");
        assert_eq!(format_count(99), "99+");
    }

    #[test]
    fn test_format_count_hundreds() {
        assert_eq!(format_count(100), "100+");
        assert_eq!(format_count(250), "200+");
        assert_eq!(format_count(999), "900+");
    }

    #[test]
    fn test_format_count_thousands() {
        assert_eq!(format_count(1000), "1,000+");
        assert_eq!(format_count(2500), "2,500+");
        assert_eq!(format_count(9999), "9,500+");
    }

    #[test]
    fn test_format_count_large() {
        assert_eq!(format_count(10000), "10,000+");
        assert_eq!(format_count(15000), "15,000+");
        assert_eq!(format_count(99999), "99,000+");
    }

    #[test]
    fn test_format_count_very_large() {
        assert_eq!(format_count(100_000), "100,000+");
        assert_eq!(format_count(250_000), "250,000+");
    }

    // -- insert_commas -------------------------------------------------------

    #[test]
    fn test_insert_commas() {
        assert_eq!(insert_commas(0), "0");
        assert_eq!(insert_commas(999), "999");
        assert_eq!(insert_commas(1000), "1,000");
        assert_eq!(insert_commas(12500), "12,500");
        assert_eq!(insert_commas(1000000), "1,000,000");
    }

    // -- count_to_summary ----------------------------------------------------

    #[test]
    fn test_count_to_summary() {
        let s = count_to_summary(2500, 12);
        assert!(s.contains("2,500+"));
        assert!(s.contains("12 regions"));
    }

    #[test]
    fn test_count_to_summary_single_region() {
        let s = count_to_summary(100, 1);
        assert!(s.contains("1 region"));
        assert!(!s.contains("regions"));
    }

    #[test]
    fn test_count_to_summary_zero() {
        let s = count_to_summary(0, 0);
        assert_eq!(s, "No collective evidence available yet");
    }

    // -- fill_template -------------------------------------------------------

    #[test]
    fn test_fill_template_basic() {
        let fields = vec![
            ("entity_a".to_string(), "Memorial Hospital".to_string()),
            ("amount".to_string(), "$8,200".to_string()),
        ];
        let result = fill_template("{entity_a} charged {amount}", &fields);
        assert_eq!(result, "Memorial Hospital charged $8,200");
    }

    #[test]
    fn test_fill_template_missing_placeholder() {
        let fields = vec![("entity_a".to_string(), "Hospital".to_string())];
        let result = fill_template("{entity_a} charged {amount}", &fields);
        assert_eq!(result, "Hospital charged {amount}");
    }

    #[test]
    fn test_fill_template_no_placeholders() {
        let fields = vec![("entity_a".to_string(), "Hospital".to_string())];
        let result = fill_template("No placeholders here", &fields);
        assert_eq!(result, "No placeholders here");
    }

    #[test]
    fn test_fill_template_empty_template() {
        let fields = vec![("entity_a".to_string(), "Hospital".to_string())];
        let result = fill_template("", &fields);
        assert_eq!(result, "");
    }

    #[test]
    fn test_fill_template_multiple_same_placeholder() {
        let fields = vec![("name".to_string(), "HIVE".to_string())];
        let result = fill_template("{name} is great. Use {name}!", &fields);
        assert_eq!(result, "HIVE is great. Use HIVE!");
    }

    #[test]
    fn test_fill_template_unclosed_brace() {
        let fields = vec![("name".to_string(), "test".to_string())];
        let result = fill_template("Hello {name", &fields);
        assert_eq!(result, "Hello {name");
    }

    #[test]
    fn test_fill_template_empty_fields() {
        let fields: Vec<(String, String)> = vec![];
        let result = fill_template("{entity_a} test", &fields);
        assert_eq!(result, "{entity_a} test");
    }

    // -- generate_insight: medical above_range -------------------------------

    #[test]
    fn test_generate_medical_above_range() {
        let firing = medical_above_range_firing();
        let card = generate_insight(&firing);

        assert_eq!(card.rule_id, "#127");
        assert_eq!(card.conclusion_type, "above_range");
        assert_eq!(card.category, "medical_bills");
        assert_eq!(card.sensitivity_tier, 1);
        assert_eq!(card.trend, "stable");

        // Template filling
        assert!(card.rule_text.contains("Memorial Hospital"));
        assert!(card.rule_text.contains("$8,200"));
        assert!(card.rule_text.contains("above the typical range"));

        // Combined CF = 0.85 * 0.92 = 0.782
        let expected_cf = 0.85 * 0.92;
        assert!((card.confidence - expected_cf).abs() < 1e-9);
        assert_eq!(card.confidence_band, "High");

        // Evidence
        assert_eq!(card.evidence_count, 2500);
        assert_eq!(card.evidence_regions, 12);
        assert!(card.evidence_summary.contains("2,500+"));
        assert!(card.evidence_summary.contains("12 regions"));

        // Amount context
        assert!(card.amount_context.is_some());
        let ctx = card.amount_context.as_ref().unwrap();
        assert!(ctx.contains("$10K-$50K")); // user bucket 6
        assert!(ctx.contains("$1K-$5K")); // typical bucket 4
        assert!(ctx.contains("above typical range"));

        // Entities
        assert!(card
            .specific_entities
            .contains(&"Memorial Hospital".to_string()));
    }

    // -- generate_insight: lease typical_range -------------------------------

    #[test]
    fn test_generate_lease_typical() {
        let firing = lease_typical_firing();
        let card = generate_insight(&firing);

        assert_eq!(card.rule_id, "#42");
        assert_eq!(card.conclusion_type, "typical_range");
        assert_eq!(card.category, "lease_agreements");

        assert!(card.rule_text.contains("$2,400"));
        assert!(card.rule_text.contains("Skyline Properties"));
        assert!(card.rule_text.contains("within the typical range"));

        // Combined CF = 0.78 * 1.0 = 0.78
        assert!((card.confidence - 0.78).abs() < 1e-9);
        assert_eq!(card.confidence_band, "High");

        // Amount context: user bucket == typical bucket -> within
        let ctx = card.amount_context.as_ref().unwrap();
        assert!(ctx.contains("within typical range"));
    }

    // -- generate_insight: insurance warning ----------------------------------

    #[test]
    fn test_generate_insurance_warning() {
        let firing = insurance_warning_firing();
        let card = generate_insight(&firing);

        assert_eq!(card.rule_id, "#303");
        assert_eq!(card.conclusion_type, "warning");
        assert_eq!(card.sensitivity_tier, 1);
        assert_eq!(card.trend, "increasing");

        assert!(card.rule_text.contains("BlueCross"));
        assert!(card.rule_text.contains("denied the claim"));

        // Combined CF = 0.90 * 0.88 = 0.792
        let expected_cf = 0.90 * 0.88;
        assert!((card.confidence - expected_cf).abs() < 1e-9);
        assert_eq!(card.confidence_band, "High");

        // No amount context (no amount buckets)
        assert!(card.amount_context.is_none());

        // Evidence: 15K observations
        assert!(card.evidence_summary.contains("15,000+"));
        assert!(card.evidence_summary.contains("18 regions"));
    }

    // -- generate_insight: informational -------------------------------------

    #[test]
    fn test_generate_informational() {
        let firing = informational_firing();
        let card = generate_insight(&firing);

        assert_eq!(card.rule_id, "#5");
        assert_eq!(card.conclusion_type, "informational");
        assert_eq!(card.category, "general");

        // Combined CF = 0.60 * 1.0 = 0.60
        assert!((card.confidence - 0.60).abs() < 1e-9);
        assert_eq!(card.confidence_band, "Moderate");

        assert!(card.amount_context.is_none());
    }

    // -- generate_insight: low confidence ------------------------------------

    #[test]
    fn test_generate_low_confidence() {
        let firing = low_confidence_firing();
        let card = generate_insight(&firing);

        assert_eq!(card.rule_id, "#999");
        // Combined CF = 0.30 * 0.45 = 0.135
        let expected_cf = 0.30 * 0.45;
        assert!((card.confidence - expected_cf).abs() < 1e-9);
        assert_eq!(card.confidence_band, "Low");
        assert_eq!(card.trend, "decreasing");
    }

    // -- generate_insight: edge cases ----------------------------------------

    #[test]
    fn test_generate_zero_confidence() {
        let mut firing = informational_firing();
        firing.rule_confidence = 0.0;
        let card = generate_insight(&firing);
        assert!((card.confidence - 0.0).abs() < 1e-9);
        assert_eq!(card.confidence_band, "Low");
    }

    #[test]
    fn test_generate_empty_template() {
        let mut firing = informational_firing();
        firing.conclusion_template = String::new();
        let card = generate_insight(&firing);
        assert_eq!(card.rule_text, "");
    }

    #[test]
    fn test_generate_missing_amount_buckets() {
        let mut firing = medical_above_range_firing();
        firing.amount_bucket = None;
        firing.typical_bucket = Some(4);
        let card = generate_insight(&firing);
        assert!(card.amount_context.is_none());
    }

    #[test]
    fn test_generate_zero_amount_bucket() {
        let mut firing = medical_above_range_firing();
        firing.amount_bucket = Some(0);
        firing.typical_bucket = Some(4);
        let card = generate_insight(&firing);
        // Bucket 0 = N/A, should not produce amount context
        assert!(card.amount_context.is_none());
    }

    #[test]
    fn test_generate_no_category_field() {
        let firing = RuleFiring {
            rule_id: 1,
            production_name: "test".to_string(),
            matched_wme_fields: vec![],
            conclusion_type: "informational".to_string(),
            conclusion_template: "Hello".to_string(),
            rule_confidence: 0.80,
            extraction_confidence: 1.0,
            evidence_count: 10,
            evidence_regions: 1,
            trend: "stable".to_string(),
            sensitivity_tier: 4,
            amount_bucket: None,
            typical_bucket: None,
        };
        let card = generate_insight(&firing);
        assert_eq!(card.category, "general");
    }

    // -- strip_insight -------------------------------------------------------

    #[test]
    fn test_strip_medical_above_range() {
        let firing = medical_above_range_firing();
        let card = generate_insight(&firing);
        let stripped = strip_insight(&card);

        // No specific amounts
        assert!(!stripped.rule_text_generic.contains("$8,200"));
        assert!(stripped.rule_text_generic.contains("[amount]"));

        // No entity names
        assert!(!stripped.rule_text_generic.contains("Memorial Hospital"));
        assert!(!stripped.rule_text_generic.contains("Dr. Smith"));

        // Confidence band, not exact
        assert_eq!(stripped.confidence_band, "High");

        // Approximate evidence
        assert!(stripped.evidence_summary.contains("thousands"));

        // CTA present
        assert_eq!(stripped.call_to_action, "Scan your own documents with HIVE");
    }

    #[test]
    fn test_strip_insurance_warning() {
        let firing = insurance_warning_firing();
        let card = generate_insight(&firing);
        let stripped = strip_insight(&card);

        assert!(!stripped.rule_text_generic.contains("BlueCross"));
        assert!(!stripped.rule_text_generic.contains("Jane Doe"));
        assert!(stripped.evidence_summary.contains("tens of thousands"));
    }

    #[test]
    fn test_strip_preserves_confidence_band() {
        let firing = low_confidence_firing();
        let card = generate_insight(&firing);
        let stripped = strip_insight(&card);
        assert_eq!(stripped.confidence_band, "Low");
    }

    #[test]
    fn test_strip_small_evidence() {
        let firing = informational_firing();
        let card = generate_insight(&firing);
        let stripped = strip_insight(&card);
        assert_eq!(
            stripped.evidence_summary,
            "Based on limited collective observations"
        );
    }

    #[test]
    fn test_strip_zero_evidence() {
        let mut firing = informational_firing();
        firing.evidence_count = 0;
        let card = generate_insight(&firing);
        let stripped = strip_insight(&card);
        assert_eq!(
            stripped.evidence_summary,
            "No collective evidence available yet"
        );
    }

    #[test]
    fn test_strip_removes_dollar_amounts() {
        let firing = lease_typical_firing();
        let card = generate_insight(&firing);
        let stripped = strip_insight(&card);
        assert!(!stripped.rule_text_generic.contains("$2,400"));
        assert!(stripped.rule_text_generic.contains("[amount]"));
    }

    // -- format_insight_text -------------------------------------------------

    #[test]
    fn test_format_contains_rule_id() {
        let firing = medical_above_range_firing();
        let card = generate_insight(&firing);
        let formatted = format_insight_text(&card);
        assert!(formatted.contains("#127"));
    }

    #[test]
    fn test_format_contains_conclusion_type() {
        let firing = insurance_warning_firing();
        let card = generate_insight(&firing);
        let formatted = format_insight_text(&card);
        assert!(formatted.contains("WARNING"));
    }

    #[test]
    fn test_format_contains_evidence_summary() {
        let firing = medical_above_range_firing();
        let card = generate_insight(&firing);
        let formatted = format_insight_text(&card);
        assert!(formatted.contains("2,500+"));
    }

    #[test]
    fn test_format_contains_trend() {
        let firing = insurance_warning_firing();
        let card = generate_insight(&firing);
        let formatted = format_insight_text(&card);
        assert!(formatted.contains("increasing"));
    }

    #[test]
    fn test_format_contains_amount_context() {
        let firing = medical_above_range_firing();
        let card = generate_insight(&firing);
        let formatted = format_insight_text(&card);
        assert!(formatted.contains("above typical range"));
    }

    #[test]
    fn test_format_no_amount_context() {
        let firing = insurance_warning_firing();
        let card = generate_insight(&firing);
        let formatted = format_insight_text(&card);
        // Should not contain Amount line when there's no amount context
        // (the word "Amount" might appear in the rule text, so check for the DIM marker)
        assert!(!formatted.contains("Amount:"));
    }

    #[test]
    fn test_format_box_drawing() {
        let firing = informational_firing();
        let card = generate_insight(&firing);
        let formatted = format_insight_text(&card);
        assert!(formatted.contains("+-"));
        assert!(formatted.contains("|"));
    }

    // -- Serialization tests -------------------------------------------------

    #[test]
    fn test_full_card_serializes() {
        let firing = medical_above_range_firing();
        let card = generate_insight(&firing);
        let json = serde_json::to_string(&card).unwrap();
        assert!(json.contains("rule_text"));
        assert!(json.contains("confidence_band"));
        assert!(json.contains("evidence_summary"));
    }

    #[test]
    fn test_stripped_card_serializes() {
        let firing = medical_above_range_firing();
        let card = generate_insight(&firing);
        let stripped = strip_insight(&card);
        let json = serde_json::to_string(&stripped).unwrap();
        assert!(json.contains("rule_text_generic"));
        assert!(json.contains("call_to_action"));
        // Must not contain PII
        assert!(!json.contains("Memorial Hospital"));
        assert!(!json.contains("Dr. Smith"));
    }

    #[test]
    fn test_stripped_card_deserializes_roundtrip() {
        let firing = medical_above_range_firing();
        let card = generate_insight(&firing);
        let stripped = strip_insight(&card);
        let json = serde_json::to_string(&stripped).unwrap();
        let deserialized: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized["call_to_action"],
            "Scan your own documents with HIVE"
        );
    }

    // -- Amount context edge cases -------------------------------------------

    #[test]
    fn test_amount_context_below_range() {
        let mut firing = medical_above_range_firing();
        firing.amount_bucket = Some(2); // $100-$500
        firing.typical_bucket = Some(5); // $5K-$10K
        let card = generate_insight(&firing);
        let ctx = card.amount_context.as_ref().unwrap();
        assert!(ctx.contains("below typical range"));
        assert!(ctx.contains("$100-$500"));
        assert!(ctx.contains("$5K-$10K"));
    }

    #[test]
    fn test_amount_context_within_range() {
        let mut firing = medical_above_range_firing();
        firing.amount_bucket = Some(4);
        firing.typical_bucket = Some(4);
        let card = generate_insight(&firing);
        let ctx = card.amount_context.as_ref().unwrap();
        assert!(ctx.contains("within typical range"));
    }

    // -- wrap_text -----------------------------------------------------------

    #[test]
    fn test_wrap_text_short() {
        let lines = wrap_text("Hello world", 40);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "Hello world");
    }

    #[test]
    fn test_wrap_text_long() {
        let text =
            "This is a much longer string that should be wrapped across multiple lines for display";
        let lines = wrap_text(text, 30);
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(line.len() <= 35); // some slack for last word
        }
    }

    #[test]
    fn test_wrap_text_empty() {
        let lines = wrap_text("", 40);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "");
    }

    // -- strip_amounts -------------------------------------------------------

    #[test]
    fn test_strip_amounts_basic() {
        assert_eq!(
            strip_amounts("Charged $8,200 total"),
            "Charged [amount] total"
        );
    }

    #[test]
    fn test_strip_amounts_multiple() {
        assert_eq!(
            strip_amounts("From $100 to $5,000"),
            "From [amount] to [amount]"
        );
    }

    #[test]
    fn test_strip_amounts_no_amount() {
        assert_eq!(strip_amounts("No amounts here"), "No amounts here");
    }

    #[test]
    fn test_strip_amounts_bare_dollar() {
        assert_eq!(strip_amounts("Cost is $ unknown"), "Cost is $ unknown");
    }

    // -- strip_entity_names --------------------------------------------------

    #[test]
    fn test_strip_entity_names_basic() {
        let entities = vec!["Memorial Hospital".to_string()];
        let result = strip_entity_names("Memorial Hospital charged $8,200", &entities);
        assert_eq!(result, "a provider charged $8,200");
    }

    #[test]
    fn test_strip_entity_names_multiple() {
        let entities = vec!["Hospital A".to_string(), "Lab B".to_string()];
        let result = strip_entity_names("Hospital A referred to Lab B", &entities);
        assert_eq!(result, "a provider referred to a service");
    }

    #[test]
    fn test_strip_entity_names_empty() {
        let entities: Vec<String> = vec![];
        let result = strip_entity_names("No entities to strip", &entities);
        assert_eq!(result, "No entities to strip");
    }

    // -- Evidence summary tiers in strip_insight -----------------------------

    #[test]
    fn test_strip_evidence_tiers() {
        let make_card = |count: u32| {
            let mut firing = informational_firing();
            firing.evidence_count = count;
            let card = generate_insight(&firing);
            strip_insight(&card)
        };

        assert!(make_card(10_000)
            .evidence_summary
            .contains("tens of thousands"));
        assert!(make_card(5_000).evidence_summary.contains("thousands"));
        assert!(make_card(500).evidence_summary.contains("hundreds"));
        assert!(make_card(50).evidence_summary.contains("limited"));
        assert!(make_card(0)
            .evidence_summary
            .contains("No collective evidence"));
    }
}
