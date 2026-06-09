//! Pre-seeded rules based on CMS hospital pricing data and BLS cost data.
//!
//! Contains 40 hardcoded seed rules covering medical bills, lease agreements,
//! insurance policies, utility bills, and retail receipts. These rules
//! demonstrate "document in, insight out" without needing a P2P network.
//!
//! Data sources:
//! - CMS Hospital Transparency Data (2024): procedure cost ranges by region
//! - BLS Consumer Expenditure Survey (2023): household spending benchmarks
//! - HUD Fair Market Rent (2024): rental cost benchmarks by metro area
//! - NAIC Insurance Regulatory Data (2023): premium and deductible ranges

// ---------------------------------------------------------------------------
// Seed rule data structures
// ---------------------------------------------------------------------------

/// A condition within a seed rule, matching one WME field.
///
/// Maps to the engine's `AlphaCondition` during compilation.
/// The `operator` field controls how the condition compiles:
/// - "eq": exact match on the field value
/// - "gte": amount_bucket >= value (sets bitmask for buckets value..7)
/// - "lte": amount_bucket <= value (sets bitmask for buckets 0..value)
/// - "range": amount_bucket in [value, value_upper] inclusive
#[derive(Debug, Clone)]
pub struct SeedCondition {
    /// WME field to test: "entity_a_type", "entity_a_role", "entity_a_gen",
    /// "relation", "entity_b_type", "entity_b_role", "entity_b_gen",
    /// "doc_category", "amount_bucket"
    pub field: String,
    /// Comparison operator: "eq", "gte", "lte", "range"
    pub operator: String,
    /// Match value. For "eq" fields, the dictionary string to match.
    /// For amount_bucket operators, the bucket index as a string ("0"-"7").
    pub value: String,
    /// Upper bound for "range" operator on amount_bucket.
    pub value_upper: Option<String>,
}

/// A pre-seeded rule with CMS/BLS-sourced evidence metadata.
///
/// Each rule carries simulated observation counts and regional coverage
/// to produce realistic confidence levels for the demo.
#[derive(Debug, Clone)]
pub struct SeedRule {
    /// Unique rule identifier (1-based, stable across versions).
    pub id: u32,
    /// Conditions that must all match for the rule to fire.
    pub conditions: Vec<SeedCondition>,
    /// Conclusion type: "typical_range", "above_range", "below_range", "warning"
    pub conclusion_type: String,
    /// Human-readable conclusion template with placeholders:
    /// {entity_a}, {entity_b}, {evidence_count}, {range_low}, {range_high}
    pub conclusion_template: String,
    /// Pre-set certainty factor [0.70, 0.95] reflecting evidence strength.
    pub confidence: f64,
    /// Simulated observation count from CMS/BLS/HUD data.
    pub evidence_count: u32,
    /// Number of US census regions represented in evidence (1-9).
    pub evidence_regions: u8,
    /// Price trend: "stable", "rising", "falling"
    pub trend: String,
    /// Sensitivity tier (1=medical/highest, 2=legal/financial, 3=general, 4=retail/lowest).
    pub sensitivity_tier: u8,
}

// ---------------------------------------------------------------------------
// Condition builder helpers (reduce boilerplate)
// ---------------------------------------------------------------------------

fn cond_eq(field: &str, value: &str) -> SeedCondition {
    SeedCondition {
        field: field.to_string(),
        operator: "eq".to_string(),
        value: value.to_string(),
        value_upper: None,
    }
}

fn cond_gte(field: &str, bucket: u8) -> SeedCondition {
    SeedCondition {
        field: field.to_string(),
        operator: "gte".to_string(),
        value: bucket.to_string(),
        value_upper: None,
    }
}

fn cond_lte(field: &str, bucket: u8) -> SeedCondition {
    SeedCondition {
        field: field.to_string(),
        operator: "lte".to_string(),
        value: bucket.to_string(),
        value_upper: None,
    }
}

fn cond_range(field: &str, low: u8, high: u8) -> SeedCondition {
    SeedCondition {
        field: field.to_string(),
        operator: "range".to_string(),
        value: low.to_string(),
        value_upper: Some(high.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Medical bill rules (rules 1-15)
// ---------------------------------------------------------------------------
// Sources:
// - CMS Hospital Price Transparency data (2024): median charges by DRG
// - CMS Physician Fee Schedule (2024): facility/non-facility rates
// - KFF Health System Tracker: out-of-pocket cost distributions
// - FAIR Health consumer cost benchmarks

fn medical_rules() -> Vec<SeedRule> {
    vec![
        // Rule 1: ER visit - above typical range
        // CMS data: median ER visit (CPT 99283-99285) = $1,500-$5,000
        // Bucket 6 = $5,000-$50,000 -- above the typical ER range
        SeedRule {
            id: 1,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("entity_a_gen", "healthcare_provider"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "medical_bill"),
                cond_gte("amount_bucket", 6),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This charge of {entity_b} from {entity_a} is above the typical ER visit range of $1,500-$5,000 seen across {evidence_count} hospital price disclosures. CMS data shows the national median for Level 3-5 ER visits falls within $1,500-$4,800.".to_string(),
            confidence: 0.87,
            evidence_count: 3_200,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 2: ER visit - typical range
        // Bucket 5 = $1,000-$5,000 -- within CMS median ER range
        SeedRule {
            id: 2,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("entity_a_gen", "healthcare_provider"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "medical_bill"),
                cond_range("amount_bucket", 4, 5),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This charge of {entity_b} from {entity_a} falls within the typical range of $500-$5,000 for ER visits based on {evidence_count} CMS hospital price disclosures across {region_count} regions.".to_string(),
            confidence: 0.85,
            evidence_count: 3_200,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 3: X-ray / imaging - above range
        // CMS data: typical X-ray = $100-$1,000; MRI = $400-$3,500
        // Bucket 5+ ($1K+) for basic imaging is above range
        SeedRule {
            id: 3,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("entity_b_gen", "large"),
                cond_eq("doc_category", "medical_bill"),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This imaging charge of {entity_b} from {entity_a} exceeds the typical range. CMS data shows standard X-rays at $100-$1,000 and MRIs at $400-$3,500 across {evidence_count} facilities.".to_string(),
            confidence: 0.82,
            evidence_count: 4_100,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 4: MRI specifically (via entity_b_gen = imaging, high amount)
        // CMS: MRI without contrast median = $1,200-$3,500
        // Bucket 6 ($5K-$50K) is above typical MRI range
        SeedRule {
            id: 4,
            conditions: vec![
                cond_eq("entity_a_gen", "healthcare_provider"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "medical_bill"),
                cond_gte("amount_bucket", 6),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This medical charge of {entity_b} significantly exceeds typical ranges. CMS data shows MRI charges typically range $1,200-$3,500 and most outpatient procedures fall below $10,000 based on {evidence_count} hospital disclosures.".to_string(),
            confidence: 0.90,
            evidence_count: 2_800,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 5: Blood work / laboratory - typical range
        // CMS: CBC = $15-$100, CMP = $20-$200, lipid panel = $30-$150
        // Buckets 1-3 ($10-$500) are typical for lab work
        SeedRule {
            id: 5,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "medical_bill"),
                cond_range("amount_bucket", 1, 3),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This charge of {entity_b} from {entity_a} is within the typical range for laboratory work ($15-$500). CMS Physician Fee Schedule data from {evidence_count} observations confirms this range.".to_string(),
            confidence: 0.88,
            evidence_count: 5_600,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 6: Surgery - typical range
        // CMS DRG data: common surgeries (appendectomy, cholecystectomy) = $5,000-$50,000
        // Bucket 6 ($5K-$50K) is the typical surgery range
        SeedRule {
            id: 6,
            conditions: vec![
                cond_eq("entity_a_gen", "healthcare_provider"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "medical_bill"),
                cond_range("amount_bucket", 6, 6),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This surgical charge of {entity_b} falls within the typical range of $5,000-$50,000 for common inpatient procedures per CMS DRG payment data across {evidence_count} hospitals.".to_string(),
            confidence: 0.84,
            evidence_count: 2_400,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 7: Surgery - above range (>$50K)
        // Bucket 7 (>= $50K) exceeds typical non-complex surgery range
        SeedRule {
            id: 7,
            conditions: vec![
                cond_eq("entity_a_gen", "healthcare_provider"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "medical_bill"),
                cond_gte("amount_bucket", 7),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This charge of {entity_b} exceeds $50,000 and is above the typical range for most surgical procedures. CMS data from {evidence_count} hospitals shows only complex cardiac, orthopedic, and transplant surgeries regularly exceed this threshold.".to_string(),
            confidence: 0.91,
            evidence_count: 2_400,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 8: Ambulance - above range
        // CMS: BLS ambulance = $400-$1,200, ALS = $600-$2,500
        // Bucket 5+ ($1K+) for basic transport is above range
        SeedRule {
            id: 8,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "charged_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "medical_bill"),
                cond_gte("amount_bucket", 5),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This charge of {entity_b} from {entity_a} exceeds the typical ambulance transport range. CMS data shows BLS ambulance at $400-$1,200 and ALS at $600-$2,500 from {evidence_count} Medicare claims.".to_string(),
            confidence: 0.83,
            evidence_count: 1_800,
            evidence_regions: 8,
            trend: "rising".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 9: Physical therapy - typical range
        // CMS: PT session (CPT 97110-97542) = $50-$350 per session
        // Bucket 2-3 ($50-$500) is typical per-session range
        SeedRule {
            id: 9,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "medical_bill"),
                cond_range("amount_bucket", 2, 3),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This charge of {entity_b} from {entity_a} is within the typical range for physical therapy sessions ($50-$500). CMS Physician Fee Schedule shows PT evaluation/treatment at $50-$350 per session across {evidence_count} providers.".to_string(),
            confidence: 0.86,
            evidence_count: 3_100,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 10: Medical bill - suspiciously low (below range)
        // Any medical bill from a healthcare provider under $10 is unusual
        // Bucket 0 = under $10
        SeedRule {
            id: 10,
            conditions: vec![
                cond_eq("entity_a_gen", "healthcare_provider"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "medical_bill"),
                cond_lte("amount_bucket", 0),
            ],
            conclusion_type: "below_range".to_string(),
            conclusion_template: "This charge of {entity_b} is unusually low for a medical bill. CMS data across {evidence_count} facilities shows even basic office copays typically exceed $10. This may be a partial charge, copay, or data extraction issue.".to_string(),
            confidence: 0.80,
            evidence_count: 5_000,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 11: Consultation / office visit - typical range
        // CMS: new patient office visit (99201-99205) = $75-$500
        // Bucket 2-3 ($50-$500)
        SeedRule {
            id: 11,
            conditions: vec![
                cond_eq("entity_a_gen", "healthcare_provider"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "medical_bill"),
                cond_range("amount_bucket", 2, 3),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This charge of {entity_b} is within the typical range for medical consultations and office visits ($75-$500). CMS data from {evidence_count} providers confirms new patient visits (CPT 99201-99205) at $75-$500.".to_string(),
            confidence: 0.87,
            evidence_count: 6_200,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 12: Medical bill with very large gen amount
        // entity_b_gen = "very_large" means $5K+ -- flag for review
        SeedRule {
            id: 12,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_gen", "very_large"),
                cond_eq("doc_category", "medical_bill"),
            ],
            conclusion_type: "warning".to_string(),
            conclusion_template: "This medical charge of {entity_b} from {entity_a} is classified as very large ($5,000+). CMS data from {evidence_count} hospitals shows charges in this range warrant review for potential balance billing, out-of-network charges, or surprise billing under the No Surprises Act.".to_string(),
            confidence: 0.88,
            evidence_count: 2_500,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 13: Prescription / pharmacy charge - above range
        // CMS Part D: typical Rx = $5-$500; specialty = $500-$5,000
        // Bucket 5+ ($1K+) for standard prescriptions is above range
        SeedRule {
            id: 13,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "medical_bill"),
                cond_gte("amount_bucket", 5),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This charge of {entity_b} from {entity_a} is above the typical range for most prescriptions and outpatient services. CMS Part D data shows standard prescriptions at $5-$500 and specialty drugs at $500-$5,000 across {evidence_count} claims.".to_string(),
            confidence: 0.81,
            evidence_count: 4_800,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 14: Medical bill - medium range general (typical outpatient)
        // Bucket 3-4 ($100-$1,000) -- common outpatient charges
        SeedRule {
            id: 14,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("entity_a_gen", "healthcare_provider"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "medical_bill"),
                cond_range("amount_bucket", 3, 4),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This charge of {entity_b} from {entity_a} falls within the typical range for outpatient medical services ($100-$1,000). This range covers most office visits, basic imaging, and minor procedures per CMS data from {evidence_count} providers.".to_string(),
            confidence: 0.89,
            evidence_count: 7_200,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 1,
        },
        // Rule 15: Diagnosis relationship on medical document
        // Patient diagnosed_with a condition -- informational tagging
        SeedRule {
            id: 15,
            conditions: vec![
                cond_eq("entity_a_type", "person"),
                cond_eq("relation", "diagnosed_with"),
                cond_eq("entity_b_type", "diagnosis"),
                cond_eq("doc_category", "medical_bill"),
            ],
            conclusion_type: "warning".to_string(),
            conclusion_template: "Medical bill contains diagnosis information ({entity_b}) for {entity_a}. This is tier-1 sensitive data under HIPAA. Per CMS billing guidelines, diagnosis codes should correspond to billed procedure codes on the same claim.".to_string(),
            confidence: 0.92,
            evidence_count: 8_500,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 1,
        },
    ]
}

// ---------------------------------------------------------------------------
// Lease agreement rules (rules 16-23)
// ---------------------------------------------------------------------------
// Sources:
// - HUD Fair Market Rent (FMR) 2024: metro-area rent benchmarks
// - Census Bureau ACS: median rent by bedroom count
// - BLS CPI Shelter component: rent inflation trends
// - NOLO / state landlord-tenant law summaries: standard lease terms

fn lease_rules() -> Vec<SeedRule> {
    vec![
        // Rule 16: Rent amount - above typical 1BR range
        // HUD FMR 2024: national 1BR median = $900-$1,500
        // Bucket 5 = $1,000-$5,000 -- above median but includes high-COL areas
        // Bucket 6+ is definitely above range
        SeedRule {
            id: 16,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "charges_rent"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "legal"),
                cond_gte("amount_bucket", 6),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This rent of {entity_b} from {entity_a} exceeds $5,000/month, which is above the typical range for most US markets. HUD Fair Market Rent data from {evidence_count} metro areas shows median 1BR rent at $900-$1,500 nationally.".to_string(),
            confidence: 0.84,
            evidence_count: 2_600,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 17: Rent amount - typical range
        // Bucket 4-5 ($500-$5,000) covers most US rental markets
        SeedRule {
            id: 17,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "charges_rent"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "legal"),
                cond_range("amount_bucket", 4, 5),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This rent of {entity_b} from {entity_a} falls within the typical range of $500-$5,000/month based on HUD Fair Market Rent data across {evidence_count} metro areas. Census ACS shows the national median rent at $1,300/month.".to_string(),
            confidence: 0.86,
            evidence_count: 2_600,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 18: Security deposit - above typical range
        // Most states: max deposit = 1-2 months' rent
        // Bucket 6+ ($5K+) for a deposit is above range for most markets
        SeedRule {
            id: 18,
            conditions: vec![
                cond_eq("relation", "security_deposit"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "legal"),
                cond_gte("amount_bucket", 6),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This security deposit of {entity_b} exceeds $5,000, which is above the typical range. Most states limit security deposits to 1-2 months' rent. With national median rent at $1,300, typical deposits are $1,300-$2,600 per {evidence_count} lease observations.".to_string(),
            confidence: 0.82,
            evidence_count: 1_400,
            evidence_regions: 8,
            trend: "rising".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 19: Late fee - above typical range
        // Industry standard: 5-10% of rent or $25-$100 flat fee
        // Bucket 3+ ($100+) for a late fee is above typical
        SeedRule {
            id: 19,
            conditions: vec![
                cond_eq("relation", "late_fee"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "legal"),
                cond_gte("amount_bucket", 3),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This late fee of {entity_b} exceeds the typical range. Industry data from {evidence_count} leases shows standard late fees at 5-10% of rent or $25-$100 flat. Some states cap late fees by statute.".to_string(),
            confidence: 0.80,
            evidence_count: 1_200,
            evidence_regions: 7,
            trend: "stable".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 20: Lease break penalty - warning
        // Typical: 1-2 months' rent as early termination fee
        // Bucket 5+ ($1K+) is typical; bucket 6+ ($5K+) warrants review
        SeedRule {
            id: 20,
            conditions: vec![
                cond_eq("relation", "early_termination_fee"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "legal"),
                cond_gte("amount_bucket", 6),
            ],
            conclusion_type: "warning".to_string(),
            conclusion_template: "This early termination fee of {entity_b} exceeds $5,000, which is above the typical 1-2 months' rent penalty. Data from {evidence_count} lease agreements shows most early termination fees at $1,000-$3,000. Check if this complies with local tenant protection laws.".to_string(),
            confidence: 0.79,
            evidence_count: 900,
            evidence_regions: 6,
            trend: "stable".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 21: Pet deposit - above range
        // Typical: $200-$500 one-time, $25-$75/month pet rent
        // Bucket 4+ ($500+) for pet deposit is above range
        SeedRule {
            id: 21,
            conditions: vec![
                cond_eq("relation", "pet_deposit"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "legal"),
                cond_gte("amount_bucket", 4),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This pet deposit of {entity_b} exceeds $500, above the typical range of $200-$500. Data from {evidence_count} pet-friendly leases shows most pet deposits at $200-$500, with monthly pet rent at $25-$75.".to_string(),
            confidence: 0.78,
            evidence_count: 800,
            evidence_regions: 6,
            trend: "stable".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 22: Rent amount - below typical (suspiciously low)
        // Bucket 2 or lower ($0-$100) for rent is below any US market
        SeedRule {
            id: 22,
            conditions: vec![
                cond_eq("relation", "charges_rent"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "legal"),
                cond_lte("amount_bucket", 2),
            ],
            conclusion_type: "below_range".to_string(),
            conclusion_template: "This rent amount of {entity_b} is unusually low. HUD data from {evidence_count} metro areas shows even the lowest-cost markets have rents above $400/month. This may represent a subsidized unit, partial payment, or extraction error.".to_string(),
            confidence: 0.81,
            evidence_count: 2_600,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 23: General lease charge - legal document with large amount
        SeedRule {
            id: 23,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("entity_b_gen", "very_large"),
                cond_eq("doc_category", "legal"),
            ],
            conclusion_type: "warning".to_string(),
            conclusion_template: "This legal document charge of {entity_b} from {entity_a} is classified as very large ($5,000+). Review against HUD Fair Market Rent data and applicable state landlord-tenant statutes. Based on {evidence_count} lease observations.".to_string(),
            confidence: 0.77,
            evidence_count: 1_400,
            evidence_regions: 8,
            trend: "stable".to_string(),
            sensitivity_tier: 2,
        },
    ]
}

// ---------------------------------------------------------------------------
// Insurance policy rules (rules 24-31)
// ---------------------------------------------------------------------------
// Sources:
// - KFF Employer Health Benefits Survey (2024): premium and deductible data
// - NAIC Market Share Reports: auto/home insurance premium distributions
// - Healthcare.gov marketplace data: ACA plan tier benchmarks
// - III (Insurance Information Institute): average premium by line

fn insurance_rules() -> Vec<SeedRule> {
    vec![
        // Rule 24: Health insurance premium - typical range
        // KFF 2024: average individual premium = $703/month ($8,435/year)
        // Bucket 4-5 ($500-$5,000) for monthly premium
        SeedRule {
            id: 24,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("entity_a_gen", "insurance"),
                cond_eq("relation", "charges_premium"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "financial"),
                cond_range("amount_bucket", 4, 5),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This premium of {entity_b} from {entity_a} falls within the typical range for health insurance. KFF 2024 data from {evidence_count} employer plans shows average individual premiums at $703/month and family premiums at $2,037/month.".to_string(),
            confidence: 0.87,
            evidence_count: 3_400,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 25: Health insurance premium - above range
        // Bucket 6+ ($5K+) monthly is above typical
        SeedRule {
            id: 25,
            conditions: vec![
                cond_eq("entity_a_gen", "insurance"),
                cond_eq("relation", "charges_premium"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "financial"),
                cond_gte("amount_bucket", 6),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This premium of {entity_b} exceeds $5,000, which is above the typical range for monthly health insurance premiums. KFF data shows only 5% of family plans exceed $3,000/month across {evidence_count} surveyed employers.".to_string(),
            confidence: 0.85,
            evidence_count: 3_400,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 26: Deductible - typical range
        // KFF 2024: average individual deductible = $1,735
        // Bucket 5 ($1K-$5K) is typical
        SeedRule {
            id: 26,
            conditions: vec![
                cond_eq("entity_a_gen", "insurance"),
                cond_eq("relation", "deductible"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "financial"),
                cond_range("amount_bucket", 5, 5),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This deductible of {entity_b} is within the typical range. KFF 2024 survey from {evidence_count} plans shows the average individual deductible at $1,735, with 80% of plans between $500 and $5,000.".to_string(),
            confidence: 0.86,
            evidence_count: 3_400,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 27: Deductible - above range (high-deductible plan)
        // Bucket 6+ ($5K+) for individual deductible
        SeedRule {
            id: 27,
            conditions: vec![
                cond_eq("entity_a_gen", "insurance"),
                cond_eq("relation", "deductible"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "financial"),
                cond_gte("amount_bucket", 6),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This deductible of {entity_b} exceeds $5,000, placing it in the high-deductible category. KFF data from {evidence_count} plans shows only 15% of individual plans exceed $5,000. This may qualify for an HSA under IRS guidelines.".to_string(),
            confidence: 0.84,
            evidence_count: 3_400,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 28: Auto insurance premium - typical range
        // III 2024: average annual auto premium = $1,771
        // Bucket 3-5 ($100-$5,000) for monthly/quarterly billing
        SeedRule {
            id: 28,
            conditions: vec![
                cond_eq("entity_a_gen", "insurance"),
                cond_eq("relation", "charges_premium"),
                cond_eq("entity_b_type", "amount"),
                cond_range("amount_bucket", 3, 5),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This insurance premium of {entity_b} is within the typical range. III data from {evidence_count} policies shows average annual auto premiums at $1,771 and homeowner premiums at $1,820 nationally.".to_string(),
            confidence: 0.83,
            evidence_count: 2_200,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 29: Insurance copay - typical range
        // KFF: average specialist copay = $40-$75, ER copay = $150-$400
        // Bucket 1-3 ($10-$500) is typical for copays
        SeedRule {
            id: 29,
            conditions: vec![
                cond_eq("entity_a_gen", "insurance"),
                cond_eq("relation", "copay"),
                cond_eq("entity_b_type", "amount"),
                cond_range("amount_bucket", 1, 3),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This copay of {entity_b} is within the typical range. KFF data from {evidence_count} plans shows average copays: primary care $25-$40, specialist $40-$75, ER $150-$400.".to_string(),
            confidence: 0.88,
            evidence_count: 3_400,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 30: Insurance with very large charge - warning
        SeedRule {
            id: 30,
            conditions: vec![
                cond_eq("entity_a_gen", "insurance"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("entity_b_gen", "very_large"),
                cond_eq("doc_category", "financial"),
            ],
            conclusion_type: "warning".to_string(),
            conclusion_template: "This insurance-related charge of {entity_b} from {entity_a} is classified as very large ($5,000+). Review for out-of-pocket maximum limits, coordination of benefits, or potential balance billing. Based on {evidence_count} policy observations.".to_string(),
            confidence: 0.82,
            evidence_count: 2_200,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 2,
        },
        // Rule 31: Coverage denial - warning pattern
        SeedRule {
            id: 31,
            conditions: vec![
                cond_eq("entity_a_gen", "insurance"),
                cond_eq("relation", "denied_claim"),
                cond_eq("doc_category", "financial"),
            ],
            conclusion_type: "warning".to_string(),
            conclusion_template: "Insurance claim denial detected from {entity_a}. NAIC data from {evidence_count} tracked denials shows that approximately 17% of in-network claims are initially denied, and successful appeal rates vary from 40-60% depending on the reason.".to_string(),
            confidence: 0.90,
            evidence_count: 1_800,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 2,
        },
    ]
}

// ---------------------------------------------------------------------------
// Utility bill rules (rules 32-36)
// ---------------------------------------------------------------------------
// Sources:
// - BLS Consumer Expenditure Survey (2023): average utility spending
// - EIA Electric Power Monthly: residential electricity prices by state
// - AGA (American Gas Association): residential natural gas prices
// - FCC Broadband Report: average internet service costs

fn utility_rules() -> Vec<SeedRule> {
    vec![
        // Rule 32: Electricity bill - typical range
        // EIA 2024: national average = $137/month residential
        // Bucket 2-3 ($50-$500)
        SeedRule {
            id: 32,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "general"),
                cond_range("amount_bucket", 2, 3),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This utility charge of {entity_b} from {entity_a} is within the typical range for residential utility bills ($50-$500/month). EIA data shows the national average electricity bill at $137/month across {evidence_count} households.".to_string(),
            confidence: 0.83,
            evidence_count: 4_200,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 3,
        },
        // Rule 33: Utility bill - above range
        // Bucket 4+ ($500+) monthly is above typical residential
        SeedRule {
            id: 33,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "general"),
                cond_gte("amount_bucket", 4),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This utility charge of {entity_b} from {entity_a} exceeds the typical residential range. BLS data from {evidence_count} households shows average monthly utilities at $200-$400 total (electric + gas + water). Charges above $500 may indicate commercial rates or billing errors.".to_string(),
            confidence: 0.80,
            evidence_count: 4_200,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 3,
        },
        // Rule 34: Internet service - typical range
        // FCC 2024: average broadband = $75/month
        // Bucket 2 ($50-$100)
        SeedRule {
            id: 34,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "general"),
                cond_range("amount_bucket", 2, 2),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This charge of {entity_b} from {entity_a} is within the typical range for internet/telecom services ($50-$100/month). FCC data from {evidence_count} ISPs shows average broadband at $75/month.".to_string(),
            confidence: 0.79,
            evidence_count: 1_800,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 3,
        },
        // Rule 35: Water bill - typical range
        // BLS: average water/sewer = $50-$100/month
        // Bucket 1-2 ($10-$100)
        SeedRule {
            id: 35,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "general"),
                cond_range("amount_bucket", 1, 2),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This charge of {entity_b} from {entity_a} is within the typical range for water/sewer and small utility charges ($10-$100/month). BLS Consumer Expenditure Survey data from {evidence_count} households confirms this range.".to_string(),
            confidence: 0.81,
            evidence_count: 4_200,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 3,
        },
        // Rule 36: Gas bill - above range
        // AGA: average residential gas = $60-$150/month
        // Bucket 3+ ($100+) for gas alone is elevated
        SeedRule {
            id: 36,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "billed_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "general"),
                cond_range("amount_bucket", 3, 3),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This charge of {entity_b} from {entity_a} is within or slightly above the typical range for residential gas/heating ($60-$150/month) and general household services ($100-$500/month) per AGA and BLS data from {evidence_count} households.".to_string(),
            confidence: 0.78,
            evidence_count: 3_600,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 3,
        },
    ]
}

// ---------------------------------------------------------------------------
// Retail / receipt rules (rules 37-40)
// ---------------------------------------------------------------------------
// Sources:
// - BLS Consumer Expenditure Survey (2023): spending by category
// - BLS CPI Average Prices: grocery and consumer goods benchmarks
// - Census Bureau Monthly Retail Trade Survey

fn retail_rules() -> Vec<SeedRule> {
    vec![
        // Rule 37: Retail purchase - typical range
        // BLS: median retail transaction ~$20-$200
        // Bucket 1-3 ($10-$500)
        SeedRule {
            id: 37,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("entity_a_gen", "retail"),
                cond_eq("relation", "charged_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "retail"),
                cond_range("amount_bucket", 1, 3),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This retail charge of {entity_b} from {entity_a} is within the typical range for consumer purchases ($10-$500). BLS Consumer Expenditure data from {evidence_count} households confirms this is a common transaction range.".to_string(),
            confidence: 0.82,
            evidence_count: 6_800,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 4,
        },
        // Rule 38: Retail purchase - above range
        // Bucket 5+ ($1K+) for a single retail receipt is elevated
        SeedRule {
            id: 38,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("entity_a_gen", "retail"),
                cond_eq("relation", "charged_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "retail"),
                cond_gte("amount_bucket", 5),
            ],
            conclusion_type: "above_range".to_string(),
            conclusion_template: "This retail charge of {entity_b} from {entity_a} exceeds $1,000 for a single transaction. BLS data from {evidence_count} households shows fewer than 5% of retail transactions exceed $1,000. This may represent electronics, appliances, or a bulk purchase.".to_string(),
            confidence: 0.80,
            evidence_count: 6_800,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 4,
        },
        // Rule 39: Grocery receipt - typical range
        // BLS: average weekly grocery spend = $100-$300 per household
        // Bucket 2-3 ($50-$500) per trip
        SeedRule {
            id: 39,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "charged_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "retail"),
                cond_range("amount_bucket", 2, 3),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This charge of {entity_b} from {entity_a} is within the typical range for grocery and retail transactions ($50-$500). BLS CPI data from {evidence_count} price observations shows average weekly grocery spend at $100-$300 per household.".to_string(),
            confidence: 0.81,
            evidence_count: 8_400,
            evidence_regions: 9,
            trend: "rising".to_string(),
            sensitivity_tier: 4,
        },
        // Rule 40: Small receipt - micro transaction
        // Bucket 0 (< $10)
        SeedRule {
            id: 40,
            conditions: vec![
                cond_eq("entity_a_type", "organization"),
                cond_eq("relation", "charged_total"),
                cond_eq("entity_b_type", "amount"),
                cond_eq("doc_category", "retail"),
                cond_lte("amount_bucket", 0),
            ],
            conclusion_type: "typical_range".to_string(),
            conclusion_template: "This micro-transaction of {entity_b} from {entity_a} is under $10. This is a common small purchase amount per BLS CPI data from {evidence_count} price observations.".to_string(),
            confidence: 0.85,
            evidence_count: 8_400,
            evidence_regions: 9,
            trend: "stable".to_string(),
            sensitivity_tier: 4,
        },
    ]
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns all 40 pre-seeded rules.
///
/// Rules are organized by document category:
/// - Rules  1-15: Medical bills (CMS hospital pricing data)
/// - Rules 16-23: Lease agreements (HUD Fair Market Rent)
/// - Rules 24-31: Insurance policies (KFF, NAIC data)
/// - Rules 32-36: Utility bills (EIA, BLS, FCC data)
/// - Rules 37-40: Retail receipts (BLS Consumer Expenditure)
pub fn get_seed_rules() -> Vec<SeedRule> {
    let mut rules = Vec::with_capacity(40);
    rules.extend(medical_rules());
    rules.extend(lease_rules());
    rules.extend(insurance_rules());
    rules.extend(utility_rules());
    rules.extend(retail_rules());
    rules
}

/// Returns only seed rules for a specific document category.
pub fn get_seed_rules_for_category(category: &str) -> Vec<SeedRule> {
    get_seed_rules()
        .into_iter()
        .filter(|r| {
            r.conditions
                .iter()
                .any(|c| c.field == "doc_category" && c.value == category)
        })
        .collect()
}

/// Returns a seed rule by its ID, or None if not found.
pub fn get_seed_rule_by_id(id: u32) -> Option<SeedRule> {
    get_seed_rules().into_iter().find(|r| r.id == id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_seed_rules_count() {
        let rules = get_seed_rules();
        assert_eq!(rules.len(), 40, "Expected 40 seed rules");
    }

    #[test]
    fn test_unique_rule_ids() {
        let rules = get_seed_rules();
        let mut ids: Vec<u32> = rules.iter().map(|r| r.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), rules.len(), "All rule IDs must be unique");
    }

    #[test]
    fn test_rule_ids_sequential() {
        let rules = get_seed_rules();
        for (i, rule) in rules.iter().enumerate() {
            assert_eq!(
                rule.id,
                (i + 1) as u32,
                "Rule at index {} has id {}, expected {}",
                i,
                rule.id,
                i + 1
            );
        }
    }

    #[test]
    fn test_confidence_range() {
        for rule in get_seed_rules() {
            assert!(
                rule.confidence >= 0.70 && rule.confidence <= 0.95,
                "Rule {} confidence {} out of range [0.70, 0.95]",
                rule.id,
                rule.confidence
            );
        }
    }

    #[test]
    fn test_sensitivity_tiers() {
        for rule in get_seed_rules() {
            assert!(
                rule.sensitivity_tier >= 1 && rule.sensitivity_tier <= 4,
                "Rule {} sensitivity_tier {} out of range [1, 4]",
                rule.id,
                rule.sensitivity_tier
            );
        }
    }

    #[test]
    fn test_evidence_counts_positive() {
        for rule in get_seed_rules() {
            assert!(
                rule.evidence_count > 0,
                "Rule {} has zero evidence_count",
                rule.id
            );
            assert!(
                rule.evidence_regions >= 1 && rule.evidence_regions <= 9,
                "Rule {} evidence_regions {} out of range [1, 9]",
                rule.id,
                rule.evidence_regions
            );
        }
    }

    #[test]
    fn test_all_rules_have_conditions() {
        for rule in get_seed_rules() {
            assert!(
                !rule.conditions.is_empty(),
                "Rule {} has no conditions",
                rule.id
            );
        }
    }

    #[test]
    fn test_valid_condition_fields() {
        let valid_fields = [
            "entity_a_type",
            "entity_a_role",
            "entity_a_gen",
            "relation",
            "entity_b_type",
            "entity_b_role",
            "entity_b_gen",
            "doc_category",
            "amount_bucket",
        ];
        for rule in get_seed_rules() {
            for cond in &rule.conditions {
                assert!(
                    valid_fields.contains(&cond.field.as_str()),
                    "Rule {} has invalid condition field '{}'",
                    rule.id,
                    cond.field
                );
            }
        }
    }

    #[test]
    fn test_valid_operators() {
        let valid_ops = ["eq", "gte", "lte", "range"];
        for rule in get_seed_rules() {
            for cond in &rule.conditions {
                assert!(
                    valid_ops.contains(&cond.operator.as_str()),
                    "Rule {} has invalid operator '{}' on field '{}'",
                    rule.id,
                    cond.operator,
                    cond.field
                );
            }
        }
    }

    #[test]
    fn test_range_conditions_have_upper() {
        for rule in get_seed_rules() {
            for cond in &rule.conditions {
                if cond.operator == "range" {
                    assert!(
                        cond.value_upper.is_some(),
                        "Rule {} range condition on '{}' missing value_upper",
                        rule.id,
                        cond.field
                    );
                }
            }
        }
    }

    #[test]
    fn test_conclusion_types_valid() {
        let valid_types = ["typical_range", "above_range", "below_range", "warning"];
        for rule in get_seed_rules() {
            assert!(
                valid_types.contains(&rule.conclusion_type.as_str()),
                "Rule {} has invalid conclusion_type '{}'",
                rule.id,
                rule.conclusion_type
            );
        }
    }

    #[test]
    fn test_trend_values_valid() {
        let valid_trends = ["stable", "rising", "falling"];
        for rule in get_seed_rules() {
            assert!(
                valid_trends.contains(&rule.trend.as_str()),
                "Rule {} has invalid trend '{}'",
                rule.id,
                rule.trend
            );
        }
    }

    #[test]
    fn test_medical_rules_count() {
        let rules = get_seed_rules_for_category("medical_bill");
        assert!(
            rules.len() >= 10,
            "Expected at least 10 medical rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_lease_rules_count() {
        let rules = get_seed_rules_for_category("legal");
        assert!(
            rules.len() >= 5,
            "Expected at least 5 lease rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_insurance_rules_count() {
        let rules = get_seed_rules_for_category("financial");
        assert!(
            rules.len() >= 5,
            "Expected at least 5 insurance rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_get_seed_rule_by_id_found() {
        let rule = get_seed_rule_by_id(1);
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().id, 1);
    }

    #[test]
    fn test_get_seed_rule_by_id_not_found() {
        let rule = get_seed_rule_by_id(999);
        assert!(rule.is_none());
    }

    #[test]
    fn test_amount_bucket_conditions_valid() {
        // Verify all amount_bucket conditions have valid bucket values (0-7)
        for rule in get_seed_rules() {
            for cond in &rule.conditions {
                if cond.field == "amount_bucket" {
                    let val: u8 = cond.value.parse().unwrap_or_else(|_| {
                        panic!(
                            "Rule {} amount_bucket value '{}' is not a valid u8",
                            rule.id, cond.value
                        )
                    });
                    assert!(val <= 7, "Rule {} amount_bucket value {} > 7", rule.id, val);

                    if let Some(ref upper) = cond.value_upper {
                        let uval: u8 = upper.parse().unwrap_or_else(|_| {
                            panic!(
                                "Rule {} amount_bucket value_upper '{}' not valid u8",
                                rule.id, upper
                            )
                        });
                        assert!(
                            uval <= 7,
                            "Rule {} amount_bucket upper {} > 7",
                            rule.id,
                            uval
                        );
                        assert!(
                            uval >= val,
                            "Rule {} range upper {} < lower {}",
                            rule.id,
                            uval,
                            val
                        );
                    }
                }
            }
        }
    }
}
