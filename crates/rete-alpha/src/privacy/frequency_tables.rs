//! Frequency data tables for k-anonymity estimation, l-diversity checks,
//! and context generalization in the HIVE privacy pipeline.
//!
//! Provides per-field frequency lookup so that other privacy stages can estimate
//! k-anonymity (how many people share a given combination of quasi-identifiers).
//!
//! For V1, all frequency data is embedded as static constants derived from
//! public US data sources (CMS procedure frequency, Census population, BLS
//! consumer expenditure). No external file I/O is required.
//!
//! ## Data Sources
//!
//! - **Medical procedures**: CMS encounter frequency patterns (~120 terms)
//! - **Organizations**: Type frequency from BLS/Census establishment data (~130 terms)
//! - **Geographic regions**: Census 2020 population proportions (50 states + DC + territories)
//! - **Amount buckets**: BLS Consumer Expenditure Survey distribution
//! - **Document categories**: HIVE pipeline document type distribution
//! - **Entity types**: HIVE extraction output distribution
//! - **Roles**: HIVE extraction output role distribution
//! - **Relations**: HIVE extraction output relation distribution
//!
//! ## Thread Safety
//!
//! `FrequencyTables` is immutable after construction and safe to share
//! across threads via `Arc<FrequencyTables>`.

use std::collections::HashMap;

// ============================================================================
// Embedded frequency data (const arrays)
// ============================================================================

// ---------------------------------------------------------------------------
// Medical procedures: CMS encounter frequency patterns
// Frequencies represent fraction of all medical encounters.
// Categories: imaging ~25%, laboratory ~30%, consultation ~15%, surgery ~10%,
//             emergency ~5%, therapy ~8%, pharmacy ~5%, preventive ~2%
// ---------------------------------------------------------------------------

/// (value, frequency) pairs for entity_b_value when the value represents
/// a medical procedure or its generalized category.
const MEDICAL_PROCEDURE_FREQS: &[(&str, f64)] = &[
    // --- Imaging category (~25% total) ---
    ("imaging", 0.2500),
    ("mri", 0.0375),
    ("ct_scan", 0.0325),
    ("x-ray", 0.0450),
    ("x_ray", 0.0450),
    ("ultrasound", 0.0350),
    ("mammogram", 0.0150),
    ("pet_scan", 0.0075),
    ("fluoroscopy", 0.0050),
    ("echocardiogram", 0.0125),
    ("ekg", 0.0175),
    ("eeg", 0.0075),
    ("dexa_scan", 0.0050),
    ("bone_scan", 0.0050),
    ("angiogram", 0.0075),
    ("angiography", 0.0075),
    ("mra", 0.0050),
    // --- Laboratory category (~30% total) ---
    ("laboratory", 0.3000),
    ("blood_test", 0.0240),
    ("blood_work", 0.0180),
    ("cbc", 0.0210),
    ("cmp", 0.0150),
    ("bmp", 0.0120),
    ("lipid_panel", 0.0150),
    ("urinalysis", 0.0120),
    ("urine_test", 0.0090),
    ("culture", 0.0090),
    ("pathology", 0.0120),
    ("cytology", 0.0060),
    ("histology", 0.0060),
    ("hba1c", 0.0120),
    ("a1c", 0.0120),
    ("glucose_test", 0.0150),
    ("cholesterol_test", 0.0120),
    ("thyroid_panel", 0.0090),
    ("tsh", 0.0090),
    ("psa", 0.0060),
    ("lab", 0.0210),
    ("lab_work", 0.0150),
    // --- Consultation category (~15% total) ---
    ("consultation", 0.1500),
    ("office_visit", 0.0375),
    ("consult", 0.0150),
    ("follow_up", 0.0225),
    ("follow-up", 0.0150),
    ("evaluation", 0.0120),
    ("assessment", 0.0090),
    ("exam", 0.0120),
    ("examination", 0.0075),
    ("telehealth", 0.0120),
    ("telemedicine", 0.0060),
    ("virtual_visit", 0.0045),
    ("second_opinion", 0.0030),
    ("referral", 0.0060),
    ("specialist_visit", 0.0075),
    // --- Surgery category (~10% total) ---
    ("surgery", 0.1000),
    ("surgical_procedure", 0.0100),
    ("appendectomy", 0.0050),
    ("cholecystectomy", 0.0045),
    ("hernia_repair", 0.0055),
    ("knee_replacement", 0.0060),
    ("hip_replacement", 0.0055),
    ("coronary_bypass", 0.0035),
    ("cabg", 0.0035),
    ("cesarean", 0.0065),
    ("c-section", 0.0065),
    ("tonsillectomy", 0.0030),
    ("mastectomy", 0.0025),
    ("lumpectomy", 0.0020),
    ("colectomy", 0.0020),
    ("gastrectomy", 0.0015),
    ("hysterectomy", 0.0040),
    ("prostatectomy", 0.0025),
    ("nephrectomy", 0.0015),
    ("arthroscopy", 0.0045),
    ("laparoscopy", 0.0045),
    ("endoscopy", 0.0055),
    ("biopsy", 0.0070),
    ("operation", 0.0050),
    // --- Emergency category (~5% total) ---
    ("emergency", 0.0500),
    ("er_visit", 0.0150),
    ("emergency_room", 0.0100),
    ("trauma", 0.0050),
    ("trauma_care", 0.0030),
    ("ambulance", 0.0045),
    ("emt", 0.0015),
    ("urgent_care", 0.0060),
    ("resuscitation", 0.0010),
    ("intubation", 0.0010),
    ("defibrillation", 0.0005),
    ("emergency_surgery", 0.0025),
    // --- Therapy category (~8% total) ---
    ("therapy", 0.0800),
    ("physical_therapy", 0.0200),
    ("pt", 0.0100),
    ("occupational_therapy", 0.0080),
    ("ot", 0.0040),
    ("speech_therapy", 0.0050),
    ("chemotherapy", 0.0060),
    ("chemo", 0.0040),
    ("radiation_therapy", 0.0050),
    ("radiation", 0.0040),
    ("dialysis", 0.0050),
    ("infusion", 0.0040),
    ("respiratory_therapy", 0.0025),
    ("rehabilitation", 0.0060),
    ("rehab", 0.0040),
    // --- Pharmacy category (~5% total) ---
    ("pharmacy", 0.0500),
    ("prescription", 0.0120),
    ("medication", 0.0100),
    ("drug", 0.0050),
    ("refill", 0.0040),
    ("dispensing", 0.0020),
    ("injection", 0.0040),
    ("vaccine", 0.0040),
    ("vaccination", 0.0030),
    ("immunization", 0.0020),
    ("flu_shot", 0.0015),
    ("insulin", 0.0015),
    ("antibiotic", 0.0010),
    // --- Preventive category (~2% total) ---
    ("preventive", 0.0200),
    ("preventive_care", 0.0020),
    ("annual_physical", 0.0035),
    ("physical_exam", 0.0025),
    ("screening", 0.0030),
    ("wellness_visit", 0.0025),
    ("checkup", 0.0020),
    ("check-up", 0.0010),
    ("colonoscopy", 0.0010),
    ("pap_smear", 0.0008),
    ("dental_cleaning", 0.0010),
    ("eye_exam", 0.0005),
    ("hearing_test", 0.0002),
    // --- Catch-all ---
    ("other_medical", 0.0050),
];

// ---------------------------------------------------------------------------
// Organization types: establishment frequency from BLS/Census
// ---------------------------------------------------------------------------

const ORGANIZATION_FREQS: &[(&str, f64)] = &[
    // Generalized categories
    ("healthcare_provider", 0.2000),
    ("financial_institution", 0.1000),
    ("insurance", 0.1200),
    ("government", 0.0600),
    ("employer", 0.1500),
    ("retail", 0.1500),
    ("educational", 0.0500),
    ("legal", 0.0300),
    ("other_org", 0.1400),
    // Specific healthcare
    ("hospital", 0.0600),
    ("clinic", 0.0450),
    ("medical_center", 0.0200),
    ("health_center", 0.0100),
    ("provider", 0.0150),
    ("physician", 0.0100),
    ("doctor", 0.0100),
    ("dentist", 0.0100),
    ("dental_office", 0.0050),
    ("urgent_care", 0.0050),
    ("nursing_home", 0.0030),
    ("assisted_living", 0.0020),
    ("rehab_center", 0.0020),
    ("lab", 0.0050),
    ("laboratory", 0.0050),
    ("diagnostic_center", 0.0020),
    ("imaging_center", 0.0020),
    ("radiology", 0.0020),
    ("mental_health", 0.0030),
    ("psychiatry", 0.0020),
    ("psychology", 0.0020),
    ("optometry", 0.0015),
    ("optometrist", 0.0015),
    ("ophthalmology", 0.0010),
    ("pediatrics", 0.0020),
    ("obgyn", 0.0015),
    ("cardiology", 0.0015),
    ("oncology", 0.0010),
    ("dermatology", 0.0015),
    ("orthopedics", 0.0015),
    ("medical_group", 0.0020),
    ("health_system", 0.0020),
    // Financial
    ("bank", 0.0350),
    ("credit_union", 0.0100),
    ("savings_bank", 0.0050),
    ("investment_firm", 0.0080),
    ("brokerage", 0.0050),
    ("broker", 0.0030),
    ("mortgage_company", 0.0060),
    ("lending", 0.0030),
    ("lender", 0.0020),
    ("financial_advisor", 0.0030),
    ("wealth_management", 0.0020),
    ("accounting_firm", 0.0030),
    ("cpa", 0.0020),
    ("tax_preparer", 0.0020),
    ("fintech", 0.0030),
    // Insurance
    ("insurer", 0.0300),
    ("insurance_company", 0.0300),
    ("hmo", 0.0100),
    ("ppo", 0.0100),
    ("health_plan", 0.0100),
    ("auto_insurance", 0.0050),
    ("home_insurance", 0.0050),
    ("life_insurance", 0.0050),
    ("insurance_provider", 0.0050),
    // Government
    ("irs", 0.0080),
    ("ssa", 0.0060),
    ("cms", 0.0040),
    ("court", 0.0050),
    ("dmv", 0.0050),
    ("post_office", 0.0040),
    ("veterans_affairs", 0.0030),
    ("va", 0.0030),
    ("medicare", 0.0060),
    ("medicaid", 0.0050),
    // Employer
    ("company", 0.0400),
    ("corporation", 0.0250),
    ("llc", 0.0200),
    ("inc", 0.0150),
    ("business", 0.0200),
    ("firm", 0.0100),
    ("startup", 0.0050),
    ("enterprise", 0.0050),
    // Retail
    ("store", 0.0350),
    ("shop", 0.0200),
    ("retailer", 0.0100),
    ("merchant", 0.0150),
    ("vendor", 0.0100),
    ("supplier", 0.0050),
    ("restaurant", 0.0200),
    ("grocery", 0.0150),
    ("supermarket", 0.0100),
    ("ecommerce", 0.0050),
    ("gas_station", 0.0050),
    // Educational
    ("university", 0.0150),
    ("college", 0.0100),
    ("school", 0.0150),
    ("academy", 0.0030),
    ("community_college", 0.0040),
    // Legal
    ("law_firm", 0.0100),
    ("attorney", 0.0080),
    ("lawyer", 0.0050),
    ("notary", 0.0020),
];

// ---------------------------------------------------------------------------
// Geographic regions: Census 2020 population proportions
// Level 0 = state, Level 1 = division, Level 2 = region
// ---------------------------------------------------------------------------

const STATE_FREQS: &[(&str, f64)] = &[
    ("CA", 0.1186),
    ("TX", 0.0884),
    ("FL", 0.0653),
    ("NY", 0.0606),
    ("PA", 0.0393),
    ("IL", 0.0387),
    ("OH", 0.0356),
    ("GA", 0.0323),
    ("NC", 0.0318),
    ("MI", 0.0303),
    ("NJ", 0.0276),
    ("VA", 0.0261),
    ("WA", 0.0232),
    ("AZ", 0.0219),
    ("MA", 0.0212),
    ("TN", 0.0210),
    ("IN", 0.0205),
    ("MO", 0.0188),
    ("MD", 0.0186),
    ("WI", 0.0178),
    ("CO", 0.0175),
    ("MN", 0.0172),
    ("SC", 0.0156),
    ("AL", 0.0153),
    ("LA", 0.0141),
    ("KY", 0.0136),
    ("OR", 0.0128),
    ("OK", 0.0121),
    ("CT", 0.0109),
    ("UT", 0.0100),
    ("IA", 0.0097),
    ("NV", 0.0094),
    ("AR", 0.0092),
    ("MS", 0.0091),
    ("KS", 0.0089),
    ("NM", 0.0064),
    ("NE", 0.0059),
    ("ID", 0.0057),
    ("WV", 0.0054),
    ("HI", 0.0043),
    ("NH", 0.0042),
    ("ME", 0.0041),
    ("MT", 0.0033),
    ("RI", 0.0032),
    ("DE", 0.0030),
    ("SD", 0.0027),
    ("ND", 0.0024),
    ("AK", 0.0022),
    ("DC", 0.0021),
    ("VT", 0.0019),
    ("WY", 0.0017),
    // Territories (small fractions)
    ("PR", 0.0098),
    ("GU", 0.0005),
    ("VI", 0.0003),
    ("AS", 0.0002),
    ("MP", 0.0002),
];

const DIVISION_FREQS: &[(&str, f64)] = &[
    ("south_atlantic", 0.2009),
    ("east_north_central", 0.1429),
    ("pacific", 0.1611),
    ("west_south_central", 0.1238),
    ("mid_atlantic", 0.1275),
    ("mountain", 0.0765),
    ("west_north_central", 0.0656),
    ("new_england", 0.0455),
    ("east_south_central", 0.0590),
    ("territory", 0.0110),
    ("unknown_geo", 0.0010),
];

const REGION_FREQS: &[(&str, f64)] = &[
    ("south", 0.3837),
    ("west", 0.2376),
    ("midwest", 0.2085),
    ("northeast", 0.1730),
    ("territory", 0.0110),
    ("unknown_geo", 0.0010),
];

// ---------------------------------------------------------------------------
// Amount buckets: BLS Consumer Expenditure Survey distribution
// Bucket indices 0-7 match the boundaries in amount_bucketer.rs
// ---------------------------------------------------------------------------

const AMOUNT_BUCKET_FREQS: &[(&str, f64)] = &[
    ("$0-$100", 0.3500),
    ("$100-$500", 0.2500),
    ("$500-$1K", 0.1500),
    ("$1K-$5K", 0.1200),
    ("$5K-$10K", 0.0600),
    ("$10K-$50K", 0.0400),
    ("$50K-$100K", 0.0200),
    ("$100K+", 0.0100),
    // Bucket index aliases (for lookup by numeric index string)
    ("0", 0.3500),
    ("1", 0.2500),
    ("2", 0.1500),
    ("3", 0.1200),
    ("4", 0.0600),
    ("5", 0.0400),
    ("6", 0.0200),
    ("7", 0.0100),
    ("na", 0.0050),
    ("255", 0.0050),
];

// ---------------------------------------------------------------------------
// Document categories
// ---------------------------------------------------------------------------

const DOCUMENT_CATEGORY_FREQS: &[(&str, f64)] = &[
    ("receipt", 0.3000),
    ("medical_bill", 0.1500),
    ("utility_bill", 0.1200),
    ("restaurant_receipt", 0.0800),
    ("bank_statement", 0.0600),
    ("insurance_eob", 0.0500),
    ("lease", 0.0500),
    ("contract", 0.0400),
    ("pay_stub", 0.0300),
    ("government_form", 0.0250),
    ("prescription", 0.0200),
    ("insurance_policy", 0.0200),
    ("medical_note", 0.0150),
    ("terms_of_service", 0.0100),
    ("invoice", 0.0100),
    ("tax_form", 0.0100),
    ("other", 0.0100),
];

// ---------------------------------------------------------------------------
// Entity types (entity_a_type and entity_b_type)
// ---------------------------------------------------------------------------

const ENTITY_TYPE_FREQS: &[(&str, f64)] = &[
    ("organization", 0.2500),
    ("product", 0.2000),
    ("procedure", 0.1500),
    ("amount", 0.1200),
    ("term", 0.0800),
    ("medication", 0.0500),
    ("diagnosis", 0.0400),
    ("code", 0.0300),
    ("percentage", 0.0200),
    ("vehicle", 0.0150),
    ("certification", 0.0100),
    ("legal_mechanism", 0.0100),
    ("person", 0.0050),
    ("address", 0.0050),
    ("phone", 0.0030),
    ("email", 0.0020),
    ("other", 0.0100),
];

// ---------------------------------------------------------------------------
// Entity roles (entity_a_role and entity_b_role)
// ---------------------------------------------------------------------------

const ROLE_FREQS: &[(&str, f64)] = &[
    ("provider", 0.1800),
    ("charge", 0.1500),
    ("merchant", 0.1200),
    ("payment", 0.0800),
    ("fee", 0.0600),
    ("employer", 0.0500),
    ("insurer", 0.0500),
    ("landlord", 0.0400),
    ("billing_code", 0.0350),
    ("category_code", 0.0300),
    ("deductible", 0.0250),
    ("premium", 0.0200),
    ("patient", 0.0200),
    ("subscriber", 0.0150),
    ("beneficiary", 0.0100),
    ("guarantor", 0.0050),
    ("other", 0.0600),
    ("unknown", 0.0500),
];

// ---------------------------------------------------------------------------
// Relation types
// ---------------------------------------------------------------------------

const RELATION_FREQS: &[(&str, f64)] = &[
    ("charged_for", 0.2000),
    ("billed_to", 0.1500),
    ("prescribed", 0.0800),
    ("charges", 0.0700),
    ("paid_for", 0.0600),
    ("covered_by", 0.0500),
    ("provided_by", 0.0500),
    ("treated_with", 0.0400),
    ("diagnosed_with", 0.0350),
    ("referred_to", 0.0300),
    ("employed_by", 0.0250),
    ("rented_from", 0.0200),
    ("purchased_from", 0.0200),
    ("insured_by", 0.0200),
    ("contracted_with", 0.0150),
    ("visited", 0.0150),
    ("received", 0.0150),
    ("owes", 0.0100),
    ("supplied_by", 0.0100),
    ("authorized_by", 0.0100),
    ("maintained_by", 0.0100),
    ("approved_by", 0.0100),
    ("other", 0.0550),
];

// ---------------------------------------------------------------------------
// Time period frequencies (year-quarter granularity)
// Roughly uniform across recent quarters, trailing off for older ones.
// ---------------------------------------------------------------------------

const TIME_PERIOD_FREQS: &[(&str, f64)] = &[
    // Current and recent quarters get higher weight
    ("2026-Q1", 0.1200),
    ("2026-Q2", 0.1200),
    ("2025-Q4", 0.1000),
    ("2025-Q3", 0.0900),
    ("2025-Q2", 0.0800),
    ("2025-Q1", 0.0700),
    ("2024-Q4", 0.0600),
    ("2024-Q3", 0.0500),
    ("2024-Q2", 0.0400),
    ("2024-Q1", 0.0400),
    ("2023", 0.1000),
    ("2022", 0.0500),
    ("2021", 0.0300),
    ("older", 0.0200),
    ("unknown", 0.0300),
    // Generalized: year level
    ("2026", 0.2400),
    ("2025", 0.3400),
    ("2024", 0.1900),
];

// ============================================================================
// Generalization level mappings
// ============================================================================

// For each field, we need to know what values map to at higher generalization
// levels. These are used by `field_frequency_at_level`.

/// Medical procedure: specific -> category -> "medical" -> "*"
/// Level 0 = specific term (e.g., "mri")
/// Level 1 = category (e.g., "imaging")
/// Level 2 = "medical"
/// Level 3 = "*" (any)
const MEDICAL_CATEGORY_MAP: &[(&str, &str)] = &[
    ("mri", "imaging"),
    ("ct_scan", "imaging"),
    ("x-ray", "imaging"),
    ("x_ray", "imaging"),
    ("ultrasound", "imaging"),
    ("mammogram", "imaging"),
    ("pet_scan", "imaging"),
    ("fluoroscopy", "imaging"),
    ("echocardiogram", "imaging"),
    ("ekg", "imaging"),
    ("eeg", "imaging"),
    ("dexa_scan", "imaging"),
    ("bone_scan", "imaging"),
    ("angiogram", "imaging"),
    ("angiography", "imaging"),
    ("mra", "imaging"),
    ("blood_test", "laboratory"),
    ("blood_work", "laboratory"),
    ("cbc", "laboratory"),
    ("cmp", "laboratory"),
    ("bmp", "laboratory"),
    ("lipid_panel", "laboratory"),
    ("urinalysis", "laboratory"),
    ("urine_test", "laboratory"),
    ("culture", "laboratory"),
    ("pathology", "laboratory"),
    ("cytology", "laboratory"),
    ("histology", "laboratory"),
    ("hba1c", "laboratory"),
    ("a1c", "laboratory"),
    ("glucose_test", "laboratory"),
    ("cholesterol_test", "laboratory"),
    ("thyroid_panel", "laboratory"),
    ("tsh", "laboratory"),
    ("psa", "laboratory"),
    ("lab", "laboratory"),
    ("lab_work", "laboratory"),
    ("office_visit", "consultation"),
    ("consult", "consultation"),
    ("follow_up", "consultation"),
    ("follow-up", "consultation"),
    ("evaluation", "consultation"),
    ("assessment", "consultation"),
    ("exam", "consultation"),
    ("examination", "consultation"),
    ("telehealth", "consultation"),
    ("telemedicine", "consultation"),
    ("virtual_visit", "consultation"),
    ("second_opinion", "consultation"),
    ("referral", "consultation"),
    ("specialist_visit", "consultation"),
    ("appendectomy", "surgery"),
    ("cholecystectomy", "surgery"),
    ("hernia_repair", "surgery"),
    ("knee_replacement", "surgery"),
    ("hip_replacement", "surgery"),
    ("coronary_bypass", "surgery"),
    ("cabg", "surgery"),
    ("cesarean", "surgery"),
    ("c-section", "surgery"),
    ("tonsillectomy", "surgery"),
    ("mastectomy", "surgery"),
    ("lumpectomy", "surgery"),
    ("colectomy", "surgery"),
    ("gastrectomy", "surgery"),
    ("hysterectomy", "surgery"),
    ("prostatectomy", "surgery"),
    ("nephrectomy", "surgery"),
    ("arthroscopy", "surgery"),
    ("laparoscopy", "surgery"),
    ("endoscopy", "surgery"),
    ("biopsy", "surgery"),
    ("surgical_procedure", "surgery"),
    ("operation", "surgery"),
    ("er_visit", "emergency"),
    ("emergency_room", "emergency"),
    ("trauma", "emergency"),
    ("trauma_care", "emergency"),
    ("ambulance", "emergency"),
    ("emt", "emergency"),
    ("urgent_care", "emergency"),
    ("resuscitation", "emergency"),
    ("intubation", "emergency"),
    ("defibrillation", "emergency"),
    ("emergency_surgery", "emergency"),
    ("physical_therapy", "therapy"),
    ("pt", "therapy"),
    ("occupational_therapy", "therapy"),
    ("ot", "therapy"),
    ("speech_therapy", "therapy"),
    ("chemotherapy", "therapy"),
    ("chemo", "therapy"),
    ("radiation_therapy", "therapy"),
    ("radiation", "therapy"),
    ("dialysis", "therapy"),
    ("infusion", "therapy"),
    ("respiratory_therapy", "therapy"),
    ("rehabilitation", "therapy"),
    ("rehab", "therapy"),
    ("prescription", "pharmacy"),
    ("medication", "pharmacy"),
    ("drug", "pharmacy"),
    ("refill", "pharmacy"),
    ("dispensing", "pharmacy"),
    ("injection", "pharmacy"),
    ("vaccine", "pharmacy"),
    ("vaccination", "pharmacy"),
    ("immunization", "pharmacy"),
    ("flu_shot", "pharmacy"),
    ("insulin", "pharmacy"),
    ("antibiotic", "pharmacy"),
    ("annual_physical", "preventive"),
    ("physical_exam", "preventive"),
    ("screening", "preventive"),
    ("wellness_visit", "preventive"),
    ("checkup", "preventive"),
    ("check-up", "preventive"),
    ("colonoscopy", "preventive"),
    ("pap_smear", "preventive"),
    ("dental_cleaning", "preventive"),
    ("eye_exam", "preventive"),
    ("hearing_test", "preventive"),
    ("preventive_care", "preventive"),
];

/// Organization: specific -> category -> "organization" -> "*"
const ORG_CATEGORY_MAP: &[(&str, &str)] = &[
    ("hospital", "healthcare_provider"),
    ("clinic", "healthcare_provider"),
    ("medical_center", "healthcare_provider"),
    ("health_center", "healthcare_provider"),
    ("physician", "healthcare_provider"),
    ("doctor", "healthcare_provider"),
    ("dentist", "healthcare_provider"),
    ("dental_office", "healthcare_provider"),
    ("nursing_home", "healthcare_provider"),
    ("assisted_living", "healthcare_provider"),
    ("rehab_center", "healthcare_provider"),
    ("diagnostic_center", "healthcare_provider"),
    ("imaging_center", "healthcare_provider"),
    ("radiology", "healthcare_provider"),
    ("mental_health", "healthcare_provider"),
    ("psychiatry", "healthcare_provider"),
    ("psychology", "healthcare_provider"),
    ("optometry", "healthcare_provider"),
    ("optometrist", "healthcare_provider"),
    ("ophthalmology", "healthcare_provider"),
    ("pediatrics", "healthcare_provider"),
    ("obgyn", "healthcare_provider"),
    ("cardiology", "healthcare_provider"),
    ("oncology", "healthcare_provider"),
    ("dermatology", "healthcare_provider"),
    ("orthopedics", "healthcare_provider"),
    ("medical_group", "healthcare_provider"),
    ("health_system", "healthcare_provider"),
    ("bank", "financial_institution"),
    ("credit_union", "financial_institution"),
    ("savings_bank", "financial_institution"),
    ("investment_firm", "financial_institution"),
    ("brokerage", "financial_institution"),
    ("broker", "financial_institution"),
    ("mortgage_company", "financial_institution"),
    ("lending", "financial_institution"),
    ("lender", "financial_institution"),
    ("financial_advisor", "financial_institution"),
    ("wealth_management", "financial_institution"),
    ("accounting_firm", "financial_institution"),
    ("cpa", "financial_institution"),
    ("tax_preparer", "financial_institution"),
    ("fintech", "financial_institution"),
    ("insurer", "insurance"),
    ("insurance_company", "insurance"),
    ("hmo", "insurance"),
    ("ppo", "insurance"),
    ("health_plan", "insurance"),
    ("auto_insurance", "insurance"),
    ("home_insurance", "insurance"),
    ("life_insurance", "insurance"),
    ("insurance_provider", "insurance"),
    ("irs", "government"),
    ("ssa", "government"),
    ("cms", "government"),
    ("court", "government"),
    ("dmv", "government"),
    ("post_office", "government"),
    ("veterans_affairs", "government"),
    ("va", "government"),
    ("medicare", "government"),
    ("medicaid", "government"),
    ("company", "employer"),
    ("corporation", "employer"),
    ("llc", "employer"),
    ("inc", "employer"),
    ("business", "employer"),
    ("firm", "employer"),
    ("startup", "employer"),
    ("enterprise", "employer"),
    ("store", "retail"),
    ("shop", "retail"),
    ("retailer", "retail"),
    ("merchant", "retail"),
    ("vendor", "retail"),
    ("supplier", "retail"),
    ("restaurant", "retail"),
    ("grocery", "retail"),
    ("supermarket", "retail"),
    ("ecommerce", "retail"),
    ("gas_station", "retail"),
    ("university", "educational"),
    ("college", "educational"),
    ("school", "educational"),
    ("academy", "educational"),
    ("community_college", "educational"),
    ("law_firm", "legal"),
    ("attorney", "legal"),
    ("lawyer", "legal"),
    ("notary", "legal"),
];

/// State -> division mapping (for geographic generalization level 1)
const STATE_DIVISION_MAP: &[(&str, &str)] = &[
    ("CT", "new_england"),
    ("ME", "new_england"),
    ("MA", "new_england"),
    ("NH", "new_england"),
    ("RI", "new_england"),
    ("VT", "new_england"),
    ("NJ", "mid_atlantic"),
    ("NY", "mid_atlantic"),
    ("PA", "mid_atlantic"),
    ("IL", "east_north_central"),
    ("IN", "east_north_central"),
    ("MI", "east_north_central"),
    ("OH", "east_north_central"),
    ("WI", "east_north_central"),
    ("IA", "west_north_central"),
    ("KS", "west_north_central"),
    ("MN", "west_north_central"),
    ("MO", "west_north_central"),
    ("NE", "west_north_central"),
    ("ND", "west_north_central"),
    ("SD", "west_north_central"),
    ("DE", "south_atlantic"),
    ("FL", "south_atlantic"),
    ("GA", "south_atlantic"),
    ("MD", "south_atlantic"),
    ("NC", "south_atlantic"),
    ("SC", "south_atlantic"),
    ("VA", "south_atlantic"),
    ("DC", "south_atlantic"),
    ("WV", "south_atlantic"),
    ("AL", "east_south_central"),
    ("KY", "east_south_central"),
    ("MS", "east_south_central"),
    ("TN", "east_south_central"),
    ("AR", "west_south_central"),
    ("LA", "west_south_central"),
    ("OK", "west_south_central"),
    ("TX", "west_south_central"),
    ("AZ", "mountain"),
    ("CO", "mountain"),
    ("ID", "mountain"),
    ("MT", "mountain"),
    ("NV", "mountain"),
    ("NM", "mountain"),
    ("UT", "mountain"),
    ("WY", "mountain"),
    ("AK", "pacific"),
    ("CA", "pacific"),
    ("HI", "pacific"),
    ("OR", "pacific"),
    ("WA", "pacific"),
    ("PR", "territory"),
    ("GU", "territory"),
    ("VI", "territory"),
    ("AS", "territory"),
    ("MP", "territory"),
];

/// Division -> region mapping
const DIVISION_REGION_MAP: &[(&str, &str)] = &[
    ("new_england", "northeast"),
    ("mid_atlantic", "northeast"),
    ("east_north_central", "midwest"),
    ("west_north_central", "midwest"),
    ("south_atlantic", "south"),
    ("east_south_central", "south"),
    ("west_south_central", "south"),
    ("mountain", "west"),
    ("pacific", "west"),
    ("territory", "territory"),
];

// ============================================================================
// FrequencyTables struct
// ============================================================================

/// Per-field frequency lookup tables for k-anonymity estimation, l-diversity
/// checks, and context generalization.
///
/// All data is loaded from embedded constants at construction time (V1).
/// The struct is immutable after construction and safe to share across threads.
pub struct FrequencyTables {
    /// field_name -> (value -> frequency)
    tables: HashMap<String, HashMap<String, f64>>,
    /// field_name -> domain_size (number of distinct values in the table)
    domain_sizes: HashMap<String, u16>,
    /// field_name -> minimum known frequency (for conservative unknown estimates)
    min_frequencies: HashMap<String, f64>,
    /// Generalization mappings: field -> (specific_value -> generalized_value)
    gen_maps: HashMap<String, HashMap<String, String>>,
}

impl Default for FrequencyTables {
    fn default() -> Self {
        Self::new()
    }
}

impl FrequencyTables {
    /// Load frequency tables from embedded constants (V1).
    ///
    /// Constructs internal HashMaps from static const arrays. This is called
    /// once at pipeline initialization. All subsequent lookups are O(1).
    pub fn new() -> Self {
        let mut tables: HashMap<String, HashMap<String, f64>> = HashMap::new();
        let mut domain_sizes: HashMap<String, u16> = HashMap::new();
        let mut min_frequencies: HashMap<String, f64> = HashMap::new();
        let mut gen_maps: HashMap<String, HashMap<String, String>> = HashMap::new();

        // Helper: load a const array into a field's frequency table
        let mut load_field = |field_name: &str, data: &[(&str, f64)]| {
            let mut map = HashMap::with_capacity(data.len());
            let mut min_freq = f64::MAX;
            for &(value, freq) in data {
                map.insert(value.to_string(), freq);
                if freq < min_freq && freq > 0.0 {
                    min_freq = freq;
                }
            }
            let size = map.len() as u16;
            domain_sizes.insert(field_name.to_string(), size);
            // Conservative: unknown values get 0.5 * smallest known frequency
            min_frequencies.insert(field_name.to_string(), min_freq * 0.5);
            tables.insert(field_name.to_string(), map);
        };

        // Load all field tables
        load_field("entity_b_value", MEDICAL_PROCEDURE_FREQS);
        load_field("entity_a_type", ENTITY_TYPE_FREQS);
        load_field("entity_b_type", ENTITY_TYPE_FREQS);
        load_field("relation", RELATION_FREQS);
        load_field("amount_bucket", AMOUNT_BUCKET_FREQS);
        load_field("document_category", DOCUMENT_CATEGORY_FREQS);
        load_field("entity_a_role", ROLE_FREQS);
        load_field("entity_b_role", ROLE_FREQS);
        load_field("time_period", TIME_PERIOD_FREQS);

        // Geographic: merge state + division + region into one table
        {
            let mut geo_map = HashMap::with_capacity(
                STATE_FREQS.len() + DIVISION_FREQS.len() + REGION_FREQS.len(),
            );
            let mut min_freq = f64::MAX;
            for &(value, freq) in STATE_FREQS {
                geo_map.insert(value.to_string(), freq);
                if freq < min_freq && freq > 0.0 {
                    min_freq = freq;
                }
            }
            for &(value, freq) in DIVISION_FREQS {
                geo_map.insert(value.to_string(), freq);
                if freq < min_freq && freq > 0.0 {
                    min_freq = freq;
                }
            }
            for &(value, freq) in REGION_FREQS {
                geo_map.insert(value.to_string(), freq);
                if freq < min_freq && freq > 0.0 {
                    min_freq = freq;
                }
            }
            let size = geo_map.len() as u16;
            domain_sizes.insert("source_region".to_string(), size);
            min_frequencies.insert("source_region".to_string(), min_freq * 0.5);
            tables.insert("source_region".to_string(), geo_map);
        }

        // Also load organization data into entity_b_value (merged with medical).
        // When a key exists in both tables (e.g., "laboratory", "pharmacy"),
        // keep the higher frequency to avoid underestimating k-anonymity.
        if let Some(eb_table) = tables.get_mut("entity_b_value") {
            for &(value, freq) in ORGANIZATION_FREQS {
                let entry = eb_table.entry(value.to_string()).or_insert(0.0);
                if freq > *entry {
                    *entry = freq;
                }
            }
            // Recalculate domain size and min frequency
            let size = eb_table.len() as u16;
            domain_sizes.insert("entity_b_value".to_string(), size);
            let min_freq = eb_table
                .values()
                .copied()
                .filter(|&f| f > 0.0)
                .fold(f64::MAX, f64::min);
            min_frequencies.insert("entity_b_value".to_string(), min_freq * 0.5);
        }

        // Load generalization maps
        {
            let mut med_gen = HashMap::with_capacity(MEDICAL_CATEGORY_MAP.len());
            for &(specific, category) in MEDICAL_CATEGORY_MAP {
                med_gen.insert(specific.to_string(), category.to_string());
            }
            gen_maps.insert("entity_b_value_medical".to_string(), med_gen);
        }
        {
            let mut org_gen = HashMap::with_capacity(ORG_CATEGORY_MAP.len());
            for &(specific, category) in ORG_CATEGORY_MAP {
                org_gen.insert(specific.to_string(), category.to_string());
            }
            gen_maps.insert("entity_b_value_org".to_string(), org_gen);
        }
        {
            let mut state_gen = HashMap::with_capacity(STATE_DIVISION_MAP.len());
            for &(state, division) in STATE_DIVISION_MAP {
                state_gen.insert(state.to_string(), division.to_string());
            }
            gen_maps.insert("source_region_to_division".to_string(), state_gen);
        }
        {
            let mut div_gen = HashMap::with_capacity(DIVISION_REGION_MAP.len());
            for &(division, region) in DIVISION_REGION_MAP {
                div_gen.insert(division.to_string(), region.to_string());
            }
            gen_maps.insert("source_region_to_region".to_string(), div_gen);
        }

        Self {
            tables,
            domain_sizes,
            min_frequencies,
            gen_maps,
        }
    }

    /// Look up the frequency (probability) of a field value in the population.
    ///
    /// Returns a value in (0.0, 1.0] representing the estimated fraction of
    /// the population sharing this field value.
    ///
    /// Unknown values get a conservative lower-bound estimate equal to
    /// `min_frequency(field)` (0.5 * smallest known frequency for that field).
    /// Unknown fields return 0.001 as a safe fallback.
    pub fn field_frequency(&self, field_name: &str, value: &str) -> f64 {
        match self.tables.get(field_name) {
            Some(field_table) => {
                // Try exact match first
                if let Some(&freq) = field_table.get(value) {
                    return freq;
                }
                // Try case-insensitive match
                let lower = value.to_lowercase();
                if let Some(&freq) = field_table.get(&lower) {
                    return freq;
                }
                // Unknown value: conservative estimate
                self.min_frequency(field_name)
            }
            None => {
                // Unknown field entirely: very conservative
                0.001
            }
        }
    }

    /// Look up frequency at a specific generalization level.
    ///
    /// Generalization levels:
    /// - Level 0: specific value (exact lookup)
    /// - Level 1: first generalization (e.g., "mri" -> "imaging", "CA" -> "pacific")
    /// - Level 2: second generalization (e.g., "imaging" -> "medical", "pacific" -> "west")
    /// - Level 3+: maximum generalization (returns 1.0 -- the value covers everything)
    ///
    /// For fields without multi-level hierarchies, levels > 0 return the
    /// level-0 frequency or 1.0 for the catch-all.
    pub fn field_frequency_at_level(&self, field_name: &str, value: &str, gen_level: u8) -> f64 {
        if gen_level == 0 {
            return self.field_frequency(field_name, value);
        }

        let lower = value.to_lowercase();

        match field_name {
            "entity_b_value" => {
                match gen_level {
                    1 => {
                        // Specific -> category: look up category via medical or org map
                        let category = self
                            .gen_maps
                            .get("entity_b_value_medical")
                            .and_then(|m| m.get(&lower))
                            .or_else(|| {
                                self.gen_maps
                                    .get("entity_b_value_org")
                                    .and_then(|m| m.get(&lower))
                            });
                        match category {
                            Some(cat) => self.field_frequency(field_name, cat),
                            // Already a category or unknown: try direct lookup
                            None => self.field_frequency(field_name, value),
                        }
                    }
                    2 => {
                        // Category -> "medical" or "organization" (broad domain)
                        // Sum of all medical categories = ~1.0, all org categories = ~1.0
                        // Conservative: return the field's broadest category sum
                        0.5
                    }
                    _ => 1.0, // Maximum generalization: covers everything
                }
            }
            "source_region" => {
                match gen_level {
                    1 => {
                        // State -> division
                        let upper = value.to_uppercase();
                        let division = self
                            .gen_maps
                            .get("source_region_to_division")
                            .and_then(|m| m.get(&upper));
                        match division {
                            Some(div) => self.field_frequency(field_name, div),
                            None => {
                                // Maybe already a division: try direct lookup
                                self.field_frequency(field_name, value)
                            }
                        }
                    }
                    2 => {
                        // State/division -> region
                        let upper = value.to_uppercase();
                        // Try state -> division -> region
                        let division = self
                            .gen_maps
                            .get("source_region_to_division")
                            .and_then(|m| m.get(&upper));
                        if let Some(div) = division {
                            let region = self
                                .gen_maps
                                .get("source_region_to_region")
                                .and_then(|m| m.get(div.as_str()));
                            if let Some(reg) = region {
                                return self.field_frequency(field_name, reg);
                            }
                        }
                        // Try division -> region directly
                        let region = self
                            .gen_maps
                            .get("source_region_to_region")
                            .and_then(|m| m.get(&lower));
                        match region {
                            Some(reg) => self.field_frequency(field_name, reg),
                            None => self.field_frequency(field_name, value),
                        }
                    }
                    _ => 1.0,
                }
            }
            "amount_bucket" => {
                // Amount buckets have a flat hierarchy: bucket -> label -> "any"
                match gen_level {
                    1 => {
                        // Generalized amount labels from generalization.rs
                        // "micro" (<$100) = bucket 0 = 0.35
                        // "small" ($100-$500) = buckets 1-2 = 0.25 + 0.15 = 0.40
                        // "medium" ($500-$5K) = buckets 2-3 = 0.15 + 0.12 = 0.27
                        // "large" ($1K-$10K) = buckets 3-4 = 0.12 + 0.06 = 0.18
                        // "very_large" (>$10K) = buckets 5-7 = 0.04 + 0.02 + 0.01 = 0.07
                        match lower.as_str() {
                            "micro" | "$0-$100" | "0" => 0.3500,
                            "small" | "$100-$500" | "1" => 0.4000,
                            "medium" | "$500-$1k" | "$500-$1K" | "2" | "3" => 0.2700,
                            "large" | "$1k-$5k" | "$1K-$5K" | "4" | "5" => 0.1800,
                            "very_large" | "6" | "7" => 0.0700,
                            "na" | "255" => 0.0050,
                            _ => self.field_frequency(field_name, value),
                        }
                    }
                    _ => 1.0,
                }
            }
            "time_period" => {
                match gen_level {
                    1 => {
                        // Quarter -> year
                        if lower.contains("-q") || lower.contains("-Q") {
                            let year = &value[..4];
                            self.field_frequency(field_name, year)
                        } else {
                            self.field_frequency(field_name, value)
                        }
                    }
                    _ => 1.0,
                }
            }
            // For fields without hierarchies (entity_a_type, entity_b_type,
            // relation, document_category, roles), there are no intermediate
            // levels -- level 1+ means "any" = 1.0
            _ => {
                if gen_level >= 2 {
                    1.0
                } else {
                    // Level 1 for flat fields: return the value's own frequency
                    // (no generalization hierarchy to climb)
                    self.field_frequency(field_name, value)
                }
            }
        }
    }

    /// Get the domain size (number of distinct values) for a field.
    ///
    /// Returns 1 for unknown fields (conservative: single-value domain
    /// maximizes selectivity estimate).
    pub fn domain_size(&self, field_name: &str) -> u16 {
        self.domain_sizes.get(field_name).copied().unwrap_or(1)
    }

    /// Conservative minimum frequency for unknown values in a field.
    ///
    /// This is 0.5 * the smallest known frequency for the field, providing
    /// a safety margin. Used by k-anonymity and l-diversity checks to
    /// conservatively estimate how rare an unknown value might be.
    ///
    /// Returns 0.0005 for unknown fields.
    pub fn min_frequency(&self, field_name: &str) -> f64 {
        self.min_frequencies
            .get(field_name)
            .copied()
            .unwrap_or(0.0005)
    }

    /// Get all known values for a field (useful for domain enumeration in OUE).
    pub fn known_values(&self, field_name: &str) -> Vec<&str> {
        match self.tables.get(field_name) {
            Some(table) => table.keys().map(|s| s.as_str()).collect(),
            None => Vec::new(),
        }
    }

    /// Get the generalized value of a specific value at a given level.
    /// Returns None if no generalization mapping exists.
    pub fn generalize_value(&self, field_name: &str, value: &str, gen_level: u8) -> Option<String> {
        if gen_level == 0 {
            return Some(value.to_string());
        }

        match field_name {
            "entity_b_value" => {
                let lower = value.to_lowercase();
                match gen_level {
                    1 => self
                        .gen_maps
                        .get("entity_b_value_medical")
                        .and_then(|m| m.get(&lower))
                        .or_else(|| {
                            self.gen_maps
                                .get("entity_b_value_org")
                                .and_then(|m| m.get(&lower))
                        })
                        .cloned(),
                    2 => Some("*".to_string()),
                    _ => Some("*".to_string()),
                }
            }
            "source_region" => {
                let upper = value.to_uppercase();
                match gen_level {
                    1 => self
                        .gen_maps
                        .get("source_region_to_division")
                        .and_then(|m| m.get(&upper))
                        .cloned(),
                    2 => {
                        let division = self
                            .gen_maps
                            .get("source_region_to_division")
                            .and_then(|m| m.get(&upper));
                        match division {
                            Some(div) => self
                                .gen_maps
                                .get("source_region_to_region")
                                .and_then(|m| m.get(div.as_str()))
                                .cloned(),
                            None => self
                                .gen_maps
                                .get("source_region_to_region")
                                .and_then(|m| m.get(&value.to_lowercase()))
                                .cloned(),
                        }
                    }
                    _ => Some("*".to_string()),
                }
            }
            _ => {
                if gen_level >= 2 {
                    Some("*".to_string())
                } else {
                    None
                }
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn tables() -> FrequencyTables {
        FrequencyTables::new()
    }

    // -----------------------------------------------------------------------
    // Construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn construction_succeeds() {
        let ft = tables();
        assert!(!ft.tables.is_empty());
        assert!(!ft.domain_sizes.is_empty());
        assert!(!ft.min_frequencies.is_empty());
    }

    #[test]
    fn all_required_fields_present() {
        let ft = tables();
        let required_fields = [
            "entity_a_type",
            "entity_b_type",
            "entity_b_value",
            "relation",
            "amount_bucket",
            "document_category",
            "source_region",
            "time_period",
            "entity_a_role",
            "entity_b_role",
        ];
        for field in &required_fields {
            assert!(
                ft.tables.contains_key(*field),
                "Missing required field: {}",
                field
            );
        }
    }

    // -----------------------------------------------------------------------
    // Medical procedure frequency tests
    // -----------------------------------------------------------------------

    #[test]
    fn medical_imaging_frequency() {
        let ft = tables();
        let freq = ft.field_frequency("entity_b_value", "imaging");
        assert!(
            (freq - 0.25).abs() < 0.001,
            "imaging should be ~25%, got {}",
            freq
        );
    }

    #[test]
    fn medical_laboratory_frequency() {
        let ft = tables();
        let freq = ft.field_frequency("entity_b_value", "laboratory");
        assert!(
            (freq - 0.30).abs() < 0.001,
            "laboratory should be ~30%, got {}",
            freq
        );
    }

    #[test]
    fn medical_surgery_frequency() {
        let ft = tables();
        let freq = ft.field_frequency("entity_b_value", "surgery");
        assert!(
            (freq - 0.10).abs() < 0.001,
            "surgery should be ~10%, got {}",
            freq
        );
    }

    #[test]
    fn medical_emergency_frequency() {
        let ft = tables();
        let freq = ft.field_frequency("entity_b_value", "emergency");
        assert!(
            (freq - 0.05).abs() < 0.001,
            "emergency should be ~5%, got {}",
            freq
        );
    }

    #[test]
    fn medical_specific_term_mri() {
        let ft = tables();
        let freq = ft.field_frequency("entity_b_value", "mri");
        assert!(
            freq > 0.0 && freq < 0.25,
            "mri should be between 0 and imaging category"
        );
        assert!((freq - 0.0375).abs() < 0.001);
    }

    #[test]
    fn medical_specific_term_blood_test() {
        let ft = tables();
        let freq = ft.field_frequency("entity_b_value", "blood_test");
        assert!(
            freq > 0.0 && freq < 0.30,
            "blood_test should be between 0 and lab category"
        );
    }

    // -----------------------------------------------------------------------
    // Organization frequency tests
    // -----------------------------------------------------------------------

    #[test]
    fn org_hospital_frequency() {
        let ft = tables();
        let freq = ft.field_frequency("entity_b_value", "hospital");
        assert!(freq > 0.0, "hospital should have positive frequency");
        assert!((freq - 0.06).abs() < 0.01);
    }

    #[test]
    fn org_healthcare_provider_category() {
        let ft = tables();
        let freq = ft.field_frequency("entity_b_value", "healthcare_provider");
        assert!(
            (freq - 0.20).abs() < 0.01,
            "healthcare_provider should be ~20%, got {}",
            freq
        );
    }

    // -----------------------------------------------------------------------
    // Geographic frequency tests
    // -----------------------------------------------------------------------

    #[test]
    fn geo_california_frequency() {
        let ft = tables();
        let freq = ft.field_frequency("source_region", "CA");
        assert!(
            (freq - 0.1186).abs() < 0.01,
            "CA should be ~11.86%, got {}",
            freq
        );
    }

    #[test]
    fn geo_texas_frequency() {
        let ft = tables();
        let freq = ft.field_frequency("source_region", "TX");
        assert!(
            (freq - 0.0884).abs() < 0.01,
            "TX should be ~8.84%, got {}",
            freq
        );
    }

    #[test]
    fn geo_south_region_frequency() {
        let ft = tables();
        let freq = ft.field_frequency("source_region", "south");
        assert!(
            (freq - 0.3837).abs() < 0.01,
            "South region should be ~38.37%, got {}",
            freq
        );
    }

    #[test]
    fn geo_division_pacific_frequency() {
        let ft = tables();
        let freq = ft.field_frequency("source_region", "pacific");
        assert!(
            freq > 0.10 && freq < 0.25,
            "Pacific division should be between 10-25%"
        );
    }

    // -----------------------------------------------------------------------
    // Amount bucket frequency tests
    // -----------------------------------------------------------------------

    #[test]
    fn amount_bucket_0_100() {
        let ft = tables();
        let freq = ft.field_frequency("amount_bucket", "$0-$100");
        assert!(
            (freq - 0.35).abs() < 0.01,
            "$0-$100 should be ~35%, got {}",
            freq
        );
    }

    #[test]
    fn amount_bucket_100_500() {
        let ft = tables();
        let freq = ft.field_frequency("amount_bucket", "$100-$500");
        assert!(
            (freq - 0.25).abs() < 0.01,
            "$100-$500 should be ~25%, got {}",
            freq
        );
    }

    #[test]
    fn amount_bucket_by_index() {
        let ft = tables();
        let freq = ft.field_frequency("amount_bucket", "0");
        assert!((freq - 0.35).abs() < 0.01, "bucket 0 should be ~35%");
    }

    #[test]
    fn amount_bucket_100k_plus() {
        let ft = tables();
        let freq = ft.field_frequency("amount_bucket", "$100K+");
        assert!(
            (freq - 0.01).abs() < 0.005,
            "$100K+ should be ~1%, got {}",
            freq
        );
    }

    // -----------------------------------------------------------------------
    // Document category frequency tests
    // -----------------------------------------------------------------------

    #[test]
    fn doc_category_receipt() {
        let ft = tables();
        let freq = ft.field_frequency("document_category", "receipt");
        assert!(
            (freq - 0.30).abs() < 0.01,
            "receipt should be ~30%, got {}",
            freq
        );
    }

    #[test]
    fn doc_category_medical_bill() {
        let ft = tables();
        let freq = ft.field_frequency("document_category", "medical_bill");
        assert!(
            (freq - 0.15).abs() < 0.01,
            "medical_bill should be ~15%, got {}",
            freq
        );
    }

    #[test]
    fn doc_category_lease() {
        let ft = tables();
        let freq = ft.field_frequency("document_category", "lease");
        assert!(
            (freq - 0.05).abs() < 0.01,
            "lease should be ~5%, got {}",
            freq
        );
    }

    // -----------------------------------------------------------------------
    // Entity type and role frequency tests
    // -----------------------------------------------------------------------

    #[test]
    fn entity_type_organization() {
        let ft = tables();
        let freq = ft.field_frequency("entity_a_type", "organization");
        assert!(
            (freq - 0.25).abs() < 0.01,
            "organization should be ~25%, got {}",
            freq
        );
    }

    #[test]
    fn entity_type_procedure() {
        let ft = tables();
        let freq = ft.field_frequency("entity_b_type", "procedure");
        assert!(
            (freq - 0.15).abs() < 0.01,
            "procedure should be ~15%, got {}",
            freq
        );
    }

    #[test]
    fn role_provider() {
        let ft = tables();
        let freq = ft.field_frequency("entity_a_role", "provider");
        assert!(
            (freq - 0.18).abs() < 0.01,
            "provider role should be ~18%, got {}",
            freq
        );
    }

    #[test]
    fn role_charge() {
        let ft = tables();
        let freq = ft.field_frequency("entity_b_role", "charge");
        assert!(
            (freq - 0.15).abs() < 0.01,
            "charge role should be ~15%, got {}",
            freq
        );
    }

    // -----------------------------------------------------------------------
    // Relation frequency tests
    // -----------------------------------------------------------------------

    #[test]
    fn relation_charged_for() {
        let ft = tables();
        let freq = ft.field_frequency("relation", "charged_for");
        assert!(
            (freq - 0.20).abs() < 0.01,
            "charged_for should be ~20%, got {}",
            freq
        );
    }

    #[test]
    fn relation_prescribed() {
        let ft = tables();
        let freq = ft.field_frequency("relation", "prescribed");
        assert!(
            (freq - 0.08).abs() < 0.01,
            "prescribed should be ~8%, got {}",
            freq
        );
    }

    // -----------------------------------------------------------------------
    // Unknown value tests
    // -----------------------------------------------------------------------

    #[test]
    fn unknown_value_returns_min_frequency() {
        let ft = tables();
        let freq = ft.field_frequency("entity_a_type", "completely_unknown_type");
        let min = ft.min_frequency("entity_a_type");
        assert!(
            (freq - min).abs() < 1e-10,
            "Unknown value should return min_frequency, got {} vs {}",
            freq,
            min
        );
    }

    #[test]
    fn unknown_value_is_conservative() {
        let ft = tables();
        let unknown_freq = ft.field_frequency("document_category", "alien_doc");
        let min_known = DOCUMENT_CATEGORY_FREQS
            .iter()
            .map(|&(_, f)| f)
            .filter(|&f| f > 0.0)
            .fold(f64::MAX, f64::min);
        // Unknown should be 0.5 * smallest known
        assert!(
            (unknown_freq - min_known * 0.5).abs() < 1e-10,
            "Unknown frequency {} should be 0.5 * min known {}",
            unknown_freq,
            min_known
        );
    }

    #[test]
    fn unknown_field_returns_fallback() {
        let ft = tables();
        let freq = ft.field_frequency("nonexistent_field", "any_value");
        assert!(
            (freq - 0.001).abs() < 1e-10,
            "Unknown field should return 0.001"
        );
    }

    #[test]
    fn min_frequency_known_field() {
        let ft = tables();
        let min = ft.min_frequency("entity_a_type");
        assert!(min > 0.0, "min_frequency should be positive");
        assert!(min < 0.01, "min_frequency should be small");
    }

    #[test]
    fn min_frequency_unknown_field() {
        let ft = tables();
        let min = ft.min_frequency("nonexistent_field");
        assert!(
            (min - 0.0005).abs() < 1e-10,
            "Unknown field min should be 0.0005"
        );
    }

    // -----------------------------------------------------------------------
    // Domain size tests
    // -----------------------------------------------------------------------

    #[test]
    fn domain_size_entity_b_value_large() {
        let ft = tables();
        let size = ft.domain_size("entity_b_value");
        // Medical (~120) + org (~130) = ~250 entries
        assert!(
            size > 100,
            "entity_b_value domain should be large, got {}",
            size
        );
    }

    #[test]
    fn domain_size_source_region() {
        let ft = tables();
        let size = ft.domain_size("source_region");
        // 51 states + 5 territories + 11 divisions + 6 regions = ~73
        assert!(
            size > 50,
            "source_region domain should include states+divisions+regions, got {}",
            size
        );
    }

    #[test]
    fn domain_size_document_category() {
        let ft = tables();
        let size = ft.domain_size("document_category");
        assert!(
            size >= 15,
            "document_category should have >= 15 values, got {}",
            size
        );
    }

    #[test]
    fn domain_size_unknown_field() {
        let ft = tables();
        let size = ft.domain_size("nonexistent_field");
        assert_eq!(
            size, 1,
            "Unknown field domain size should be 1 (conservative)"
        );
    }

    #[test]
    fn domain_size_amount_bucket() {
        let ft = tables();
        let size = ft.domain_size("amount_bucket");
        assert!(
            size >= 16,
            "amount_bucket should have label+index entries, got {}",
            size
        );
    }

    // -----------------------------------------------------------------------
    // Generalization level tests
    // -----------------------------------------------------------------------

    #[test]
    fn level_0_equals_direct_lookup() {
        let ft = tables();
        let direct = ft.field_frequency("entity_b_value", "mri");
        let level0 = ft.field_frequency_at_level("entity_b_value", "mri", 0);
        assert!(
            (direct - level0).abs() < 1e-10,
            "Level 0 should equal direct lookup"
        );
    }

    #[test]
    fn level_1_medical_specific_to_category() {
        let ft = tables();
        let level1 = ft.field_frequency_at_level("entity_b_value", "mri", 1);
        let imaging = ft.field_frequency("entity_b_value", "imaging");
        assert!(
            (level1 - imaging).abs() < 1e-10,
            "mri at level 1 should equal imaging frequency: {} vs {}",
            level1,
            imaging
        );
    }

    #[test]
    fn level_1_medical_blood_test_to_lab() {
        let ft = tables();
        let level1 = ft.field_frequency_at_level("entity_b_value", "blood_test", 1);
        let lab = ft.field_frequency("entity_b_value", "laboratory");
        assert!(
            (level1 - lab).abs() < 1e-10,
            "blood_test at level 1 should equal laboratory frequency"
        );
    }

    #[test]
    fn level_1_org_hospital_to_healthcare() {
        let ft = tables();
        let level1 = ft.field_frequency_at_level("entity_b_value", "hospital", 1);
        let hcp = ft.field_frequency("entity_b_value", "healthcare_provider");
        assert!(
            (level1 - hcp).abs() < 1e-10,
            "hospital at level 1 should equal healthcare_provider frequency"
        );
    }

    #[test]
    fn level_2_returns_broad_estimate() {
        let ft = tables();
        let level2 = ft.field_frequency_at_level("entity_b_value", "mri", 2);
        assert!(
            level2 >= 0.1,
            "Level 2 generalization should be a broad fraction"
        );
    }

    #[test]
    fn level_3_returns_one() {
        let ft = tables();
        let level3 = ft.field_frequency_at_level("entity_b_value", "mri", 3);
        assert!(
            (level3 - 1.0).abs() < 1e-10,
            "Level 3+ should return 1.0 (covers everything)"
        );
    }

    #[test]
    fn level_1_geo_state_to_division() {
        let ft = tables();
        let level1 = ft.field_frequency_at_level("source_region", "CA", 1);
        let pacific = ft.field_frequency("source_region", "pacific");
        assert!(
            (level1 - pacific).abs() < 1e-10,
            "CA at level 1 should equal pacific frequency: {} vs {}",
            level1,
            pacific
        );
    }

    #[test]
    fn level_2_geo_state_to_region() {
        let ft = tables();
        let level2 = ft.field_frequency_at_level("source_region", "CA", 2);
        let west = ft.field_frequency("source_region", "west");
        assert!(
            (level2 - west).abs() < 1e-10,
            "CA at level 2 should equal west region frequency: {} vs {}",
            level2,
            west
        );
    }

    #[test]
    fn level_1_amount_bucket_generalized() {
        let ft = tables();
        // Bucket 0 ($0-$100) at level 1 should give the "micro" frequency
        let level1 = ft.field_frequency_at_level("amount_bucket", "$0-$100", 1);
        assert!(
            (level1 - 0.35).abs() < 0.01,
            "$0-$100 at level 1 should be ~35%, got {}",
            level1
        );
    }

    #[test]
    fn level_1_time_period_quarter_to_year() {
        let ft = tables();
        let level1 = ft.field_frequency_at_level("time_period", "2025-Q3", 1);
        let year = ft.field_frequency("time_period", "2025");
        assert!(
            (level1 - year).abs() < 1e-10,
            "2025-Q3 at level 1 should equal 2025 frequency: {} vs {}",
            level1,
            year
        );
    }

    #[test]
    fn level_2_flat_field_returns_one() {
        let ft = tables();
        // entity_a_type has no hierarchy, level 2+ should return 1.0
        let level2 = ft.field_frequency_at_level("entity_a_type", "organization", 2);
        assert!(
            (level2 - 1.0).abs() < 1e-10,
            "Flat field at level 2 should return 1.0"
        );
    }

    // -----------------------------------------------------------------------
    // Generalize value tests
    // -----------------------------------------------------------------------

    #[test]
    fn generalize_mri_to_imaging() {
        let ft = tables();
        let gen = ft.generalize_value("entity_b_value", "mri", 1);
        assert_eq!(gen, Some("imaging".to_string()));
    }

    #[test]
    fn generalize_hospital_to_healthcare_provider() {
        let ft = tables();
        let gen = ft.generalize_value("entity_b_value", "hospital", 1);
        assert_eq!(gen, Some("healthcare_provider".to_string()));
    }

    #[test]
    fn generalize_ca_to_pacific() {
        let ft = tables();
        let gen = ft.generalize_value("source_region", "CA", 1);
        assert_eq!(gen, Some("pacific".to_string()));
    }

    #[test]
    fn generalize_ca_to_west() {
        let ft = tables();
        let gen = ft.generalize_value("source_region", "CA", 2);
        assert_eq!(gen, Some("west".to_string()));
    }

    #[test]
    fn generalize_level_0_returns_identity() {
        let ft = tables();
        let gen = ft.generalize_value("entity_b_value", "mri", 0);
        assert_eq!(gen, Some("mri".to_string()));
    }

    #[test]
    fn generalize_level_3_returns_star() {
        let ft = tables();
        let gen = ft.generalize_value("entity_b_value", "mri", 3);
        assert_eq!(gen, Some("*".to_string()));
    }

    // -----------------------------------------------------------------------
    // Distribution validity tests
    // -----------------------------------------------------------------------

    #[test]
    fn region_frequencies_sum_near_one() {
        let sum: f64 = REGION_FREQS.iter().map(|&(_, f)| f).sum();
        assert!(
            (sum - 1.0).abs() < 0.02,
            "Region frequencies should sum to ~1.0, got {}",
            sum
        );
    }

    #[test]
    fn document_category_frequencies_sum_near_one() {
        let sum: f64 = DOCUMENT_CATEGORY_FREQS.iter().map(|&(_, f)| f).sum();
        assert!(
            (sum - 1.0).abs() < 0.02,
            "Document category frequencies should sum to ~1.0, got {}",
            sum
        );
    }

    #[test]
    fn entity_type_frequencies_sum_near_one() {
        let sum: f64 = ENTITY_TYPE_FREQS.iter().map(|&(_, f)| f).sum();
        assert!(
            (sum - 1.0).abs() < 0.02,
            "Entity type frequencies should sum to ~1.0, got {}",
            sum
        );
    }

    #[test]
    fn role_frequencies_sum_near_one() {
        let sum: f64 = ROLE_FREQS.iter().map(|&(_, f)| f).sum();
        assert!(
            (sum - 1.0).abs() < 0.02,
            "Role frequencies should sum to ~1.0, got {}",
            sum
        );
    }

    #[test]
    fn relation_frequencies_sum_near_one() {
        let sum: f64 = RELATION_FREQS.iter().map(|&(_, f)| f).sum();
        assert!(
            (sum - 1.0).abs() < 0.02,
            "Relation frequencies should sum to ~1.0, got {}",
            sum
        );
    }

    #[test]
    fn state_frequencies_sum_near_one() {
        let sum: f64 = STATE_FREQS.iter().map(|&(_, f)| f).sum();
        assert!(
            (sum - 1.0).abs() < 0.05,
            "State frequencies should sum to ~1.0, got {}",
            sum
        );
    }

    #[test]
    fn all_frequencies_positive() {
        let ft = tables();
        for (field_name, field_table) in &ft.tables {
            for (value, &freq) in field_table {
                assert!(
                    freq > 0.0,
                    "Frequency for {}.{} should be positive, got {}",
                    field_name,
                    value,
                    freq
                );
            }
        }
    }

    #[test]
    fn all_frequencies_at_most_one() {
        let ft = tables();
        for (field_name, field_table) in &ft.tables {
            for (value, &freq) in field_table {
                assert!(
                    freq <= 1.0,
                    "Frequency for {}.{} should be <= 1.0, got {}",
                    field_name,
                    value,
                    freq
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Thread safety (compile-time check: FrequencyTables is Send + Sync)
    // -----------------------------------------------------------------------

    #[test]
    fn frequency_tables_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FrequencyTables>();
    }

    // -----------------------------------------------------------------------
    // Known values enumeration
    // -----------------------------------------------------------------------

    #[test]
    fn known_values_entity_b_value_nonempty() {
        let ft = tables();
        let vals = ft.known_values("entity_b_value");
        assert!(
            vals.len() > 100,
            "entity_b_value should have > 100 known values, got {}",
            vals.len()
        );
    }

    #[test]
    fn known_values_unknown_field_empty() {
        let ft = tables();
        let vals = ft.known_values("nonexistent");
        assert!(vals.is_empty());
    }
}
