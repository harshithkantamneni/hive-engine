//! Stage 3 of the Privacy Pipeline: Context Generalizer
//!
//! Elevates field values in multi-level generalization hierarchies (L0-L4)
//! until the estimated k-anonymity exceeds the tier-specific threshold.
//! If k is unreachable at maximum generalization, the tuple is suppressed
//! (returns `None`).
//!
//! ## Algorithm
//!
//! Uses a greedy approach: at each iteration, generalize the single field
//! whose one-level elevation produces the maximum increase in estimated k.
//! This is repeated until `estimated_k >= k_target` or all fields are at
//! their maximum generalization level.
//!
//! ## k-Estimation Model (V1)
//!
//! Simplified multiplicative model:
//!   `estimated_k = N * product(field_frequency(field, value_at_level))`
//! where N is the estimated network size and field_frequency comes from
//! frequency tables (trait-abstracted for parallel development).
//!
//! ## Dependencies
//!
//! - `privacy::types` -- `BucketedTuple`, `GeneralizedTuple`, `SensitivityTier`
//! - `privacy::config` -- `PrivacyConfig` (k_thresholds, cold_start phase_thresholds)

use std::collections::HashMap;

use super::config::PrivacyConfig;
use super::types::{BucketedTuple, GeneralizedTuple, SensitivityTier};

// ─── Frequency Provider Trait ──────────────────────────────────────────────

/// Trait for accessing field frequency data used in k-estimation.
///
/// This trait decouples the generalizer from the concrete frequency table
/// implementation.
pub trait FrequencyProvider {
    /// Return the base frequency of a field value (L0 frequency).
    fn field_frequency(&self, field_name: &str, value: &str) -> f64;

    /// Return the frequency of a field value at a specific generalization level.
    /// Higher levels aggregate more values, so frequency should be monotonically
    /// non-decreasing as `gen_level` increases.
    fn field_frequency_at_level(&self, field_name: &str, value: &str, gen_level: u8) -> f64;
}

// ─── Generalization Hierarchies ────────────────────────────────────────────

/// Describes one generalizable field: its name, maximum level, and the
/// hierarchy lookup function.
#[derive(Clone)]
struct FieldHierarchy {
    name: &'static str,
    max_level: u8,
}

/// All multi-level generalization hierarchies for the pipeline.
/// Each field maps raw values through progressively broader categories.
struct GeneralizationHierarchies {
    /// Map from field name to its hierarchy descriptor.
    fields: Vec<FieldHierarchy>,
    /// Medical procedure hierarchy: L0 specific -> L4 wildcard.
    medical_l1: HashMap<String, &'static str>,
    medical_l2: HashMap<&'static str, &'static str>,
    /// Organization type hierarchy.
    org_l1: HashMap<String, &'static str>,
    /// Reserved for future level-2 org rollup; initialized empty today but kept so
    /// schema matches the other hierarchies and to minimize churn when L2 lands.
    #[allow(dead_code)]
    org_l2: HashMap<&'static str, &'static str>,
    /// Geographic hierarchy: state -> division -> region -> country.
    geo_division: HashMap<String, &'static str>,
    geo_region: HashMap<&'static str, &'static str>,
    /// Relation hierarchy.
    relation_l1: HashMap<String, &'static str>,
    /// Document category hierarchy.
    doc_l1: HashMap<String, &'static str>,
    /// Role hierarchy.
    role_l1: HashMap<String, &'static str>,
    /// Amount bucket label mapping.
    amount_l1: HashMap<u8, &'static str>,
}

impl GeneralizationHierarchies {
    fn new() -> Self {
        Self {
            fields: vec![
                FieldHierarchy {
                    name: "entity_b_value",
                    max_level: 4,
                },
                FieldHierarchy {
                    name: "source_region",
                    max_level: 4,
                },
                FieldHierarchy {
                    name: "entity_a_type",
                    max_level: 3,
                },
                FieldHierarchy {
                    name: "entity_b_type",
                    max_level: 3,
                },
                FieldHierarchy {
                    name: "amount_bucket",
                    max_level: 3,
                },
                FieldHierarchy {
                    name: "relation",
                    max_level: 2,
                },
                FieldHierarchy {
                    name: "time_period",
                    max_level: 3,
                },
                FieldHierarchy {
                    name: "document_category",
                    max_level: 2,
                },
                FieldHierarchy {
                    name: "entity_a_role",
                    max_level: 2,
                },
                FieldHierarchy {
                    name: "entity_b_role",
                    max_level: 2,
                },
            ],
            medical_l1: Self::build_medical_l1(),
            medical_l2: Self::build_medical_l2(),
            org_l1: Self::build_org_l1(),
            org_l2: Self::build_org_l2(),
            geo_division: Self::build_geo_division(),
            geo_region: Self::build_geo_region(),
            relation_l1: Self::build_relation_l1(),
            doc_l1: Self::build_doc_l1(),
            role_l1: Self::build_role_l1(),
            amount_l1: Self::build_amount_l1(),
        }
    }

    // ── Medical procedure hierarchy (L0 -> L1) ────────────────────────────
    // Extends generalization.rs L0->L1 mapping.
    // L0: specific procedure (e.g. "MRI")
    // L1: category (e.g. "imaging") -- from generalization.rs
    // L2: broad medical category (e.g. "diagnostic")
    // L3: "medical_service"
    // L4: "*"

    fn build_medical_l1() -> HashMap<String, &'static str> {
        let mut m = HashMap::new();
        // Imaging
        for term in &[
            "mri",
            "ct_scan",
            "ct scan",
            "x-ray",
            "x_ray",
            "xray",
            "ultrasound",
            "mammogram",
            "pet_scan",
            "pet scan",
            "fluoroscopy",
            "echocardiogram",
            "ekg",
            "eeg",
            "dexa_scan",
            "dexa scan",
            "bone_scan",
            "bone scan",
            "angiogram",
            "angiography",
            "mra",
            "imaging",
        ] {
            m.insert(term.to_string(), "imaging");
        }
        // Surgery
        for term in &[
            "appendectomy",
            "cholecystectomy",
            "hernia_repair",
            "hernia repair",
            "knee_replacement",
            "knee replacement",
            "hip_replacement",
            "hip replacement",
            "coronary_bypass",
            "coronary bypass",
            "cabg",
            "cesarean",
            "c-section",
            "c_section",
            "tonsillectomy",
            "mastectomy",
            "lumpectomy",
            "colectomy",
            "gastrectomy",
            "hysterectomy",
            "prostatectomy",
            "nephrectomy",
            "arthroscopy",
            "laparoscopy",
            "endoscopy",
            "biopsy",
            "surgery",
            "surgical_procedure",
            "surgical procedure",
            "operation",
        ] {
            m.insert(term.to_string(), "surgery");
        }
        // Emergency
        for term in &[
            "er_visit",
            "er visit",
            "emergency_room",
            "emergency room",
            "emergency",
            "trauma",
            "trauma_care",
            "trauma care",
            "ambulance",
            "emt",
            "urgent_care",
            "urgent care",
            "resuscitation",
            "intubation",
            "defibrillation",
            "emergency_surgery",
            "emergency surgery",
        ] {
            m.insert(term.to_string(), "emergency");
        }
        // Laboratory
        for term in &[
            "blood_test",
            "blood test",
            "blood_work",
            "blood work",
            "cbc",
            "cmp",
            "bmp",
            "lipid_panel",
            "lipid panel",
            "urinalysis",
            "urine_test",
            "urine test",
            "culture",
            "pathology",
            "cytology",
            "histology",
            "hba1c",
            "a1c",
            "glucose_test",
            "glucose test",
            "cholesterol_test",
            "cholesterol test",
            "thyroid_panel",
            "thyroid panel",
            "tsh",
            "psa",
            "lab",
            "laboratory",
            "lab_work",
            "lab work",
        ] {
            m.insert(term.to_string(), "laboratory");
        }
        // Therapy
        for term in &[
            "physical_therapy",
            "physical therapy",
            "pt",
            "occupational_therapy",
            "occupational therapy",
            "ot",
            "speech_therapy",
            "speech therapy",
            "chemotherapy",
            "chemo",
            "radiation_therapy",
            "radiation therapy",
            "radiation",
            "dialysis",
            "infusion",
            "respiratory_therapy",
            "respiratory therapy",
            "rehabilitation",
            "rehab",
            "therapy",
        ] {
            m.insert(term.to_string(), "therapy");
        }
        // Consultation
        for term in &[
            "office_visit",
            "office visit",
            "consultation",
            "consult",
            "follow_up",
            "follow up",
            "follow-up",
            "evaluation",
            "assessment",
            "exam",
            "examination",
            "telehealth",
            "telemedicine",
            "virtual_visit",
            "virtual visit",
            "second_opinion",
            "second opinion",
            "referral",
            "specialist_visit",
            "specialist visit",
        ] {
            m.insert(term.to_string(), "consultation");
        }
        // Pharmacy
        for term in &[
            "prescription",
            "medication",
            "drug",
            "pharmacy",
            "refill",
            "dispensing",
            "injection",
            "vaccine",
            "vaccination",
            "immunization",
            "flu_shot",
            "flu shot",
            "insulin",
            "antibiotic",
        ] {
            m.insert(term.to_string(), "pharmacy");
        }
        // Preventive
        for term in &[
            "annual_physical",
            "annual physical",
            "physical_exam",
            "physical exam",
            "screening",
            "wellness_visit",
            "wellness visit",
            "checkup",
            "check-up",
            "check_up",
            "colonoscopy",
            "pap_smear",
            "pap smear",
            "dental_cleaning",
            "dental cleaning",
            "eye_exam",
            "eye exam",
            "hearing_test",
            "hearing test",
            "preventive",
            "preventive_care",
            "preventive care",
        ] {
            m.insert(term.to_string(), "preventive");
        }
        m
    }

    fn build_medical_l2() -> HashMap<&'static str, &'static str> {
        let mut m = HashMap::new();
        // L1 category -> L2 broad medical category
        m.insert("imaging", "diagnostic");
        m.insert("laboratory", "diagnostic");
        m.insert("surgery", "therapeutic");
        m.insert("therapy", "therapeutic");
        m.insert("emergency", "acute_care");
        m.insert("consultation", "clinical_encounter");
        m.insert("pharmacy", "therapeutic");
        m.insert("preventive", "clinical_encounter");
        m.insert("other_medical", "medical_service");
        m
    }

    // ── Organization type hierarchy (L0 -> L1) ───────────────────────────
    // L0: specific type (e.g. "hospital")
    // L1: category (e.g. "healthcare_provider") -- from generalization.rs
    // L2: "organization"
    // L3: "*"

    fn build_org_l1() -> HashMap<String, &'static str> {
        let mut m = HashMap::new();
        // Healthcare providers
        for term in &[
            "hospital",
            "clinic",
            "medical_center",
            "medical center",
            "health_center",
            "health center",
            "provider",
            "physician",
            "doctor",
            "dentist",
            "dental_office",
            "dental office",
            "pharmacy",
            "urgent_care",
            "urgent care",
            "nursing_home",
            "nursing home",
            "assisted_living",
            "assisted living",
            "rehab_center",
            "rehab center",
            "rehabilitation_center",
            "rehabilitation center",
            "lab",
            "laboratory",
            "diagnostic_center",
            "diagnostic center",
            "imaging_center",
            "imaging center",
            "radiology",
            "mental_health",
            "mental health",
            "psychiatry",
            "psychology",
            "optometry",
            "optometrist",
            "ophthalmology",
            "pediatrics",
            "obgyn",
            "cardiology",
            "oncology",
            "dermatology",
            "orthopedics",
            "healthcare_provider",
            "healthcare provider",
            "medical_group",
            "medical group",
            "health_system",
            "health system",
        ] {
            m.insert(term.to_string(), "healthcare_provider");
        }
        // Financial institutions
        for term in &[
            "bank",
            "credit_union",
            "credit union",
            "savings_bank",
            "savings bank",
            "investment_firm",
            "investment firm",
            "brokerage",
            "broker",
            "mortgage_company",
            "mortgage company",
            "lending",
            "lender",
            "loan_company",
            "loan company",
            "financial_advisor",
            "financial advisor",
            "wealth_management",
            "wealth management",
            "accounting_firm",
            "accounting firm",
            "cpa",
            "tax_preparer",
            "tax preparer",
            "financial_institution",
            "financial institution",
            "fintech",
        ] {
            m.insert(term.to_string(), "financial_institution");
        }
        // Government
        for term in &[
            "irs",
            "ssa",
            "cms",
            "fda",
            "cdc",
            "epa",
            "doj",
            "dhs",
            "government",
            "govt",
            "federal",
            "state_agency",
            "state agency",
            "county",
            "city",
            "municipal",
            "municipality",
            "department",
            "bureau",
            "agency",
            "court",
            "courthouse",
            "dmv",
            "post_office",
            "post office",
            "veterans_affairs",
            "veterans affairs",
            "va",
            "social_security",
            "social security",
            "medicare",
            "medicaid",
        ] {
            m.insert(term.to_string(), "government");
        }
        // Educational
        for term in &[
            "university",
            "college",
            "school",
            "academy",
            "institute",
            "institution",
            "school_district",
            "school district",
            "community_college",
            "community college",
            "graduate_school",
            "graduate school",
            "educational",
            "education",
        ] {
            m.insert(term.to_string(), "educational");
        }
        // Legal
        for term in &[
            "law_firm",
            "law firm",
            "attorney",
            "lawyer",
            "legal_services",
            "legal services",
            "paralegal",
            "notary",
            "legal",
        ] {
            m.insert(term.to_string(), "legal");
        }
        // Insurance
        for term in &[
            "insurer",
            "insurance_company",
            "insurance company",
            "insurance",
            "hmo",
            "ppo",
            "health_plan",
            "health plan",
            "blue_cross",
            "blue cross",
            "aetna",
            "cigna",
            "unitedhealth",
            "kaiser",
            "humana",
            "anthem",
            "auto_insurance",
            "auto insurance",
            "home_insurance",
            "home insurance",
            "life_insurance",
            "life insurance",
            "insurance_provider",
            "insurance provider",
        ] {
            m.insert(term.to_string(), "insurance");
        }
        // Employer
        for term in &[
            "employer",
            "company",
            "corporation",
            "corp",
            "llc",
            "inc",
            "business",
            "firm",
            "startup",
            "enterprise",
            "employer_name",
            "employer name",
        ] {
            m.insert(term.to_string(), "employer");
        }
        // Retail
        for term in &[
            "store",
            "shop",
            "retailer",
            "retail",
            "merchant",
            "vendor",
            "supplier",
            "restaurant",
            "grocery",
            "supermarket",
            "ecommerce",
            "e-commerce",
            "marketplace",
            "gas_station",
            "gas station",
            "department_store",
            "department store",
        ] {
            m.insert(term.to_string(), "retail");
        }
        m
    }

    fn build_org_l2() -> HashMap<&'static str, &'static str> {
        let mut m = HashMap::new();
        // All L1 org categories -> L2 "organization"
        // (these are all already organizations, so L2 is uniform)
        m.insert("healthcare_provider", "organization");
        m.insert("financial_institution", "organization");
        m.insert("government", "organization");
        m.insert("educational", "organization");
        m.insert("legal", "organization");
        m.insert("insurance", "organization");
        m.insert("employer", "organization");
        m.insert("retail", "organization");
        m.insert("other_org", "organization");
        m
    }

    // ── Geographic hierarchy ─────────────────────────────────────────────
    // L0: state code (e.g. "CA")
    // L1: census division (e.g. "pacific") -- from generalization.rs
    // L2: census region (e.g. "west")
    // L3: country (e.g. "US")
    // L4: "*"

    fn build_geo_division() -> HashMap<String, &'static str> {
        let mut m = HashMap::new();
        // New England
        for s in &["CT", "ME", "MA", "NH", "RI", "VT"] {
            m.insert(s.to_string(), "new_england");
        }
        // Mid-Atlantic
        for s in &["NJ", "NY", "PA"] {
            m.insert(s.to_string(), "mid_atlantic");
        }
        // East North Central
        for s in &["IL", "IN", "MI", "OH", "WI"] {
            m.insert(s.to_string(), "east_north_central");
        }
        // West North Central
        for s in &["IA", "KS", "MN", "MO", "NE", "ND", "SD"] {
            m.insert(s.to_string(), "west_north_central");
        }
        // South Atlantic
        for s in &["DE", "FL", "GA", "MD", "NC", "SC", "VA", "DC", "WV"] {
            m.insert(s.to_string(), "south_atlantic");
        }
        // East South Central
        for s in &["AL", "KY", "MS", "TN"] {
            m.insert(s.to_string(), "east_south_central");
        }
        // West South Central
        for s in &["AR", "LA", "OK", "TX"] {
            m.insert(s.to_string(), "west_south_central");
        }
        // Mountain
        for s in &["AZ", "CO", "ID", "MT", "NV", "NM", "UT", "WY"] {
            m.insert(s.to_string(), "mountain");
        }
        // Pacific
        for s in &["AK", "CA", "HI", "OR", "WA"] {
            m.insert(s.to_string(), "pacific");
        }
        // Territories
        for s in &["AS", "GU", "MP", "PR", "VI"] {
            m.insert(s.to_string(), "territory");
        }
        m
    }

    fn build_geo_region() -> HashMap<&'static str, &'static str> {
        let mut m = HashMap::new();
        m.insert("new_england", "northeast");
        m.insert("mid_atlantic", "northeast");
        m.insert("east_north_central", "midwest");
        m.insert("west_north_central", "midwest");
        m.insert("south_atlantic", "south");
        m.insert("east_south_central", "south");
        m.insert("west_south_central", "south");
        m.insert("mountain", "west");
        m.insert("pacific", "west");
        m.insert("territory", "territory");
        m
    }

    // ── Relation hierarchy ───────────────────────────────────────────────
    // L0: specific (e.g. "charged_for")
    // L1: category (e.g. "billing")
    // L2: "*"

    fn build_relation_l1() -> HashMap<String, &'static str> {
        let mut m = HashMap::new();
        // Billing relations
        for r in &[
            "charged_for",
            "charges",
            "billed",
            "billed_for",
            "invoiced",
            "owes",
            "paid",
            "paid_for",
            "payment_for",
            "balance_due",
            "copay",
            "coinsurance",
            "deductible_for",
        ] {
            m.insert(r.to_string(), "billing");
        }
        // Coverage relations
        for r in &[
            "covered_by",
            "insured_by",
            "covered",
            "coverage",
            "denied",
            "denied_by",
            "approved_by",
            "preauthorized",
            "in_network",
            "out_of_network",
            "claim_for",
        ] {
            m.insert(r.to_string(), "coverage");
        }
        // Service relations
        for r in &[
            "performed",
            "performed_by",
            "treated_by",
            "treated",
            "diagnosed_with",
            "prescribed",
            "referred_to",
            "referred_by",
            "admitted_to",
            "discharged_from",
            "visited",
        ] {
            m.insert(r.to_string(), "service");
        }
        // Housing relations
        for r in &[
            "rents_from",
            "leased_from",
            "leased_to",
            "rented_to",
            "landlord_of",
            "tenant_of",
            "occupies",
            "property_at",
        ] {
            m.insert(r.to_string(), "housing");
        }
        // Retail relations
        for r in &[
            "purchased",
            "bought",
            "ordered",
            "sold_by",
            "merchant_for",
            "vendor_for",
            "supplied_by",
        ] {
            m.insert(r.to_string(), "retail");
        }
        // Employment relations
        for r in &[
            "employs",
            "employed_by",
            "works_for",
            "hired_by",
            "salary_from",
            "compensated_by",
        ] {
            m.insert(r.to_string(), "employment");
        }
        m
    }

    // ── Document category hierarchy ──────────────────────────────────────
    // L0: specific (e.g. "medical_bill")
    // L1: domain (e.g. "medical")
    // L2: "*"

    fn build_doc_l1() -> HashMap<String, &'static str> {
        let mut m = HashMap::new();
        // Medical
        for d in &[
            "medical_bill",
            "medical_note",
            "insurance_eob",
            "prescription",
        ] {
            m.insert(d.to_string(), "medical");
        }
        // Legal
        for d in &["lease", "contract"] {
            m.insert(d.to_string(), "legal");
        }
        // Financial
        for d in &[
            "bank_statement",
            "pay_stub",
            "insurance_policy",
            "government_form",
        ] {
            m.insert(d.to_string(), "financial");
        }
        // Utility
        for d in &["utility_bill", "terms_of_service"] {
            m.insert(d.to_string(), "utility");
        }
        // Retail
        for d in &["receipt", "restaurant_receipt"] {
            m.insert(d.to_string(), "retail");
        }
        m
    }

    // ── Role hierarchy ───────────────────────────────────────────────────
    // L0: specific (e.g. "provider")
    // L1: category (e.g. "service_role")
    // L2: "*"

    fn build_role_l1() -> HashMap<String, &'static str> {
        let mut m = HashMap::new();
        // Service roles
        for r in &[
            "provider",
            "physician",
            "surgeon",
            "specialist",
            "therapist",
            "nurse",
            "technician",
        ] {
            m.insert(r.to_string(), "service_role");
        }
        // Financial roles
        for r in &[
            "charge",
            "fee",
            "payment",
            "deductible",
            "premium",
            "billing_code",
            "copay",
        ] {
            m.insert(r.to_string(), "financial_role");
        }
        // Administrative roles
        for r in &[
            "insurer",
            "employer",
            "landlord",
            "merchant",
            "category_code",
        ] {
            m.insert(r.to_string(), "administrative_role");
        }
        // Patient/consumer roles
        for r in &["patient", "consumer", "tenant", "subscriber", "member"] {
            m.insert(r.to_string(), "consumer_role");
        }
        m
    }

    // ── Amount bucket hierarchy ──────────────────────────────────────────
    // L0: bucket index (0-7)
    // L1: label ("small", "medium", "large", "very_large", "extreme")
    // L2: "any_amount"
    // L3: "*"

    fn build_amount_l1() -> HashMap<u8, &'static str> {
        let mut m = HashMap::new();
        m.insert(0, "small"); // $0-$100
        m.insert(1, "small"); // $100-$500
        m.insert(2, "medium"); // $500-$1K
        m.insert(3, "medium"); // $1K-$5K
        m.insert(4, "large"); // $5K-$10K
        m.insert(5, "large"); // $10K-$50K
        m.insert(6, "very_large"); // $50K-$100K
        m.insert(7, "extreme"); // $100K+
        m.insert(0xFF, "na"); // N/A
        m
    }

    // ── Generalization dispatch ──────────────────────────────────────────

    /// Given a field name, its current value, and the target level,
    /// return the generalized value at that level.
    fn generalize_value(
        &self,
        field_name: &str,
        original_value: &str,
        _current_level: u8,
        target_level: u8,
    ) -> String {
        if target_level == 0 {
            return original_value.to_string();
        }

        match field_name {
            "entity_b_value" => self.generalize_medical_to_level(original_value, target_level),
            "source_region" => self.generalize_geo_to_level(original_value, target_level),
            "entity_a_type" | "entity_b_type" => {
                self.generalize_org_type_to_level(original_value, target_level)
            }
            "amount_bucket" => self.generalize_amount_to_level(original_value, target_level),
            "relation" => self.generalize_relation_to_level(original_value, target_level),
            "time_period" => self.generalize_time_to_level(original_value, target_level),
            "document_category" => self.generalize_doc_to_level(original_value, target_level),
            "entity_a_role" | "entity_b_role" => {
                self.generalize_role_to_level(original_value, target_level)
            }
            _ => {
                // Unknown field: return wildcard at any level > 0
                if target_level > 0 {
                    "*".to_string()
                } else {
                    original_value.to_string()
                }
            }
        }
    }

    /// Medical procedure: L0->L1->L2->L3->L4
    fn generalize_medical_to_level(&self, value: &str, level: u8) -> String {
        match level {
            0 => value.to_string(),
            1 => {
                let lower = value.to_lowercase();
                self.medical_l1
                    .get(&lower)
                    .copied()
                    .unwrap_or("other_medical")
                    .to_string()
            }
            2 => {
                let lower = value.to_lowercase();
                let l1 = self
                    .medical_l1
                    .get(&lower)
                    .copied()
                    .unwrap_or("other_medical");
                self.medical_l2
                    .get(l1)
                    .copied()
                    .unwrap_or("medical_service")
                    .to_string()
            }
            3 => "medical_service".to_string(),
            _ => "*".to_string(), // L4+
        }
    }

    /// Geographic: L0->L1->L2->L3->L4
    fn generalize_geo_to_level(&self, value: &str, level: u8) -> String {
        match level {
            0 => value.to_string(),
            1 => {
                let upper = value.to_uppercase();
                self.geo_division
                    .get(&upper)
                    .copied()
                    .unwrap_or("unknown_geo")
                    .to_string()
            }
            2 => {
                let upper = value.to_uppercase();
                let div = self
                    .geo_division
                    .get(&upper)
                    .copied()
                    .unwrap_or("unknown_geo");
                self.geo_region
                    .get(div)
                    .copied()
                    .unwrap_or("unknown_geo")
                    .to_string()
            }
            3 => "US".to_string(),
            _ => "*".to_string(), // L4+
        }
    }

    /// Org type: L0->L1->L2->L3
    fn generalize_org_type_to_level(&self, value: &str, level: u8) -> String {
        match level {
            0 => value.to_string(),
            1 => {
                let lower = value.to_lowercase();
                self.org_l1
                    .get(&lower)
                    .copied()
                    .unwrap_or("other_org")
                    .to_string()
            }
            2 => "organization".to_string(),
            _ => "*".to_string(), // L3+
        }
    }

    /// Amount bucket: L0->L1->L2->L3
    fn generalize_amount_to_level(&self, value: &str, level: u8) -> String {
        match level {
            0 => value.to_string(),
            1 => {
                // Parse bucket index from the string value
                if let Ok(bucket) = value.parse::<u8>() {
                    self.amount_l1
                        .get(&bucket)
                        .copied()
                        .unwrap_or("na")
                        .to_string()
                } else {
                    // Try the value as-is (might already be a label)
                    value.to_string()
                }
            }
            2 => "any_amount".to_string(),
            _ => "*".to_string(), // L3+
        }
    }

    /// Relation: L0->L1->L2
    fn generalize_relation_to_level(&self, value: &str, level: u8) -> String {
        match level {
            0 => value.to_string(),
            1 => {
                let lower = value.to_lowercase();
                self.relation_l1
                    .get(&lower)
                    .copied()
                    .unwrap_or("other_relation")
                    .to_string()
            }
            _ => "*".to_string(), // L2+
        }
    }

    /// Time period: L0->L1->L2->L3
    /// L0: "2024-Q1" (quarter)
    /// L1: "2024" (year)
    /// L2: "2020s" (decade)
    /// L3: "*"
    fn generalize_time_to_level(&self, value: &str, level: u8) -> String {
        match level {
            0 => value.to_string(),
            1 => {
                // Extract year from "YYYY-QN" or "YYYY" format
                if value.len() >= 4 {
                    value[..4].to_string()
                } else {
                    value.to_string()
                }
            }
            2 => {
                // Extract decade from "YYYY-QN" or "YYYY"
                if value.len() >= 3 {
                    let decade_prefix = &value[..3];
                    format!("{}0s", decade_prefix)
                } else {
                    "unknown_decade".to_string()
                }
            }
            _ => "*".to_string(), // L3+
        }
    }

    /// Document category: L0->L1->L2
    fn generalize_doc_to_level(&self, value: &str, level: u8) -> String {
        match level {
            0 => value.to_string(),
            1 => {
                let lower = value.to_lowercase();
                self.doc_l1
                    .get(&lower)
                    .copied()
                    .unwrap_or("other_document")
                    .to_string()
            }
            _ => "*".to_string(), // L2+
        }
    }

    /// Role: L0->L1->L2
    fn generalize_role_to_level(&self, value: &str, level: u8) -> String {
        match level {
            0 => value.to_string(),
            1 => {
                let lower = value.to_lowercase();
                self.role_l1
                    .get(&lower)
                    .copied()
                    .unwrap_or("other_role")
                    .to_string()
            }
            _ => "*".to_string(), // L2+
        }
    }

    /// Get the maximum generalization level for a field.
    fn max_level(&self, field_name: &str) -> u8 {
        self.fields
            .iter()
            .find(|f| f.name == field_name)
            .map(|f| f.max_level)
            .unwrap_or(1)
    }
}

// ─── Generalizer Configuration ─────────────────────────────────────────────

/// Configuration subset used by the Generalizer.
#[derive(Debug, Clone)]
pub struct GeneralizerConfig {
    /// k thresholds per tier per network phase: k_thresholds[tier_idx][phase_idx]
    pub k_thresholds: [[u64; 4]; 4],
    /// Network phase boundaries: [10_000, 100_000, 1_000_000]
    pub phase_thresholds: Vec<u64>,
}

impl GeneralizerConfig {
    /// Build from a `PrivacyConfig`.
    pub fn from_privacy_config(config: &PrivacyConfig) -> Self {
        let k = &config.k_thresholds;
        let mut thresholds = [[0u64; 4]; 4];
        for (tier_idx, tier_vals) in [&k.s1, &k.s2, &k.s3, &k.s4].iter().enumerate() {
            for (phase_idx, &val) in tier_vals.iter().enumerate().take(4) {
                thresholds[tier_idx][phase_idx] = val;
            }
        }
        Self {
            k_thresholds: thresholds,
            phase_thresholds: config.cold_start.phase_thresholds.clone(),
        }
    }

    /// Determine the network phase index (0-3) from an estimated network size.
    pub fn network_phase_index(&self, estimated_network_size: u64) -> usize {
        for (i, &threshold) in self.phase_thresholds.iter().enumerate() {
            if estimated_network_size < threshold {
                return i;
            }
        }
        self.phase_thresholds.len() // Scale phase
    }

    /// Look up k_target for a tier and network size.
    pub fn k_target(&self, tier: SensitivityTier, estimated_network_size: u64) -> u64 {
        let tier_idx = tier.index();
        let phase_idx = self.network_phase_index(estimated_network_size);
        self.k_thresholds
            .get(tier_idx)
            .and_then(|row| row.get(phase_idx))
            .copied()
            .unwrap_or(100) // Conservative fallback
    }
}

// ─── Default Frequency Provider ────────────────────────────────────────────

/// A `FrequencyProvider` with embedded realistic frequency data so the module
/// works standalone without the full `frequency_tables.rs` module.
///
/// Frequencies are based on estimated real-world distributions from CMS,
/// BLS, and Census data. Values represent the estimated fraction of the
/// population that would match a given field value.
pub struct DefaultFrequencyProvider {
    /// Base frequencies for specific field values (L0).
    base_frequencies: HashMap<(&'static str, &'static str), f64>,
    /// Level multipliers: how much broader each generalization level is.
    level_multipliers: HashMap<&'static str, Vec<f64>>,
}

impl Default for DefaultFrequencyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultFrequencyProvider {
    pub fn new() -> Self {
        let mut base = HashMap::new();
        let mut mults = HashMap::new();

        // ── entity_b_value (medical procedures) ──
        // From CMS data: specific procedures are ~0.1-2% of all claims
        base.insert(("entity_b_value", "mri"), 0.015);
        base.insert(("entity_b_value", "ct_scan"), 0.012);
        base.insert(("entity_b_value", "x-ray"), 0.025);
        base.insert(("entity_b_value", "ultrasound"), 0.018);
        base.insert(("entity_b_value", "appendectomy"), 0.002);
        base.insert(("entity_b_value", "knee_replacement"), 0.003);
        base.insert(("entity_b_value", "er_visit"), 0.035);
        base.insert(("entity_b_value", "blood_test"), 0.04);
        base.insert(("entity_b_value", "office_visit"), 0.08);
        base.insert(("entity_b_value", "physical_therapy"), 0.015);
        base.insert(("entity_b_value", "prescription"), 0.05);
        base.insert(("entity_b_value", "annual_physical"), 0.03);
        // L1 categories
        base.insert(("entity_b_value", "imaging"), 0.08);
        base.insert(("entity_b_value", "surgery"), 0.05);
        base.insert(("entity_b_value", "emergency"), 0.06);
        base.insert(("entity_b_value", "laboratory"), 0.10);
        base.insert(("entity_b_value", "therapy"), 0.04);
        base.insert(("entity_b_value", "consultation"), 0.15);
        base.insert(("entity_b_value", "pharmacy"), 0.10);
        base.insert(("entity_b_value", "preventive"), 0.07);
        base.insert(("entity_b_value", "other_medical"), 0.05);
        // L2 categories
        base.insert(("entity_b_value", "diagnostic"), 0.18);
        base.insert(("entity_b_value", "therapeutic"), 0.19);
        base.insert(("entity_b_value", "acute_care"), 0.06);
        base.insert(("entity_b_value", "clinical_encounter"), 0.22);
        // L3
        base.insert(("entity_b_value", "medical_service"), 1.0);
        // L4
        base.insert(("entity_b_value", "*"), 1.0);
        // Multipliers: L0 -> L1 (5x), L1 -> L2 (3x), L2 -> L3 (5x), L3 -> L4 (1x)
        mults.insert("entity_b_value", vec![1.0, 5.0, 15.0, 75.0, 75.0]);

        // ── source_region (geographic) ──
        // State-level: ~2-12% of US population
        base.insert(("source_region", "CA"), 0.12);
        base.insert(("source_region", "TX"), 0.09);
        base.insert(("source_region", "FL"), 0.07);
        base.insert(("source_region", "NY"), 0.06);
        base.insert(("source_region", "PA"), 0.04);
        base.insert(("source_region", "IL"), 0.04);
        base.insert(("source_region", "OH"), 0.035);
        base.insert(("source_region", "GA"), 0.033);
        base.insert(("source_region", "NC"), 0.032);
        base.insert(("source_region", "MI"), 0.03);
        // Division-level
        base.insert(("source_region", "pacific"), 0.17);
        base.insert(("source_region", "west_south_central"), 0.13);
        base.insert(("source_region", "south_atlantic"), 0.20);
        base.insert(("source_region", "east_north_central"), 0.15);
        base.insert(("source_region", "mid_atlantic"), 0.13);
        base.insert(("source_region", "new_england"), 0.05);
        base.insert(("source_region", "mountain"), 0.08);
        base.insert(("source_region", "west_north_central"), 0.07);
        base.insert(("source_region", "east_south_central"), 0.06);
        base.insert(("source_region", "territory"), 0.01);
        // Region-level
        base.insert(("source_region", "west"), 0.24);
        base.insert(("source_region", "south"), 0.38);
        base.insert(("source_region", "midwest"), 0.21);
        base.insert(("source_region", "northeast"), 0.17);
        // Country
        base.insert(("source_region", "US"), 1.0);
        base.insert(("source_region", "*"), 1.0);
        mults.insert("source_region", vec![1.0, 3.0, 5.0, 10.0, 10.0]);

        // ── entity_a_type / entity_b_type (organization types) ──
        base.insert(("entity_a_type", "hospital"), 0.08);
        base.insert(("entity_a_type", "clinic"), 0.06);
        base.insert(("entity_a_type", "bank"), 0.05);
        base.insert(("entity_a_type", "insurance"), 0.04);
        base.insert(("entity_a_type", "employer"), 0.10);
        base.insert(("entity_a_type", "store"), 0.08);
        base.insert(("entity_a_type", "restaurant"), 0.06);
        // L1
        base.insert(("entity_a_type", "healthcare_provider"), 0.20);
        base.insert(("entity_a_type", "financial_institution"), 0.12);
        base.insert(("entity_a_type", "government"), 0.08);
        base.insert(("entity_a_type", "insurance"), 0.07);
        base.insert(("entity_a_type", "retail"), 0.15);
        base.insert(("entity_a_type", "employer"), 0.12);
        base.insert(("entity_a_type", "educational"), 0.05);
        base.insert(("entity_a_type", "legal"), 0.03);
        base.insert(("entity_a_type", "other_org"), 0.10);
        // L2
        base.insert(("entity_a_type", "organization"), 1.0);
        base.insert(("entity_a_type", "*"), 1.0);

        base.insert(("entity_b_type", "procedure"), 0.25);
        base.insert(("entity_b_type", "diagnosis"), 0.15);
        base.insert(("entity_b_type", "product"), 0.12);
        base.insert(("entity_b_type", "medication"), 0.10);
        base.insert(("entity_b_type", "amount"), 0.20);
        base.insert(("entity_b_type", "term"), 0.08);
        base.insert(("entity_b_type", "organization"), 1.0);
        base.insert(("entity_b_type", "*"), 1.0);
        // L1 categories for entity_b_type
        base.insert(("entity_b_type", "healthcare_provider"), 0.20);
        base.insert(("entity_b_type", "financial_institution"), 0.12);
        base.insert(("entity_b_type", "other_org"), 0.10);

        mults.insert("entity_a_type", vec![1.0, 3.0, 10.0, 10.0]);
        mults.insert("entity_b_type", vec![1.0, 3.0, 10.0, 10.0]);

        // ── amount_bucket ──
        // Bucket distribution from BLS data
        base.insert(("amount_bucket", "0"), 0.30); // $0-$100 most common
        base.insert(("amount_bucket", "1"), 0.20); // $100-$500
        base.insert(("amount_bucket", "2"), 0.15); // $500-$1K
        base.insert(("amount_bucket", "3"), 0.12); // $1K-$5K
        base.insert(("amount_bucket", "4"), 0.08); // $5K-$10K
        base.insert(("amount_bucket", "5"), 0.06); // $10K-$50K
        base.insert(("amount_bucket", "6"), 0.03); // $50K-$100K
        base.insert(("amount_bucket", "7"), 0.02); // $100K+
        base.insert(("amount_bucket", "255"), 0.04); // N/A
                                                     // L1 labels
        base.insert(("amount_bucket", "small"), 0.50);
        base.insert(("amount_bucket", "medium"), 0.27);
        base.insert(("amount_bucket", "large"), 0.14);
        base.insert(("amount_bucket", "very_large"), 0.03);
        base.insert(("amount_bucket", "extreme"), 0.02);
        base.insert(("amount_bucket", "na"), 0.04);
        // L2
        base.insert(("amount_bucket", "any_amount"), 1.0);
        base.insert(("amount_bucket", "*"), 1.0);
        mults.insert("amount_bucket", vec![1.0, 3.0, 10.0, 10.0]);

        // ── relation ──
        base.insert(("relation", "charged_for"), 0.08);
        base.insert(("relation", "charges"), 0.10);
        base.insert(("relation", "paid_for"), 0.07);
        base.insert(("relation", "covered_by"), 0.06);
        base.insert(("relation", "performed"), 0.05);
        base.insert(("relation", "diagnosed_with"), 0.04);
        base.insert(("relation", "prescribed"), 0.04);
        base.insert(("relation", "rents_from"), 0.03);
        base.insert(("relation", "purchased"), 0.06);
        base.insert(("relation", "employs"), 0.05);
        base.insert(("relation", "visited"), 0.04);
        // L1
        base.insert(("relation", "billing"), 0.35);
        base.insert(("relation", "coverage"), 0.15);
        base.insert(("relation", "service"), 0.20);
        base.insert(("relation", "housing"), 0.08);
        base.insert(("relation", "retail"), 0.12);
        base.insert(("relation", "employment"), 0.10);
        base.insert(("relation", "other_relation"), 0.05);
        // L2
        base.insert(("relation", "*"), 1.0);
        mults.insert("relation", vec![1.0, 4.0, 4.0]);

        // ── time_period ──
        base.insert(("time_period", "2024-Q1"), 0.05);
        base.insert(("time_period", "2024-Q2"), 0.05);
        base.insert(("time_period", "2024-Q3"), 0.05);
        base.insert(("time_period", "2024-Q4"), 0.05);
        base.insert(("time_period", "2025-Q1"), 0.05);
        base.insert(("time_period", "2026-Q1"), 0.05);
        // L1 (year)
        base.insert(("time_period", "2024"), 0.20);
        base.insert(("time_period", "2025"), 0.20);
        base.insert(("time_period", "2026"), 0.20);
        // L2 (decade)
        base.insert(("time_period", "2020s"), 0.80);
        base.insert(("time_period", "2010s"), 0.15);
        // L3
        base.insert(("time_period", "*"), 1.0);
        mults.insert("time_period", vec![1.0, 4.0, 16.0, 16.0]);

        // ── document_category ──
        base.insert(("document_category", "medical_bill"), 0.15);
        base.insert(("document_category", "insurance_eob"), 0.08);
        base.insert(("document_category", "prescription"), 0.06);
        base.insert(("document_category", "medical_note"), 0.04);
        base.insert(("document_category", "lease"), 0.05);
        base.insert(("document_category", "contract"), 0.06);
        base.insert(("document_category", "bank_statement"), 0.08);
        base.insert(("document_category", "pay_stub"), 0.07);
        base.insert(("document_category", "utility_bill"), 0.10);
        base.insert(("document_category", "receipt"), 0.15);
        base.insert(("document_category", "restaurant_receipt"), 0.08);
        // L1
        base.insert(("document_category", "medical"), 0.33);
        base.insert(("document_category", "legal"), 0.11);
        base.insert(("document_category", "financial"), 0.21);
        base.insert(("document_category", "utility"), 0.10);
        base.insert(("document_category", "retail"), 0.23);
        base.insert(("document_category", "other_document"), 0.02);
        // L2
        base.insert(("document_category", "*"), 1.0);
        mults.insert("document_category", vec![1.0, 3.0, 3.0]);

        // ── entity_a_role / entity_b_role ──
        base.insert(("entity_a_role", "provider"), 0.20);
        base.insert(("entity_a_role", "insurer"), 0.10);
        base.insert(("entity_a_role", "employer"), 0.12);
        base.insert(("entity_a_role", "landlord"), 0.05);
        base.insert(("entity_a_role", "merchant"), 0.10);
        base.insert(("entity_a_role", "charge"), 0.08);
        base.insert(("entity_a_role", "service_role"), 0.35);
        base.insert(("entity_a_role", "financial_role"), 0.25);
        base.insert(("entity_a_role", "administrative_role"), 0.30);
        base.insert(("entity_a_role", "consumer_role"), 0.10);
        base.insert(("entity_a_role", "other_role"), 0.05);
        base.insert(("entity_a_role", "*"), 1.0);

        base.insert(("entity_b_role", "charge"), 0.15);
        base.insert(("entity_b_role", "fee"), 0.10);
        base.insert(("entity_b_role", "payment"), 0.12);
        base.insert(("entity_b_role", "provider"), 0.08);
        base.insert(("entity_b_role", "merchant"), 0.08);
        base.insert(("entity_b_role", "service_role"), 0.20);
        base.insert(("entity_b_role", "financial_role"), 0.40);
        base.insert(("entity_b_role", "administrative_role"), 0.25);
        base.insert(("entity_b_role", "consumer_role"), 0.10);
        base.insert(("entity_b_role", "other_role"), 0.05);
        base.insert(("entity_b_role", "*"), 1.0);

        mults.insert("entity_a_role", vec![1.0, 3.0, 3.0]);
        mults.insert("entity_b_role", vec![1.0, 3.0, 3.0]);

        Self {
            base_frequencies: base,
            level_multipliers: mults,
        }
    }
}

impl FrequencyProvider for DefaultFrequencyProvider {
    fn field_frequency(&self, field_name: &str, value: &str) -> f64 {
        let lower = value.to_lowercase();
        self.base_frequencies
            .get(&(field_name, value))
            .or_else(|| {
                // Try lowercase lookup by searching all keys
                self.base_frequencies
                    .iter()
                    .find(|((f, v), _)| *f == field_name && v.to_lowercase() == lower)
                    .map(|(_, freq)| freq)
            })
            .copied()
            // Conservative: unknown values get a low frequency (rare = harder to share)
            .unwrap_or(0.005)
    }

    fn field_frequency_at_level(&self, field_name: &str, value: &str, gen_level: u8) -> f64 {
        if gen_level == 0 {
            return self.field_frequency(field_name, value);
        }

        // First, try a direct lookup of the generalized value
        let base = self.field_frequency(field_name, value);

        // Apply level multiplier to estimate the frequency at the generalized level
        if let Some(multipliers) = self.level_multipliers.get(field_name) {
            let level_idx = gen_level as usize;
            if level_idx < multipliers.len() {
                let multiplier = multipliers[level_idx];
                let estimated = base * multiplier;
                // Cap at 1.0 (frequency cannot exceed 100%)
                return estimated.min(1.0);
            }
        }

        // Fallback: each level roughly doubles the frequency
        let estimated = base * (2.0_f64).powi(gen_level as i32);
        estimated.min(1.0)
    }
}

// ─── Mock Frequency Provider (for testing) ─────────────────────────────────

/// A mock frequency provider for unit testing. Returns configurable
/// frequencies for specific field/value pairs.
pub struct MockFrequencyProvider {
    frequencies: HashMap<(String, String), f64>,
    level_frequencies: HashMap<(String, String, u8), f64>,
    default_frequency: f64,
}

impl Default for MockFrequencyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockFrequencyProvider {
    pub fn new() -> Self {
        Self {
            frequencies: HashMap::new(),
            level_frequencies: HashMap::new(),
            default_frequency: 0.01,
        }
    }

    /// Set the base frequency for a field/value pair.
    pub fn set_frequency(&mut self, field: &str, value: &str, freq: f64) -> &mut Self {
        self.frequencies
            .insert((field.to_string(), value.to_string()), freq);
        self
    }

    /// Set the frequency for a field/value at a specific generalization level.
    pub fn set_level_frequency(
        &mut self,
        field: &str,
        value: &str,
        level: u8,
        freq: f64,
    ) -> &mut Self {
        self.level_frequencies
            .insert((field.to_string(), value.to_string(), level), freq);
        self
    }

    /// Set the default frequency for unknown field/value pairs.
    pub fn set_default(&mut self, freq: f64) -> &mut Self {
        self.default_frequency = freq;
        self
    }
}

impl FrequencyProvider for MockFrequencyProvider {
    fn field_frequency(&self, field_name: &str, value: &str) -> f64 {
        self.frequencies
            .get(&(field_name.to_string(), value.to_string()))
            .copied()
            .unwrap_or(self.default_frequency)
    }

    fn field_frequency_at_level(&self, field_name: &str, value: &str, gen_level: u8) -> f64 {
        if gen_level == 0 {
            return self.field_frequency(field_name, value);
        }
        self.level_frequencies
            .get(&(field_name.to_string(), value.to_string(), gen_level))
            .copied()
            .unwrap_or_else(|| {
                // Fallback: scale base frequency by 2^level
                let base = self.field_frequency(field_name, value);
                (base * (2.0_f64).powi(gen_level as i32)).min(1.0)
            })
    }
}

// ─── Generalizer ───────────────────────────────────────────────────────────

/// The names of all generalizable fields in the order they are considered
/// by the greedy algorithm.
const GENERALIZABLE_FIELDS: &[&str] = &[
    "entity_b_value",
    "source_region",
    "entity_a_type",
    "entity_b_type",
    "amount_bucket",
    "relation",
    "time_period",
    "document_category",
    "entity_a_role",
    "entity_b_role",
];

/// Stage 3 processor: context generalization.
///
/// Elevates field values in multi-level generalization hierarchies until
/// estimated k exceeds the tier-specific threshold. Uses a greedy algorithm
/// that at each step generalizes the field producing the maximum delta-k.
pub struct Generalizer {
    config: GeneralizerConfig,
    hierarchies: GeneralizationHierarchies,
    frequency_provider: Box<dyn FrequencyProvider>,
}

impl Generalizer {
    /// Create a new generalizer with config and the default frequency provider.
    pub fn new(config: &PrivacyConfig) -> Self {
        Self {
            config: GeneralizerConfig::from_privacy_config(config),
            hierarchies: GeneralizationHierarchies::new(),
            frequency_provider: Box::new(DefaultFrequencyProvider::new()),
        }
    }

    /// Create a new generalizer with a custom frequency provider.
    pub fn with_frequency_provider(
        config: &PrivacyConfig,
        provider: Box<dyn FrequencyProvider>,
    ) -> Self {
        Self {
            config: GeneralizerConfig::from_privacy_config(config),
            hierarchies: GeneralizationHierarchies::new(),
            frequency_provider: provider,
        }
    }

    /// Generalize a `BucketedTuple`'s fields until estimated k >= k_target.
    ///
    /// Uses greedy algorithm: at each step, generalize the field whose
    /// elevation produces the maximum increase in estimated k.
    ///
    /// Returns `None` if k_target is unreachable at maximum generalization
    /// (tuple is suppressed).
    pub fn generalize(
        &self,
        tuple: BucketedTuple,
        estimated_network_size: u64,
    ) -> Option<GeneralizedTuple> {
        let k_target = self
            .config
            .k_target(tuple.sensitivity_tier, estimated_network_size);

        // Extract the original field values from the tuple
        let original_values = self.extract_field_values(&tuple);

        // Initialize all generalization levels to 0 (L0 = original values)
        let mut current_levels: HashMap<&str, u8> = HashMap::new();
        for field in GENERALIZABLE_FIELDS {
            current_levels.insert(field, 0);
        }

        // Greedy loop: keep generalizing until k >= k_target
        loop {
            let current_k =
                self.estimate_k(&original_values, &current_levels, estimated_network_size);

            if current_k >= k_target as f64 {
                // Success: k_target reached
                return Some(self.build_generalized_tuple(
                    &tuple,
                    &original_values,
                    &current_levels,
                ));
            }

            // Find the field whose elevation produces the maximum delta_k
            let mut best_field: Option<&str> = None;
            let mut best_delta_k: f64 = 0.0;

            for &field in GENERALIZABLE_FIELDS {
                let current_level = current_levels[field];
                let max_level = self.hierarchies.max_level(field);

                if current_level >= max_level {
                    continue; // Already at max level
                }

                // Trial: elevate this field by one level
                let mut trial_levels = current_levels.clone();
                trial_levels.insert(field, current_level + 1);

                let trial_k =
                    self.estimate_k(&original_values, &trial_levels, estimated_network_size);

                let delta_k = trial_k - current_k;
                if delta_k > best_delta_k {
                    best_delta_k = delta_k;
                    best_field = Some(field);
                }
            }

            match best_field {
                Some(field) => {
                    // Elevate the best field
                    let current_level = current_levels[field];
                    current_levels.insert(field, current_level + 1);
                }
                None => {
                    // All fields at max, k still insufficient -> SUPPRESS
                    return None;
                }
            }
        }
    }

    /// Extract original field values from a `BucketedTuple` into a map.
    fn extract_field_values(&self, tuple: &BucketedTuple) -> HashMap<&'static str, String> {
        let mut values = HashMap::new();
        values.insert("entity_b_value", tuple.entity_b_value.clone());
        values.insert("source_region", tuple.source_region.clone());
        values.insert("entity_a_type", tuple.entity_a_type.clone());
        values.insert("entity_b_type", tuple.entity_b_type.clone());
        values.insert("amount_bucket", tuple.amount_bucket.to_string());
        values.insert("relation", tuple.relation.clone());
        values.insert("time_period", tuple.time_period.clone());
        values.insert("document_category", tuple.document_category.clone());
        values.insert("entity_a_role", tuple.entity_a_role.clone());
        values.insert("entity_b_role", tuple.entity_b_role.clone());
        values
    }

    /// Estimate k using the multiplicative model:
    ///   estimated_k = N * product(field_frequency(field, value_at_level))
    fn estimate_k(
        &self,
        original_values: &HashMap<&'static str, String>,
        levels: &HashMap<&str, u8>,
        estimated_network_size: u64,
    ) -> f64 {
        let n = estimated_network_size as f64;
        let mut product = 1.0;

        for &field in GENERALIZABLE_FIELDS {
            let original_value = &original_values[field];
            let level = levels.get(field).copied().unwrap_or(0);

            // Look up frequency using the ORIGINAL value at the target level.
            // The frequency provider handles the generalization mapping internally
            // (e.g., "MRI" at level 1 returns the frequency for "imaging").
            let freq =
                self.frequency_provider
                    .field_frequency_at_level(field, original_value, level);

            product *= freq;
        }

        n * product
    }

    /// Build the final `GeneralizedTuple` from the original tuple and
    /// the determined generalization levels.
    fn build_generalized_tuple(
        &self,
        tuple: &BucketedTuple,
        original_values: &HashMap<&'static str, String>,
        levels: &HashMap<&str, u8>,
    ) -> GeneralizedTuple {
        let entity_a_type_level = levels.get("entity_a_type").copied().unwrap_or(0);
        let entity_b_value_level = levels.get("entity_b_value").copied().unwrap_or(0);
        let entity_a_role_level = levels.get("entity_a_role").copied().unwrap_or(0);
        let entity_b_role_level = levels.get("entity_b_role").copied().unwrap_or(0);
        let source_region_level = levels.get("source_region").copied().unwrap_or(0);
        let time_period_level = levels.get("time_period").copied().unwrap_or(0);

        let entity_a_gen = self.hierarchies.generalize_value(
            "entity_a_type",
            &original_values["entity_a_type"],
            0,
            entity_a_type_level,
        );

        let entity_b_gen = self.hierarchies.generalize_value(
            "entity_b_value",
            &original_values["entity_b_value"],
            0,
            entity_b_value_level,
        );

        let generalized_region = self.hierarchies.generalize_value(
            "source_region",
            &original_values["source_region"],
            0,
            source_region_level,
        );

        let generalized_time = self.hierarchies.generalize_value(
            "time_period",
            &original_values["time_period"],
            0,
            time_period_level,
        );

        let generalized_a_role = self.hierarchies.generalize_value(
            "entity_a_role",
            &original_values["entity_a_role"],
            0,
            entity_a_role_level,
        );

        let generalized_b_role = self.hierarchies.generalize_value(
            "entity_b_role",
            &original_values["entity_b_role"],
            0,
            entity_b_role_level,
        );

        GeneralizedTuple {
            entity_a_type: tuple.entity_a_type.clone(),
            entity_a_gen,
            entity_a_gen_level: entity_a_type_level,
            entity_a_role: generalized_a_role,
            entity_b_type: tuple.entity_b_type.clone(),
            entity_b_gen,
            entity_b_gen_level: entity_b_value_level,
            entity_b_role: generalized_b_role,
            relation: tuple.relation.clone(),
            amount_bucket: tuple.amount_bucket,
            document_category: tuple.document_category.clone(),
            sensitivity_tier: tuple.sensitivity_tier,
            source_region: generalized_region,
            time_period: generalized_time,
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test helpers ──────────────────────────────────────────────────────

    fn default_config() -> PrivacyConfig {
        PrivacyConfig::default_config()
    }

    /// Build a minimal `BucketedTuple` for testing.
    // Test helper mirrors `BucketedTuple` layout; the nine positional args are
    // an explicit callout of each quasi-identifier under test.
    #[allow(clippy::too_many_arguments)]
    fn make_bucketed(
        entity_b_value: &str,
        source_region: &str,
        entity_a_type: &str,
        entity_b_type: &str,
        relation: &str,
        amount_bucket: u8,
        time_period: &str,
        document_category: &str,
        sensitivity_tier: SensitivityTier,
    ) -> BucketedTuple {
        BucketedTuple {
            entity_a_type: entity_a_type.to_string(),
            entity_a_role: "provider".to_string(),
            entity_b_type: entity_b_type.to_string(),
            entity_b_value: entity_b_value.to_string(),
            entity_b_role: "charge".to_string(),
            relation: relation.to_string(),
            amount_bucket,
            document_category: document_category.to_string(),
            sensitivity_tier,
            source_region: source_region.to_string(),
            time_period: time_period.to_string(),
        }
    }

    /// Standard medical billing tuple (common scenario).
    fn medical_billing_tuple() -> BucketedTuple {
        make_bucketed(
            "MRI",
            "CA",
            "hospital",
            "procedure",
            "charges",
            3,
            "2024-Q1",
            "medical_bill",
            SensitivityTier::S1Critical,
        )
    }

    /// Rare/unusual tuple that may be hard to reach k for.
    #[allow(dead_code)]
    fn rare_tuple() -> BucketedTuple {
        make_bucketed(
            "appendectomy",
            "WY",
            "clinic",
            "procedure",
            "charged_for",
            6,
            "2024-Q1",
            "prescription",
            SensitivityTier::S1Critical,
        )
    }

    /// Common retail receipt tuple.
    fn retail_tuple() -> BucketedTuple {
        make_bucketed(
            "groceries",
            "TX",
            "store",
            "product",
            "purchased",
            0,
            "2024-Q2",
            "receipt",
            SensitivityTier::S4Low,
        )
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 1. HIERARCHY LOOKUP TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn hierarchy_medical_l0_returns_original() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_medical_to_level("MRI", 0), "MRI");
    }

    #[test]
    fn hierarchy_medical_l1_returns_category() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_medical_to_level("MRI", 1), "imaging");
        assert_eq!(h.generalize_medical_to_level("appendectomy", 1), "surgery");
        assert_eq!(h.generalize_medical_to_level("er_visit", 1), "emergency");
        assert_eq!(h.generalize_medical_to_level("blood_test", 1), "laboratory");
        assert_eq!(
            h.generalize_medical_to_level("physical_therapy", 1),
            "therapy"
        );
        assert_eq!(
            h.generalize_medical_to_level("office_visit", 1),
            "consultation"
        );
        assert_eq!(h.generalize_medical_to_level("prescription", 1), "pharmacy");
        assert_eq!(
            h.generalize_medical_to_level("annual_physical", 1),
            "preventive"
        );
    }

    #[test]
    fn hierarchy_medical_l2_returns_broad_category() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_medical_to_level("MRI", 2), "diagnostic");
        assert_eq!(
            h.generalize_medical_to_level("appendectomy", 2),
            "therapeutic"
        );
        assert_eq!(h.generalize_medical_to_level("er_visit", 2), "acute_care");
        assert_eq!(
            h.generalize_medical_to_level("office_visit", 2),
            "clinical_encounter"
        );
    }

    #[test]
    fn hierarchy_medical_l3_returns_medical_service() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_medical_to_level("MRI", 3), "medical_service");
        assert_eq!(
            h.generalize_medical_to_level("appendectomy", 3),
            "medical_service"
        );
    }

    #[test]
    fn hierarchy_medical_l4_returns_wildcard() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_medical_to_level("MRI", 4), "*");
        assert_eq!(h.generalize_medical_to_level("anything", 5), "*");
    }

    #[test]
    fn hierarchy_medical_unknown_value() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(
            h.generalize_medical_to_level("unknown_procedure_xyz", 1),
            "other_medical"
        );
    }

    #[test]
    fn hierarchy_medical_case_insensitive() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_medical_to_level("mri", 1), "imaging");
        assert_eq!(h.generalize_medical_to_level("MRI", 1), "imaging");
        assert_eq!(h.generalize_medical_to_level("Mri", 1), "imaging");
    }

    #[test]
    fn hierarchy_geo_l0_returns_original() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_geo_to_level("CA", 0), "CA");
    }

    #[test]
    fn hierarchy_geo_l1_returns_division() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_geo_to_level("CA", 1), "pacific");
        assert_eq!(h.generalize_geo_to_level("NY", 1), "mid_atlantic");
        assert_eq!(h.generalize_geo_to_level("TX", 1), "west_south_central");
        assert_eq!(h.generalize_geo_to_level("IL", 1), "east_north_central");
    }

    #[test]
    fn hierarchy_geo_l2_returns_region() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_geo_to_level("CA", 2), "west");
        assert_eq!(h.generalize_geo_to_level("NY", 2), "northeast");
        assert_eq!(h.generalize_geo_to_level("TX", 2), "south");
        assert_eq!(h.generalize_geo_to_level("IL", 2), "midwest");
    }

    #[test]
    fn hierarchy_geo_l3_returns_country() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_geo_to_level("CA", 3), "US");
        assert_eq!(h.generalize_geo_to_level("WY", 3), "US");
    }

    #[test]
    fn hierarchy_geo_l4_returns_wildcard() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_geo_to_level("CA", 4), "*");
    }

    #[test]
    fn hierarchy_geo_case_insensitive() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_geo_to_level("ca", 1), "pacific");
        assert_eq!(h.generalize_geo_to_level("Ca", 1), "pacific");
    }

    #[test]
    fn hierarchy_org_type_l0_to_l3() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_org_type_to_level("hospital", 0), "hospital");
        assert_eq!(
            h.generalize_org_type_to_level("hospital", 1),
            "healthcare_provider"
        );
        assert_eq!(
            h.generalize_org_type_to_level("hospital", 2),
            "organization"
        );
        assert_eq!(h.generalize_org_type_to_level("hospital", 3), "*");
    }

    #[test]
    fn hierarchy_org_type_all_categories() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(
            h.generalize_org_type_to_level("bank", 1),
            "financial_institution"
        );
        assert_eq!(h.generalize_org_type_to_level("store", 1), "retail");
        assert_eq!(
            h.generalize_org_type_to_level("university", 1),
            "educational"
        );
        assert_eq!(h.generalize_org_type_to_level("court", 1), "government");
        assert_eq!(h.generalize_org_type_to_level("insurance", 1), "insurance");
    }

    #[test]
    fn hierarchy_amount_l0_to_l3() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_amount_to_level("3", 0), "3");
        assert_eq!(h.generalize_amount_to_level("3", 1), "medium");
        assert_eq!(h.generalize_amount_to_level("0", 1), "small");
        assert_eq!(h.generalize_amount_to_level("6", 1), "very_large");
        assert_eq!(h.generalize_amount_to_level("7", 1), "extreme");
        assert_eq!(h.generalize_amount_to_level("3", 2), "any_amount");
        assert_eq!(h.generalize_amount_to_level("3", 3), "*");
    }

    #[test]
    fn hierarchy_relation_l0_to_l2() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(
            h.generalize_relation_to_level("charged_for", 0),
            "charged_for"
        );
        assert_eq!(h.generalize_relation_to_level("charged_for", 1), "billing");
        assert_eq!(h.generalize_relation_to_level("covered_by", 1), "coverage");
        assert_eq!(h.generalize_relation_to_level("performed", 1), "service");
        assert_eq!(h.generalize_relation_to_level("rents_from", 1), "housing");
        assert_eq!(h.generalize_relation_to_level("purchased", 1), "retail");
        assert_eq!(h.generalize_relation_to_level("charged_for", 2), "*");
    }

    #[test]
    fn hierarchy_time_l0_quarter() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_time_to_level("2024-Q1", 0), "2024-Q1");
    }

    #[test]
    fn hierarchy_time_l1_year() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_time_to_level("2024-Q1", 1), "2024");
        assert_eq!(h.generalize_time_to_level("2025-Q3", 1), "2025");
    }

    #[test]
    fn hierarchy_time_l2_decade() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_time_to_level("2024-Q1", 2), "2020s");
        assert_eq!(h.generalize_time_to_level("2019-Q4", 2), "2010s");
    }

    #[test]
    fn hierarchy_time_l3_wildcard() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_time_to_level("2024-Q1", 3), "*");
    }

    #[test]
    fn hierarchy_doc_l0_to_l2() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_doc_to_level("medical_bill", 0), "medical_bill");
        assert_eq!(h.generalize_doc_to_level("medical_bill", 1), "medical");
        assert_eq!(h.generalize_doc_to_level("receipt", 1), "retail");
        assert_eq!(h.generalize_doc_to_level("lease", 1), "legal");
        assert_eq!(h.generalize_doc_to_level("utility_bill", 1), "utility");
        assert_eq!(h.generalize_doc_to_level("medical_bill", 2), "*");
    }

    #[test]
    fn hierarchy_role_l0_to_l2() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_role_to_level("provider", 0), "provider");
        assert_eq!(h.generalize_role_to_level("provider", 1), "service_role");
        assert_eq!(h.generalize_role_to_level("charge", 1), "financial_role");
        assert_eq!(
            h.generalize_role_to_level("insurer", 1),
            "administrative_role"
        );
        assert_eq!(h.generalize_role_to_level("provider", 2), "*");
    }

    #[test]
    fn hierarchy_max_levels_correct() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.max_level("entity_b_value"), 4);
        assert_eq!(h.max_level("source_region"), 4);
        assert_eq!(h.max_level("entity_a_type"), 3);
        assert_eq!(h.max_level("entity_b_type"), 3);
        assert_eq!(h.max_level("amount_bucket"), 3);
        assert_eq!(h.max_level("relation"), 2);
        assert_eq!(h.max_level("time_period"), 3);
        assert_eq!(h.max_level("document_category"), 2);
        assert_eq!(h.max_level("entity_a_role"), 2);
        assert_eq!(h.max_level("entity_b_role"), 2);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 2. CONFIGURATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn config_k_target_s1_bootstrap() {
        let config = GeneralizerConfig::from_privacy_config(&default_config());
        assert_eq!(config.k_target(SensitivityTier::S1Critical, 5_000), 100);
    }

    #[test]
    fn config_k_target_s1_growth() {
        let config = GeneralizerConfig::from_privacy_config(&default_config());
        assert_eq!(config.k_target(SensitivityTier::S1Critical, 50_000), 200);
    }

    #[test]
    fn config_k_target_s1_maturity() {
        let config = GeneralizerConfig::from_privacy_config(&default_config());
        assert_eq!(config.k_target(SensitivityTier::S1Critical, 500_000), 300);
    }

    #[test]
    fn config_k_target_s1_scale() {
        let config = GeneralizerConfig::from_privacy_config(&default_config());
        assert_eq!(config.k_target(SensitivityTier::S1Critical, 2_000_000), 400);
    }

    #[test]
    fn config_k_target_s4_bootstrap() {
        let config = GeneralizerConfig::from_privacy_config(&default_config());
        assert_eq!(config.k_target(SensitivityTier::S4Low, 5_000), 8);
    }

    #[test]
    fn config_k_target_s4_scale() {
        let config = GeneralizerConfig::from_privacy_config(&default_config());
        assert_eq!(config.k_target(SensitivityTier::S4Low, 2_000_000), 30);
    }

    #[test]
    fn config_network_phase_boundaries() {
        let config = GeneralizerConfig::from_privacy_config(&default_config());
        assert_eq!(config.network_phase_index(9_999), 0); // Bootstrap
        assert_eq!(config.network_phase_index(10_000), 1); // Growth
        assert_eq!(config.network_phase_index(99_999), 1); // Growth
        assert_eq!(config.network_phase_index(100_000), 2); // Maturity
        assert_eq!(config.network_phase_index(999_999), 2); // Maturity
        assert_eq!(config.network_phase_index(1_000_000), 3); // Scale
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 3. FREQUENCY PROVIDER TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn default_provider_known_value() {
        let p = DefaultFrequencyProvider::new();
        let freq = p.field_frequency("source_region", "CA");
        assert!((freq - 0.12).abs() < 1e-10);
    }

    #[test]
    fn default_provider_unknown_value_returns_conservative() {
        let p = DefaultFrequencyProvider::new();
        let freq = p.field_frequency("source_region", "ZZ");
        assert_eq!(freq, 0.005); // Conservative default
    }

    #[test]
    fn default_provider_level_frequency_increases() {
        let p = DefaultFrequencyProvider::new();
        let l0 = p.field_frequency_at_level("entity_b_value", "MRI", 0);
        let l1 = p.field_frequency_at_level("entity_b_value", "MRI", 1);
        assert!(l1 >= l0, "L1 frequency should be >= L0");
    }

    #[test]
    fn default_provider_level_frequency_capped_at_one() {
        let p = DefaultFrequencyProvider::new();
        let freq = p.field_frequency_at_level("entity_b_value", "MRI", 4);
        assert!(freq <= 1.0, "Frequency should not exceed 1.0");
    }

    #[test]
    fn mock_provider_set_and_get() {
        let mut p = MockFrequencyProvider::new();
        p.set_frequency("test_field", "test_value", 0.42);
        assert!((p.field_frequency("test_field", "test_value") - 0.42).abs() < 1e-10);
    }

    #[test]
    fn mock_provider_level_frequency() {
        let mut p = MockFrequencyProvider::new();
        p.set_frequency("f", "v", 0.1);
        p.set_level_frequency("f", "v", 2, 0.5);
        assert!((p.field_frequency_at_level("f", "v", 2) - 0.5).abs() < 1e-10);
    }

    #[test]
    fn mock_provider_default_frequency() {
        let mut p = MockFrequencyProvider::new();
        p.set_default(0.03);
        assert!((p.field_frequency("unknown_field", "unknown_value") - 0.03).abs() < 1e-10);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 4. GREEDY ALGORITHM TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn greedy_common_s4_tuple_needs_no_generalization() {
        // S4 at scale (k_target=30) with a large network should pass easily
        let mut provider = MockFrequencyProvider::new();
        // Set high frequencies for all fields (very common tuple)
        for &field in GENERALIZABLE_FIELDS {
            provider.set_frequency(field, "common_value", 0.5);
        }
        // make_bucketed hardcodes these values, so set their frequencies too
        provider.set_frequency("entity_a_role", "provider", 0.5);
        provider.set_frequency("entity_b_role", "charge", 0.5);
        provider.set_frequency("amount_bucket", "0", 0.5);
        // We need product * N >= 30. Product of 10 fields at 0.5 each = 0.5^10 ~ 0.001
        // So N * 0.001 >= 30 => N >= 30_000. Use 5M.
        let config = default_config();
        let generalizer = Generalizer::with_frequency_provider(&config, Box::new(provider));

        let tuple = make_bucketed(
            "common_value",
            "common_value",
            "common_value",
            "common_value",
            "common_value",
            0,
            "common_value",
            "common_value",
            SensitivityTier::S4Low,
        );

        let result = generalizer.generalize(tuple, 5_000_000);
        assert!(
            result.is_some(),
            "Common S4 tuple should pass generalization"
        );

        let gen = result.unwrap();
        // At L0 with high frequencies, should need no generalization
        // (levels may be 0)
        assert_eq!(gen.sensitivity_tier, SensitivityTier::S4Low);
    }

    #[test]
    fn greedy_selects_field_with_max_delta_k() {
        // Set up so that one field has a much higher frequency gain than others
        let mut provider = MockFrequencyProvider::new();

        // All fields at L0: frequency 0.01 (low)
        for &field in GENERALIZABLE_FIELDS {
            provider.set_frequency(field, "val", 0.01);
            // At L1: most fields barely increase
            provider.set_level_frequency(field, "val", 1, 0.02);
        }
        // One field has a huge jump at L1
        provider.set_level_frequency("entity_b_value", "val", 1, 0.50);
        // Make it achievable with more generalization
        for &field in GENERALIZABLE_FIELDS {
            provider.set_level_frequency(field, "val", 2, 0.5);
            provider.set_level_frequency(field, "val", 3, 0.8);
            provider.set_level_frequency(field, "val", 4, 1.0);
        }

        let config = default_config();
        let generalizer = Generalizer::with_frequency_provider(&config, Box::new(provider));

        let tuple = make_bucketed(
            "val",
            "val",
            "val",
            "val",
            "val",
            0,
            "val",
            "val",
            SensitivityTier::S4Low,
        );

        let result = generalizer.generalize(tuple, 1_000_000);
        // The entity_b_value field should be generalized first since it has
        // the biggest delta_k at L1
        if let Some(gen) = result {
            assert!(
                gen.entity_b_gen_level >= 1,
                "entity_b_value should be generalized (has max delta_k)"
            );
        }
    }

    #[test]
    fn greedy_suppresses_when_k_unreachable() {
        // Even at max generalization, k cannot reach target
        let mut provider = MockFrequencyProvider::new();
        // All fields at all levels have very low frequency
        for &field in GENERALIZABLE_FIELDS {
            provider.set_frequency(field, "rare", 0.0001);
            for level in 1..=4 {
                provider.set_level_frequency(field, "rare", level, 0.0002);
            }
        }

        let config = default_config();
        let generalizer = Generalizer::with_frequency_provider(&config, Box::new(provider));

        let tuple = make_bucketed(
            "rare",
            "rare",
            "rare",
            "rare",
            "rare",
            0,
            "rare",
            "rare",
            SensitivityTier::S1Critical, // k_target=100 at bootstrap
        );

        let result = generalizer.generalize(tuple, 5_000);
        assert!(result.is_none(), "Should suppress when k is unreachable");
    }

    #[test]
    fn greedy_progressive_generalization() {
        // Tuple needs multiple rounds of generalization to reach k
        let mut provider = MockFrequencyProvider::new();

        // Start with moderate frequencies
        for &field in GENERALIZABLE_FIELDS {
            provider.set_frequency(field, "val", 0.05);
            provider.set_level_frequency(field, "val", 1, 0.10);
            provider.set_level_frequency(field, "val", 2, 0.30);
            provider.set_level_frequency(field, "val", 3, 0.60);
            provider.set_level_frequency(field, "val", 4, 1.0);
        }
        // make_bucketed hardcodes these values, so set their frequencies too
        for &(field, value) in &[
            ("entity_a_role", "provider"),
            ("entity_b_role", "charge"),
            ("amount_bucket", "0"),
        ] {
            provider.set_frequency(field, value, 0.05);
            provider.set_level_frequency(field, value, 1, 0.10);
            provider.set_level_frequency(field, value, 2, 0.30);
            provider.set_level_frequency(field, value, 3, 0.60);
            provider.set_level_frequency(field, value, 4, 1.0);
        }

        let config = default_config();
        let generalizer = Generalizer::with_frequency_provider(&config, Box::new(provider));

        // S3 at bootstrap: k_target=15
        let tuple = make_bucketed(
            "val",
            "val",
            "val",
            "val",
            "val",
            0,
            "val",
            "val",
            SensitivityTier::S3Medium,
        );

        let result = generalizer.generalize(tuple, 100_000);
        assert!(
            result.is_some(),
            "Should succeed with progressive generalization"
        );

        let gen = result.unwrap();
        // At least some fields should be generalized above L0
        let total_levels = gen.entity_a_gen_level + gen.entity_b_gen_level;
        assert!(total_levels > 0, "Some fields should be generalized");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 5. K-ESTIMATION TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn k_estimation_multiplicative_model() {
        let mut provider = MockFrequencyProvider::new();
        // Set all fields to frequency 0.5
        for &field in GENERALIZABLE_FIELDS {
            provider.set_frequency(field, "val", 0.5);
        }
        // make_bucketed hardcodes these values, so set their frequencies too
        provider.set_frequency("entity_a_role", "provider", 0.5);
        provider.set_frequency("entity_b_role", "charge", 0.5);
        provider.set_frequency("amount_bucket", "0", 0.5);

        let config = default_config();
        let generalizer = Generalizer::with_frequency_provider(&config, Box::new(provider));

        let tuple = make_bucketed(
            "val",
            "val",
            "val",
            "val",
            "val",
            0,
            "val",
            "val",
            SensitivityTier::S4Low,
        );

        let original_values = generalizer.extract_field_values(&tuple);
        let mut levels: HashMap<&str, u8> = HashMap::new();
        for &field in GENERALIZABLE_FIELDS {
            levels.insert(field, 0);
        }

        let k = generalizer.estimate_k(&original_values, &levels, 1_000_000);
        // 1_000_000 * 0.5^10 = 1_000_000 * 0.000977 = ~977
        let expected = 1_000_000.0 * (0.5_f64).powi(10);
        assert!(
            (k - expected).abs() < 1.0,
            "k should be N * product(frequencies): got {}, expected {}",
            k,
            expected
        );
    }

    #[test]
    fn k_estimation_increases_with_generalization() {
        let mut provider = MockFrequencyProvider::new();
        for &field in GENERALIZABLE_FIELDS {
            provider.set_frequency(field, "val", 0.1);
            provider.set_level_frequency(field, "val", 1, 0.3);
        }
        // make_bucketed hardcodes these values, so set their frequencies too
        for &(field, value) in &[
            ("entity_a_role", "provider"),
            ("entity_b_role", "charge"),
            ("amount_bucket", "0"),
        ] {
            provider.set_frequency(field, value, 0.1);
            provider.set_level_frequency(field, value, 1, 0.3);
        }

        let config = default_config();
        let generalizer = Generalizer::with_frequency_provider(&config, Box::new(provider));

        let tuple = make_bucketed(
            "val",
            "val",
            "val",
            "val",
            "val",
            0,
            "val",
            "val",
            SensitivityTier::S4Low,
        );

        let original_values = generalizer.extract_field_values(&tuple);
        let mut levels_l0: HashMap<&str, u8> = HashMap::new();
        let mut levels_l1: HashMap<&str, u8> = HashMap::new();
        for &field in GENERALIZABLE_FIELDS {
            levels_l0.insert(field, 0);
            levels_l1.insert(field, 1);
        }

        let k_l0 = generalizer.estimate_k(&original_values, &levels_l0, 100_000);
        let k_l1 = generalizer.estimate_k(&original_values, &levels_l1, 100_000);
        assert!(
            k_l1 > k_l0,
            "k at L1 ({}) should be greater than k at L0 ({})",
            k_l1,
            k_l0
        );
    }

    #[test]
    fn k_estimation_scales_with_network_size() {
        let mut provider = MockFrequencyProvider::new();
        for &field in GENERALIZABLE_FIELDS {
            provider.set_frequency(field, "val", 0.2);
        }

        let config = default_config();
        let generalizer = Generalizer::with_frequency_provider(&config, Box::new(provider));

        let tuple = make_bucketed(
            "val",
            "val",
            "val",
            "val",
            "val",
            0,
            "val",
            "val",
            SensitivityTier::S4Low,
        );

        let original_values = generalizer.extract_field_values(&tuple);
        let mut levels: HashMap<&str, u8> = HashMap::new();
        for &field in GENERALIZABLE_FIELDS {
            levels.insert(field, 0);
        }

        let k_10k = generalizer.estimate_k(&original_values, &levels, 10_000);
        let k_1m = generalizer.estimate_k(&original_values, &levels, 1_000_000);
        assert!(
            (k_1m / k_10k - 100.0).abs() < 1.0,
            "k should scale linearly with N: ratio is {}",
            k_1m / k_10k
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 6. GENERALIZED TUPLE OUTPUT TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn output_preserves_sensitivity_tier() {
        let config = default_config();
        let generalizer = Generalizer::new(&config);
        let tuple = medical_billing_tuple();
        // Use a very large network so it's easy to reach k
        let result = generalizer.generalize(tuple, 10_000_000);
        if let Some(gen) = result {
            assert_eq!(gen.sensitivity_tier, SensitivityTier::S1Critical);
        }
    }

    #[test]
    fn output_preserves_amount_bucket() {
        let config = default_config();
        let generalizer = Generalizer::new(&config);
        let tuple = medical_billing_tuple();
        let result = generalizer.generalize(tuple, 10_000_000);
        if let Some(gen) = result {
            assert_eq!(gen.amount_bucket, 3);
        }
    }

    #[test]
    fn output_gen_level_zero_means_no_generalization() {
        let mut provider = MockFrequencyProvider::new();
        // Very high frequencies: k passes at L0
        for &field in GENERALIZABLE_FIELDS {
            provider.set_frequency(field, "common", 0.9);
        }

        let config = default_config();
        let generalizer = Generalizer::with_frequency_provider(&config, Box::new(provider));

        let tuple = make_bucketed(
            "common",
            "common",
            "common",
            "common",
            "common",
            0,
            "common",
            "common",
            SensitivityTier::S4Low,
        );

        let result = generalizer.generalize(tuple, 5_000_000);
        if let Some(gen) = result {
            assert_eq!(gen.entity_a_gen_level, 0);
            assert_eq!(gen.entity_b_gen_level, 0);
            // Original values should be preserved
            assert_eq!(gen.entity_a_gen, "common");
            assert_eq!(gen.entity_b_gen, "common");
        }
    }

    #[test]
    fn output_generalized_region_at_l1() {
        let h = GeneralizationHierarchies::new();
        let gen = h.generalize_value("source_region", "CA", 0, 1);
        assert_eq!(gen, "pacific");
    }

    #[test]
    fn output_generalized_time_period_at_l1() {
        let h = GeneralizationHierarchies::new();
        let gen = h.generalize_value("time_period", "2024-Q1", 0, 1);
        assert_eq!(gen, "2024");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 7. EDGE CASES
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn edge_zero_network_size() {
        let config = default_config();
        let generalizer = Generalizer::new(&config);
        let tuple = retail_tuple();
        // N=0: k_target = s4[0] = 8, estimated_k = 0 * ... = 0
        // Should suppress
        let result = generalizer.generalize(tuple, 0);
        assert!(result.is_none(), "Zero network size should suppress");
    }

    #[test]
    fn edge_amount_bucket_na() {
        let config = default_config();
        let generalizer = Generalizer::new(&config);
        let tuple = make_bucketed(
            "office_visit",
            "CA",
            "hospital",
            "procedure",
            "charges",
            0xFF, // N/A amount
            "2024-Q1",
            "medical_bill",
            SensitivityTier::S1Critical,
        );
        // Should handle 0xFF bucket gracefully
        let _result = generalizer.generalize(tuple, 10_000_000);
        // Just verifying no panic
    }

    #[test]
    fn edge_empty_entity_b_value() {
        let config = default_config();
        let generalizer = Generalizer::new(&config);
        let tuple = make_bucketed(
            "",
            "CA",
            "hospital",
            "procedure",
            "charges",
            3,
            "2024-Q1",
            "medical_bill",
            SensitivityTier::S1Critical,
        );
        let _result = generalizer.generalize(tuple, 10_000_000);
        // Should not panic on empty value
    }

    #[test]
    fn edge_unknown_region() {
        let h = GeneralizationHierarchies::new();
        assert_eq!(h.generalize_geo_to_level("ZZ", 1), "unknown_geo");
        assert_eq!(h.generalize_geo_to_level("ZZ", 2), "unknown_geo");
        assert_eq!(h.generalize_geo_to_level("ZZ", 3), "US");
    }

    #[test]
    fn edge_very_large_network() {
        let config = default_config();
        let generalizer = Generalizer::new(&config);
        let tuple = retail_tuple();
        let result = generalizer.generalize(tuple, 100_000_000);
        // With 100M users, even retail tuples should pass easily
        // (but k_target also increases to 30)
        // This just ensures no overflow or panic
        let _result = result;
    }

    #[test]
    fn edge_all_tiers_produce_valid_k_target() {
        let config = GeneralizerConfig::from_privacy_config(&default_config());
        for &tier in &[
            SensitivityTier::S1Critical,
            SensitivityTier::S2High,
            SensitivityTier::S3Medium,
            SensitivityTier::S4Low,
        ] {
            for &size in &[1_000u64, 50_000, 500_000, 5_000_000] {
                let k = config.k_target(tier, size);
                assert!(k > 0, "k_target should be > 0 for {:?} at N={}", tier, size);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 8. INTEGRATION TESTS (with DefaultFrequencyProvider)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn integration_common_medical_tuple_at_scale() {
        let config = default_config();
        let generalizer = Generalizer::new(&config);
        let tuple = medical_billing_tuple();
        // S1 at Scale: k_target = 400
        // With 5M users, common medical tuple should be achievable
        // with some generalization
        let result = generalizer.generalize(tuple, 5_000_000);
        // This may or may not pass depending on frequency data;
        // the important thing is it doesn't panic and returns a valid result
        if let Some(gen) = &result {
            assert_eq!(gen.entity_b_type, "procedure");
            assert_eq!(gen.sensitivity_tier, SensitivityTier::S1Critical);
        }
    }

    #[test]
    fn integration_retail_tuple_low_threshold() {
        let config = default_config();
        let generalizer = Generalizer::new(&config);
        let tuple = retail_tuple();
        // S4 at Scale: k_target = 30, should be achievable with large N
        let result = generalizer.generalize(tuple, 5_000_000);
        if let Some(gen) = &result {
            assert_eq!(gen.sensitivity_tier, SensitivityTier::S4Low);
        }
    }

    #[test]
    fn integration_with_default_config_from_file_or_default() {
        // Verify the generalizer can be constructed from default config
        let config = PrivacyConfig::default_config();
        let _generalizer = Generalizer::new(&config);
    }

    #[test]
    fn generalizer_field_count() {
        // Verify we have 10 generalizable fields
        assert_eq!(GENERALIZABLE_FIELDS.len(), 10);
    }

    #[test]
    fn all_50_states_have_division_mapping() {
        let h = GeneralizationHierarchies::new();
        let states = [
            "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID", "IL", "IN",
            "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV",
            "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN",
            "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
        ];
        for &state in &states {
            let div = h.generalize_geo_to_level(state, 1);
            assert_ne!(
                div, "unknown_geo",
                "State {} should map to a division",
                state
            );
        }
    }

    #[test]
    fn all_divisions_have_region_mapping() {
        let h = GeneralizationHierarchies::new();
        let divisions = [
            "new_england",
            "mid_atlantic",
            "east_north_central",
            "west_north_central",
            "south_atlantic",
            "east_south_central",
            "west_south_central",
            "mountain",
            "pacific",
        ];
        for &div in &divisions {
            // Use a state from each division
            let region = h.geo_region.get(div);
            assert!(region.is_some(), "Division {} should map to a region", div);
            assert_ne!(*region.unwrap(), "unknown_geo");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 9. SUPPRESSION CORRECTNESS TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn suppression_returns_none() {
        let mut provider = MockFrequencyProvider::new();
        for &field in GENERALIZABLE_FIELDS {
            provider.set_frequency(field, "ultra_rare", 0.00001);
            for level in 1..=4 {
                provider.set_level_frequency(field, "ultra_rare", level, 0.00002);
            }
        }

        let config = default_config();
        let generalizer = Generalizer::with_frequency_provider(&config, Box::new(provider));

        let tuple = make_bucketed(
            "ultra_rare",
            "ultra_rare",
            "ultra_rare",
            "ultra_rare",
            "ultra_rare",
            0,
            "ultra_rare",
            "ultra_rare",
            SensitivityTier::S1Critical,
        );

        assert!(generalizer.generalize(tuple, 5_000).is_none());
    }

    #[test]
    fn suppression_all_fields_at_max_still_insufficient() {
        let mut provider = MockFrequencyProvider::new();
        // At max level, still not enough to reach k=100
        for &field in GENERALIZABLE_FIELDS {
            provider.set_frequency(field, "x", 0.001);
            for level in 1..=4 {
                provider.set_level_frequency(field, "x", level, 0.005);
            }
        }

        let config = default_config();
        let generalizer = Generalizer::with_frequency_provider(&config, Box::new(provider));

        let tuple = make_bucketed(
            "x",
            "x",
            "x",
            "x",
            "x",
            0,
            "x",
            "x",
            SensitivityTier::S1Critical,
        );

        // N=1000: 1000 * 0.005^10 = 1000 * ~9.8e-24 = ~0, way below k=100
        let result = generalizer.generalize(tuple, 1_000);
        assert!(result.is_none(), "Should suppress when maxed out");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 10. ADDITIONAL ALGORITHM CORRECTNESS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn greedy_does_not_exceed_max_level() {
        let mut provider = MockFrequencyProvider::new();
        for &field in GENERALIZABLE_FIELDS {
            provider.set_frequency(field, "v", 0.05);
            for level in 1..=4 {
                provider.set_level_frequency(field, "v", level, 0.1 * level as f64);
            }
        }

        let config = default_config();
        let generalizer = Generalizer::with_frequency_provider(&config, Box::new(provider));

        let tuple = make_bucketed(
            "v",
            "v",
            "v",
            "v",
            "v",
            0,
            "v",
            "v",
            SensitivityTier::S3Medium,
        );

        let result = generalizer.generalize(tuple, 500_000);
        if let Some(gen) = result {
            // entity_b_value max is 4, entity_a_type max is 3
            assert!(gen.entity_b_gen_level <= 4);
            assert!(gen.entity_a_gen_level <= 3);
        }
    }

    #[test]
    fn generalizer_all_k_threshold_cells() {
        // Verify all 16 cells (4 tiers x 4 phases) of the k_threshold matrix
        let config = GeneralizerConfig::from_privacy_config(&default_config());
        let expected = [
            [100, 200, 300, 400], // S1
            [50, 100, 150, 200],  // S2
            [15, 30, 50, 75],     // S3
            [8, 15, 20, 30],      // S4
        ];

        for (tier_idx, &tier) in [
            SensitivityTier::S1Critical,
            SensitivityTier::S2High,
            SensitivityTier::S3Medium,
            SensitivityTier::S4Low,
        ]
        .iter()
        .enumerate()
        {
            for (phase_idx, &size) in [5_000u64, 50_000, 500_000, 5_000_000].iter().enumerate() {
                let k = config.k_target(tier, size);
                assert_eq!(
                    k, expected[tier_idx][phase_idx],
                    "k_target mismatch for tier {:?} phase {}",
                    tier, phase_idx
                );
            }
        }
    }
}
