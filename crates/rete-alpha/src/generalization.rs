//! Generalization Hierarchy Data Tables for WME field generalization.
//!
//! Provides static lookup tables that generalize entity values into broader
//! categories for rule matching in the Rete-II engine. This enables rules
//! to fire on categories (e.g., "imaging") rather than specific values
//! (e.g., "MRI", "CT_scan", "X-ray").
//!
//! Hierarchies:
//! - Medical procedures -> category (e.g., "MRI" -> "imaging")
//! - Organizations -> type (e.g., "hospital" -> "healthcare_provider")
//! - Amounts -> label (e.g., bucket 5 -> "large")
//! - Geographic: state -> division -> region (e.g., "CA" -> "Pacific" -> "West")

// ---------------------------------------------------------------------------
// Medical procedure generalization
// ---------------------------------------------------------------------------

/// Generalize a medical procedure or diagnosis value to a broad category.
///
/// Categories: "imaging", "surgery", "emergency", "laboratory",
/// "therapy", "consultation", "pharmacy", "preventive", "other_medical"
pub fn generalize_medical(value: &str) -> &'static str {
    match value.to_lowercase().as_str() {
        // Imaging
        "mri" | "ct_scan" | "ct scan" | "x-ray" | "x_ray" | "xray" | "ultrasound" | "mammogram"
        | "pet_scan" | "pet scan" | "fluoroscopy" | "echocardiogram" | "ekg" | "eeg"
        | "dexa_scan" | "dexa scan" | "bone_scan" | "bone scan" | "angiogram" | "angiography"
        | "mra" | "imaging" => "imaging",

        // Surgery
        "appendectomy" | "cholecystectomy" | "hernia_repair" | "hernia repair"
        | "knee_replacement" | "knee replacement" | "hip_replacement" | "hip replacement"
        | "coronary_bypass" | "coronary bypass" | "cabg" | "cesarean" | "c-section"
        | "c_section" | "tonsillectomy" | "mastectomy" | "lumpectomy" | "colectomy"
        | "gastrectomy" | "hysterectomy" | "prostatectomy" | "nephrectomy" | "arthroscopy"
        | "laparoscopy" | "endoscopy" | "biopsy" | "surgery" | "surgical_procedure"
        | "surgical procedure" | "operation" => "surgery",

        // Emergency
        "er_visit" | "er visit" | "emergency_room" | "emergency room" | "emergency" | "trauma"
        | "trauma_care" | "trauma care" | "ambulance" | "emt" | "urgent_care" | "urgent care"
        | "resuscitation" | "intubation" | "defibrillation" | "emergency_surgery"
        | "emergency surgery" => "emergency",

        // Laboratory
        "blood_test" | "blood test" | "blood_work" | "blood work" | "cbc" | "cmp" | "bmp"
        | "lipid_panel" | "lipid panel" | "urinalysis" | "urine_test" | "urine test"
        | "culture" | "pathology" | "cytology" | "histology" | "hba1c" | "a1c" | "glucose_test"
        | "glucose test" | "cholesterol_test" | "cholesterol test" | "thyroid_panel"
        | "thyroid panel" | "tsh" | "psa" | "lab" | "laboratory" | "lab_work" | "lab work" => {
            "laboratory"
        }

        // Therapy
        "physical_therapy"
        | "physical therapy"
        | "pt"
        | "occupational_therapy"
        | "occupational therapy"
        | "ot"
        | "speech_therapy"
        | "speech therapy"
        | "chemotherapy"
        | "chemo"
        | "radiation_therapy"
        | "radiation therapy"
        | "radiation"
        | "dialysis"
        | "infusion"
        | "respiratory_therapy"
        | "respiratory therapy"
        | "rehabilitation"
        | "rehab"
        | "therapy" => "therapy",

        // Consultation
        "office_visit" | "office visit" | "consultation" | "consult" | "follow_up"
        | "follow up" | "follow-up" | "evaluation" | "assessment" | "exam" | "examination"
        | "telehealth" | "telemedicine" | "virtual_visit" | "virtual visit" | "second_opinion"
        | "second opinion" | "referral" | "specialist_visit" | "specialist visit" => "consultation",

        // Pharmacy
        "prescription" | "medication" | "drug" | "pharmacy" | "refill" | "dispensing"
        | "injection" | "vaccine" | "vaccination" | "immunization" | "flu_shot" | "flu shot"
        | "insulin" | "antibiotic" => "pharmacy",

        // Preventive
        "annual_physical" | "annual physical" | "physical_exam" | "physical exam" | "screening"
        | "wellness_visit" | "wellness visit" | "checkup" | "check-up" | "check_up"
        | "colonoscopy" | "pap_smear" | "pap smear" | "dental_cleaning" | "dental cleaning"
        | "eye_exam" | "eye exam" | "hearing_test" | "hearing test" | "preventive"
        | "preventive_care" | "preventive care" => "preventive",

        _ => "other_medical",
    }
}

// ---------------------------------------------------------------------------
// Organization generalization
// ---------------------------------------------------------------------------

/// Generalize an organization value to a broad category.
///
/// Categories: "healthcare_provider", "financial_institution", "government",
/// "educational", "legal", "insurance", "employer", "retail", "other_org"
pub fn generalize_organization(value: &str) -> &'static str {
    match value.to_lowercase().as_str() {
        // Healthcare providers
        "hospital"
        | "clinic"
        | "medical_center"
        | "medical center"
        | "health_center"
        | "health center"
        | "provider"
        | "physician"
        | "doctor"
        | "dentist"
        | "dental_office"
        | "dental office"
        | "pharmacy"
        | "urgent_care"
        | "urgent care"
        | "nursing_home"
        | "nursing home"
        | "assisted_living"
        | "assisted living"
        | "rehab_center"
        | "rehab center"
        | "rehabilitation_center"
        | "rehabilitation center"
        | "lab"
        | "laboratory"
        | "diagnostic_center"
        | "diagnostic center"
        | "imaging_center"
        | "imaging center"
        | "radiology"
        | "mental_health"
        | "mental health"
        | "psychiatry"
        | "psychology"
        | "optometry"
        | "optometrist"
        | "ophthalmology"
        | "pediatrics"
        | "obgyn"
        | "cardiology"
        | "oncology"
        | "dermatology"
        | "orthopedics"
        | "healthcare_provider"
        | "healthcare provider"
        | "medical_group"
        | "medical group"
        | "health_system"
        | "health system" => "healthcare_provider",

        // Financial institutions
        "bank"
        | "credit_union"
        | "credit union"
        | "savings_bank"
        | "savings bank"
        | "investment_firm"
        | "investment firm"
        | "brokerage"
        | "broker"
        | "mortgage_company"
        | "mortgage company"
        | "lending"
        | "lender"
        | "loan_company"
        | "loan company"
        | "financial_advisor"
        | "financial advisor"
        | "wealth_management"
        | "wealth management"
        | "accounting_firm"
        | "accounting firm"
        | "cpa"
        | "tax_preparer"
        | "tax preparer"
        | "financial_institution"
        | "financial institution"
        | "fintech" => "financial_institution",

        // Government
        "irs" | "ssa" | "cms" | "fda" | "cdc" | "epa" | "doj" | "dhs" | "government" | "govt"
        | "federal" | "state_agency" | "state agency" | "county" | "city" | "municipal"
        | "municipality" | "department" | "bureau" | "agency" | "court" | "courthouse" | "dmv"
        | "post_office" | "post office" | "veterans_affairs" | "veterans affairs" | "va"
        | "social_security" | "social security" | "medicare" | "medicaid" => "government",

        // Educational
        "university" | "college" | "school" | "academy" | "institute" | "institution"
        | "school_district" | "school district" | "community_college" | "community college"
        | "graduate_school" | "graduate school" | "educational" | "education" => "educational",

        // Legal
        "law_firm" | "law firm" | "attorney" | "lawyer" | "legal_services" | "legal services"
        | "paralegal" | "notary" | "legal" => "legal",

        // Insurance
        "insurer" | "insurance_company" | "insurance company" | "insurance" | "hmo" | "ppo"
        | "health_plan" | "health plan" | "blue_cross" | "blue cross" | "aetna" | "cigna"
        | "unitedhealth" | "kaiser" | "humana" | "anthem" | "auto_insurance" | "auto insurance"
        | "home_insurance" | "home insurance" | "life_insurance" | "life insurance"
        | "insurance_provider" | "insurance provider" => "insurance",

        // Employer
        "employer" | "company" | "corporation" | "corp" | "llc" | "inc" | "business" | "firm"
        | "startup" | "enterprise" | "employer_name" | "employer name" => "employer",

        // Retail
        "store" | "shop" | "retailer" | "retail" | "merchant" | "vendor" | "supplier"
        | "restaurant" | "grocery" | "supermarket" | "ecommerce" | "e-commerce" | "marketplace"
        | "gas_station" | "gas station" | "department_store" | "department store" => "retail",

        _ => "other_org",
    }
}

// ---------------------------------------------------------------------------
// Amount label generalization
// ---------------------------------------------------------------------------

/// Generalize an amount bucket (0-7, 255) to a human-readable label.
///
/// Labels: "micro" (<$10), "small" ($10-100), "medium" ($100-1K),
/// "large" ($1K-10K), "very_large" (>$10K), "na" (N/A)
///
/// Note: buckets 0-7 from tuple_adapter::compute_bucket() are mapped
/// to 5 generalized labels. This collapses some fine-grained buckets.
pub fn generalize_amount_bucket(bucket: u8) -> &'static str {
    match bucket {
        0 => "micro",          // < $10
        1 | 2 => "small",      // $10 - $100
        3 | 4 => "medium",     // $100 - $1K
        5 => "large",          // $1K - $5K
        6 | 7 => "very_large", // $5K+
        _ => "na",             // 255 or invalid
    }
}

// ---------------------------------------------------------------------------
// Geographic generalization: State -> Division -> Region
// ---------------------------------------------------------------------------

/// Census Division for a US state abbreviation.
///
/// Returns one of: "new_england", "mid_atlantic", "east_north_central",
/// "west_north_central", "south_atlantic", "east_south_central",
/// "west_south_central", "mountain", "pacific", "territory", "unknown_geo"
pub fn state_to_division(state: &str) -> &'static str {
    match state.to_uppercase().as_str() {
        // New England
        "CT" | "ME" | "MA" | "NH" | "RI" | "VT" => "new_england",
        // Mid-Atlantic
        "NJ" | "NY" | "PA" => "mid_atlantic",
        // East North Central
        "IL" | "IN" | "MI" | "OH" | "WI" => "east_north_central",
        // West North Central
        "IA" | "KS" | "MN" | "MO" | "NE" | "ND" | "SD" => "west_north_central",
        // South Atlantic
        "DE" | "FL" | "GA" | "MD" | "NC" | "SC" | "VA" | "DC" | "WV" => "south_atlantic",
        // East South Central
        "AL" | "KY" | "MS" | "TN" => "east_south_central",
        // West South Central
        "AR" | "LA" | "OK" | "TX" => "west_south_central",
        // Mountain
        "AZ" | "CO" | "ID" | "MT" | "NV" | "NM" | "UT" | "WY" => "mountain",
        // Pacific
        "AK" | "CA" | "HI" | "OR" | "WA" => "pacific",
        // Territories
        "AS" | "GU" | "MP" | "PR" | "VI" => "territory",
        _ => "unknown_geo",
    }
}

/// Census Region for a US state abbreviation.
///
/// Returns one of: "northeast", "midwest", "south", "west",
/// "territory", "unknown_geo"
pub fn state_to_region(state: &str) -> &'static str {
    match state.to_uppercase().as_str() {
        // Northeast
        "CT" | "ME" | "MA" | "NH" | "RI" | "VT" | "NJ" | "NY" | "PA" => "northeast",
        // Midwest
        "IL" | "IN" | "MI" | "OH" | "WI" | "IA" | "KS" | "MN" | "MO" | "NE" | "ND" | "SD" => {
            "midwest"
        }
        // South
        "DE" | "FL" | "GA" | "MD" | "NC" | "SC" | "VA" | "DC" | "WV" | "AL" | "KY" | "MS"
        | "TN" | "AR" | "LA" | "OK" | "TX" => "south",
        // West
        "AZ" | "CO" | "ID" | "MT" | "NV" | "NM" | "UT" | "WY" | "AK" | "CA" | "HI" | "OR"
        | "WA" => "west",
        // Territories
        "AS" | "GU" | "MP" | "PR" | "VI" => "territory",
        _ => "unknown_geo",
    }
}

/// Division to Region mapping (for chained generalization).
pub fn division_to_region(division: &str) -> &'static str {
    match division {
        "new_england" | "mid_atlantic" => "northeast",
        "east_north_central" | "west_north_central" => "midwest",
        "south_atlantic" | "east_south_central" | "west_south_central" => "south",
        "mountain" | "pacific" => "west",
        "territory" => "territory",
        _ => "unknown_geo",
    }
}

// ---------------------------------------------------------------------------
// Unified generalization dispatch
// ---------------------------------------------------------------------------

/// Generalize a raw entity value based on its entity type.
///
/// Dispatches to the appropriate hierarchy based on entity_type:
/// - diagnosis / medical_condition / procedure -> medical hierarchy
/// - organization -> organization hierarchy
/// - amount / total / balance / payment -> amount label (via value parsing)
/// - address / location / state -> geographic hierarchy (region level)
///
/// Returns a generalized category string. Unknown types return "unknown".
pub fn generalize(value: &str, entity_type: &str) -> &'static str {
    if value.is_empty() {
        return "unknown";
    }

    match entity_type.to_lowercase().as_str() {
        // Medical procedures/diagnoses
        "diagnosis" | "medical_condition" | "procedure" | "treatment" | "service" | "cpt_code" => {
            generalize_medical(value)
        }

        // Organizations
        "organization" | "provider" | "facility" | "institution" | "company" | "employer" => {
            generalize_organization(value)
        }

        // Amounts: generalize by parsing and bucketing
        "amount" | "total" | "balance" | "payment" | "charge" | "cost" | "fee" | "price"
        | "salary" | "income" => match crate::tuple_adapter::parse_amount(value) {
            Some(v) => {
                let bucket = crate::tuple_adapter::compute_bucket(Some(v));
                generalize_amount_bucket(bucket)
            }
            None => "na",
        },

        // Geographic: try to interpret value as a US state abbreviation
        "address" | "location" | "state" | "region" | "zip_code" => {
            let trimmed = value.trim();
            // If it looks like a 2-letter state code, generalize to region
            if trimmed.len() == 2 && trimmed.chars().all(|c| c.is_ascii_alphabetic()) {
                state_to_region(trimmed)
            } else {
                "unknown_geo"
            }
        }

        // Person, date, and other types don't generalize meaningfully
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Medical generalization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_medical_imaging() {
        assert_eq!(generalize_medical("MRI"), "imaging");
        assert_eq!(generalize_medical("mri"), "imaging");
        assert_eq!(generalize_medical("CT_scan"), "imaging");
        assert_eq!(generalize_medical("X-ray"), "imaging");
        assert_eq!(generalize_medical("ultrasound"), "imaging");
        assert_eq!(generalize_medical("mammogram"), "imaging");
        assert_eq!(generalize_medical("EKG"), "imaging");
    }

    #[test]
    fn test_medical_surgery() {
        assert_eq!(generalize_medical("appendectomy"), "surgery");
        assert_eq!(generalize_medical("Appendectomy"), "surgery");
        assert_eq!(generalize_medical("knee_replacement"), "surgery");
        assert_eq!(generalize_medical("CABG"), "surgery");
        assert_eq!(generalize_medical("biopsy"), "surgery");
        assert_eq!(generalize_medical("laparoscopy"), "surgery");
    }

    #[test]
    fn test_medical_emergency() {
        assert_eq!(generalize_medical("ER visit"), "emergency");
        assert_eq!(generalize_medical("er_visit"), "emergency");
        assert_eq!(generalize_medical("trauma"), "emergency");
        assert_eq!(generalize_medical("ambulance"), "emergency");
        assert_eq!(generalize_medical("urgent_care"), "emergency");
    }

    #[test]
    fn test_medical_laboratory() {
        assert_eq!(generalize_medical("blood_test"), "laboratory");
        assert_eq!(generalize_medical("CBC"), "laboratory");
        assert_eq!(generalize_medical("urinalysis"), "laboratory");
        assert_eq!(generalize_medical("pathology"), "laboratory");
        assert_eq!(generalize_medical("HbA1c"), "laboratory");
    }

    #[test]
    fn test_medical_therapy() {
        assert_eq!(generalize_medical("physical_therapy"), "therapy");
        assert_eq!(generalize_medical("chemotherapy"), "therapy");
        assert_eq!(generalize_medical("dialysis"), "therapy");
        assert_eq!(generalize_medical("rehabilitation"), "therapy");
    }

    #[test]
    fn test_medical_consultation() {
        assert_eq!(generalize_medical("office_visit"), "consultation");
        assert_eq!(generalize_medical("follow_up"), "consultation");
        assert_eq!(generalize_medical("telehealth"), "consultation");
        assert_eq!(generalize_medical("evaluation"), "consultation");
    }

    #[test]
    fn test_medical_pharmacy() {
        assert_eq!(generalize_medical("prescription"), "pharmacy");
        assert_eq!(generalize_medical("vaccine"), "pharmacy");
        assert_eq!(generalize_medical("insulin"), "pharmacy");
    }

    #[test]
    fn test_medical_preventive() {
        assert_eq!(generalize_medical("annual_physical"), "preventive");
        assert_eq!(generalize_medical("screening"), "preventive");
        assert_eq!(generalize_medical("colonoscopy"), "preventive");
        assert_eq!(generalize_medical("wellness_visit"), "preventive");
    }

    #[test]
    fn test_medical_unknown() {
        assert_eq!(
            generalize_medical("some_unknown_procedure"),
            "other_medical"
        );
        assert_eq!(generalize_medical(""), "other_medical");
        assert_eq!(generalize_medical("xyz"), "other_medical");
    }

    // -----------------------------------------------------------------------
    // Organization generalization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_org_healthcare() {
        assert_eq!(generalize_organization("hospital"), "healthcare_provider");
        assert_eq!(generalize_organization("Hospital"), "healthcare_provider");
        assert_eq!(generalize_organization("clinic"), "healthcare_provider");
        assert_eq!(
            generalize_organization("medical_center"),
            "healthcare_provider"
        );
        assert_eq!(generalize_organization("pharmacy"), "healthcare_provider");
        assert_eq!(generalize_organization("dentist"), "healthcare_provider");
    }

    #[test]
    fn test_org_financial() {
        assert_eq!(generalize_organization("bank"), "financial_institution");
        assert_eq!(generalize_organization("Bank"), "financial_institution");
        assert_eq!(
            generalize_organization("credit_union"),
            "financial_institution"
        );
        assert_eq!(
            generalize_organization("brokerage"),
            "financial_institution"
        );
        assert_eq!(generalize_organization("cpa"), "financial_institution");
    }

    #[test]
    fn test_org_government() {
        assert_eq!(generalize_organization("IRS"), "government");
        assert_eq!(generalize_organization("government"), "government");
        assert_eq!(generalize_organization("court"), "government");
        assert_eq!(generalize_organization("medicare"), "government");
    }

    #[test]
    fn test_org_educational() {
        assert_eq!(generalize_organization("university"), "educational");
        assert_eq!(generalize_organization("school"), "educational");
        assert_eq!(generalize_organization("college"), "educational");
    }

    #[test]
    fn test_org_insurance() {
        assert_eq!(generalize_organization("insurance"), "insurance");
        assert_eq!(generalize_organization("HMO"), "insurance");
        assert_eq!(generalize_organization("aetna"), "insurance");
    }

    #[test]
    fn test_org_employer() {
        assert_eq!(generalize_organization("employer"), "employer");
        assert_eq!(generalize_organization("corporation"), "employer");
        assert_eq!(generalize_organization("LLC"), "employer");
    }

    #[test]
    fn test_org_retail() {
        assert_eq!(generalize_organization("store"), "retail");
        assert_eq!(generalize_organization("restaurant"), "retail");
        assert_eq!(generalize_organization("grocery"), "retail");
    }

    #[test]
    fn test_org_unknown() {
        assert_eq!(generalize_organization("some_unknown_org"), "other_org");
        assert_eq!(generalize_organization(""), "other_org");
    }

    // -----------------------------------------------------------------------
    // Amount label generalization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_amount_labels() {
        assert_eq!(generalize_amount_bucket(0), "micro");
        assert_eq!(generalize_amount_bucket(1), "small");
        assert_eq!(generalize_amount_bucket(2), "small");
        assert_eq!(generalize_amount_bucket(3), "medium");
        assert_eq!(generalize_amount_bucket(4), "medium");
        assert_eq!(generalize_amount_bucket(5), "large");
        assert_eq!(generalize_amount_bucket(6), "very_large");
        assert_eq!(generalize_amount_bucket(7), "very_large");
        assert_eq!(generalize_amount_bucket(255), "na");
        assert_eq!(generalize_amount_bucket(200), "na");
    }

    // -----------------------------------------------------------------------
    // Geographic generalization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_state_to_division() {
        assert_eq!(state_to_division("CA"), "pacific");
        assert_eq!(state_to_division("ca"), "pacific");
        assert_eq!(state_to_division("NY"), "mid_atlantic");
        assert_eq!(state_to_division("TX"), "west_south_central");
        assert_eq!(state_to_division("IL"), "east_north_central");
        assert_eq!(state_to_division("MA"), "new_england");
        assert_eq!(state_to_division("FL"), "south_atlantic");
        assert_eq!(state_to_division("CO"), "mountain");
        assert_eq!(state_to_division("PR"), "territory");
        assert_eq!(state_to_division("XX"), "unknown_geo");
    }

    #[test]
    fn test_state_to_region() {
        assert_eq!(state_to_region("CA"), "west");
        assert_eq!(state_to_region("NY"), "northeast");
        assert_eq!(state_to_region("TX"), "south");
        assert_eq!(state_to_region("IL"), "midwest");
        assert_eq!(state_to_region("FL"), "south");
        assert_eq!(state_to_region("WA"), "west");
        assert_eq!(state_to_region("MA"), "northeast");
        assert_eq!(state_to_region("OH"), "midwest");
        assert_eq!(state_to_region("PR"), "territory");
        assert_eq!(state_to_region("ZZ"), "unknown_geo");
    }

    #[test]
    fn test_state_to_region_all_50_states() {
        // Verify all 50 states map to a real region (not unknown_geo)
        let states = [
            "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID", "IL", "IN",
            "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV",
            "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN",
            "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
        ];
        for s in &states {
            let region = state_to_region(s);
            assert_ne!(
                region, "unknown_geo",
                "State {} should map to a known region, got unknown_geo",
                s
            );
            assert_ne!(
                region, "territory",
                "State {} should not map to territory",
                s
            );
        }
    }

    #[test]
    fn test_division_to_region() {
        assert_eq!(division_to_region("new_england"), "northeast");
        assert_eq!(division_to_region("mid_atlantic"), "northeast");
        assert_eq!(division_to_region("east_north_central"), "midwest");
        assert_eq!(division_to_region("west_north_central"), "midwest");
        assert_eq!(division_to_region("south_atlantic"), "south");
        assert_eq!(division_to_region("east_south_central"), "south");
        assert_eq!(division_to_region("west_south_central"), "south");
        assert_eq!(division_to_region("mountain"), "west");
        assert_eq!(division_to_region("pacific"), "west");
        assert_eq!(division_to_region("territory"), "territory");
        assert_eq!(division_to_region("bogus"), "unknown_geo");
    }

    // -----------------------------------------------------------------------
    // Unified generalize() dispatch tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_generalize_dispatch_medical() {
        assert_eq!(generalize("MRI", "diagnosis"), "imaging");
        assert_eq!(generalize("appendectomy", "procedure"), "surgery");
        assert_eq!(generalize("blood_test", "medical_condition"), "laboratory");
    }

    #[test]
    fn test_generalize_dispatch_organization() {
        assert_eq!(
            generalize("hospital", "organization"),
            "healthcare_provider"
        );
        assert_eq!(generalize("bank", "organization"), "financial_institution");
        assert_eq!(generalize("university", "facility"), "educational");
    }

    #[test]
    fn test_generalize_dispatch_amount() {
        assert_eq!(generalize("$5.00", "amount"), "micro");
        assert_eq!(generalize("$50.00", "amount"), "small");
        assert_eq!(generalize("$500.00", "amount"), "medium");
        assert_eq!(generalize("$1,234.56", "amount"), "large");
        assert_eq!(generalize("$50,000.00", "amount"), "very_large");
        assert_eq!(generalize("N/A", "amount"), "na");
        assert_eq!(generalize("$99.99", "total"), "small");
    }

    #[test]
    fn test_generalize_dispatch_geographic() {
        assert_eq!(generalize("CA", "state"), "west");
        assert_eq!(generalize("NY", "address"), "northeast");
        assert_eq!(generalize("TX", "location"), "south");
        assert_eq!(generalize("123 Main St", "address"), "unknown_geo");
    }

    #[test]
    fn test_generalize_dispatch_unknown_type() {
        assert_eq!(generalize("John Smith", "person"), "unknown");
        assert_eq!(generalize("2024-01-15", "date"), "unknown");
    }

    #[test]
    fn test_generalize_empty_value() {
        assert_eq!(generalize("", "diagnosis"), "unknown");
        assert_eq!(generalize("", "organization"), "unknown");
        assert_eq!(generalize("", "amount"), "unknown");
    }
}
