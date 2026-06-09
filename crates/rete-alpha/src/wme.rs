//! WME (Working Memory Element) struct with dictionary-encoded u16 fields.
//! Compact representation for cache-friendly access.

use slotmap::new_key_type;

new_key_type! {
    /// Generational key for WME storage in SlotMap.
    /// 8 bytes: 4-byte index + 4-byte generation.
    pub struct WmeKey;
}

/// Working Memory Element -- the core data unit processed by the alpha network.
///
/// All string fields are dictionary-encoded to u16 for:
/// - 4-byte savings per field vs String (24-byte header + heap)
/// - Single-instruction hash comparison on u16
/// - Cache-friendly: entire WME fits in a single cache line (32 bytes)
///
/// Compact layout chosen to fit a single cache line.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[repr(C)]
pub struct Wme {
    pub entity_a_type: u16,    // dict index: "organization", "person", etc.
    pub entity_a_role: u16,    // dict index: "provider", "landlord", etc.
    pub relation: u16,         // dict index: "billed_at", "charged_total", etc.
    pub entity_b_type: u16,    // dict index: "amount", "organization", etc.
    pub entity_b_role: u16,    // dict index: "federal_tax", etc.
    pub amount_bucket: u8,     // 0-7 bucketed magnitude, 255 = N/A
    pub document_category: u8, // dict index (fits u8: 10 categories)
    pub extraction_cf: f32,    // extraction confidence [0.0, 1.0]
    pub entity_a_gen: u16,     // dict index: generalized entity_a value
    pub entity_b_gen: u16,     // dict index: generalized entity_b value
                               // Total: 20 bytes. With padding to align f32: 20 bytes packed.
}

impl Wme {
    /// Create a new WME from dictionary-encoded field values.
    ///
    /// The ten discrete dictionary fields are each load-bearing attributes of the
    /// tuple schema (see `docs/schema.md`), so a positional constructor is more
    /// ergonomic than a builder in the hot path.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        entity_a_type: u16,
        entity_a_role: u16,
        entity_a_gen: u16,
        relation: u16,
        entity_b_type: u16,
        entity_b_role: u16,
        entity_b_gen: u16,
        amount_bucket: u8,
        document_category: u8,
        extraction_cf: f32,
    ) -> Self {
        Self {
            entity_a_type,
            entity_a_role,
            entity_a_gen,
            relation,
            entity_b_type,
            entity_b_role,
            entity_b_gen,
            amount_bucket,
            document_category,
            extraction_cf,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_wme_size() {
        // Verify compact representation -- should be <= 24 bytes
        let size = mem::size_of::<Wme>();
        assert!(size <= 24, "Wme size {} exceeds 24 bytes", size);
    }

    #[test]
    fn test_wme_creation() {
        let wme = Wme::new(0, 1, 2, 3, 4, 5, 6, 3, 0, 0.91);
        assert_eq!(wme.entity_a_type, 0);
        assert_eq!(wme.amount_bucket, 3);
        assert!((wme.extraction_cf - 0.91).abs() < 1e-6);
    }
}
