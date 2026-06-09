//! Alpha Network: FxHashMap-based field indexes with conjunction bitmask checking.
//!
//! Architecture: Each indexed field has a HashMap<field_value, Vec<(ProductionId, condition_bit)>>.
//! When a WME arrives, we look up each field value and collect which conditions of which
//! productions are satisfied. Then we check the conjunction bitmask.

use rustc_hash::FxHashMap;

/// A single entry in a field index: which production, and which condition bit.
#[derive(Debug, Clone, Copy)]
pub struct AlphaEntry {
    pub production_idx: u32,
    pub condition_bit: u8, // which bit in the production's condition_mask
}

/// Field-level index: maps a field value (u16 dict id) to alpha entries.
/// For hash-indexed fields (entity_a_type, relation, etc.)
#[derive(Debug, Clone, Default)]
pub struct FieldIndex {
    /// value_id -> list of (production_idx, condition_bit)
    pub index: FxHashMap<u16, Vec<AlphaEntry>>,
}

impl FieldIndex {
    pub fn new() -> Self {
        Self {
            index: FxHashMap::default(),
        }
    }

    /// Register that production_idx's condition_bit is satisfied when this field equals value_id.
    pub fn add_entry(&mut self, value_id: u16, production_idx: u32, condition_bit: u8) {
        self.index.entry(value_id).or_default().push(AlphaEntry {
            production_idx,
            condition_bit,
        });
    }

    /// Look up all alpha entries matching a given field value.
    #[inline(always)]
    pub fn lookup(&self, value_id: u16) -> &[AlphaEntry] {
        self.index.get(&value_id).map_or(&[], |v| v.as_slice())
    }
}

/// Amount bucket index: pre-expanded per-bucket entry lists for O(1) lookup.
///
/// On registration, a bitmask is expanded into per-bucket entry lists.
/// This trades memory for speed: 8 Vecs instead of one linear scan.
#[derive(Debug, Clone)]
pub struct AmountBucketIndex {
    /// bucket_entries[b] = list of (production_idx, condition_bit) that match bucket b.
    pub bucket_entries: [Vec<AlphaEntry>; 8],
}

impl Default for AmountBucketIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl AmountBucketIndex {
    pub fn new() -> Self {
        Self {
            bucket_entries: Default::default(),
        }
    }

    /// Register a bitmask condition on amount_bucket.
    /// Pre-expands the bitmask into per-bucket lists for O(1) lookup.
    pub fn add_entry(&mut self, bucket_mask: u8, production_idx: u32, condition_bit: u8) {
        let entry = AlphaEntry {
            production_idx,
            condition_bit,
        };
        for b in 0..8u8 {
            if (bucket_mask >> b) & 1 == 1 {
                self.bucket_entries[b as usize].push(entry);
            }
        }
    }

    /// O(k) lookup where k = entries matching this specific bucket.
    #[inline(always)]
    pub fn lookup(&self, bucket: u8) -> &[AlphaEntry] {
        if bucket < 8 {
            &self.bucket_entries[bucket as usize]
        } else {
            &[]
        }
    }
}

/// Identifies which field a condition tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ConditionField {
    EntityAType,
    EntityARole,
    EntityAGen,
    Relation,
    EntityBType,
    EntityBRole,
    EntityBGen,
    DocumentCategory,
    AmountBucket,
}

/// A condition to be compiled into the alpha network.
#[derive(Debug, Clone)]
pub struct AlphaCondition {
    pub field: ConditionField,
    /// For hash-indexed fields: the u16 dict value to match.
    /// For amount_bucket: the bitmask (stored in value_id as u16, use low byte).
    pub value_id: u16,
}

/// Composite key for the primary 3-field index.
/// (entity_a_type, relation, document_category) packed into a single u64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompositeKey(u64);

impl CompositeKey {
    #[inline(always)]
    pub fn new(entity_a_type: u16, relation: u16, doc_category: u8) -> Self {
        Self((entity_a_type as u64) | ((relation as u64) << 16) | ((doc_category as u64) << 32))
    }
}

/// The complete alpha network: field indexes + amount bucket index.
///
/// Optimized with a primary composite index on (entity_a_type, relation, doc_category)
/// to dramatically reduce candidate sets (from ~1400 entries to ~20-50).
#[derive(Debug)]
pub struct AlphaNetwork {
    pub entity_a_type_idx: FieldIndex,
    pub entity_a_role_idx: FieldIndex,
    pub entity_a_gen_idx: FieldIndex,
    pub relation_idx: FieldIndex,
    pub entity_b_type_idx: FieldIndex,
    pub entity_b_role_idx: FieldIndex,
    pub entity_b_gen_idx: FieldIndex,
    pub document_category_idx: FieldIndex,
    pub amount_bucket_idx: AmountBucketIndex,
    /// Primary composite index: (entity_a_type, relation, doc_category) -> Vec<production_idx>
    /// Used for fast initial candidate filtering.
    pub primary_composite_idx: FxHashMap<CompositeKey, Vec<u32>>,
}

impl AlphaNetwork {
    pub fn new() -> Self {
        Self {
            entity_a_type_idx: FieldIndex::new(),
            entity_a_role_idx: FieldIndex::new(),
            entity_a_gen_idx: FieldIndex::new(),
            relation_idx: FieldIndex::new(),
            entity_b_type_idx: FieldIndex::new(),
            entity_b_role_idx: FieldIndex::new(),
            entity_b_gen_idx: FieldIndex::new(),
            document_category_idx: FieldIndex::new(),
            amount_bucket_idx: AmountBucketIndex::new(),
            primary_composite_idx: FxHashMap::default(),
        }
    }

    /// Compile a condition into the network for a given production.
    pub fn add_condition(
        &mut self,
        condition: &AlphaCondition,
        production_idx: u32,
        condition_bit: u8,
    ) {
        match condition.field {
            ConditionField::EntityAType => {
                self.entity_a_type_idx
                    .add_entry(condition.value_id, production_idx, condition_bit);
            }
            ConditionField::EntityARole => {
                self.entity_a_role_idx
                    .add_entry(condition.value_id, production_idx, condition_bit);
            }
            ConditionField::EntityAGen => {
                self.entity_a_gen_idx
                    .add_entry(condition.value_id, production_idx, condition_bit);
            }
            ConditionField::Relation => {
                self.relation_idx
                    .add_entry(condition.value_id, production_idx, condition_bit);
            }
            ConditionField::EntityBType => {
                self.entity_b_type_idx
                    .add_entry(condition.value_id, production_idx, condition_bit);
            }
            ConditionField::EntityBRole => {
                self.entity_b_role_idx
                    .add_entry(condition.value_id, production_idx, condition_bit);
            }
            ConditionField::EntityBGen => {
                self.entity_b_gen_idx
                    .add_entry(condition.value_id, production_idx, condition_bit);
            }
            ConditionField::DocumentCategory => {
                self.document_category_idx.add_entry(
                    condition.value_id,
                    production_idx,
                    condition_bit,
                );
            }
            ConditionField::AmountBucket => {
                self.amount_bucket_idx.add_entry(
                    condition.value_id as u8,
                    production_idx,
                    condition_bit,
                );
            }
        }
    }
}

impl Default for AlphaNetwork {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_index_lookup() {
        let mut idx = FieldIndex::new();
        idx.add_entry(5, 0, 0);
        idx.add_entry(5, 1, 2);
        idx.add_entry(10, 2, 0);

        let entries = idx.lookup(5);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].production_idx, 0);
        assert_eq!(entries[1].production_idx, 1);

        let empty = idx.lookup(99);
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn test_amount_bucket_bitmask() {
        let mut idx = AmountBucketIndex::new();
        // Condition: bucket >= 4 -> mask = 0b11110000
        idx.add_entry(0b11110000, 0, 3);
        // Condition: bucket == 2 -> mask = 0b00000100
        idx.add_entry(0b00000100, 1, 1);

        let matches = idx.lookup(5); // bucket 5 >= 4
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].production_idx, 0);

        let matches = idx.lookup(2); // bucket 2 == 2
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].production_idx, 1);

        let matches = idx.lookup(1); // bucket 1 -- no match
        assert_eq!(matches.len(), 0);
    }
}
