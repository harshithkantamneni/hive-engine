//! Dictionary module: string-to-u16 encoding for WME fields.
//! Compact field representation.

use rustc_hash::FxHashMap;

/// Bidirectional string<->u16 dictionary for field encoding.
/// Saves ~22 bytes per field per WME compared to String storage.
#[derive(Debug, Clone)]
pub struct Dictionary {
    to_id: FxHashMap<String, u16>,
    to_str: Vec<String>,
}

impl Dictionary {
    pub fn new() -> Self {
        Self {
            to_id: FxHashMap::default(),
            to_str: Vec::new(),
        }
    }

    /// Get or insert a string, returning its u16 id.
    /// Panics if dictionary exceeds 65535 entries (impossible for HIVE's domain).
    pub fn get_or_insert(&mut self, s: &str) -> u16 {
        if let Some(&id) = self.to_id.get(s) {
            return id;
        }
        let id = self.to_str.len() as u16;
        self.to_str.push(s.to_string());
        self.to_id.insert(s.to_string(), id);
        id
    }

    /// Lookup id for an existing string. Returns None if not present.
    pub fn get_id(&self, s: &str) -> Option<u16> {
        self.to_id.get(s).copied()
    }

    /// Lookup string for an id. Returns None if out of range.
    pub fn get_str(&self, id: u16) -> Option<&str> {
        self.to_str.get(id as usize).map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.to_str.len()
    }

    pub fn is_empty(&self) -> bool {
        self.to_str.is_empty()
    }
}

impl Default for Dictionary {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_lookup() {
        let mut dict = Dictionary::new();
        let id1 = dict.get_or_insert("organization");
        let id2 = dict.get_or_insert("person");
        let id3 = dict.get_or_insert("organization"); // duplicate

        assert_eq!(id1, 0);
        assert_eq!(id2, 1);
        assert_eq!(id3, 0); // same as first
        assert_eq!(dict.get_str(0), Some("organization"));
        assert_eq!(dict.get_str(1), Some("person"));
        assert_eq!(dict.get_id("organization"), Some(0));
        assert_eq!(dict.get_id("unknown"), None);
        assert_eq!(dict.len(), 2);
    }
}
