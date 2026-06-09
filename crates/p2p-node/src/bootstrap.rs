//! Cold-start bootstrap: progressive shard download with Merkle verification.
//!
//! Provides:
//! - Progressive shard download via DHT GET with timeouts
//! - Merkle verification using BLAKE3 hash tree
//! - Priority ordering (user categories first, then S4, then S3/S2/S1)
//! - Shard compression using zstd

use std::collections::HashSet;
use std::io::Read;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::rule::{
    default_tier_for_category, RuleMessage, SensitivityTier, ShardKey, DOCUMENT_CATEGORIES,
};

// ============================================================================
// Constants
// ============================================================================

/// DHT key prefix for shard data records.
const DHT_DATA_PREFIX: &[u8] = b"hive-rule-shard-v1";

/// DHT key prefix for shard metadata records.
const DHT_META_PREFIX: &[u8] = b"hive-rule-shard-meta-v1";

/// Default zstd compression level (3 = good balance of speed/ratio).
const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

/// Default DHT GET timeout in seconds.
const DEFAULT_DHT_TIMEOUT_SECS: u64 = 10;

/// Default maximum retries per shard.
const DEFAULT_MAX_RETRIES: u32 = 3;

/// Maximum number of rules allowed in a single shard. Prevents memory exhaustion
/// from malicious wire data claiming an enormous rule_count.
const MAX_RULES_PER_SHARD: usize = 10_000;

/// Maximum decompressed shard size in bytes.
/// MAX_RULES_PER_SHARD * 512 (max rule wire size) = 5,120,000 bytes (~5 MB).
/// Enforced DURING decompression to prevent zip-bomb attacks.
const MAX_DECOMPRESSED_SHARD_SIZE: usize = MAX_RULES_PER_SHARD * 512;

// ============================================================================
// Genesis shard Merkle root pins
// ============================================================================

/// Known-good Merkle roots for genesis shards. Computed from the canonical
/// genesis rule set at network launch. Any shard whose DHT metadata contains
/// a Merkle root that does NOT match the pinned value for its key is rejected
/// as potentially poisoned.
///
/// The HashMap is constructed once per process start (cheap -- genesis set is
/// small). If a shard key has no pinned root, verification is skipped with a
/// warning so that new categories added post-genesis still bootstrap.
use std::collections::HashMap as StdHashMap;
use std::sync::LazyLock;

static GENESIS_SHARD_ROOTS: LazyLock<StdHashMap<(&str, u8), [u8; 32]>> = LazyLock::new(|| {
    // NOTE: These are placeholder roots computed from the empty genesis set.
    // In production, replace with roots derived from the canonical genesis
    // rule data committed at network launch.
    //
    // Format: (doc_category, sensitivity_tier_u8) -> BLAKE3 Merkle root.
    let mut m = StdHashMap::new();
    let empty_root = *blake3::hash(b"").as_bytes();
    for &cat in DOCUMENT_CATEGORIES {
        let tier = default_tier_for_category(cat) as u8;
        m.insert((cat, tier), empty_root);
    }
    m
});

// ============================================================================
// Error types
// ============================================================================

/// Errors during cold-start bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapError {
    /// DHT GET timed out for a shard.
    DhtTimeout,
    /// zstd compression failed (e.g., invalid compression level).
    CompressionFailed,
    /// zstd decompression failed.
    DecompressionFailed,
    /// Merkle root mismatch after decompression.
    MerkleVerificationFailed,
    /// Shard contains no rules.
    ShardEmpty,
    /// Rule deserialization or validation failed.
    InvalidRule(String),
    /// Merkle root does not match the pinned genesis root.
    GenesisRootMismatch,
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootstrapError::DhtTimeout => write!(f, "DHT GET timed out"),
            BootstrapError::CompressionFailed => write!(f, "zstd compression failed"),
            BootstrapError::DecompressionFailed => write!(f, "zstd decompression failed"),
            BootstrapError::MerkleVerificationFailed => {
                write!(f, "Merkle root verification failed")
            }
            BootstrapError::ShardEmpty => write!(f, "shard contains no rules"),
            BootstrapError::InvalidRule(reason) => write!(f, "invalid rule: {}", reason),
            BootstrapError::GenesisRootMismatch => {
                write!(f, "Merkle root does not match pinned genesis root")
            }
        }
    }
}

impl std::error::Error for BootstrapError {}

// ============================================================================
// Configuration
// ============================================================================

/// Bootstrap configuration parameters.
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// Timeout for each DHT GET operation.
    pub dht_timeout: Duration,
    /// Maximum retries per shard before marking as failed.
    pub max_retries: u32,
    /// zstd compression level (1-22, default 3).
    pub compression_level: i32,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            dht_timeout: Duration::from_secs(DEFAULT_DHT_TIMEOUT_SECS),
            max_retries: DEFAULT_MAX_RETRIES,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
        }
    }
}

// ============================================================================
// Result type
// ============================================================================

/// Summary of a bootstrap run.
#[derive(Debug, Clone)]
pub struct BootstrapResult {
    /// Total rules loaded across all shards.
    pub loaded_rules: u32,
    /// Number of shards successfully loaded.
    pub loaded_shards: u32,
    /// Shards that could not be loaded after retries.
    pub failed_shards: Vec<ShardKey>,
    /// Total elapsed time.
    pub elapsed: Duration,
}

// ============================================================================
// Shard metadata
// ============================================================================

/// Metadata stored in DHT for each shard. Retrieved before the data
/// so we can verify integrity after decompression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardMetadata {
    /// The shard this metadata describes.
    pub shard_key: ShardKey,
    /// BLAKE3 Merkle root of the rule bytes in this shard.
    pub merkle_root: [u8; 32],
    /// Number of rules in the shard.
    pub rule_count: u32,
    /// Size of compressed shard data in bytes.
    pub compressed_size: u32,
    /// Timestamp of last update (micros since UNIX epoch).
    pub updated_at: u64,
}

// ============================================================================
// DHT key computation
// ============================================================================

/// Compute the DHT key for shard data: BLAKE3("hive-rule-shard-v1" || category || tier).
/// This matches `ShardKey::dht_key()` in rule.rs.
pub fn compute_shard_data_key(shard_key: &ShardKey) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DHT_DATA_PREFIX);
    hasher.update(shard_key.doc_category.as_bytes());
    hasher.update(shard_key.sensitivity_tier.to_string().as_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute the DHT key for shard metadata: BLAKE3("hive-rule-shard-meta-v1" || category || tier).
pub fn compute_shard_meta_key(shard_key: &ShardKey) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DHT_META_PREFIX);
    hasher.update(shard_key.doc_category.as_bytes());
    hasher.update(shard_key.sensitivity_tier.to_string().as_bytes());
    *hasher.finalize().as_bytes()
}

// ============================================================================
// Merkle verification (BLAKE3)
// ============================================================================

/// Compute the BLAKE3 Merkle root of a list of rule byte slices.
///
/// Algorithm:
/// 1. Compute BLAKE3 hash of each individual rule (leaf hashes).
/// 2. Iteratively pair adjacent hashes and hash them together until one root remains.
/// 3. If the number of hashes is odd at any level, the last hash is promoted as-is.
/// 4. Empty input returns the hash of an empty byte slice.
pub fn compute_merkle_root(rules: &[Vec<u8>]) -> [u8; 32] {
    if rules.is_empty() {
        return *blake3::hash(b"").as_bytes();
    }

    // Leaf hashes
    let mut hashes: Vec<[u8; 32]> = rules.iter().map(|r| *blake3::hash(r).as_bytes()).collect();

    // Build tree bottom-up
    while hashes.len() > 1 {
        let mut next_level = Vec::with_capacity(hashes.len().div_ceil(2));
        let mut i = 0;
        while i < hashes.len() {
            if i + 1 < hashes.len() {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&hashes[i]);
                hasher.update(&hashes[i + 1]);
                next_level.push(*hasher.finalize().as_bytes());
                i += 2;
            } else {
                // Odd element: promote
                next_level.push(hashes[i]);
                i += 1;
            }
        }
        hashes = next_level;
    }

    hashes[0]
}

// ============================================================================
// Priority ordering
// ============================================================================

/// Compute the priority-ordered download schedule for cold-start bootstrap.
///
/// Priority levels:
/// 1. User's own document categories at their default sensitivity tier
/// 2. All S4 (lowest sensitivity) shards not already in priority 1
/// 3. Remaining shards in order S3, S2, S1 (not already included)
///
/// If `user_categories` is empty, all 40 shards are returned in tier-priority
/// order (S4 first, then S3, S2, S1).
pub fn prioritize_shards(user_categories: &[String]) -> Vec<ShardKey> {
    let mut result = Vec::with_capacity(40);
    let mut seen = HashSet::new();

    // Priority 1: user categories at their default tier
    for cat in user_categories {
        if DOCUMENT_CATEGORIES.contains(&cat.as_str()) {
            let tier = default_tier_for_category(cat);
            let key = ShardKey::new(cat, tier);
            if seen.insert(key.to_string()) {
                result.push(key);
            }
        }
    }

    // Priority 2: all S4 shards not already included
    for cat in DOCUMENT_CATEGORIES {
        let key = ShardKey::new(cat, SensitivityTier::S4);
        if seen.insert(key.to_string()) {
            result.push(key);
        }
    }

    // Priority 3: remaining shards in order S3, S2, S1
    let remaining_tiers = [
        SensitivityTier::S3,
        SensitivityTier::S2,
        SensitivityTier::S1,
    ];
    for tier in &remaining_tiers {
        for cat in DOCUMENT_CATEGORIES {
            let key = ShardKey::new(cat, tier.clone());
            if seen.insert(key.to_string()) {
                result.push(key);
            }
        }
    }

    result
}

// ============================================================================
// Shard compression (zstd)
// ============================================================================

/// Compress a list of serialized rules into a single zstd-compressed blob.
///
/// Wire format: `[u32 rule_count][u32 len_0][bytes_0][u32 len_1][bytes_1]...`
/// then zstd-compressed.
pub fn compress_shard(
    rules: &[Vec<u8>],
    compression_level: i32,
) -> Result<Vec<u8>, BootstrapError> {
    // Build length-prefixed buffer
    let mut buf = Vec::new();
    let count = rules.len() as u32;
    buf.extend_from_slice(&count.to_le_bytes());
    for rule in rules {
        let len = rule.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(rule);
    }

    // zstd compress
    zstd::encode_all(buf.as_slice(), compression_level)
        .map_err(|_| BootstrapError::CompressionFailed)
}

/// Decompress a zstd-compressed shard blob back into individual rule byte vectors.
///
/// Enforces `MAX_DECOMPRESSED_SHARD_SIZE` DURING decompression to prevent
/// zip-bomb attacks. Uses `Read::take()` to cap the number of bytes
/// read from the zstd decoder.
pub fn decompress_shard(compressed: &[u8]) -> Result<Vec<Vec<u8>>, BootstrapError> {
    let decoder =
        zstd::Decoder::new(compressed).map_err(|_| BootstrapError::DecompressionFailed)?;

    // Cap the number of bytes we will read. We allow one extra byte beyond the
    // limit so we can distinguish "exactly at limit" from "over limit".
    let limit = (MAX_DECOMPRESSED_SHARD_SIZE as u64) + 1;
    let mut limited_reader = decoder.take(limit);

    let mut decompressed = Vec::new();
    limited_reader
        .read_to_end(&mut decompressed)
        .map_err(|_| BootstrapError::DecompressionFailed)?;

    if decompressed.len() > MAX_DECOMPRESSED_SHARD_SIZE {
        return Err(BootstrapError::DecompressionFailed);
    }

    if decompressed.len() < 4 {
        return Err(BootstrapError::DecompressionFailed);
    }

    let count = u32::from_le_bytes(
        decompressed[..4]
            .try_into()
            .map_err(|_| BootstrapError::DecompressionFailed)?,
    ) as usize;

    if count > MAX_RULES_PER_SHARD {
        return Err(BootstrapError::InvalidRule(
            "rule count exceeds maximum".to_string(),
        ));
    }

    let mut rules = Vec::with_capacity(count);
    let mut offset = 4;

    for _ in 0..count {
        if offset + 4 > decompressed.len() {
            return Err(BootstrapError::DecompressionFailed);
        }
        let len = u32::from_le_bytes(
            decompressed[offset..offset + 4]
                .try_into()
                .map_err(|_| BootstrapError::DecompressionFailed)?,
        ) as usize;
        offset += 4;

        if offset + len > decompressed.len() {
            return Err(BootstrapError::DecompressionFailed);
        }
        rules.push(decompressed[offset..offset + len].to_vec());
        offset += len;
    }

    Ok(rules)
}

// ============================================================================
// DHT provider trait (for testability)
// ============================================================================

/// Trait abstracting DHT GET operations so bootstrap can be tested without a
/// real libp2p swarm. Production impl wraps `kad::Behaviour<MemoryStore>`.
#[async_trait::async_trait]
pub trait DhtProvider: Send + Sync {
    /// Retrieve a value from the DHT by key. Returns None on timeout or not found.
    async fn dht_get(&self, key: &[u8; 32]) -> Option<Vec<u8>>;
}

// ============================================================================
// Progressive shard download (bootstrap_rules)
// ============================================================================

/// Execute the cold-start bootstrap: download all shards in priority order,
/// verify Merkle roots, decompress, and return validated rules.
///
/// Flow:
/// 1. Compute priority-ordered shard list
/// 2. For each shard:
///    a. DHT GET metadata (merkle_root, rule_count, compressed_size)
///    b. DHT GET compressed data
///    c. zstd decompress
///    d. Compute Merkle root of decompressed rules
///    e. Verify root matches metadata
///    f. Deserialize rules
/// 3. Return `BootstrapResult` with loaded rules and any failed shards
pub async fn bootstrap_rules(
    dht: &dyn DhtProvider,
    config: &BootstrapConfig,
    user_categories: &[String],
) -> BootstrapResult {
    let start = std::time::Instant::now();
    let ordered_shards = prioritize_shards(user_categories);

    let mut loaded_rules: u32 = 0;
    let mut loaded_shards: u32 = 0;
    let mut failed_shards: Vec<ShardKey> = Vec::new();

    info!(
        total_shards = ordered_shards.len(),
        user_categories = ?user_categories,
        "Starting cold-start bootstrap"
    );

    for shard_key in &ordered_shards {
        let result = download_shard(dht, config, shard_key).await;

        match result {
            Ok(rules) => {
                let count = rules.len() as u32;
                loaded_rules += count;
                loaded_shards += 1;
                info!(
                    shard = %shard_key,
                    rules = count,
                    total_loaded = loaded_rules,
                    "Shard loaded successfully"
                );
            }
            Err(e) => {
                warn!(shard = %shard_key, err = %e, "Shard download failed");
                failed_shards.push(shard_key.clone());
            }
        }
    }

    let elapsed = start.elapsed();
    info!(
        loaded_shards = loaded_shards,
        loaded_rules = loaded_rules,
        failed_shards = failed_shards.len(),
        elapsed_ms = elapsed.as_millis(),
        "Bootstrap complete"
    );

    BootstrapResult {
        loaded_rules,
        loaded_shards,
        failed_shards,
        elapsed,
    }
}

/// Download and verify a single shard from the DHT with retries.
async fn download_shard(
    dht: &dyn DhtProvider,
    config: &BootstrapConfig,
    shard_key: &ShardKey,
) -> Result<Vec<RuleMessage>, BootstrapError> {
    let meta_dht_key = compute_shard_meta_key(shard_key);
    let data_dht_key = compute_shard_data_key(shard_key);

    for attempt in 0..config.max_retries {
        debug!(
            shard = %shard_key,
            attempt = attempt + 1,
            max_retries = config.max_retries,
            "Attempting shard download"
        );

        // Step 1: GET metadata
        let meta_bytes =
            match tokio::time::timeout(config.dht_timeout, dht.dht_get(&meta_dht_key)).await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    debug!(shard = %shard_key, "Metadata not found in DHT");
                    continue;
                }
                Err(_) => {
                    debug!(shard = %shard_key, "Metadata DHT GET timed out");
                    continue;
                }
            };

        let metadata: ShardMetadata = match serde_json::from_slice(&meta_bytes) {
            Ok(m) => m,
            Err(e) => {
                warn!(shard = %shard_key, err = %e, "Failed to parse shard metadata");
                continue;
            }
        };

        if metadata.rule_count == 0 {
            return Err(BootstrapError::ShardEmpty);
        }

        // Step 2: GET compressed data
        let compressed =
            match tokio::time::timeout(config.dht_timeout, dht.dht_get(&data_dht_key)).await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    debug!(shard = %shard_key, "Data not found in DHT");
                    continue;
                }
                Err(_) => {
                    debug!(shard = %shard_key, "Data DHT GET timed out");
                    continue;
                }
            };

        // Step 3: Decompress
        let rule_bytes = decompress_shard(&compressed)?;

        // Step 4: Verify Merkle root
        let computed_root = compute_merkle_root(&rule_bytes);
        if computed_root != metadata.merkle_root {
            warn!(
                shard = %shard_key,
                expected = ?metadata.merkle_root,
                computed = ?computed_root,
                "Merkle root mismatch"
            );
            return Err(BootstrapError::MerkleVerificationFailed);
        }

        // Step 4b: Verify against pinned genesis Merkle root.
        // If this shard has a pinned root AND the pinned root is not the
        // placeholder (BLAKE3 of empty), the metadata root MUST match it.
        // New categories added post-genesis skip this check with a warning.
        let tier_u8 = shard_key.sensitivity_tier.clone() as u8;
        let genesis_key = (shard_key.doc_category.as_str(), tier_u8);
        let placeholder_root = *blake3::hash(b"").as_bytes();
        if let Some(pinned_root) = GENESIS_SHARD_ROOTS.get(&genesis_key) {
            if *pinned_root != placeholder_root && *pinned_root != metadata.merkle_root {
                warn!(
                    shard = %shard_key,
                    pinned = ?pinned_root,
                    received = ?metadata.merkle_root,
                    "Merkle root does not match pinned genesis root"
                );
                return Err(BootstrapError::GenesisRootMismatch);
            }
        } else {
            warn!(
                shard = %shard_key,
                "No pinned genesis root for this shard; skipping genesis verification"
            );
        }

        // Step 5: Deserialize rules
        let mut rules = Vec::with_capacity(rule_bytes.len());
        for (i, bytes) in rule_bytes.iter().enumerate() {
            match RuleMessage::from_bytes(bytes) {
                Ok(rule) => {
                    if let Err(e) = rule.validate() {
                        return Err(BootstrapError::InvalidRule(format!(
                            "rule {} in shard {}: {}",
                            i, shard_key, e
                        )));
                    }
                    rules.push(rule);
                }
                Err(e) => {
                    return Err(BootstrapError::InvalidRule(format!(
                        "rule {} in shard {}: {}",
                        i, shard_key, e
                    )));
                }
            }
        }

        return Ok(rules);
    }

    // All retries exhausted
    Err(BootstrapError::DhtTimeout)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::create_test_rule;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // -----------------------------------------------------------------------
    // Mock DHT provider
    // -----------------------------------------------------------------------

    /// In-memory mock DHT for testing without a real network.
    #[derive(Clone, Default)]
    struct MockDht {
        store: Arc<Mutex<HashMap<[u8; 32], Vec<u8>>>>,
    }

    impl MockDht {
        fn new() -> Self {
            Self {
                store: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        async fn put(&self, key: [u8; 32], value: Vec<u8>) {
            self.store.lock().await.insert(key, value);
        }
    }

    #[async_trait::async_trait]
    impl DhtProvider for MockDht {
        async fn dht_get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
            self.store.lock().await.get(key).cloned()
        }
    }

    /// Mock DHT that always returns None (simulates timeout/not found).
    struct EmptyDht;

    #[async_trait::async_trait]
    impl DhtProvider for EmptyDht {
        async fn dht_get(&self, _key: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Create rules, compress, compute metadata, store in mock DHT.
    async fn populate_shard(
        dht: &MockDht,
        shard_key: &ShardKey,
        rules: &[RuleMessage],
        compression_level: i32,
    ) {
        let rule_bytes: Vec<Vec<u8>> = rules.iter().map(|r| r.to_bytes()).collect();
        let merkle_root = compute_merkle_root(&rule_bytes);
        let compressed = compress_shard(&rule_bytes, compression_level).unwrap();

        let metadata = ShardMetadata {
            shard_key: shard_key.clone(),
            merkle_root,
            rule_count: rules.len() as u32,
            compressed_size: compressed.len() as u32,
            updated_at: 1_000_000,
        };

        let meta_key = compute_shard_meta_key(shard_key);
        let data_key = compute_shard_data_key(shard_key);

        dht.put(meta_key, serde_json::to_vec(&metadata).unwrap())
            .await;
        dht.put(data_key, compressed).await;
    }

    // =======================================================================
    // Merkle verification tests
    // =======================================================================

    #[test]
    fn test_merkle_root_single_rule() {
        let rule = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        let bytes = vec![rule.to_bytes()];
        let root = compute_merkle_root(&bytes);

        // Single leaf: root == hash of that leaf
        let expected = *blake3::hash(&bytes[0]).as_bytes();
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_two_rules() {
        let r1 = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        let r2 = create_test_rule("receipt", SensitivityTier::S4, 2, 0.70);
        let bytes = vec![r1.to_bytes(), r2.to_bytes()];
        let root = compute_merkle_root(&bytes);

        // Two leaves: root = BLAKE3(hash(r1) || hash(r2))
        let h1 = *blake3::hash(&bytes[0]).as_bytes();
        let h2 = *blake3::hash(&bytes[1]).as_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&h1);
        hasher.update(&h2);
        let expected = *hasher.finalize().as_bytes();
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_three_rules_odd() {
        let r1 = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        let r2 = create_test_rule("receipt", SensitivityTier::S4, 2, 0.70);
        let r3 = create_test_rule("lease", SensitivityTier::S3, 3, 0.60);
        let bytes = vec![r1.to_bytes(), r2.to_bytes(), r3.to_bytes()];
        let root = compute_merkle_root(&bytes);

        // 3 leaves: pair(h1,h2) and promote h3, then hash those two
        let h1 = *blake3::hash(&bytes[0]).as_bytes();
        let h2 = *blake3::hash(&bytes[1]).as_bytes();
        let h3 = *blake3::hash(&bytes[2]).as_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&h1);
        hasher.update(&h2);
        let h12 = *hasher.finalize().as_bytes();
        let mut hasher2 = blake3::Hasher::new();
        hasher2.update(&h12);
        hasher2.update(&h3);
        let expected = *hasher2.finalize().as_bytes();
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_empty() {
        let root = compute_merkle_root(&[]);
        let expected = *blake3::hash(b"").as_bytes();
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let r1 = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        let bytes = vec![r1.to_bytes()];
        let root1 = compute_merkle_root(&bytes);
        let root2 = compute_merkle_root(&bytes);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_merkle_root_tamper_detection() {
        let r1 = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        let r2 = create_test_rule("receipt", SensitivityTier::S4, 2, 0.70);
        let original = vec![r1.to_bytes(), r2.to_bytes()];
        let original_root = compute_merkle_root(&original);

        // Tamper with second rule
        let mut tampered_r2 = r2.clone();
        tampered_r2.confidence = 0.99;
        let tampered = vec![r1.to_bytes(), tampered_r2.to_bytes()];
        let tampered_root = compute_merkle_root(&tampered);

        assert_ne!(
            original_root, tampered_root,
            "Tampering must change the Merkle root"
        );
    }

    // =======================================================================
    // Priority ordering tests
    // =======================================================================

    #[test]
    fn test_prioritize_shards_total_count() {
        let shards = prioritize_shards(&[]);
        assert_eq!(shards.len(), 40, "Should return all 40 shards");
    }

    #[test]
    fn test_prioritize_shards_no_duplicates() {
        let user_cats = vec!["medical_bill".to_string(), "receipt".to_string()];
        let shards = prioritize_shards(&user_cats);
        assert_eq!(shards.len(), 40);

        let unique: HashSet<String> = shards.iter().map(|s| s.to_string()).collect();
        assert_eq!(unique.len(), 40, "No duplicate shards");
    }

    #[test]
    fn test_prioritize_user_categories_first() {
        let user_cats = vec!["medical_bill".to_string(), "lease".to_string()];
        let shards = prioritize_shards(&user_cats);

        // medical_bill default tier = S1, lease default tier = S3
        assert_eq!(shards[0].doc_category, "medical_bill");
        assert_eq!(shards[0].sensitivity_tier, SensitivityTier::S1);
        assert_eq!(shards[1].doc_category, "lease");
        assert_eq!(shards[1].sensitivity_tier, SensitivityTier::S3);
    }

    #[test]
    fn test_prioritize_s4_second() {
        let user_cats = vec!["medical_bill".to_string()];
        let shards = prioritize_shards(&user_cats);

        // First is user category (medical_bill:S1)
        assert_eq!(shards[0].doc_category, "medical_bill");
        assert_eq!(shards[0].sensitivity_tier, SensitivityTier::S1);

        // Next should be S4 shards (10 categories)
        for s in &shards[1..11] {
            assert_eq!(
                s.sensitivity_tier,
                SensitivityTier::S4,
                "Priority 2 should be S4, got {:?} for {}",
                s.sensitivity_tier,
                s.doc_category,
            );
        }
    }

    #[test]
    fn test_prioritize_empty_user_categories() {
        let shards = prioritize_shards(&[]);

        // With no user categories, S4 should come first
        for s in &shards[0..10] {
            assert_eq!(
                s.sensitivity_tier,
                SensitivityTier::S4,
                "Without user categories, S4 should be first"
            );
        }
    }

    #[test]
    fn test_prioritize_unknown_category_ignored() {
        let user_cats = vec!["unknown_thing".to_string(), "receipt".to_string()];
        let shards = prioritize_shards(&user_cats);
        assert_eq!(shards.len(), 40);

        // receipt:S4 (default tier for receipt is S4) should be first
        assert_eq!(shards[0].doc_category, "receipt");
        assert_eq!(shards[0].sensitivity_tier, SensitivityTier::S4);
    }

    #[test]
    fn test_prioritize_remaining_tiers_order() {
        let shards = prioritize_shards(&[]);

        // S4 first (10), then S3 (10), then S2 (10), then S1 (10)
        for s in &shards[0..10] {
            assert_eq!(s.sensitivity_tier, SensitivityTier::S4);
        }
        for s in &shards[10..20] {
            assert_eq!(s.sensitivity_tier, SensitivityTier::S3);
        }
        for s in &shards[20..30] {
            assert_eq!(s.sensitivity_tier, SensitivityTier::S2);
        }
        for s in &shards[30..40] {
            assert_eq!(s.sensitivity_tier, SensitivityTier::S1);
        }
    }

    // =======================================================================
    // Compression tests
    // =======================================================================

    #[test]
    fn test_compress_decompress_roundtrip() {
        let r1 = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        let r2 = create_test_rule("receipt", SensitivityTier::S4, 2, 0.70);
        let rule_bytes = vec![r1.to_bytes(), r2.to_bytes()];

        let compressed = compress_shard(&rule_bytes, DEFAULT_COMPRESSION_LEVEL).unwrap();
        let decompressed = decompress_shard(&compressed).unwrap();

        assert_eq!(decompressed.len(), 2);
        assert_eq!(decompressed[0], rule_bytes[0]);
        assert_eq!(decompressed[1], rule_bytes[1]);
    }

    #[test]
    fn test_compression_ratio() {
        // Create 10 similar rules -- zstd should compress well
        let rules: Vec<Vec<u8>> = (0..10)
            .map(|i| create_test_rule("medical_bill", SensitivityTier::S1, i, 0.85).to_bytes())
            .collect();

        let uncompressed_size: usize = rules.iter().map(|r| r.len() + 4).sum::<usize>() + 4;
        let compressed = compress_shard(&rules, DEFAULT_COMPRESSION_LEVEL).unwrap();

        assert!(
            compressed.len() < uncompressed_size,
            "Compressed ({}) should be smaller than uncompressed ({})",
            compressed.len(),
            uncompressed_size,
        );
    }

    #[test]
    fn test_compress_empty_rules() {
        let compressed = compress_shard(&[], DEFAULT_COMPRESSION_LEVEL).unwrap();
        let decompressed = decompress_shard(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_decompress_invalid_data() {
        let result = decompress_shard(&[0xFF, 0xFE, 0xFD]);
        assert_eq!(result, Err(BootstrapError::DecompressionFailed));
    }

    #[test]
    fn test_decompress_truncated_data() {
        let r1 = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        let rule_bytes = vec![r1.to_bytes()];
        let compressed = compress_shard(&rule_bytes, DEFAULT_COMPRESSION_LEVEL).unwrap();

        // Truncate compressed data
        let truncated = &compressed[..compressed.len() / 2];
        let result = decompress_shard(truncated);
        assert!(result.is_err());
    }

    // =======================================================================
    // DHT key computation tests
    // =======================================================================

    #[test]
    fn test_data_key_matches_shard_key_dht_key() {
        // compute_shard_data_key uses the same prefix as ShardKey::dht_key()
        let shard = ShardKey::new("medical_bill", SensitivityTier::S1);
        let data_key = compute_shard_data_key(&shard);
        let shard_dht_key = shard.dht_key();
        assert_eq!(data_key, shard_dht_key);
    }

    #[test]
    fn test_meta_key_differs_from_data_key() {
        let shard = ShardKey::new("medical_bill", SensitivityTier::S1);
        let data_key = compute_shard_data_key(&shard);
        let meta_key = compute_shard_meta_key(&shard);
        assert_ne!(data_key, meta_key, "Data and meta keys must differ");
    }

    #[test]
    fn test_dht_keys_deterministic() {
        let shard = ShardKey::new("receipt", SensitivityTier::S4);
        let k1 = compute_shard_data_key(&shard);
        let k2 = compute_shard_data_key(&shard);
        assert_eq!(k1, k2);

        let m1 = compute_shard_meta_key(&shard);
        let m2 = compute_shard_meta_key(&shard);
        assert_eq!(m1, m2);
    }

    #[test]
    fn test_different_shards_different_keys() {
        let s1 = ShardKey::new("medical_bill", SensitivityTier::S1);
        let s2 = ShardKey::new("receipt", SensitivityTier::S4);
        assert_ne!(compute_shard_data_key(&s1), compute_shard_data_key(&s2));
        assert_ne!(compute_shard_meta_key(&s1), compute_shard_meta_key(&s2));
    }

    // =======================================================================
    // Progressive download (integration tests with mock DHT)
    // =======================================================================

    #[tokio::test]
    async fn test_bootstrap_single_shard() {
        let dht = MockDht::new();
        let shard = ShardKey::new("medical_bill", SensitivityTier::S1);
        let rules = vec![
            create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85),
            create_test_rule("medical_bill", SensitivityTier::S1, 2, 0.75),
        ];

        populate_shard(&dht, &shard, &rules, DEFAULT_COMPRESSION_LEVEL).await;

        let config = BootstrapConfig::default();
        let user_cats = vec!["medical_bill".to_string()];
        let result = bootstrap_rules(&dht, &config, &user_cats).await;

        assert_eq!(result.loaded_rules, 2);
        assert_eq!(result.loaded_shards, 1);
        // The other 39 shards are not in the DHT so they fail
        assert_eq!(result.failed_shards.len(), 39);
    }

    #[tokio::test]
    async fn test_bootstrap_multiple_shards() {
        let dht = MockDht::new();

        // Populate 3 shards
        let shards_and_rules = vec![
            (
                ShardKey::new("medical_bill", SensitivityTier::S1),
                vec![create_test_rule(
                    "medical_bill",
                    SensitivityTier::S1,
                    1,
                    0.85,
                )],
            ),
            (
                ShardKey::new("receipt", SensitivityTier::S4),
                vec![
                    create_test_rule("receipt", SensitivityTier::S4, 2, 0.70),
                    create_test_rule("receipt", SensitivityTier::S4, 3, 0.65),
                ],
            ),
            (
                ShardKey::new("lease", SensitivityTier::S3),
                vec![create_test_rule("lease", SensitivityTier::S3, 4, 0.60)],
            ),
        ];

        for (shard, rules) in &shards_and_rules {
            populate_shard(&dht, shard, rules, DEFAULT_COMPRESSION_LEVEL).await;
        }

        let config = BootstrapConfig::default();
        let result = bootstrap_rules(&dht, &config, &[]).await;

        assert_eq!(result.loaded_rules, 4);
        assert_eq!(result.loaded_shards, 3);
        assert_eq!(result.failed_shards.len(), 37);
    }

    #[tokio::test]
    async fn test_bootstrap_all_shards_fail() {
        let dht = EmptyDht;
        let config = BootstrapConfig {
            max_retries: 1, // speed up test
            ..Default::default()
        };

        let result = bootstrap_rules(&dht, &config, &[]).await;

        assert_eq!(result.loaded_rules, 0);
        assert_eq!(result.loaded_shards, 0);
        assert_eq!(result.failed_shards.len(), 40);
    }

    #[tokio::test]
    async fn test_bootstrap_merkle_mismatch_detected() {
        let dht = MockDht::new();
        let shard = ShardKey::new("medical_bill", SensitivityTier::S1);
        let rules = [create_test_rule(
            "medical_bill",
            SensitivityTier::S1,
            1,
            0.85,
        )];

        let rule_bytes: Vec<Vec<u8>> = rules.iter().map(|r| r.to_bytes()).collect();
        let compressed = compress_shard(&rule_bytes, DEFAULT_COMPRESSION_LEVEL).unwrap();

        // Store metadata with WRONG merkle root
        let metadata = ShardMetadata {
            shard_key: shard.clone(),
            merkle_root: [0xAA; 32], // intentionally wrong
            rule_count: 1,
            compressed_size: compressed.len() as u32,
            updated_at: 1_000_000,
        };

        let meta_key = compute_shard_meta_key(&shard);
        let data_key = compute_shard_data_key(&shard);
        dht.put(meta_key, serde_json::to_vec(&metadata).unwrap())
            .await;
        dht.put(data_key, compressed).await;

        let config = BootstrapConfig {
            max_retries: 1,
            ..Default::default()
        };
        let user_cats = vec!["medical_bill".to_string()];
        let result = bootstrap_rules(&dht, &config, &user_cats).await;

        // medical_bill:S1 should fail due to Merkle mismatch
        assert!(
            result
                .failed_shards
                .iter()
                .any(|s| s.doc_category == "medical_bill"
                    && s.sensitivity_tier == SensitivityTier::S1),
            "Shard with wrong Merkle root should be in failed_shards"
        );
    }

    #[tokio::test]
    async fn test_bootstrap_empty_shard_error() {
        let dht = MockDht::new();
        let shard = ShardKey::new("receipt", SensitivityTier::S4);

        // Store metadata with rule_count = 0
        let metadata = ShardMetadata {
            shard_key: shard.clone(),
            merkle_root: [0; 32],
            rule_count: 0,
            compressed_size: 0,
            updated_at: 1_000_000,
        };

        let meta_key = compute_shard_meta_key(&shard);
        dht.put(meta_key, serde_json::to_vec(&metadata).unwrap())
            .await;

        let config = BootstrapConfig {
            max_retries: 1,
            ..Default::default()
        };
        let result = bootstrap_rules(&dht, &config, &[]).await;

        assert!(
            result
                .failed_shards
                .iter()
                .any(|s| s.doc_category == "receipt" && s.sensitivity_tier == SensitivityTier::S4),
            "Empty shard should be in failed_shards"
        );
    }

    // =======================================================================
    // Error display tests
    // =======================================================================

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", BootstrapError::DhtTimeout),
            "DHT GET timed out"
        );
        assert_eq!(
            format!("{}", BootstrapError::CompressionFailed),
            "zstd compression failed"
        );
        assert_eq!(
            format!("{}", BootstrapError::DecompressionFailed),
            "zstd decompression failed"
        );
        assert_eq!(
            format!("{}", BootstrapError::MerkleVerificationFailed),
            "Merkle root verification failed"
        );
        assert_eq!(
            format!("{}", BootstrapError::ShardEmpty),
            "shard contains no rules"
        );
        assert_eq!(
            format!("{}", BootstrapError::InvalidRule("bad".to_string())),
            "invalid rule: bad"
        );
    }

    // =======================================================================
    // Config default test
    // =======================================================================

    #[test]
    fn test_config_defaults() {
        let config = BootstrapConfig::default();
        assert_eq!(config.dht_timeout, Duration::from_secs(10));
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.compression_level, 3);
    }

    // =======================================================================
    // ShardMetadata serialization roundtrip
    // =======================================================================

    #[test]
    fn test_shard_metadata_serialization() {
        let meta = ShardMetadata {
            shard_key: ShardKey::new("medical_bill", SensitivityTier::S1),
            merkle_root: [0x42; 32],
            rule_count: 5,
            compressed_size: 1024,
            updated_at: 999_999,
        };

        let bytes = serde_json::to_vec(&meta).unwrap();
        let decoded: ShardMetadata = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(decoded.shard_key.doc_category, "medical_bill");
        assert_eq!(decoded.shard_key.sensitivity_tier, SensitivityTier::S1);
        assert_eq!(decoded.merkle_root, [0x42; 32]);
        assert_eq!(decoded.rule_count, 5);
        assert_eq!(decoded.compressed_size, 1024);
        assert_eq!(decoded.updated_at, 999_999);
    }

    // =======================================================================
    // Bounded decompression tests
    // =======================================================================

    #[test]
    fn test_decompress_oversized_blob_rejected() {
        // Create a payload that exceeds MAX_DECOMPRESSED_SHARD_SIZE when
        // decompressed. We build a valid length-prefixed shard wire format
        // that is larger than the 5 MB limit, then compress it.
        let oversized_len = MAX_DECOMPRESSED_SHARD_SIZE + 1;
        let mut buf = Vec::with_capacity(oversized_len);
        // Claim 1 rule with a body that pushes total past the limit.
        let count: u32 = 1;
        buf.extend_from_slice(&count.to_le_bytes());
        let rule_body_len = (oversized_len - 8) as u32; // minus count(4) + len prefix(4)
        buf.extend_from_slice(&rule_body_len.to_le_bytes());
        buf.resize(oversized_len, 0xAA); // fill with padding bytes

        // Compress it (repetitive data compresses extremely well).
        let compressed = zstd::encode_all(buf.as_slice(), 1).unwrap();

        // decompress_shard must reject this as it exceeds the bound.
        let result = decompress_shard(&compressed);
        assert_eq!(
            result,
            Err(BootstrapError::DecompressionFailed),
            "Oversized decompressed blob must be rejected"
        );
    }

    #[test]
    fn test_decompress_within_limit_accepted() {
        // A normal-sized shard should still decompress fine.
        let r1 = create_test_rule("medical_bill", SensitivityTier::S1, 1, 0.85);
        let r2 = create_test_rule("receipt", SensitivityTier::S4, 2, 0.70);
        let rule_bytes = vec![r1.to_bytes(), r2.to_bytes()];

        let compressed = compress_shard(&rule_bytes, DEFAULT_COMPRESSION_LEVEL).unwrap();
        let decompressed = decompress_shard(&compressed).unwrap();

        assert_eq!(decompressed.len(), 2);
        assert_eq!(decompressed[0], rule_bytes[0]);
        assert_eq!(decompressed[1], rule_bytes[1]);
    }

    #[test]
    fn test_max_decompressed_shard_size_constant() {
        // Verify the constant equals MAX_RULES_PER_SHARD * 512.
        assert_eq!(MAX_DECOMPRESSED_SHARD_SIZE, 10_000 * 512);
        assert_eq!(MAX_DECOMPRESSED_SHARD_SIZE, 5_120_000);
    }

    // =======================================================================
    // Genesis shard root pinning tests
    // =======================================================================

    #[test]
    fn test_genesis_shard_roots_populated() {
        // GENESIS_SHARD_ROOTS must have an entry for every default
        // (category, tier) pair in DOCUMENT_CATEGORIES.
        for &cat in DOCUMENT_CATEGORIES {
            let tier = default_tier_for_category(cat) as u8;
            assert!(
                GENESIS_SHARD_ROOTS.get(&(cat, tier)).is_some(),
                "Missing genesis root for ({}, tier {})",
                cat,
                tier
            );
        }
    }

    #[test]
    fn test_genesis_shard_roots_are_blake3_empty() {
        // Current genesis roots are all BLAKE3("") (placeholder for empty genesis set).
        let expected = *blake3::hash(b"").as_bytes();
        for (key, root) in GENESIS_SHARD_ROOTS.iter() {
            assert_eq!(
                *root, expected,
                "Genesis root for {:?} does not match expected empty hash",
                key
            );
        }
    }

    #[test]
    fn test_genesis_root_mismatch_error_display() {
        let err = BootstrapError::GenesisRootMismatch;
        assert_eq!(
            format!("{}", err),
            "Merkle root does not match pinned genesis root"
        );
    }
}
