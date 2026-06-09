//! HIVE configuration persistence.
//!
//! Stores onboarding state and privacy mode in `~/.hive/config.toml`.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Current on-disk config schema version. Bump when a non-additive change is
/// made (field rename, field semantics shift). Pure additions of new fields
/// with serde defaults do NOT require a bump because old files still parse.
pub const CURRENT_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// PrivacyMode
// ---------------------------------------------------------------------------

/// Privacy mode selected during onboarding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    /// Local analysis only. No network. Default.
    #[default]
    LocalOnly,
    /// Local + anonymous pattern sharing with the collective.
    Collective,
}

// ---------------------------------------------------------------------------
// HiveConfig
// ---------------------------------------------------------------------------

/// Persistent HIVE configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HiveConfig {
    /// On-disk schema version. Always equals `CURRENT_VERSION` for any
    /// `HiveConfig` produced by `Default::default()` or successful `load*`.
    /// Introduced as the migration anchor for config persistence.
    pub version: u32,
    /// Whether the user has completed first-run onboarding.
    pub onboarding_complete: bool,
    /// Privacy mode chosen during onboarding.
    pub privacy_mode: PrivacyMode,
    /// Whether the watch folder feature is enabled.
    pub watch_enabled: bool,
    /// Custom watch directory path (None = default `~/.hive/watch/`).
    pub watch_dir: Option<String>,
}

impl Default for HiveConfig {
    fn default() -> Self {
        Self {
            version: CURRENT_VERSION,
            onboarding_complete: false,
            privacy_mode: PrivacyMode::LocalOnly,
            watch_enabled: false,
            watch_dir: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Migration error
// ---------------------------------------------------------------------------

/// Errors that can occur during HiveConfig load + migration.
#[derive(Debug)]
pub enum LoadError {
    /// Could not read the file (I/O error, missing parent dir, etc.). The
    /// caller is expected to fall back to `Default::default()` for the
    /// "fresh install" path.
    Io(std::io::Error),
    /// File contents do not parse as TOML for the current (or any known)
    /// schema. The caller should NOT silently overwrite -- the user may
    /// have hand-edited the file.
    Parse(String),
    /// On-disk schema version is newer than this binary understands. The
    /// binary refuses to load rather than risk dropping fields it does not
    /// know about. Operator must upgrade HIVE.
    UnsupportedVersion { on_disk: u32, supported: u32 },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "config I/O error: {}", e),
            Self::Parse(s) => write!(f, "config parse error: {}", s),
            Self::UnsupportedVersion { on_disk, supported } => write!(
                f,
                "config schema version {} is newer than this binary supports \
                 (max {}). Upgrade hive, or remove ~/.hive/config.toml to \
                 reinitialize.",
                on_disk, supported
            ),
        }
    }
}

impl std::error::Error for LoadError {}

/// Outcome of a load: the parsed config plus a flag indicating whether the
/// caller should rewrite the file to upgrade the on-disk schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadOutcome {
    pub config: HiveConfig,
    /// True when the on-disk file was a legacy (pre-version) format and
    /// should be rewritten with the current schema. Callers are expected to
    /// call `config.save()` on a best-effort basis when this is set.
    pub migrated: bool,
}

/// Permissive intermediate form used to detect legacy (pre-version) configs
/// without losing the rest of the data.
#[derive(Deserialize)]
#[serde(default)]
struct RawHiveConfig {
    version: Option<u32>,
    onboarding_complete: bool,
    privacy_mode: PrivacyMode,
    watch_enabled: bool,
    watch_dir: Option<String>,
}

impl Default for RawHiveConfig {
    fn default() -> Self {
        Self {
            version: None,
            onboarding_complete: false,
            privacy_mode: PrivacyMode::LocalOnly,
            watch_enabled: false,
            watch_dir: None,
        }
    }
}

/// Parse a TOML string with explicit version handling.
/// - missing `version` -> legacy file, treat as v1, signal `migrated = true`
/// - `version == CURRENT_VERSION` -> normal load
/// - `version > CURRENT_VERSION` -> reject (do not silently truncate)
fn parse_with_migration(contents: &str) -> Result<LoadOutcome, LoadError> {
    let raw: RawHiveConfig =
        toml::from_str(contents).map_err(|e| LoadError::Parse(e.to_string()))?;

    let (version, migrated) = match raw.version {
        None => (CURRENT_VERSION, true),
        Some(v) if v == CURRENT_VERSION => (v, false),
        Some(v) if v < CURRENT_VERSION => {
            // Reserved for future migrations (e.g. v1 -> v2 field rename).
            // Today CURRENT_VERSION == 1 and the only "below current" case
            // is None (legacy), already handled above. If a hypothetical v0
            // file appears, treat it like legacy and rewrite as v1.
            (CURRENT_VERSION, true)
        }
        Some(v) => {
            return Err(LoadError::UnsupportedVersion {
                on_disk: v,
                supported: CURRENT_VERSION,
            });
        }
    };

    Ok(LoadOutcome {
        config: HiveConfig {
            version,
            onboarding_complete: raw.onboarding_complete,
            privacy_mode: raw.privacy_mode,
            watch_enabled: raw.watch_enabled,
            watch_dir: raw.watch_dir,
        },
        migrated,
    })
}

impl HiveConfig {
    /// Path to the config file: `~/.hive/config.toml`.
    pub fn config_path() -> Option<PathBuf> {
        dirs_home().map(|home| home.join(".hive").join("config.toml"))
    }

    /// Load config from `~/.hive/config.toml`.
    ///
    /// This is the convenience wrapper that swallows recoverable
    /// errors (file missing, parse failure, legacy-format migration) and
    /// returns a usable `HiveConfig`. If migration was performed, the
    /// upgraded file is written back on a best-effort basis so the next
    /// load is fast and stable.
    ///
    /// Use `load_strict` (or `load_outcome_from`) if you need to distinguish
    /// "fresh install" from "user has a future-version file we cannot
    /// safely interpret".
    pub fn load() -> Self {
        let path = match Self::config_path() {
            Some(p) => p,
            None => return Self::default(),
        };

        match Self::load_outcome_from(&path) {
            Ok(outcome) => {
                if outcome.migrated {
                    // Rewrite the file with the current schema so we do not
                    // pay the migration check on every startup. Best-effort:
                    // if the disk is read-only or HOME is unwritable, the
                    // user just sees the migration message every launch.
                    let _ = outcome.config.save_to(&path);
                }
                outcome.config
            }
            Err(LoadError::Io(_)) => Self::default(),
            Err(LoadError::Parse(_)) => Self::default(),
            Err(LoadError::UnsupportedVersion { on_disk, supported }) => {
                eprintln!(
                    "[hive] WARNING: ~/.hive/config.toml schema version {} \
                     is newer than this binary supports (max {}). Falling \
                     back to defaults; please upgrade hive.",
                    on_disk, supported
                );
                Self::default()
            }
        }
    }

    /// Load config strictly: returns the migration outcome, or surfaces any
    /// error (including unsupported-version). Caller is responsible for
    /// deciding whether to write the migration back.
    pub fn load_strict() -> Result<LoadOutcome, LoadError> {
        let path = Self::config_path().ok_or_else(|| {
            LoadError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "$HOME not set",
            ))
        })?;
        Self::load_outcome_from(&path)
    }

    /// Load config from a specific path (for testing).
    /// This also goes through the migration helper, so a legacy
    /// (pre-version) test fixture loads as v1 -- but the file is NOT
    /// rewritten, because that would break tests that assert on input.
    pub fn load_from(path: &Path) -> Self {
        Self::load_outcome_from(path)
            .map(|o| o.config)
            .unwrap_or_default()
    }

    /// Load config from a specific path, returning the migration outcome
    /// (and surfacing parse / unsupported-version errors).
    pub fn load_outcome_from(path: &Path) -> Result<LoadOutcome, LoadError> {
        let contents = fs::read_to_string(path).map_err(LoadError::Io)?;
        parse_with_migration(&contents)
    }

    /// Save config to `~/.hive/config.toml`.
    /// Creates `~/.hive/` directory if it does not exist.
    ///
    /// Writes are atomic (tmp + rename) with mode 0600 on
    /// the file and 0700 on the containing directory. Previous behavior used
    /// `fs::write` which left the config world-readable (0644 on most macOS
    /// setups) and briefly exposed a half-written file if the process died
    /// mid-save.
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = Self::config_path().ok_or("$HOME not set; cannot locate ~/.hive/")?;
        self.save_to(&path)
    }

    /// Save config to a specific path (for testing).
    ///
    /// Atomic tmp+rename with explicit 0600 mode on unix.
    pub fn save_to(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let toml_str = toml::to_string_pretty(self)?;
        write_secret_atomic(path, toml_str.as_bytes())?;
        Ok(())
    }
}

/// Atomically write `bytes` to `path` with mode 0600 and
/// ensure the containing directory is mode 0700.
///
/// Semantics:
///   1. Ensure `path.parent()` exists and is 0700 (unix).
///   2. Open `<path>.tmp` with `OpenOptions::mode(0o600)` (unix) or plain
///      create (other platforms; Windows ACLs are out of scope here).
///   3. Write, flush, drop the handle.
///   4. `fs::rename(tmp, path)` — atomic on POSIX within the same fs.
///
/// The tmp file lives beside the destination so the rename is intra-fs.
///
/// Not marked `pub` because the function is intentionally HIVE-specific
/// (sibling `.tmp` suffix, explicit mode bits). Callers who need different
/// semantics should implement their own helper.
fn write_secret_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            // Propagate set_permissions failure. Previously
            // we swallowed the error here on the theory that "the dir might
            // be a symlink we do not own" -- but in that case the rename
            // below will silently leave the dir permissions wrong (e.g.
            // 0755) and the secret file will sit inside a world-readable
            // directory. Surface the error so the caller can decide.
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }

    let tmp_path = {
        let mut p = path.to_path_buf();
        let mut name = p.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        name.push(".tmp");
        p.set_file_name(name);
        p
    };

    // Open the tmp file with mode 0600 (unix) so there is never a window
    // where the secret lands on disk with weaker permissions.
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    {
        let mut f = opts.open(&tmp_path)?;
        f.write_all(bytes)?;
        f.flush()?;
    }

    // On unix, also clamp mode explicitly in case umask or a prior run
    // left the file more permissive.
    #[cfg(unix)]
    {
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    }

    // Atomic swap. On POSIX, rename(2) replaces the destination atomically.
    fs::rename(&tmp_path, path)?;

    Ok(())
}

/// Get the user's home directory. Uses $HOME on Unix.
fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

// ---------------------------------------------------------------------------
// ~/.hive/ subdirectory bootstrap
// ---------------------------------------------------------------------------

/// The list of subdirectories under `~/.hive/` that HIVE maintains with mode
/// 0700 on unix. Kept as a constant so tests and the bootstrap helper agree.
///
/// - `watch/`    -- drop-box for the file watcher to pick up new documents
/// - `insights/` -- exported insight cards / diagnostic reports
///
/// Both directories hold unprocessed user content or derived output that may
/// contain PII, so they must match the 0700 mode that `~/.hive/config.toml`
/// already enforces.
pub const HIVE_SUBDIRS: &[&str] = &["watch", "insights"];

/// Create the per-user HIVE subdirectories (`~/.hive/watch/` and
/// `~/.hive/insights/`) with mode 0700 on unix. Idempotent: existing dirs
/// are fixed up to the correct mode without being removed.
///
/// Previously the binary wrote the
/// config file and then assumed sibling dirs existed; on a clean VM they did
/// not, and users saw "no such file or directory" when trying to drop a
/// document into the watch folder. We now pre-create them at startup, in
/// Rust (not shell), so the macOS + Linux paths share one implementation.
pub fn ensure_hive_subdirs() -> std::io::Result<()> {
    let home = dirs_home()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "$HOME not set"))?;
    ensure_hive_subdirs_in(&home.join(".hive"))
}

/// Implementation backing `ensure_hive_subdirs`, parameterised on the HIVE
/// root so tests can exercise the bootstrap without touching `$HOME`.
pub fn ensure_hive_subdirs_in(hive_root: &Path) -> std::io::Result<()> {
    // Ensure the root itself exists and carries 0700 so the child-dir
    // permissions are not undermined by a world-readable parent. This
    // matches the contract in `write_secret_atomic` for the config file.
    fs::create_dir_all(hive_root)?;
    #[cfg(unix)]
    {
        fs::set_permissions(hive_root, fs::Permissions::from_mode(0o700))?;
    }

    for name in HIVE_SUBDIRS {
        let path = hive_root.join(name);
        fs::create_dir_all(&path)?;
        #[cfg(unix)]
        {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_default_config() {
        let config = HiveConfig::default();
        assert!(!config.onboarding_complete);
        assert_eq!(config.privacy_mode, PrivacyMode::LocalOnly);
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let config = HiveConfig {
            onboarding_complete: true,
            privacy_mode: PrivacyMode::Collective,
            ..HiveConfig::default()
        };
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let loaded: HiveConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config, loaded);
    }

    #[test]
    fn test_save_and_load_from_file() {
        let dir = std::env::temp_dir().join("hive_config_test");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");

        let config = HiveConfig {
            onboarding_complete: true,
            privacy_mode: PrivacyMode::Collective,
            ..HiveConfig::default()
        };
        config.save_to(&path).unwrap();

        let loaded = HiveConfig::load_from(&path);
        assert!(loaded.onboarding_complete);
        assert_eq!(loaded.privacy_mode, PrivacyMode::Collective);

        // Cleanup.
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_missing_file_returns_default() {
        let path = PathBuf::from("/tmp/hive_nonexistent_test_dir/config.toml");
        let loaded = HiveConfig::load_from(&path);
        assert_eq!(loaded, HiveConfig::default());
    }

    #[test]
    fn test_privacy_mode_serde() {
        // LocalOnly
        let toml_str = "privacy_mode = \"local_only\"\nonboarding_complete = false\n";
        let config: HiveConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.privacy_mode, PrivacyMode::LocalOnly);

        // Collective
        let toml_str = "privacy_mode = \"collective\"\nonboarding_complete = true\n";
        let config: HiveConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.privacy_mode, PrivacyMode::Collective);
    }

    #[test]
    fn test_config_path_exists() {
        // config_path should return Some on any machine with $HOME set.
        let path = HiveConfig::config_path();
        if std::env::var("HOME").is_ok() {
            assert!(path.is_some());
            let p = path.unwrap();
            assert!(p.to_string_lossy().contains(".hive"));
            assert!(p.to_string_lossy().ends_with("config.toml"));
        }
    }

    // -----------------------------------------------------------------------
    // Secret-file mode enforcement
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn test_save_to_writes_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("hive_config_mode_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");

        let config = HiveConfig {
            onboarding_complete: true,
            privacy_mode: PrivacyMode::Collective,
            ..HiveConfig::default()
        };
        config.save_to(&path).expect("save_to must succeed");

        let meta = fs::metadata(&path).expect("config file must exist after save");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "config file must be mode 0600, got 0o{:o}",
            mode
        );

        let dir_meta = fs::metadata(&dir).expect("config dir must exist");
        let dir_mode = dir_meta.permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "config dir must be mode 0700, got 0o{:o}",
            dir_mode
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Schema version + migration policy
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_uses_current_version() {
        let config = HiveConfig::default();
        assert_eq!(config.version, CURRENT_VERSION);
    }

    #[test]
    fn test_legacy_config_migrates_to_v1() {
        // Legacy file: no `version` key. Mimics anything written by
        // earlier binaries.
        let legacy_toml = r#"
onboarding_complete = true
privacy_mode = "collective"
watch_enabled = false
"#;
        let outcome = parse_with_migration(legacy_toml).expect("legacy config must parse");
        assert!(outcome.migrated, "legacy file must signal migrated=true");
        assert_eq!(outcome.config.version, CURRENT_VERSION);
        assert!(outcome.config.onboarding_complete);
        assert_eq!(outcome.config.privacy_mode, PrivacyMode::Collective);
    }

    #[test]
    fn test_current_version_loads_normally() {
        let current_toml = format!(
            r#"
version = {}
onboarding_complete = true
privacy_mode = "local_only"
watch_enabled = false
"#,
            CURRENT_VERSION
        );
        let outcome =
            parse_with_migration(&current_toml).expect("current-version config must parse");
        assert!(!outcome.migrated, "current-version file must not migrate");
        assert_eq!(outcome.config.version, CURRENT_VERSION);
        assert!(outcome.config.onboarding_complete);
        assert_eq!(outcome.config.privacy_mode, PrivacyMode::LocalOnly);
    }

    #[test]
    fn test_future_version_rejected() {
        let future_version = CURRENT_VERSION + 7;
        let future_toml = format!(
            r#"
version = {}
onboarding_complete = true
privacy_mode = "local_only"
"#,
            future_version
        );
        let err =
            parse_with_migration(&future_toml).expect_err("future-version config must be rejected");
        match err {
            LoadError::UnsupportedVersion { on_disk, supported } => {
                assert_eq!(on_disk, future_version);
                assert_eq!(supported, CURRENT_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {:?}", other),
        }
    }

    #[test]
    fn test_load_outcome_from_legacy_file() {
        // End-to-end: write a legacy file to disk, load it via
        // load_outcome_from, verify migration flag.
        let dir = std::env::temp_dir().join(format!("hive_legacy_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        fs::write(
            &path,
            "onboarding_complete = true\nprivacy_mode = \"collective\"\n",
        )
        .unwrap();

        let outcome = HiveConfig::load_outcome_from(&path)
            .expect("load_outcome_from must succeed on legacy file");
        assert!(outcome.migrated);
        assert_eq!(outcome.config.version, CURRENT_VERSION);
        assert!(outcome.config.onboarding_complete);
        assert_eq!(outcome.config.privacy_mode, PrivacyMode::Collective);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_save_then_load_round_trips_with_version() {
        let dir = std::env::temp_dir().join(format!("hive_roundtrip_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");

        let original = HiveConfig {
            onboarding_complete: true,
            privacy_mode: PrivacyMode::Collective,
            ..HiveConfig::default()
        };
        original.save_to(&path).unwrap();

        // Re-read via the strict path -- migrated must be false now.
        let outcome = HiveConfig::load_outcome_from(&path).expect("freshly-saved file must load");
        assert!(!outcome.migrated, "current-schema file must not re-migrate");
        assert_eq!(outcome.config, original);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_save_to_overwrites_existing_file() {
        // Second save (with different data) must not fail, must leave the
        // file at mode 0600, and must return the new contents on load.
        use std::os::unix::fs::PermissionsExt;

        let dir =
            std::env::temp_dir().join(format!("hive_config_overwrite_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");

        HiveConfig::default().save_to(&path).unwrap();

        let second = HiveConfig {
            onboarding_complete: true,
            privacy_mode: PrivacyMode::Collective,
            ..HiveConfig::default()
        };
        second.save_to(&path).unwrap();

        let loaded = HiveConfig::load_from(&path);
        assert_eq!(loaded, second);

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // ensure_hive_subdirs_in bootstrap
    // -----------------------------------------------------------------------

    #[test]
    fn test_ensure_hive_subdirs_creates_watch_and_insights() {
        let root =
            std::env::temp_dir().join(format!("hive_subdirs_create_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        ensure_hive_subdirs_in(&root).expect("bootstrap must succeed");

        for name in HIVE_SUBDIRS {
            let p = root.join(name);
            assert!(p.is_dir(), "{} must be a directory", p.display());
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_ensure_hive_subdirs_is_idempotent() {
        // Calling the bootstrap twice must not fail and must leave the
        // directories in place. This covers the common restart case where
        // ~/.hive/watch/ already exists from a previous run.
        let root = std::env::temp_dir().join(format!(
            "hive_subdirs_idempotent_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);

        ensure_hive_subdirs_in(&root).expect("first bootstrap must succeed");
        ensure_hive_subdirs_in(&root).expect("second bootstrap must succeed");

        for name in HIVE_SUBDIRS {
            assert!(root.join(name).is_dir());
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_hive_subdirs_mode_0700() {
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("hive_subdirs_mode_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        ensure_hive_subdirs_in(&root).expect("bootstrap must succeed");

        let root_mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(root_mode, 0o700, "~/.hive root must be 0700");

        for name in HIVE_SUBDIRS {
            let p = root.join(name);
            let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o700,
                "{} must be mode 0700, got 0o{:o}",
                p.display(),
                mode
            );
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_hive_subdirs_fixes_up_loose_mode() {
        // If a previous (pre-fix) run created the subdirs with mode 0755,
        // bootstrap must tighten them back to 0700 without erroring out.
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("hive_subdirs_fixup_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        for name in HIVE_SUBDIRS {
            let p = root.join(name);
            fs::create_dir_all(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }

        ensure_hive_subdirs_in(&root).expect("bootstrap must repair modes");

        for name in HIVE_SUBDIRS {
            let p = root.join(name);
            let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o700,
                "{} must be tightened to 0700, got 0o{:o}",
                p.display(),
                mode
            );
        }

        let _ = fs::remove_dir_all(&root);
    }
}
