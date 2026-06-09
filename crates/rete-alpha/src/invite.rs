//! Invite code system for HIVE alpha.
//!
//! Offline, zero-infrastructure invite codes.
//!
//! Design:
//! - Format: `HIVE-XXXX-XXXX-XXXX` (16 alphanumeric, no ambiguous chars)
//! - First char after `HIVE-` encodes generation: 0=team, 1=alpha tester, 2=second gen
//! - CSPRNG-based (ChaCha20Rng) for uniqueness without a central server
//! - Activation persists to `~/.hive/activation.toml`
//! - Honor-based: structural validation only, no DRM

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Alphabet: alphanumeric minus ambiguous chars (0, O, 1, I, l).
const ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnopqrstuvwxyz";

/// Ambiguous characters that must NOT appear in codes.
const AMBIGUOUS: &[char] = &['0', 'O', '1', 'I', 'l'];

/// Prefix for all invite codes.
const CODE_PREFIX: &str = "HIVE-";

// ---------------------------------------------------------------------------
// Code generation (~80 lines)
// ---------------------------------------------------------------------------

/// Generation tier encoded as the first character after HIVE-.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Generation {
    /// Core team (generation 0).
    Team = 0,
    /// Alpha testers invited by team (generation 1).
    AlphaTester = 1,
    /// Second-generation invitees (generation 2).
    SecondGen = 2,
}

impl Generation {
    /// The character encoding for this generation in the code.
    pub fn code_char(&self) -> char {
        match self {
            Generation::Team => '2', // first valid char in ALPHABET
            Generation::AlphaTester => '3',
            Generation::SecondGen => '4',
        }
    }

    /// Parse generation from the first char after HIVE-.
    pub fn from_code_char(c: char) -> Option<Self> {
        match c {
            '2' => Some(Generation::Team),
            '3' => Some(Generation::AlphaTester),
            '4' => Some(Generation::SecondGen),
            _ => None,
        }
    }

    /// The generation one level down from this one (for sub-invites).
    pub fn child_generation(&self) -> Option<Generation> {
        match self {
            Generation::Team => Some(Generation::AlphaTester),
            Generation::AlphaTester => Some(Generation::SecondGen),
            Generation::SecondGen => None, // Cannot invite further
        }
    }
}

/// Generate a single invite code using CSPRNG.
///
/// Format: `HIVE-GXXX-XXXX-XXXX` where G is the generation char
/// and X is drawn from ALPHABET (no ambiguous chars).
pub fn generate_code(rng: &mut ChaCha20Rng, generation: Generation) -> String {
    let mut code = String::with_capacity(19); // HIVE-XXXX-XXXX-XXXX
    code.push_str(CODE_PREFIX);

    // First char: generation indicator
    code.push(generation.code_char());

    // Remaining 11 chars (3 in first group + 4 + 4)
    for i in 0..11 {
        let idx = rng.random_range(0..ALPHABET.len());
        code.push(ALPHABET[idx] as char);
        // Insert dashes: after position 3 (total group of 4) and 7 (total 8)
        if i == 2 || i == 6 {
            code.push('-');
        }
    }

    code
}

/// Generate N invite codes for a given generation.
pub fn generate_codes(n: usize, generation: Generation) -> Vec<String> {
    let mut rng = ChaCha20Rng::from_os_rng();
    (0..n)
        .map(|_| generate_code(&mut rng, generation))
        .collect()
}

/// Create a new ChaCha20Rng from system entropy.
pub fn new_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_os_rng()
}

// ---------------------------------------------------------------------------
// Code validation (~40 lines)
// ---------------------------------------------------------------------------

/// Validate an invite code format.
///
/// Checks:
/// 1. Starts with `HIVE-`
/// 2. Format is `HIVE-XXXX-XXXX-XXXX` (19 chars total)
/// 3. No ambiguous characters (0, O, 1, I, l)
/// 4. First char after HIVE- is a valid generation
/// 5. All non-dash chars are alphanumeric
pub fn validate_code(code: &str) -> Result<Generation, CodeError> {
    // Length check: HIVE-XXXX-XXXX-XXXX = 19 chars
    if code.len() != 19 {
        return Err(CodeError::InvalidLength { actual: code.len() });
    }

    // Prefix check
    if !code.starts_with(CODE_PREFIX) {
        return Err(CodeError::InvalidPrefix);
    }

    // Dash positions: 4, 9, 14
    let chars: Vec<char> = code.chars().collect();
    if chars[4] != '-' || chars[9] != '-' || chars[14] != '-' {
        return Err(CodeError::InvalidFormat);
    }

    // Check generation char
    let gen_char = chars[5];
    let generation = Generation::from_code_char(gen_char).ok_or(CodeError::InvalidGeneration {
        char_found: gen_char,
    })?;

    // Check all payload characters (positions 5..19, excluding dashes at 9, 14)
    for (i, &c) in chars.iter().enumerate() {
        if i < 5 || c == '-' {
            continue;
        }
        if AMBIGUOUS.contains(&c) {
            return Err(CodeError::AmbiguousCharacter { char_found: c });
        }
        if !c.is_alphanumeric() {
            return Err(CodeError::InvalidCharacter { char_found: c });
        }
    }

    Ok(generation)
}

/// Errors from code validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeError {
    InvalidLength { actual: usize },
    InvalidPrefix,
    InvalidFormat,
    InvalidGeneration { char_found: char },
    AmbiguousCharacter { char_found: char },
    InvalidCharacter { char_found: char },
}

impl std::fmt::Display for CodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength { actual } => {
                write!(f, "Invalid code length: {} (expected 19)", actual)
            }
            Self::InvalidPrefix => write!(f, "Code must start with 'HIVE-'"),
            Self::InvalidFormat => write!(f, "Code must be in format HIVE-XXXX-XXXX-XXXX"),
            Self::InvalidGeneration { char_found } => {
                write!(f, "Invalid generation character: '{}'", char_found)
            }
            Self::AmbiguousCharacter { char_found } => {
                write!(f, "Ambiguous character not allowed: '{}'", char_found)
            }
            Self::InvalidCharacter { char_found } => {
                write!(f, "Invalid character: '{}'", char_found)
            }
        }
    }
}

impl std::error::Error for CodeError {}

// ---------------------------------------------------------------------------
// Activation errors (replay-guard remediation)
// ---------------------------------------------------------------------------

/// Errors from activation attempts.
///
/// Previously `activate()` returned
/// `Result<_, Box<dyn Error>>`, which obscured the replay-attack case
/// (re-running `activate` with the same code silently overwrote the prior
/// activation.toml and minted 3 fresh child invites). This enum makes the
/// replay case a first-class error so the CLI can reject it loudly.
#[derive(Debug)]
pub enum ActivationError {
    /// Code format was invalid (wraps `CodeError`).
    InvalidCode(CodeError),
    /// An activation file already exists at the target path.
    /// Without this check, repeated invocation of
    /// `activate <code>` with the same code would overwrite activation.toml
    /// and issue 3 new child invites per call, enabling unbounded amplification
    /// of the invite hierarchy with a single leaked code.
    AlreadyActivated { path: PathBuf },
    /// Filesystem I/O failure during persistence.
    Io(std::io::Error),
    /// TOML serialization failure.
    Serialize(toml::ser::Error),
}

impl std::fmt::Display for ActivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCode(e) => write!(f, "Invalid invite code: {}", e),
            Self::AlreadyActivated { path } => write!(
                f,
                "HIVE is already activated (activation file exists at {}). \
                 Re-activation is refused to prevent invite amplification. \
                 If you really intend to re-activate, remove the file first.",
                path.display()
            ),
            Self::Io(e) => write!(f, "Activation I/O error: {}", e),
            Self::Serialize(e) => write!(f, "Activation serialization error: {}", e),
        }
    }
}

impl std::error::Error for ActivationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCode(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Serialize(e) => Some(e),
            Self::AlreadyActivated { .. } => None,
        }
    }
}

impl From<CodeError> for ActivationError {
    fn from(e: CodeError) -> Self {
        Self::InvalidCode(e)
    }
}

impl From<std::io::Error> for ActivationError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<toml::ser::Error> for ActivationError {
    fn from(e: toml::ser::Error) -> Self {
        Self::Serialize(e)
    }
}

// ---------------------------------------------------------------------------
// Activation persistence (~30 lines)
// ---------------------------------------------------------------------------

/// Activation state persisted to `~/.hive/activation.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Activation {
    /// The invite code used to activate.
    pub code: String,
    /// Generation of the activation code.
    pub generation: u8,
    /// ISO date of activation (YYYY-MM-DD).
    pub activated_at: String,
    /// 3 invite codes generated at activation time for this user to share.
    pub my_invites: Vec<String>,
}

/// Path to activation file: `~/.hive/activation.toml`.
pub fn activation_path() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".hive").join("activation.toml"))
}

/// Load activation state from disk. Returns None if not activated.
pub fn load_activation() -> Option<Activation> {
    let path = activation_path()?;
    let contents = fs::read_to_string(&path).ok()?;
    toml::from_str(&contents).ok()
}

/// Load activation from a specific path (for testing).
pub fn load_activation_from(path: &PathBuf) -> Option<Activation> {
    let contents = fs::read_to_string(path).ok()?;
    toml::from_str(&contents).ok()
}

/// Save activation state to disk.
///
/// Writes atomically via `.tmp` + rename
/// and sets the parent dir to 0o700 + the activation file to 0o600 on
/// Unix (secrets must not be world-readable).
pub fn save_activation(activation: &Activation) -> Result<(), ActivationError> {
    let path = activation_path().ok_or_else(|| {
        ActivationError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not determine home directory",
        ))
    })?;
    save_activation_to(activation, &path)
}

/// Save activation to a specific path (for testing).
///
/// Atomic tmp+rename with 0o600 mode on
/// the file and 0o700 mode on the parent directory (Unix only).
pub fn save_activation_to(activation: &Activation, path: &PathBuf) -> Result<(), ActivationError> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            // Best-effort: if we can't tighten, surface but do not panic on non-owner
            if let Err(e) = fs::set_permissions(dir, perms) {
                // Only fail hard for unexpected errors; permission errors on
                // shared parents (e.g., /tmp on macOS) are acceptable because
                // mkstemp() semantics + individual-file 0o600 still gate access.
                if e.kind() != std::io::ErrorKind::PermissionDenied {
                    return Err(ActivationError::Io(e));
                }
            }
        }
    }
    let toml_str = toml::to_string_pretty(activation)?;

    // Atomic write: write to .tmp, then rename into place.
    let tmp_path = path.with_extension("toml.tmp");
    {
        use std::io::Write;
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&tmp_path)?
        };
        #[cfg(not(unix))]
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)?;
        let mut file = file;
        file.write_all(toml_str.as_bytes())?;
        file.sync_all()?;
    }
    // Rename is atomic on POSIX filesystems.
    fs::rename(&tmp_path, path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Activate command (~40 lines)
// ---------------------------------------------------------------------------

/// Activate HIVE with an invite code.
///
/// Steps:
/// 1. Validate code format
/// 2. **Refuse if activation file already exists (replay guard)**
/// 3. Determine child generation for sub-invites
/// 4. Generate 3 invite codes at the child generation
/// 5. Persist activation to disk
///
/// Returns the Activation on success.
pub fn activate(code: &str) -> Result<Activation, ActivationError> {
    let path = activation_path().ok_or_else(|| {
        ActivationError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not determine home directory",
        ))
    })?;
    activate_to(code, &path)
}

/// Activate with a specific save path (for testing).
///
/// Fail fast if `save_path` already exists.
/// Running `activate HIVE-XXXX-XXXX-XXXX` twice with the same code would
/// otherwise overwrite activation.toml and mint 3 fresh child codes per call,
/// amplifying a single leaked invite into an unbounded fan-out of generation-2
/// codes. We refuse replay structurally rather than trusting the user to not
/// re-run.
pub fn activate_to(code: &str, save_path: &PathBuf) -> Result<Activation, ActivationError> {
    let generation = validate_code(code)?;

    // Replay guard: refuse if activation file already exists.
    // Uses `try_exists` to distinguish existence errors from not-found.
    match save_path.try_exists() {
        Ok(true) => {
            return Err(ActivationError::AlreadyActivated {
                path: save_path.clone(),
            });
        }
        Ok(false) => {}
        Err(e) => return Err(ActivationError::Io(e)),
    }

    let my_invites: Vec<String> = match generation.child_generation() {
        Some(child_gen) => {
            let mut rng = new_rng();
            (0..3).map(|_| generate_code(&mut rng, child_gen)).collect()
        }
        None => vec![], // SecondGen users get NO child codes — generation chain stops
    };

    let date = crate::diagnostics::current_date_string();

    let activation = Activation {
        code: code.to_string(),
        generation: generation as u8,
        activated_at: date,
        my_invites,
    };

    save_activation_to(&activation, save_path)?;

    Ok(activation)
}

// ---------------------------------------------------------------------------
// My-invites display (~30 lines)
// ---------------------------------------------------------------------------

/// Format the user's invite codes for display.
pub fn format_my_invites(activation: &Activation) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("Your HIVE invite codes (share with friends):\n");
    out.push_str("=============================================\n\n");
    for (i, code) in activation.my_invites.iter().enumerate() {
        out.push_str(&format!("  {}. {}\n", i + 1, code));
    }
    out.push_str("\nEach code can activate one HIVE installation.\n");
    out.push_str(&format!(
        "Activated: {} (generation {})\n",
        activation.activated_at, activation.generation,
    ));
    out
}

// ---------------------------------------------------------------------------
// Tests (~15)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Code generation produces valid format ---

    #[test]
    fn test_generate_code_format() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let code = generate_code(&mut rng, Generation::Team);
        assert_eq!(code.len(), 19, "Code must be 19 chars: {}", code);
        assert!(
            code.starts_with("HIVE-"),
            "Code must start with HIVE-: {}",
            code
        );
        // Check dash positions
        let chars: Vec<char> = code.chars().collect();
        assert_eq!(chars[4], '-');
        assert_eq!(chars[9], '-');
        assert_eq!(chars[14], '-');
    }

    #[test]
    fn test_generate_code_valid() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let code = generate_code(&mut rng, Generation::AlphaTester);
        assert!(
            validate_code(&code).is_ok(),
            "Generated code must validate: {}",
            code
        );
    }

    // --- Code format validation (valid and invalid) ---

    #[test]
    fn test_validate_valid_code() {
        let mut rng = ChaCha20Rng::seed_from_u64(123);
        for gen in [
            Generation::Team,
            Generation::AlphaTester,
            Generation::SecondGen,
        ] {
            let code = generate_code(&mut rng, gen);
            let result = validate_code(&code);
            assert!(
                result.is_ok(),
                "Code {} should be valid, got {:?}",
                code,
                result
            );
        }
    }

    #[test]
    fn test_validate_invalid_length() {
        assert!(matches!(
            validate_code("HIVE-2ABC"),
            Err(CodeError::InvalidLength { .. })
        ));
    }

    #[test]
    fn test_validate_invalid_prefix() {
        assert!(matches!(
            validate_code("BUZZ-2ABC-DEFG-HJKM"),
            Err(CodeError::InvalidPrefix)
        ));
    }

    #[test]
    fn test_validate_invalid_format_dashes() {
        assert!(matches!(
            validate_code("HIVE-2ABCXDEFG-HJKM"),
            Err(CodeError::InvalidFormat)
        ));
    }

    #[test]
    fn test_validate_invalid_generation() {
        // '9' is not a valid generation char
        assert!(matches!(
            validate_code("HIVE-9ABC-DEFG-HJKM"),
            Err(CodeError::InvalidGeneration { .. })
        ));
    }

    // --- Generation encoding (0, 1, 2) ---

    #[test]
    fn test_generation_encoding() {
        let mut rng = ChaCha20Rng::seed_from_u64(99);

        let code_team = generate_code(&mut rng, Generation::Team);
        assert_eq!(code_team.chars().nth(5).unwrap(), '2');

        let code_alpha = generate_code(&mut rng, Generation::AlphaTester);
        assert_eq!(code_alpha.chars().nth(5).unwrap(), '3');

        let code_second = generate_code(&mut rng, Generation::SecondGen);
        assert_eq!(code_second.chars().nth(5).unwrap(), '4');
    }

    #[test]
    fn test_generation_round_trip() {
        for gen in [
            Generation::Team,
            Generation::AlphaTester,
            Generation::SecondGen,
        ] {
            let c = gen.code_char();
            let parsed = Generation::from_code_char(c).unwrap();
            assert_eq!(parsed, gen);
        }
    }

    // --- Activation persists to file ---

    #[test]
    fn test_activation_persistence() {
        let dir = std::env::temp_dir().join("hive_invite_test_persist");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("activation.toml");

        let mut rng = ChaCha20Rng::seed_from_u64(77);
        let code = generate_code(&mut rng, Generation::Team);

        let activation = activate_to(&code, &path).unwrap();
        assert_eq!(activation.code, code);
        assert_eq!(activation.generation, Generation::Team as u8);
        assert_eq!(activation.my_invites.len(), 3);

        // Reload from disk
        let loaded = load_activation_from(&path).unwrap();
        assert_eq!(loaded, activation);

        let _ = fs::remove_dir_all(&dir);
    }

    // --- My-invites returns 3 codes ---

    #[test]
    fn test_my_invites_count() {
        let dir = std::env::temp_dir().join("hive_invite_test_count");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("activation.toml");

        let mut rng = ChaCha20Rng::seed_from_u64(55);
        let code = generate_code(&mut rng, Generation::AlphaTester);
        let activation = activate_to(&code, &path).unwrap();
        assert_eq!(activation.my_invites.len(), 3);

        // All generated invites must also be valid
        for invite in &activation.my_invites {
            assert!(
                validate_code(invite).is_ok(),
                "Invite {} must be valid",
                invite
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    // --- CSPRNG produces unique codes ---

    #[test]
    fn test_codes_are_unique() {
        let codes = generate_codes(100, Generation::Team);
        let unique: std::collections::HashSet<&String> = codes.iter().collect();
        assert_eq!(unique.len(), 100, "All 100 codes must be unique");
    }

    // --- No ambiguous characters ---

    #[test]
    fn test_no_ambiguous_characters() {
        let codes = generate_codes(50, Generation::AlphaTester);
        for code in &codes {
            let payload = &code[5..]; // skip "HIVE-"
            for c in payload.chars() {
                if c == '-' {
                    continue;
                }
                assert!(
                    !AMBIGUOUS.contains(&c),
                    "Code {} contains ambiguous char '{}'",
                    code,
                    c,
                );
            }
        }
    }

    // --- Child generation logic ---

    #[test]
    fn test_child_generation() {
        assert_eq!(
            Generation::Team.child_generation(),
            Some(Generation::AlphaTester)
        );
        assert_eq!(
            Generation::AlphaTester.child_generation(),
            Some(Generation::SecondGen)
        );
        assert_eq!(Generation::SecondGen.child_generation(), None);
    }

    // --- Display formatting ---

    #[test]
    fn test_format_my_invites() {
        let activation = Activation {
            code: "HIVE-2ABC-DEFG-HJKM".to_string(),
            generation: 0,
            activated_at: "2026-04-16".to_string(),
            my_invites: vec![
                "HIVE-3XYZ-ABCD-EFGH".to_string(),
                "HIVE-3MNP-QRST-UVWX".to_string(),
                "HIVE-3JKL-MNPQ-RSTU".to_string(),
            ],
        };
        let output = format_my_invites(&activation);
        assert!(output.contains("HIVE-3XYZ-ABCD-EFGH"));
        assert!(output.contains("HIVE-3MNP-QRST-UVWX"));
        assert!(output.contains("HIVE-3JKL-MNPQ-RSTU"));
        assert!(output.contains("generation 0"));
    }

    // --- Error display ---

    #[test]
    fn test_code_error_display() {
        let err = CodeError::AmbiguousCharacter { char_found: 'O' };
        let msg = format!("{}", err);
        assert!(msg.contains("Ambiguous"));
        assert!(msg.contains("O"));
    }

    // --- generation depth enforcement ---

    #[test]
    fn test_secondgen_activation_produces_zero_child_codes() {
        let dir = std::env::temp_dir().join("hive_invite_test_secondgen_zero");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("activation.toml");

        let mut rng = ChaCha20Rng::seed_from_u64(200);
        let code = generate_code(&mut rng, Generation::SecondGen);
        let activation = activate_to(&code, &path).unwrap();

        assert_eq!(
            activation.my_invites.len(),
            0,
            "SecondGen activation must produce ZERO child codes, got {}",
            activation.my_invites.len()
        );
        assert_eq!(activation.generation, Generation::SecondGen as u8);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_team_activation_produces_three_alpha_codes() {
        let dir = std::env::temp_dir().join("hive_invite_test_team_alpha");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("activation.toml");

        let mut rng = ChaCha20Rng::seed_from_u64(300);
        let code = generate_code(&mut rng, Generation::Team);
        let activation = activate_to(&code, &path).unwrap();

        assert_eq!(
            activation.my_invites.len(),
            3,
            "Team activation must produce 3 child codes"
        );
        // All child codes must be AlphaTester generation (char '3' at position 5)
        for invite in &activation.my_invites {
            let gen = validate_code(invite).unwrap();
            assert_eq!(
                gen,
                Generation::AlphaTester,
                "Team child code {} must be AlphaTester generation",
                invite
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_alpha_activation_produces_three_secondgen_codes() {
        let dir = std::env::temp_dir().join("hive_invite_test_alpha_secondgen");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("activation.toml");

        let mut rng = ChaCha20Rng::seed_from_u64(400);
        let code = generate_code(&mut rng, Generation::AlphaTester);
        let activation = activate_to(&code, &path).unwrap();

        assert_eq!(
            activation.my_invites.len(),
            3,
            "AlphaTester activation must produce 3 child codes"
        );
        // All child codes must be SecondGen generation (char '4' at position 5)
        for invite in &activation.my_invites {
            let gen = validate_code(invite).unwrap();
            assert_eq!(
                gen,
                Generation::SecondGen,
                "AlphaTester child code {} must be SecondGen generation",
                invite
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    // --- invite replay guard ---

    /// Regression test: re-activating with the same code to the
    /// same path must fail with `ActivationError::AlreadyActivated`, and
    /// must NOT overwrite the existing activation file (which would mint
    /// fresh child codes and amplify a leaked invite).
    #[test]
    fn activate_same_code_twice_returns_error() {
        let dir = std::env::temp_dir().join("hive_invite_test_replay_guard");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("activation.toml");

        let mut rng = ChaCha20Rng::seed_from_u64(4144);
        let code = generate_code(&mut rng, Generation::AlphaTester);

        // First activation succeeds.
        let first = activate_to(&code, &path).expect("first activation should succeed");
        let first_invites = first.my_invites.clone();

        // Second activation with same code MUST fail with AlreadyActivated.
        let second = activate_to(&code, &path);
        match second {
            Err(ActivationError::AlreadyActivated { path: p }) => {
                assert_eq!(p, path, "AlreadyActivated must report the conflicting path");
            }
            Ok(_) => panic!(
                "replay regression: replay succeeded. Second activate_to call \
                 overwrote activation.toml — invite amplification possible."
            ),
            Err(other) => panic!("Expected AlreadyActivated, got {:?}", other),
        }

        // Defense-in-depth: on-disk file must still be the original activation.
        let loaded = load_activation_from(&path).expect("activation must still be on disk");
        assert_eq!(
            loaded.my_invites, first_invites,
            "replay regression: replay mutated the on-disk activation.toml"
        );

        // Even a DIFFERENT valid code must also be rejected while a prior activation exists.
        let mut rng2 = ChaCha20Rng::seed_from_u64(4145);
        let other_code = generate_code(&mut rng2, Generation::AlphaTester);
        let second_code_attempt = activate_to(&other_code, &path);
        assert!(
            matches!(
                second_code_attempt,
                Err(ActivationError::AlreadyActivated { .. })
            ),
            "replay regression: a second, different code bypassed the replay guard"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Regression test: activation.toml must be written with mode 0o600
    /// on Unix (not world-readable). Home secrets must not leak to other local
    /// users on multi-user systems.
    #[cfg(unix)]
    #[test]
    fn activation_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("hive_invite_test_mode0600");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("activation.toml");

        let mut rng = ChaCha20Rng::seed_from_u64(600);
        let code = generate_code(&mut rng, Generation::Team);
        let _ = activate_to(&code, &path).expect("activation should succeed");

        let meta = fs::metadata(&path).expect("stat activation.toml");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "permissions regression: activation.toml mode is 0o{:o}, expected 0o600",
            mode
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
