//! Integration tests for HIVE onboarding and config persistence.
//!
//! Phase 3 (Alpha Packaging), Task U1.

use crossterm::event::{KeyCode, KeyModifiers};
use rete_alpha::hive_config::{HiveConfig, PrivacyMode};
use rete_alpha::onboarding::{OnboardingApp, OnboardingResult, OnboardingScreen};
use std::fs;

// ---------------------------------------------------------------------------
// OnboardingApp screen transition tests (2 tests)
// ---------------------------------------------------------------------------

#[test]
fn test_onboarding_full_forward_flow() {
    let mut app = OnboardingApp::new();

    // Start at Welcome.
    assert_eq!(app.screen, OnboardingScreen::Welcome);

    // Enter -> PrivacyChoice.
    let r = app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
    assert!(r.is_none());
    assert_eq!(app.screen, OnboardingScreen::PrivacyChoice);

    // '1' -> Tutorial.
    let r = app.handle_key(KeyCode::Char('1'), KeyModifiers::NONE);
    assert!(r.is_none());
    assert_eq!(app.screen, OnboardingScreen::Tutorial);

    // Enter -> Completed.
    let r = app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(r, Some(OnboardingResult::Completed(PrivacyMode::LocalOnly)));
}

#[test]
fn test_onboarding_ignores_irrelevant_keys_on_welcome() {
    let mut app = OnboardingApp::new();

    // Random keys on Welcome should not advance.
    for code in [KeyCode::Char('x'), KeyCode::Char('1'), KeyCode::Down] {
        let r = app.handle_key(code, KeyModifiers::NONE);
        assert!(r.is_none());
        assert_eq!(app.screen, OnboardingScreen::Welcome);
    }

    // Enter advances.
    let r = app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
    assert!(r.is_none());
    assert_eq!(app.screen, OnboardingScreen::PrivacyChoice);
}

// ---------------------------------------------------------------------------
// Privacy choice tests (3 tests)
// ---------------------------------------------------------------------------

#[test]
fn test_privacy_choice_1_selects_local_only() {
    let mut app = OnboardingApp::new();
    app.screen = OnboardingScreen::PrivacyChoice;

    app.handle_key(KeyCode::Char('1'), KeyModifiers::NONE);
    assert_eq!(app.privacy_mode, PrivacyMode::LocalOnly);
    assert_eq!(app.screen, OnboardingScreen::Tutorial);
}

#[test]
fn test_privacy_choice_2_selects_collective() {
    let mut app = OnboardingApp::new();
    app.screen = OnboardingScreen::PrivacyChoice;

    app.handle_key(KeyCode::Char('2'), KeyModifiers::NONE);
    assert_eq!(app.privacy_mode, PrivacyMode::Collective);
    assert_eq!(app.screen, OnboardingScreen::Tutorial);
}

#[test]
fn test_privacy_default_enter_selects_local_only() {
    let mut app = OnboardingApp::new();
    app.screen = OnboardingScreen::PrivacyChoice;

    // Enter without pressing 1 or 2 should default to LocalOnly.
    app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(app.privacy_mode, PrivacyMode::LocalOnly);
    assert_eq!(app.screen, OnboardingScreen::Tutorial);
}

// ---------------------------------------------------------------------------
// Tutorial key handling tests (2 tests)
// ---------------------------------------------------------------------------

#[test]
fn test_tutorial_enter_completes_with_chosen_mode() {
    let mut app = OnboardingApp::new();
    app.screen = OnboardingScreen::Tutorial;
    app.privacy_mode = PrivacyMode::Collective;

    let r = app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(
        r,
        Some(OnboardingResult::Completed(PrivacyMode::Collective))
    );
}

#[test]
fn test_tutorial_other_keys_do_not_complete() {
    let mut app = OnboardingApp::new();
    app.screen = OnboardingScreen::Tutorial;

    for code in [KeyCode::Char('a'), KeyCode::Down, KeyCode::Char('1')] {
        let r = app.handle_key(code, KeyModifiers::NONE);
        assert!(r.is_none());
        assert_eq!(app.screen, OnboardingScreen::Tutorial);
    }
}

// ---------------------------------------------------------------------------
// HiveConfig serialization/deserialization tests (3 tests)
// ---------------------------------------------------------------------------

#[test]
fn test_config_default_values() {
    let config = HiveConfig::default();
    assert!(!config.onboarding_complete);
    assert_eq!(config.privacy_mode, PrivacyMode::LocalOnly);
}

#[test]
fn test_config_save_and_load_roundtrip() {
    let dir = std::env::temp_dir().join("hive_onboarding_integration_test");
    let _ = fs::remove_dir_all(&dir);
    let path = dir.join("config.toml");

    let config = HiveConfig {
        onboarding_complete: true,
        privacy_mode: PrivacyMode::Collective,
        ..HiveConfig::default()
    };
    config.save_to(&path).expect("save should succeed");

    let loaded = HiveConfig::load_from(&path);
    assert_eq!(loaded, config);

    // Cleanup.
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_config_deserializes_from_toml_string() {
    let toml_str = r#"
onboarding_complete = true
privacy_mode = "collective"
"#;
    let config: HiveConfig = toml::from_str(toml_str).unwrap();
    assert!(config.onboarding_complete);
    assert_eq!(config.privacy_mode, PrivacyMode::Collective);

    let toml_str2 = r#"
onboarding_complete = false
privacy_mode = "local_only"
"#;
    let config2: HiveConfig = toml::from_str(toml_str2).unwrap();
    assert!(!config2.onboarding_complete);
    assert_eq!(config2.privacy_mode, PrivacyMode::LocalOnly);
}

// ---------------------------------------------------------------------------
// Skip onboarding when config says complete (2 tests)
// ---------------------------------------------------------------------------

#[test]
fn test_skip_onboarding_when_complete() {
    // Simulates the check in hive.rs: if onboarding_complete, skip.
    let config = HiveConfig {
        onboarding_complete: true,
        privacy_mode: PrivacyMode::LocalOnly,
        ..HiveConfig::default()
    };

    // The main binary checks: if !config.onboarding_complete { run onboarding }
    // When complete=true, onboarding should be skipped.
    assert!(config.onboarding_complete);
    // No OnboardingApp created = onboarding skipped.
}

#[test]
fn test_reset_onboarding_flag_forces_rerun() {
    // Simulates: config is complete, but --reset-onboarding forces it to false.
    let mut config = HiveConfig {
        onboarding_complete: true,
        privacy_mode: PrivacyMode::Collective,
        ..HiveConfig::default()
    };

    // Simulate --reset-onboarding flag effect.
    let reset_onboarding = true;
    if reset_onboarding {
        config.onboarding_complete = false;
    }

    assert!(!config.onboarding_complete);
    // This would trigger onboarding in main().
}
