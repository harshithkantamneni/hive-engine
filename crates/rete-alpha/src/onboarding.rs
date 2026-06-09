//! First-run onboarding screens for HIVE alpha.
//!
//! Phase 3 (Alpha Packaging), Task U1: First-run onboarding.
//!
//! Three-screen onboarding flow:
//!   1. Welcome -- what HIVE does, privacy guarantee
//!   2. Privacy Choice -- local-only vs. collective mode
//!   3. Quick Tutorial -- how to use the TUI
//!
//! Returns the user's privacy mode choice on completion.

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};

use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;
use ratatui::Terminal;

use crate::hive_config::PrivacyMode;

// ---------------------------------------------------------------------------
// OnboardingScreen: which screen is active
// ---------------------------------------------------------------------------

/// The three onboarding screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingScreen {
    Welcome,
    PrivacyChoice,
    Tutorial,
}

// ---------------------------------------------------------------------------
// OnboardingResult: what happens when onboarding completes
// ---------------------------------------------------------------------------

/// Result of the onboarding flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnboardingResult {
    /// User completed onboarding with a privacy choice.
    Completed(PrivacyMode),
    /// User quit during onboarding.
    Quit,
}

// ---------------------------------------------------------------------------
// OnboardingApp: state machine for the onboarding flow
// ---------------------------------------------------------------------------

/// Onboarding application state. Drives the three-screen flow.
pub struct OnboardingApp {
    /// Current screen.
    pub screen: OnboardingScreen,
    /// Selected privacy mode (updated on Screen 2).
    pub privacy_mode: PrivacyMode,
    /// Whether the user requested quit.
    pub should_quit: bool,
}

impl Default for OnboardingApp {
    fn default() -> Self {
        Self::new()
    }
}

impl OnboardingApp {
    /// Create a new onboarding app starting at the Welcome screen.
    pub fn new() -> Self {
        Self {
            screen: OnboardingScreen::Welcome,
            privacy_mode: PrivacyMode::LocalOnly,
            should_quit: false,
        }
    }

    /// Handle a key event. Returns `Some(result)` when onboarding is done.
    pub fn handle_key(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
    ) -> Option<OnboardingResult> {
        // Ctrl+C quits from any screen.
        if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
            self.should_quit = true;
            return Some(OnboardingResult::Quit);
        }

        // Esc quits from any screen.
        if code == KeyCode::Esc {
            self.should_quit = true;
            return Some(OnboardingResult::Quit);
        }

        match self.screen {
            OnboardingScreen::Welcome => {
                if code == KeyCode::Enter {
                    self.screen = OnboardingScreen::PrivacyChoice;
                }
                None
            }
            OnboardingScreen::PrivacyChoice => {
                match code {
                    KeyCode::Char('1') => {
                        self.privacy_mode = PrivacyMode::LocalOnly;
                        self.screen = OnboardingScreen::Tutorial;
                    }
                    KeyCode::Char('2') => {
                        self.privacy_mode = PrivacyMode::Collective;
                        self.screen = OnboardingScreen::Tutorial;
                    }
                    KeyCode::Enter => {
                        // Enter accepts the default (LocalOnly) and advances.
                        self.screen = OnboardingScreen::Tutorial;
                    }
                    _ => {}
                }
                None
            }
            OnboardingScreen::Tutorial => {
                if code == KeyCode::Enter {
                    return Some(OnboardingResult::Completed(self.privacy_mode.clone()));
                }
                None
            }
        }
    }

    /// Draw the current onboarding screen.
    pub fn draw(&self, frame: &mut Frame) {
        let area = frame.area();

        match self.screen {
            OnboardingScreen::Welcome => self.draw_welcome(frame, area),
            OnboardingScreen::PrivacyChoice => self.draw_privacy_choice(frame, area),
            OnboardingScreen::Tutorial => self.draw_tutorial(frame, area),
        }
    }

    // -----------------------------------------------------------------------
    // Screen 1: Welcome
    // -----------------------------------------------------------------------

    fn draw_welcome(&self, frame: &mut Frame, area: Rect) {
        let content_area = centered_rect(60, 18, area);

        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "HIVE - Collective Document Intelligence",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(""),
            Line::from(Span::styled(
                "HIVE analyzes your documents locally and compares",
                Style::default().fg(Color::White),
            )),
            Line::from(Span::styled(
                "them against patterns observed by the collective.",
                Style::default().fg(Color::White),
            )),
            Line::from(""),
            Line::from(""),
            Line::from(vec![
                Span::styled("  - ", Style::default().fg(Color::Green)),
                Span::styled(
                    "Your documents NEVER leave this device",
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("  - ", Style::default().fg(Color::Green)),
                Span::styled(
                    "Insights come from 40+ pre-seeded rules",
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled("  - ", Style::default().fg(Color::Green)),
                Span::styled(
                    "Only anonymized patterns are shared (with your consent)",
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(""),
            Line::from(""),
            Line::from(Span::styled(
                "Press [Enter] to continue",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        let paragraph = Paragraph::new(lines).alignment(Alignment::Center).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .border_type(BorderType::Rounded)
                .title(" Welcome ")
                .title_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
        );

        frame.render_widget(paragraph, content_area);
    }

    // -----------------------------------------------------------------------
    // Screen 2: Privacy Choice
    // -----------------------------------------------------------------------

    fn draw_privacy_choice(&self, frame: &mut Frame, area: Rect) {
        let content_area = centered_rect(62, 20, area);

        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "PRIVACY SETTINGS",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "HIVE can work in two modes:",
                Style::default().fg(Color::White),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "[1] LOCAL ONLY (default)",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "    Analyze documents using pre-seeded rules.",
                Style::default().fg(Color::White),
            )),
            Line::from(Span::styled(
                "    Nothing shared. No network connection needed.",
                Style::default().fg(Color::White),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "[2] COLLECTIVE MODE",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "    Same local analysis, PLUS contribute anonymous",
                Style::default().fg(Color::White),
            )),
            Line::from(Span::styled(
                "    patterns to help others. You receive collective",
                Style::default().fg(Color::White),
            )),
            Line::from(Span::styled(
                "    rules in return.",
                Style::default().fg(Color::White),
            )),
            Line::from(""),
            Line::from(""),
            Line::from(Span::styled(
                "Select [1] or [2]:",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        let paragraph = Paragraph::new(lines).alignment(Alignment::Center).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .border_type(BorderType::Rounded)
                .title(" Privacy ")
                .title_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
        );

        frame.render_widget(paragraph, content_area);
    }

    // -----------------------------------------------------------------------
    // Screen 3: Tutorial
    // -----------------------------------------------------------------------

    fn draw_tutorial(&self, frame: &mut Frame, area: Rect) {
        let content_area = centered_rect(66, 22, area);

        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "HOW TO USE HIVE",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "1. Drop a document:",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "   Type a file path or drag a file into this window",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "2. Wait for analysis (~15-30 seconds):",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "   HIVE extracts entities and checks them against known patterns",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "3. Review insight cards:",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(vec![
                Span::styled("   Color-coded: ", Style::default().fg(Color::Gray)),
                Span::styled("GREEN", Style::default().fg(Color::Green)),
                Span::styled(" (informational), ", Style::default().fg(Color::Gray)),
                Span::styled("YELLOW", Style::default().fg(Color::Yellow)),
                Span::styled(" (notable), ", Style::default().fg(Color::Gray)),
                Span::styled("RED", Style::default().fg(Color::Red)),
                Span::styled(" (significant)", Style::default().fg(Color::Gray)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "4. Share an insight:",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "   Press [s] on any card to copy a privacy-safe version to clipboard",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from(""),
            Line::from(Span::styled(
                "Press [Enter] to start analyzing",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        let paragraph = Paragraph::new(lines).alignment(Alignment::Center).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .border_type(BorderType::Rounded)
                .title(" Tutorial ")
                .title_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
        );

        frame.render_widget(paragraph, content_area);
    }
}

// ---------------------------------------------------------------------------
// Centering helper
// ---------------------------------------------------------------------------

/// Create a centered rectangle of `width` columns and `height` rows within `area`.
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area);

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(vertical[1]);

    horizontal[1]
}

// ---------------------------------------------------------------------------
// Run onboarding: terminal setup, event loop, teardown
// ---------------------------------------------------------------------------

/// Run the full onboarding flow in the terminal.
///
/// Sets up raw mode and alternate screen, runs the three-screen sequence,
/// then restores the terminal. Returns the user's privacy choice or Quit.
pub fn run_onboarding() -> Result<OnboardingResult, Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = OnboardingApp::new();
    let result = onboarding_event_loop(&mut terminal, &mut app);

    // Restore terminal before returning.
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;

    result
}

/// Event loop for the onboarding screens.
fn onboarding_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut OnboardingApp,
) -> Result<OnboardingResult, Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|frame| {
            app.draw(frame);
        })?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key_event) = event::read()? {
                if let Some(result) = app.handle_key(key_event.code, key_event.modifiers) {
                    return Ok(result);
                }
            }
        }

        if app.should_quit {
            return Ok(OnboardingResult::Quit);
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Screen transition tests --

    #[test]
    fn test_welcome_to_privacy_on_enter() {
        let mut app = OnboardingApp::new();
        assert_eq!(app.screen, OnboardingScreen::Welcome);

        let result = app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
        assert!(result.is_none()); // Not done yet.
        assert_eq!(app.screen, OnboardingScreen::PrivacyChoice);
    }

    #[test]
    fn test_privacy_to_tutorial_on_selection() {
        let mut app = OnboardingApp::new();
        app.screen = OnboardingScreen::PrivacyChoice;

        let result = app.handle_key(KeyCode::Char('1'), KeyModifiers::NONE);
        assert!(result.is_none());
        assert_eq!(app.screen, OnboardingScreen::Tutorial);
        assert_eq!(app.privacy_mode, PrivacyMode::LocalOnly);
    }

    // -- Privacy choice tests --

    #[test]
    fn test_privacy_choice_1_is_local_only() {
        let mut app = OnboardingApp::new();
        app.screen = OnboardingScreen::PrivacyChoice;

        app.handle_key(KeyCode::Char('1'), KeyModifiers::NONE);
        assert_eq!(app.privacy_mode, PrivacyMode::LocalOnly);
    }

    #[test]
    fn test_privacy_choice_2_is_collective() {
        let mut app = OnboardingApp::new();
        app.screen = OnboardingScreen::PrivacyChoice;

        app.handle_key(KeyCode::Char('2'), KeyModifiers::NONE);
        assert_eq!(app.privacy_mode, PrivacyMode::Collective);
    }

    #[test]
    fn test_privacy_default_on_enter_is_local_only() {
        let mut app = OnboardingApp::new();
        app.screen = OnboardingScreen::PrivacyChoice;

        app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.screen, OnboardingScreen::Tutorial);
        assert_eq!(app.privacy_mode, PrivacyMode::LocalOnly);
    }

    // -- Tutorial key handling tests --

    #[test]
    fn test_tutorial_enter_completes_onboarding() {
        let mut app = OnboardingApp::new();
        app.screen = OnboardingScreen::Tutorial;

        let result = app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(
            result,
            Some(OnboardingResult::Completed(PrivacyMode::LocalOnly))
        );
    }

    #[test]
    fn test_tutorial_non_enter_does_not_complete() {
        let mut app = OnboardingApp::new();
        app.screen = OnboardingScreen::Tutorial;

        let result = app.handle_key(KeyCode::Char('x'), KeyModifiers::NONE);
        assert!(result.is_none());
        assert_eq!(app.screen, OnboardingScreen::Tutorial);
    }

    // -- Quit handling --

    #[test]
    fn test_ctrl_c_quits_from_any_screen() {
        for screen in [
            OnboardingScreen::Welcome,
            OnboardingScreen::PrivacyChoice,
            OnboardingScreen::Tutorial,
        ] {
            let mut app = OnboardingApp::new();
            app.screen = screen;

            let result = app.handle_key(KeyCode::Char('c'), KeyModifiers::CONTROL);
            assert_eq!(result, Some(OnboardingResult::Quit));
            assert!(app.should_quit);
        }
    }

    #[test]
    fn test_esc_quits() {
        let mut app = OnboardingApp::new();
        let result = app.handle_key(KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(result, Some(OnboardingResult::Quit));
    }

    // -- Full flow test --

    #[test]
    fn test_full_flow_local_only() {
        let mut app = OnboardingApp::new();

        // Screen 1: Welcome -> Enter
        assert_eq!(app.screen, OnboardingScreen::Welcome);
        let r = app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
        assert!(r.is_none());

        // Screen 2: Privacy -> select 1
        assert_eq!(app.screen, OnboardingScreen::PrivacyChoice);
        let r = app.handle_key(KeyCode::Char('1'), KeyModifiers::NONE);
        assert!(r.is_none());

        // Screen 3: Tutorial -> Enter
        assert_eq!(app.screen, OnboardingScreen::Tutorial);
        let r = app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(r, Some(OnboardingResult::Completed(PrivacyMode::LocalOnly)));
    }

    #[test]
    fn test_full_flow_collective() {
        let mut app = OnboardingApp::new();

        app.handle_key(KeyCode::Enter, KeyModifiers::NONE); // Welcome -> Privacy
        app.handle_key(KeyCode::Char('2'), KeyModifiers::NONE); // Privacy -> Tutorial (Collective)

        let r = app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(
            r,
            Some(OnboardingResult::Completed(PrivacyMode::Collective))
        );
    }
}
