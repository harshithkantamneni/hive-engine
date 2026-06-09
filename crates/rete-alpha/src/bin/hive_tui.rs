//! Standalone TUI demo binary for HIVE.
//!
//! Demonstrates the terminal UI with mock data -- no extraction or engine needed.
//! Proves the UI works independently of the orchestrator.
//!
//! Usage: cargo run --bin hive_tui
//!
//! Key bindings:
//!   q / Ctrl+C  : Quit
//!   Enter       : Submit file path (loads mock insights)
//!   Up/Down/j/k : Scroll through insight cards
//!   s           : Share selected insight (strips PII)
//!   c           : Clear insights

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};

use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use rete_alpha::tui::{mock_insights, AppAction, KeyEvent as TuiKeyEvent, TuiApp};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // -- Terminal setup --
    // Install a panic hook that restores the terminal before printing the panic.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = restore_terminal();
        original_hook(panic_info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // -- Initialize app --
    let mut app = TuiApp::new();
    app.rules_loaded = 35; // mock: 35 rules loaded

    // -- Event loop --
    let result = run_event_loop(&mut terminal, &mut app);

    // -- Terminal cleanup (always runs) --
    restore_terminal()?;

    result
}

/// Main event loop. Draws the UI and handles keyboard input.
fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut TuiApp,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // Draw.
        terminal.draw(|frame| {
            app.draw(frame);
        })?;

        // Poll for events with 50ms timeout (20 FPS effective refresh).
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key_event) = event::read()? {
                let tui_key = map_crossterm_key(key_event);

                let action = app.handle_input(tui_key);

                match action {
                    AppAction::Quit => break,
                    AppAction::ProcessFile(path) => {
                        // In the standalone demo, simulate processing.
                        simulate_processing(app, &path);
                    }
                    AppAction::ShareInsight(idx) => {
                        // The TUI already updates last_shared; just log.
                        if let Some(ref stripped) = app.last_shared {
                            app.set_status(&format!(
                                "Shared insight {}: \"{}\" (stripped)",
                                idx + 1,
                                truncate(&stripped.rule_text_generic, 40)
                            ));
                        }
                    }
                    AppAction::ShowDetail(idx) => {
                        // The TUI already transitioned to DetailView state.
                        app.set_status(&format!(
                            "Detail view: insight {} of {}",
                            idx + 1,
                            app.insights.len()
                        ));
                    }
                    AppAction::ModeChanged(_) => {
                        // Privacy mode changed and persisted. Standalone demo
                        // has no pipeline/P2P to propagate to.
                    }
                    AppAction::ClearInsights => {
                        // Already handled by TuiApp.
                    }
                    AppAction::None => {}
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

/// Map a crossterm KeyEvent to our simplified TuiKeyEvent.
fn map_crossterm_key(key: event::KeyEvent) -> TuiKeyEvent {
    // Check for Ctrl+C first.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return TuiKeyEvent::CtrlC;
    }

    match key.code {
        KeyCode::Char(c) => TuiKeyEvent::Char(c),
        KeyCode::Enter => TuiKeyEvent::Enter,
        KeyCode::Backspace => TuiKeyEvent::Backspace,
        KeyCode::Delete => TuiKeyEvent::Delete,
        KeyCode::Esc => TuiKeyEvent::Escape,
        KeyCode::Up => TuiKeyEvent::Up,
        KeyCode::Down => TuiKeyEvent::Down,
        KeyCode::Left => TuiKeyEvent::Left,
        KeyCode::Right => TuiKeyEvent::Right,
        KeyCode::Home => TuiKeyEvent::Home,
        KeyCode::End => TuiKeyEvent::End,
        _ => TuiKeyEvent::Other,
    }
}

/// Simulate document processing with mock insights.
/// In the real system, this would be an async call to the orchestrator.
fn simulate_processing(app: &mut TuiApp, path: &str) {
    app.begin_processing(path);

    // Immediately push mock insights (no actual extraction).
    let cards = mock_insights();
    let count = cards.len();

    for card in cards {
        app.push_insight(card);
    }

    app.finish_processing();
    app.set_status(&format!(
        "Demo mode: loaded {} mock insights for {}",
        count, path
    ));
}

/// Restore terminal state. Called on normal exit and on panic.
fn restore_terminal() -> Result<(), Box<dyn std::error::Error>> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

/// Truncate a string to `max_len` characters, appending "..." if truncated.
/// Uses char_indices for UTF-8 safety.
fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let end = max_len.saturating_sub(3);
        let byte_end = s.char_indices().nth(end).map_or(s.len(), |(i, _)| i);
        format!("{}...", &s[..byte_end])
    }
}
