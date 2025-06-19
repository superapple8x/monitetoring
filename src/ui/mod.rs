pub mod terminal;
pub mod utils;
pub mod input;
pub mod charts;
pub mod renderers;
pub mod widgets;

use std::io;
use ratatui::{backend::CrosstermBackend, Terminal};
use crate::types::{App, AppMode};

// Re-export the main public functions
pub use terminal::{setup_terminal, restore_terminal};
pub use charts::update_chart_datasets;

/// Main UI rendering function that delegates to specific mode renderers
pub fn render_ui(app: &App, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<(), io::Error> {
    terminal.draw(|f| {
        match app.mode {
            AppMode::Normal => {
                if app.bandwidth_mode {
                    renderers::bandwidth::render(f, app);
                } else {
                    renderers::normal::render(f, app);
                }
            }
            AppMode::EditingAlert => renderers::alert::render(f, app),
            AppMode::SystemOverview => renderers::overview::render(f, app),
            AppMode::Settings => renderers::settings::render(f, app),
            AppMode::PacketDetails => renderers::packet_details::render(f, app),
        }
    })?;
    Ok(())
} 