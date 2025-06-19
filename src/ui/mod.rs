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
pub fn render_ui(app: &mut App, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<(), io::Error> {
    terminal.draw(|f| {
        // SOLUTION 2 & 4: Force clear on mode transitions and when force_redraw is set
        // This helps reset terminal state when switching between different renderers
        use std::cell::RefCell;
        thread_local! {
            static LAST_MODE: RefCell<Option<AppMode>> = RefCell::new(None);
        }
        
        let current_mode = app.mode;
        let should_clear = app.force_redraw;
        
        let should_clear_frame = LAST_MODE.with(|last_mode| {
            let mut last = last_mode.borrow_mut();
            let clear = last.is_none() || *last != Some(current_mode) || should_clear;
            if clear {
                *last = Some(current_mode);
            }
            clear
        });
        
        if should_clear_frame {
            // Mode transition or force redraw detected - clear the frame
            use ratatui::widgets::Clear;
            f.render_widget(Clear, f.size());
        }
        
        // Reset force redraw flag after clearing
        if should_clear {
            // Note: We can't modify app here due to borrow checker, 
            // so we'll reset it in the main loop
        }

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