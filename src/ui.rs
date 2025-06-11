use std::io;
use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, Paragraph, Table, Row, Cell},
    layout::{Layout, Constraint, Direction},
    style::{Style, Color},
    Terminal
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use crate::types::{App, SortColumn, ProcessInfo};

pub fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>, io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

pub fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<(), io::Error> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

pub fn render_ui(app: &App, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<(), io::Error> {
    terminal.draw(|f| {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints(
                [
                    Constraint::Length(3), // Title
                    Constraint::Min(0),    // Table
                    Constraint::Length(3), // Footer
                ]
                .as_ref(),
            )
            .split(f.size());

        let title = Block::default().title("Rust-Hogs").borders(Borders::ALL);
        f.render_widget(title, chunks[0]);

        let header_cells = if app.containers_mode {
            vec!["(P)ID", "Name", "(S)ent", "(R)eceived", "(C)ontainer"]
        } else {
            vec!["(P)ID", "Name", "(S)ent", "(R)eceived"]
        };
        let header_cells: Vec<_> = header_cells
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Red)))
            .collect();
        let header = Row::new(header_cells);

        let rows = app.sorted_stats().into_iter().map(|(pid, data)| {
            if app.containers_mode {
                Row::new(vec![
                    Cell::from(pid.to_string()),
                    Cell::from(data.name.clone()),
                    Cell::from(data.sent.to_string()),
                    Cell::from(data.received.to_string()),
                    Cell::from(data.container_name.as_ref().unwrap_or(&"host".to_string()).clone()),
                ])
            } else {
                Row::new(vec![
                    Cell::from(pid.to_string()),
                    Cell::from(data.name.clone()),
                    Cell::from(data.sent.to_string()),
                    Cell::from(data.received.to_string()),
                ])
            }
        });

        let widths = if app.containers_mode {
            [
                Constraint::Percentage(15),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(10),
            ].as_slice()
        } else {
            [
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
            ].as_slice()
        };
        let table = Table::new(rows, widths)
            .header(header)
            .block(Block::default().borders(Borders::ALL).title("Processes"));
        f.render_widget(table, chunks[1]);
        
        let footer_text = if app.containers_mode {
            "Press 'q' to quit, 'p'/'n'/'s'/'r'/'c' to sort"
        } else {
            "Press 'q' to quit, 'p'/'n'/'s'/'r' to sort"
        };
        let footer = Paragraph::new(footer_text)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, chunks[2]);
    })?;
    Ok(())
}

pub fn handle_key_event(app: &mut App, key: KeyCode) -> bool {
    match key {
        KeyCode::Char('q') => true, // Signal to quit
        KeyCode::Char('p') => {
            app.sort_by = SortColumn::Pid;
            false
        }
        KeyCode::Char('n') => {
            app.sort_by = SortColumn::Name;
            false
        }
        KeyCode::Char('s') => {
            app.sort_by = SortColumn::Sent;
            false
        }
        KeyCode::Char('r') => {
            app.sort_by = SortColumn::Received;
            false
        }
        KeyCode::Char('c') => {
            if app.containers_mode {
                app.sort_by = SortColumn::Container;
            }
            false
        }
        _ => false,
    }
} 