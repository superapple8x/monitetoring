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

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: f64 = 1024.0;
    
    if bytes == 0 {
        return "0 B".to_string();
    }
    
    let bytes_f = bytes as f64;
    let unit_index = (bytes_f.log(THRESHOLD).floor() as usize).min(UNITS.len() - 1);
    let size = bytes_f / THRESHOLD.powi(unit_index as i32);
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

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
            vec!["(P)ID", "Name", "(S)ent Total", "Sent/s", "(R)eceived Total", "Recv/s", "(C)ontainer"]
        } else {
            vec!["(P)ID", "Name", "(S)ent Total", "Sent/s", "(R)eceived Total", "Recv/s"]
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
                    Cell::from(format_bytes(data.sent)),
                    Cell::from(format!("{}/s", format_bytes(data.sent_rate))),
                    Cell::from(format_bytes(data.received)),
                    Cell::from(format!("{}/s", format_bytes(data.received_rate))),
                    Cell::from(data.container_name.as_ref().unwrap_or(&"host".to_string()).clone()),
                ])
            } else {
                Row::new(vec![
                    Cell::from(pid.to_string()),
                    Cell::from(data.name.clone()),
                    Cell::from(format_bytes(data.sent)),
                    Cell::from(format!("{}/s", format_bytes(data.sent_rate))),
                    Cell::from(format_bytes(data.received)),
                    Cell::from(format!("{}/s", format_bytes(data.received_rate))),
                ])
            }
        });

        let widths = if app.containers_mode {
            [
                Constraint::Percentage(10),  // PID
                Constraint::Percentage(20),  // Name
                Constraint::Percentage(15),  // Sent Total
                Constraint::Percentage(15),  // Sent Rate
                Constraint::Percentage(15),  // Received Total
                Constraint::Percentage(15),  // Received Rate
                Constraint::Percentage(10),  // Container
            ].as_slice()
        } else {
            [
                Constraint::Percentage(15),  // PID
                Constraint::Percentage(25),  // Name
                Constraint::Percentage(20),  // Sent Total
                Constraint::Percentage(20),  // Sent Rate
                Constraint::Percentage(20),  // Received Total
                Constraint::Percentage(20),  // Received Rate
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