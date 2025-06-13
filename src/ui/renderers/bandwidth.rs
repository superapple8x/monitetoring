use ratatui::{
    widgets::{Block, Borders, Paragraph, Table, Row, Cell, TableState},
    layout::{Layout, Constraint, Direction},
    style::{Style, Color, Modifier},
    Frame
};
use crate::types::{App, SortColumn, SortDirection};
use crate::ui::{utils::format_bytes, charts::render_charts};

/// Render the bandwidth mode view with prominent chart display
pub fn render(f: &mut Frame, app: &App) {
    // Layout: Title, Chart, Table (expanded), Totals
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),               // Title
                Constraint::Percentage(60),          // Chart
                Constraint::Min(0),                  // Table (expanded to use available space)
                Constraint::Length(3),               // Totals
            ]
            .as_ref(),
        )
        .split(f.size());

    render_title(f, main_chunks[0]);
    render_charts(f, app, main_chunks[1]);
    render_process_table(f, app, main_chunks[2]);
    render_totals_bar(f, app, main_chunks[3]);
    // Removed footer rendering - no alert/command messages in bandwidth mode
}

/// Render the title bar for bandwidth mode
fn render_title(f: &mut Frame, area: ratatui::layout::Rect) {
    let navigation_text = "q: quit | Tab: switch mode | t: chart type | ↑/↓: select | Enter: actions";
    let title = Paragraph::new(navigation_text)
        .block(Block::default().title("Monitetoring – Bandwidth View").borders(Borders::ALL));
    f.render_widget(title, area);
}

/// Render the process table (similar to normal mode but more compact)
fn render_process_table(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let header_titles_str = if app.containers_mode {
        vec!["(P)ID", "Name", "Sent/s", "(S)ent Total", "Recv/s", "(R)eceived Total", "(C)ontainer"]
    } else {
        vec!["(P)ID", "Name", "Sent/s", "(S)ent Total", "Recv/s", "(R)eceived Total"]
    };
    let mut header_titles: Vec<String> = header_titles_str.iter().map(|s| s.to_string()).collect();

    let sort_indicator = if app.sort_direction == SortDirection::Asc { " ▲" } else { " ▼" };
    match app.sort_by {
        SortColumn::Pid => header_titles[0].push_str(sort_indicator),
        SortColumn::Name => header_titles[1].push_str(sort_indicator),
        SortColumn::Sent => header_titles[2].push_str(sort_indicator),
        SortColumn::Received => header_titles[4].push_str(sort_indicator),
        SortColumn::Container if app.containers_mode => header_titles[6].push_str(sort_indicator),
        _ => {}
    }

    let header_cells: Vec<_> = header_titles
        .iter()
        .map(|h| Cell::from(h.as_str()).style(Style::default().fg(Color::Red)))
        .collect();
    let header = Row::new(header_cells);

    let sorted_stats = app.sorted_stats();
    let rows = sorted_stats.iter().map(|(pid, data)| {
        let mut style = Style::default();
        if data.has_alert {
            style = style.bg(Color::Yellow).fg(Color::Black);
        }
        if app.selected_process == Some(**pid) {
            style = style.add_modifier(Modifier::BOLD);
        }

        let cells = if app.containers_mode {
            vec![
                Cell::from(pid.to_string()),
                Cell::from(data.name.clone()),
                Cell::from(format!("{}/s", format_bytes(data.sent_rate))),
                Cell::from(format_bytes(data.sent)),
                Cell::from(format!("{}/s", format_bytes(data.received_rate))),
                Cell::from(format_bytes(data.received)),
                Cell::from(data.container_name.as_ref().unwrap_or(&"host".to_string()).clone()),
            ]
        } else {
            vec![
                Cell::from(pid.to_string()),
                Cell::from(data.name.clone()),
                Cell::from(format!("{}/s", format_bytes(data.sent_rate))),
                Cell::from(format_bytes(data.sent)),
                Cell::from(format!("{}/s", format_bytes(data.received_rate))),
                Cell::from(format_bytes(data.received)),
            ]
        };
        Row::new(cells).style(style)
    });

    let widths = if app.containers_mode {
        [
            Constraint::Percentage(10),
            Constraint::Percentage(20),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(10),
        ]
        .as_slice()
    } else {
        [
            Constraint::Percentage(15),
            Constraint::Percentage(25),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ]
        .as_slice()
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Processes"));

    // Create table state and set selection to the currently selected process
    let mut table_state = TableState::default();
    if let Some(selected_pid) = app.selected_process {
        if let Some(index) = sorted_stats.iter().position(|(pid, _)| **pid == selected_pid) {
            table_state.select(Some(index));
        }
    }
    
    f.render_stateful_widget(table, area, &mut table_state);
}

/// Render the totals bar
fn render_totals_bar(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let (total_sent, total_received, total_sent_rate, total_received_rate) = app.totals();
    let totals_text = format!(
        "📊 TOTALS: Sent {}/s ({} total) | Received {}/s ({} total)",
        format_bytes(total_sent_rate),
        format_bytes(total_sent),
        format_bytes(total_received_rate),
        format_bytes(total_received)
    );
    let totals = Paragraph::new(totals_text)
        .block(Block::default().borders(Borders::ALL).title("Network Totals"));
    f.render_widget(totals, area);
} 