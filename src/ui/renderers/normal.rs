use ratatui::{
    widgets::{Block, Borders, Paragraph, Table, Row, Cell, TableState},
    layout::{Layout, Constraint, Direction},
    style::{Style, Color, Modifier},
    text::{Line, Span, Text},
    Frame
};
use crate::types::{App, SortColumn, SortDirection};
use crate::ui::{utils::format_bytes, charts::render_charts};

/// Render the normal mode view
pub fn render(f: &mut Frame, app: &App) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3), // Title
                Constraint::Min(0),    // Main content (Table + Action Panel)
                Constraint::Length(3), // Totals
                Constraint::Length(3), // Footer / Alert Message
            ]
            .as_ref(),
        )
        .split(f.size());

    let title = Block::default().title("Monitetoring").borders(Borders::ALL);
    f.render_widget(title, main_chunks[0]);

    // When bandwidth_mode is inactive, use full width for table; otherwise split for potential side chart
    let content_chunks = if app.bandwidth_mode {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
            .split(main_chunks[1])
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(100)].as_ref())
            .split(main_chunks[1])
    };

    let table_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if app.show_action_panel {
            vec![Constraint::Percentage(80), Constraint::Percentage(20)]
        } else {
            vec![Constraint::Percentage(100)]
        })
        .split(content_chunks[0]);

    render_process_table(f, app, table_chunks[0]);

    if app.show_action_panel {
        render_action_panel(f, app, table_chunks[1]);
    }

    if app.bandwidth_mode && content_chunks.len() > 1 {
        render_charts(f, app, content_chunks[1]);
    }

    render_totals_bar(f, app, main_chunks[2]);
    render_footer(f, app, main_chunks[3]);
}

/// Render the process table
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

/// Render the action panel
fn render_action_panel(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let action_panel_text = if let Some(pid) = app.selected_process {
        let mut actions = vec!["Kill Process", "Set/Edit Bandwidth Alert"];
        if app.alerts.contains_key(&pid) {
            actions.push("Remove Alert");
        }

        let action_lines: Vec<Line> = actions
            .iter()
            .enumerate()
            .map(|(i, action)| {
                if i == app.selected_action {
                    Line::from(Span::styled(
                        format!("> {}", action),
                        Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
                    ))
                } else {
                    Line::from(format!("  {}", action))
                }
            })
            .collect();

        let mut text = Text::from(vec![Line::from(format!("Actions for PID {}:", pid))]);
        text.extend(action_lines);
        text
    } else {
        Text::from("No process selected")
    };

    let action_panel = Paragraph::new(action_panel_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Actions (Esc to close)")
                .style(Style::default().bg(Color::DarkGray))
        );
    f.render_widget(action_panel, area);
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

/// Render the footer
fn render_footer(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    if let Some(msg) = &app.last_alert_message {
        let alert_message = Paragraph::new(msg.as_str())
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Last Alert"));
        f.render_widget(alert_message, area);
    } else {
        let footer_text = if app.containers_mode {
            "q: quit | o: overview | b: bandwidth | p/n/s/r/c: sort | d: direction | ↑/↓: select | Enter: actions"
        } else {
            "q: quit | o: overview | b: bandwidth | p/n/s/r: sort | d: direction | ↑/↓: select | Enter: actions"
        };
        let footer = Paragraph::new(footer_text).block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, area);
    }
} 