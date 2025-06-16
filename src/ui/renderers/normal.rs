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
    let terminal_height = f.size().height;
    let is_cramped = terminal_height < 25; // Detect if we're in a cramped terminal (raised threshold)
    
    // Check if we have messages to show
    let recent_log_entry = app.command_execution_log.last();
    let has_messages = app.last_alert_message.is_some() || recent_log_entry.is_some();
    
    // Adaptive layout based on whether we have messages to show and if action panel is active
    let main_chunks = if has_messages {
        // When messages exist, allocate space for them
        Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3), // Navigation
                Constraint::Min(0),    // Main content (Table + Action Panel)
                if app.show_action_panel { 
                    Constraint::Length(0) // Hide totals when action panel is shown
                } else { 
                    Constraint::Length(3) // Totals
                },
                Constraint::Length(6), // Footer / Alert Message (space for dual messages)
            ])
            .split(f.size())
    } else {
        // When no messages, expand main content area
        Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3), // Navigation
                Constraint::Min(0),    // Main content (Table + Action Panel) - expanded
                if app.show_action_panel { 
                    Constraint::Length(0) // Hide totals when action panel is shown
                } else { 
                    Constraint::Length(3) // Totals
                },
            ])
            .split(f.size())
    };

    let navigation_text = if app.containers_mode {
        "q: quit | Tab: switch mode | p/n/u/s/r/c: sort | d: direction | ↑/↓: select | Enter: actions"
    } else {
        "q: quit | Tab: switch mode | p/n/u/s/r: sort | d: direction | ↑/↓: select | Enter: actions"
    };
    let title = Paragraph::new(navigation_text)
        .block(Block::default().title("Monitetoring").borders(Borders::ALL));
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

    // Adaptive table/action panel layout based on terminal height and available space
    let action_panel_height = if app.show_action_panel {
        if is_cramped { 
            // In cramped conditions, give much more space to action panel
            40 
        } else {
            // Normal conditions, but still give more space than before
            25 
        }
    } else { 
        0 
    };
    
    let table_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if app.show_action_panel {
            vec![
                Constraint::Percentage(100 - action_panel_height), 
                Constraint::Percentage(action_panel_height)
            ]
        } else {
            vec![Constraint::Percentage(100)]
        })
        .split(content_chunks[0]);

    render_process_table(f, app, table_chunks[0]);

    if app.show_action_panel {
        render_action_panel(f, app, table_chunks[1], is_cramped);
    }

    if app.bandwidth_mode && content_chunks.len() > 1 {
        render_charts(f, app, content_chunks[1]);
    }

    // Only render totals if action panel is not shown
    if !app.show_action_panel {
        render_totals_bar(f, app, main_chunks[2]);
    }
    
    // Only render footer if we have messages to show
    if has_messages {
        let footer_index = if !app.show_action_panel { 3 } else { 2 };
        if footer_index < main_chunks.len() {
            render_footer(f, app, main_chunks[footer_index]);
        }
    }
}

/// Render the process table
fn render_process_table(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let header_titles_str = if app.show_total_columns {
        if app.containers_mode {
            vec!["(P)ID", "(N)ame", "(U)ser", "Sent/s", "(S)Tot", "Recv/s", "(R)Tot", "(C)ontainer"]
        } else {
            vec!["(P)ID", "(N)ame", "(U)ser", "Sent/s", "(S)Tot", "Recv/s", "(R)Tot"]
        }
    } else {
        if app.containers_mode {
            vec!["(P)ID", "(N)ame", "(U)ser", "Sent/s", "Recv/s", "(C)ontainer"]
        } else {
            vec!["(P)ID", "(N)ame", "(U)ser", "Sent/s", "Recv/s"]
        }
    };
    let mut header_titles: Vec<String> = header_titles_str.iter().map(|s| s.to_string()).collect();

    let sort_indicator = if app.sort_direction == SortDirection::Asc { " ▲" } else { " ▼" };
    match app.sort_by {
        SortColumn::Pid => header_titles[0].push_str(sort_indicator),
        SortColumn::Name => header_titles[1].push_str(sort_indicator),
        SortColumn::User => header_titles[2].push_str(sort_indicator),
        SortColumn::Sent => {
            if app.show_total_columns {
                header_titles[4].push_str(sort_indicator); // (S)Tot column
            } else {
                header_titles[3].push_str(sort_indicator); // Sent/s column when totals not shown
            }
        },
        SortColumn::SentRate => {
            header_titles[3].push_str(sort_indicator); // Sent/s column
        },
        SortColumn::Received => {
            if app.show_total_columns {
                header_titles[6].push_str(sort_indicator); // (R)Tot column
            } else {
                header_titles[4].push_str(sort_indicator); // Recv/s column when totals not shown
            }
        },
        SortColumn::ReceivedRate => {
            if app.show_total_columns {
                header_titles[5].push_str(sort_indicator); // Recv/s column
            } else {
                header_titles[4].push_str(sort_indicator); // Recv/s column when totals not shown
            }
        },
        SortColumn::Container if app.containers_mode => {
            let container_idx = if app.show_total_columns { 7 } else { 5 };
            header_titles[container_idx].push_str(sort_indicator);
        },
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

        let cells = if app.show_total_columns {
            if app.containers_mode {
                vec![
                    Cell::from(pid.to_string()),
                    Cell::from(data.name.clone()),
                    Cell::from(data.user_name.as_ref().unwrap_or(&"unknown".to_string()).clone()),
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
                    Cell::from(data.user_name.as_ref().unwrap_or(&"unknown".to_string()).clone()),
                    Cell::from(format!("{}/s", format_bytes(data.sent_rate))),
                    Cell::from(format_bytes(data.sent)),
                    Cell::from(format!("{}/s", format_bytes(data.received_rate))),
                    Cell::from(format_bytes(data.received)),
                ]
            }
        } else {
            if app.containers_mode {
                vec![
                    Cell::from(pid.to_string()),
                    Cell::from(data.name.clone()),
                    Cell::from(data.user_name.as_ref().unwrap_or(&"unknown".to_string()).clone()),
                    Cell::from(format!("{}/s", format_bytes(data.sent_rate))),
                    Cell::from(format!("{}/s", format_bytes(data.received_rate))),
                    Cell::from(data.container_name.as_ref().unwrap_or(&"host".to_string()).clone()),
                ]
            } else {
                vec![
                    Cell::from(pid.to_string()),
                    Cell::from(data.name.clone()),
                    Cell::from(data.user_name.as_ref().unwrap_or(&"unknown".to_string()).clone()),
                    Cell::from(format!("{}/s", format_bytes(data.sent_rate))),
                    Cell::from(format!("{}/s", format_bytes(data.received_rate))),
                ]
            }
        };
        Row::new(cells).style(style)
    });

    let widths = if app.show_total_columns {
        if app.containers_mode {
            [
                Constraint::Percentage(8),   // PID
                Constraint::Percentage(18),  // Name
                Constraint::Percentage(8),   // User
                Constraint::Percentage(12),  // Sent/s
                Constraint::Percentage(12),  // (S)Tot
                Constraint::Percentage(12),  // Recv/s
                Constraint::Percentage(12),  // (R)Tot
                Constraint::Percentage(18),  // Container
            ]
            .as_slice()
        } else {
            [
                Constraint::Percentage(12),  // PID
                Constraint::Percentage(20),  // Name
                Constraint::Percentage(10),  // User
                Constraint::Percentage(14),  // Sent/s
                Constraint::Percentage(14),  // (S)Tot
                Constraint::Percentage(15),  // Recv/s
                Constraint::Percentage(15),  // (R)Tot
            ]
            .as_slice()
        }
    } else {
        if app.containers_mode {
            [
                Constraint::Percentage(15),  // PID
                Constraint::Percentage(30),  // Name
                Constraint::Percentage(15),  // User
                Constraint::Percentage(20),  // Sent/s
                Constraint::Percentage(20),  // Recv/s
                Constraint::Percentage(15),  // Container
            ]
            .as_slice()
        } else {
            [
                Constraint::Percentage(15),  // PID
                Constraint::Percentage(35),  // Name  
                Constraint::Percentage(15),  // User
                Constraint::Percentage(17),  // Sent/s
                Constraint::Percentage(18),  // Recv/s
            ]
            .as_slice()
        }
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
fn render_action_panel(f: &mut Frame, app: &App, area: ratatui::layout::Rect, is_cramped: bool) {
    let action_panel_text = if let Some(pid) = app.selected_process {
        let mut actions = vec!["Kill Process", "Set/Edit Bandwidth Alert"];
        if app.alerts.contains_key(&pid) {
            actions.push("Remove Alert");
        }

        if (is_cramped || area.height < 6) && area.width > 50 {
            // Horizontal layout for cramped vertical space but sufficient horizontal space
            let selected_action_text = actions.get(app.selected_action).unwrap_or(&"Unknown");
            
            // Create a horizontal list of actions with the selected one highlighted
            let action_text = actions
                .iter()
                .enumerate()
                .map(|(i, action)| {
                    if i == app.selected_action {
                        format!(">{}<", action)
                    } else {
                        format!(" {} ", action)
                    }
                })
                .collect::<Vec<_>>()
                .join(" | ");
            
            let mut text = Text::from(vec![
                Line::from(Span::styled(
                    action_text,
                    Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
                )),
            ]);
            text
        } else {
            // Vertical layout (original behavior) - but ensure all options are visible
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

            let mut text_lines = action_lines;
            
            // Add a current selection indicator if we have limited space
            if area.height < 6 {
                let selected_action_text = actions.get(app.selected_action).unwrap_or(&"Unknown");
                text_lines.push(Line::from(Span::styled(
                    format!(">> {}", selected_action_text),
                    Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow),
                )));
            }
            
            Text::from(text_lines)
        }
    } else {
        Text::from("No process selected")
    };

    let title = if let Some(pid) = app.selected_process {
        format!("Actions for PID {} (Esc to close)", pid)
    } else {
        "Actions (Esc to close)".to_string()
    };
    
    let action_panel = Paragraph::new(action_panel_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
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
    // Check if we have recent command execution or alert message
    let recent_log_entry = app.command_execution_log.last();
    
    if let Some(msg) = &app.last_alert_message {
        if let Some((timestamp, log_msg)) = recent_log_entry {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Length(3)].as_ref())
                .split(area);

            // Command execution box (top box gets the dismiss guide)
            let elapsed = timestamp.elapsed().as_secs();
            let time_str = if elapsed < 60 { format!("{}s ago", elapsed) } else { format!("{}m ago", elapsed / 60) };
            let mut parts = log_msg.splitn(2, '\n');
            let header = parts.next().unwrap_or("Command Execution");
            let body = parts.next().unwrap_or("");
            let exec_paragraph = Paragraph::new(format!("{} ({})", body.trim(), time_str))
                .style(Style::default().fg(Color::Cyan))
                .block(Block::default().borders(Borders::ALL).title(format!("{} (Esc to dismiss)", header)));
            f.render_widget(exec_paragraph, chunks[0]);

            // Alert message box (no dismiss guide since top box has it)
            let alert_paragraph = format_alert_message(msg, false);
            f.render_widget(alert_paragraph, chunks[1]);
        } else {
            // Only alert message
            let alert_paragraph = format_alert_message(msg, true);
            f.render_widget(alert_paragraph, area);
        }
    } else if let Some((timestamp, log_msg)) = recent_log_entry {
        let elapsed = timestamp.elapsed().as_secs();
        let time_str = if elapsed < 60 { format!("{}s ago", elapsed) } else { format!("{}m ago", elapsed / 60) };
        let mut parts = log_msg.splitn(2, '\n');
        let header = parts.next().unwrap_or("Command Execution");
        let body = parts.next().unwrap_or("");
        let exec_paragraph = Paragraph::new(format!("{} ({})", body.trim(), time_str))
            .style(Style::default().fg(Color::Cyan))
            .block(Block::default().borders(Borders::ALL).title(format!("{} (Esc to dismiss)", header)));
        f.render_widget(exec_paragraph, area);
    }
    // If no messages to show, leave the space empty (removed the "No Action Executed" box)
}

fn format_alert_message(msg: &str, show_dismiss_guide: bool) -> Paragraph {
    if let Some(pos) = msg.find(':') {
        let header = &msg[..=pos];
        let body = msg[pos + 1..].trim();
        let title = if show_dismiss_guide {
            format!("{} (Esc to dismiss)", header)
        } else {
            header.to_string()
        };
        Paragraph::new(body)
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title(title))
    } else {
        let title = if show_dismiss_guide {
            "Alert (Esc to dismiss)".to_string()
        } else {
            "Alert".to_string()
        };
        Paragraph::new(msg)
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title(title))
    }
} 