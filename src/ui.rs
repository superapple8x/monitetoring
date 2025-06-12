use std::io;
use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, Paragraph, Table, Row, Cell},
    layout::{Layout, Constraint, Direction},
    style::{Style, Color, Modifier},
    text::{Line, Span, Text},
    Terminal,
    Frame
};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use crate::types::{Alert, AlertAction, App, AppMode, SortColumn, SortDirection, EditingField};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

fn parse_input_to_bytes(input: &str) -> u64 {
    let input = input.trim().to_uppercase();
    let mut num_part = String::new();
    let mut unit_part = String::new();

    for c in input.chars() {
        if c.is_digit(10) || c == '.' {
            num_part.push(c);
        } else {
            unit_part.push(c);
        }
    }

    let num = num_part.parse::<f64>().unwrap_or(0.0);
    let unit = unit_part.trim();

    let multiplier = match unit {
        "KB" => 1024.0,
        "MB" => 1024.0 * 1024.0,
        "GB" => 1024.0 * 1024.0 * 1024.0,
        "TB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    };

    (num * multiplier) as u64
}

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
        match app.mode {
            AppMode::Normal => render_normal_mode(f, app),
            AppMode::EditingAlert => render_editing_alert_mode(f, app),
        }
    })?;
    Ok(())
}

fn render_normal_mode(f: &mut Frame, app: &App) {
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

    let content_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if app.show_action_panel {
            vec![Constraint::Percentage(80), Constraint::Percentage(20)]
        } else {
            vec![Constraint::Percentage(100)]
        })
        .split(main_chunks[1]);

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
    f.render_widget(table, content_chunks[0]);

    if app.show_action_panel {
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
        f.render_widget(action_panel, content_chunks[1]);
    }

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
    f.render_widget(totals, main_chunks[2]);

    if let Some(msg) = &app.last_alert_message {
        let alert_message = Paragraph::new(msg.as_str())
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Last Alert"));
        f.render_widget(alert_message, main_chunks[3]);
    } else {
        let footer_text = if app.containers_mode {
            "q: quit | p/n/s/r/c: sort | d: direction | ↑/↓: select | Enter: actions"
        } else {
            "q: quit | p/n/s/r: sort | d: direction | ↑/↓: select | Enter: actions"
        };
        let footer = Paragraph::new(footer_text).block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, main_chunks[3]);
    }
}

fn render_editing_alert_mode(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints(
            [
                Constraint::Length(3), // Title
                Constraint::Length(3), // Threshold Input
                Constraint::Length(3), // Command Input
                Constraint::Min(0),    // Actions
            ]
            .as_ref(),
        )
        .split(f.size());

    let title_text = if let Some(pid) = app.selected_process {
        format!("Editing Alert for PID: {}", pid)
    } else {
        "Editing Alert".to_string()
    };
    let title = Paragraph::new(title_text)
        .block(Block::default().borders(Borders::ALL).title("Alert Editor (Esc to cancel, Enter to save)"));
    f.render_widget(title, chunks[0]);

    // Threshold Input
    let threshold_input = Paragraph::new(app.alert_input.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Threshold (e.g., 10MB, 2GB)")
        );
    f.render_widget(threshold_input, chunks[1]);

    // Command Input
    let command_input = Paragraph::new(app.command_input.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Command (leave empty to kill process)")
        );
    f.render_widget(command_input, chunks[2]);

    // Set cursor based on the currently editing field
    match app.current_editing_field {
        EditingField::Threshold => {
            f.set_cursor(chunks[1].x + app.alert_input.len() as u16 + 1, chunks[1].y + 1);
        }
        EditingField::Command => {
            f.set_cursor(chunks[2].x + app.command_input.len() as u16 + 1, chunks[2].y + 1);
        }
    }

    let actions = vec!["Kill Process", "Custom Command"];
    let action_lines: Vec<Line> = actions
        .iter()
        .enumerate()
        .map(|(i, action)| {
            if i == app.selected_alert_action {
                Line::from(Span::styled(
                    format!("> {}", action),
                    Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
                ))
            } else {
                Line::from(format!("  {}", action))
            }
        })
        .collect();

    let actions_widget = Paragraph::new(Text::from(action_lines))
        .block(Block::default().borders(Borders::ALL).title("Action (use Tab to switch fields)"));
    f.render_widget(actions_widget, chunks[3]);
}

pub fn handle_key_event(app: &mut App, key: KeyCode) -> bool {
    match app.mode {
        AppMode::EditingAlert => {
            match key {
                KeyCode::Char(c) => {
                    match app.current_editing_field {
                        EditingField::Threshold => app.alert_input.push(c),
                        EditingField::Command => app.command_input.push(c),
                    }
                }
                KeyCode::Backspace => {
                    match app.current_editing_field {
                        EditingField::Threshold => { app.alert_input.pop(); },
                        EditingField::Command => { app.command_input.pop(); },
                    }
                }
                KeyCode::Esc => {
                    app.mode = AppMode::Normal;
                    app.alert_input.clear();
                    app.command_input.clear();
                }
                KeyCode::Up => {
                    if app.selected_alert_action > 0 {
                        app.selected_alert_action -= 1;
                    }
                }
                KeyCode::Down => {
                    if app.selected_alert_action < 1 {
                        app.selected_alert_action += 1;
                    }
                }
                KeyCode::Tab => {
                    app.current_editing_field = match app.current_editing_field {
                        EditingField::Threshold => EditingField::Command,
                        EditingField::Command => EditingField::Threshold,
                    };
                }
                KeyCode::Enter => {
                    if let Some(pid) = app.selected_process {
                        let (threshold, action) = match app.selected_alert_action {
                            0 => {
                                // Kill Process - just parse threshold
                                (parse_input_to_bytes(&app.alert_input), AlertAction::Kill)
                            },
                            1 => {
                                // Custom Command - parse "threshold,command" format
                                let threshold = parse_input_to_bytes(&app.alert_input);
                                let command = app.command_input.trim().to_string();
                                if command.is_empty() {
                                    (threshold, AlertAction::Kill)
                                } else {
                                    (threshold, AlertAction::CustomCommand(command))
                                }
                            },
                            _ => (1024 * 1024, AlertAction::Kill),
                        };
                        
                        let new_alert = Alert {
                            process_pid: pid,
                            threshold_bytes: threshold,
                            action,
                        };
                        app.alerts.insert(pid, new_alert);
                    }
                    app.mode = AppMode::Normal;
                    app.alert_input.clear();
                    app.command_input.clear();
                }
                _ => {}
            }
            return false;
        }
        AppMode::Normal => {
            if app.show_action_panel {
                let mut num_actions = 2;
                if let Some(pid) = app.selected_process {
                    if app.alerts.contains_key(&pid) {
                        num_actions = 3;
                    }
                }

                match key {
                    KeyCode::Esc => {
                        app.show_action_panel = false;
                        app.selected_action = 0;
                    }
                    KeyCode::Up => {
                        if app.selected_action > 0 {
                            app.selected_action -= 1;
                        }
                    }
                    KeyCode::Down => {
                        if app.selected_action < num_actions - 1 {
                            app.selected_action += 1;
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(pid) = app.selected_process {
                            let has_alert = app.alerts.contains_key(&pid);
                            let action_str = match app.selected_action {
                                0 => "Kill",
                                1 => "Edit",
                                2 if has_alert => "Remove",
                                _ => "",
                            };

                            match action_str {
                                "Kill" => {
                                    if signal::kill(Pid::from_raw(pid), Signal::SIGKILL).is_ok() {
                                        app.stats.remove(&pid);
                                        app.alerts.remove(&pid);
                                        app.killed_processes.insert(pid);
                                        app.selected_process = None;
                                    }
                                }
                                "Edit" => {
                                    app.mode = AppMode::EditingAlert;
                                    if let Some(alert) = app.alerts.get(&pid) {
                                        app.selected_alert_action = match &alert.action {
                                            AlertAction::Kill => {
                                                app.alert_input = format_bytes(alert.threshold_bytes);
                                                0
                                            },
                                            AlertAction::CustomCommand(cmd) => {
                                                app.alert_input = format_bytes(alert.threshold_bytes);
                                                app.command_input = cmd.clone();
                                                1
                                            },
                                        };
                                    } else {
                                        app.alert_input.clear();
                                        app.selected_alert_action = 0;
                                    }
                                    app.command_input.clear();
                                }
                                "Remove" => {
                                    app.alerts.remove(&pid);
                                }
                                _ => {}
                            }
                        }
                        app.show_action_panel = false;
                        app.selected_action = 0;
                    }
                    _ => {}
                }
            } else {
                match key {
                    KeyCode::Char('q') => return true,
                    KeyCode::Char('p') => app.sort_by = SortColumn::Pid,
                    KeyCode::Char('n') => app.sort_by = SortColumn::Name,
                    KeyCode::Char('s') => app.sort_by = SortColumn::Sent,
                    KeyCode::Char('r') => app.sort_by = SortColumn::Received,
                    KeyCode::Char('c') => {
                        if app.containers_mode {
                            app.sort_by = SortColumn::Container;
                        }
                    }
                    KeyCode::Char('d') => {
                        app.sort_direction = if app.sort_direction == SortDirection::Asc {
                            SortDirection::Desc
                        } else {
                            SortDirection::Asc
                        };
                    }
                    KeyCode::Down => {
                        let sorted_pids: Vec<i32> = app.sorted_stats().iter().map(|(pid, _)| **pid).collect();
                        if let Some(current_pid) = app.selected_process {
                            if let Some(current_index) = sorted_pids.iter().position(|p| *p == current_pid) {
                                if current_index < sorted_pids.len() - 1 {
                                    app.selected_process = Some(sorted_pids[current_index + 1]);
                                }
                            }
                        } else if !sorted_pids.is_empty() {
                            app.selected_process = Some(sorted_pids[0]);
                        }
                    }
                    KeyCode::Up => {
                        let sorted_pids: Vec<i32> = app.sorted_stats().iter().map(|(pid, _)| **pid).collect();
                        if let Some(current_pid) = app.selected_process {
                            if let Some(current_index) = sorted_pids.iter().position(|p| *p == current_pid) {
                                if current_index > 0 {
                                    app.selected_process = Some(sorted_pids[current_index - 1]);
                                }
                            }
                        } else if !sorted_pids.is_empty() {
                            app.selected_process = Some(sorted_pids[sorted_pids.len() - 1]);
                        }
                    }
                    KeyCode::Enter => {
                        if app.selected_process.is_some() {
                            app.show_action_panel = true;
                            app.selected_action = 0;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    false
}