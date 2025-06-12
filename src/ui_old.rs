use std::io;
use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, Paragraph, Table, Row, Cell, Chart, Dataset, Axis, GraphType, TableState, Gauge, BarChart, Bar, BarGroup},
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
use crate::types::{Alert, AlertAction, App, AppMode, SortColumn, SortDirection, EditingField, ChartType, MetricsMode};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::collections::HashSet;

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
            AppMode::Normal => {
                if app.bandwidth_mode {
                    render_bandwidth_mode(f, app);
                } else {
                    render_normal_mode(f, app);
                }
            }
            AppMode::EditingAlert => render_editing_alert_mode(f, app),
            AppMode::SystemOverview => render_system_overview_mode(f, app),
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
    
    f.render_stateful_widget(table, content_chunks[0], &mut table_state);

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
        f.render_widget(action_panel, table_chunks[1]);
    }

    if app.bandwidth_mode && content_chunks.len() > 1 {
        render_charts(f, app, content_chunks[1]);
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
            "q: quit | o: overview | b: bandwidth | p/n/s/r/c: sort | d: direction | ↑/↓: select | Enter: actions"
        } else {
            "q: quit | o: overview | b: bandwidth | p/n/s/r: sort | d: direction | ↑/↓: select | Enter: actions"
        };
        let footer = Paragraph::new(footer_text).block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, main_chunks[3]);
    }
}

fn render_charts(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let (datasets, y_max, chart_title) = match app.chart_type {
        ChartType::ProcessLines => {
            // Line chart for individual process (existing logic)
            if let Some(pid) = app.selected_process {
                if let Some(process_info) = app.stats.get(&pid) {
                    let mut max_val = 0f64;
                    for &(_, v) in process_info.sent_history.iter().chain(process_info.received_history.iter()) {
                        if v > max_val {
                            max_val = v;
                        }
                    }
                    let y_max = if max_val < 1f64 { 1f64 } else { max_val * 1.2 };
                    let datasets = vec![
                        Dataset::default()
                            .name("Sent")
                            .marker(ratatui::symbols::Marker::Braille)
                            .style(Style::default().fg(Color::Cyan))
                            .graph_type(GraphType::Line)
                            .data(&process_info.sent_history),
                        Dataset::default()
                            .name("Received")
                            .marker(ratatui::symbols::Marker::Braille)
                            .style(Style::default().fg(Color::Magenta))
                            .graph_type(GraphType::Line)
                            .data(&process_info.received_history),
                    ];
                    (datasets, y_max, format!("Process {} Bandwidth (last 5 min)", pid))
                } else {
                    (Vec::new(), 1f64, "Process Bandwidth (last 5 min)".to_string())
                }
            } else {
                (Vec::new(), 1f64, "Process Bandwidth (last 5 min)".to_string())
            }
        },
        ChartType::SystemStacked => {
            // Stacked area chart for system-wide bandwidth
            if app.chart_datasets.is_empty() {
                (Vec::new(), 1f64, "System Bandwidth Stack (last 5 min)".to_string())
            } else {
                // Use pre-built datasets from app
                let datasets: Vec<Dataset> = app.chart_datasets.iter()
                    .map(|(name, data, color)| {
                        Dataset::default()
                            .name(name.clone())
                            .marker(ratatui::symbols::Marker::Braille)
                            .style(Style::default().fg(*color))
                            .graph_type(GraphType::Line)
                            .data(data)
                    })
                    .collect();

                let max_stack = app.chart_datasets.iter()
                    .flat_map(|(_, data, _)| data.iter().map(|(_, y)| *y))
                    .fold(1f64, |acc, val| if val > acc { val } else { acc });

                let y_max = max_stack * 1.2;
                let metrics_label = match app.metrics_mode {
                    MetricsMode::Combined => "Combined (Send + Receive)",
                    MetricsMode::SendOnly => "Send Only", 
                    MetricsMode::ReceiveOnly => "Receive Only",
                };
                (datasets, y_max, format!("System Bandwidth Stack - {} (top 5)", metrics_label))
            }
        },
    };

    let now = app.start_time.elapsed().as_secs_f64();
    let x_min = if now > 300.0 { now - 300.0 } else { 0.0 };
    let x_axis = Axis::default()
        .title("Time (s)")
        .style(Style::default().fg(Color::Gray))
        .bounds([x_min, now]);

    // Helper to format rate nicely for axis labels
    let format_rate = |rate: f64| -> String {
        format!("{}/s", format_bytes(rate as u64))
    };

    // Build 5 evenly spaced labels for Y axis (0, 25%, 50%, 75%, 100%)
    let y_labels: Vec<Span> = (0..=4)
        .map(|i| {
            let val = y_max * i as f64 / 4.0;
            Span::raw(format_rate(val))
        })
        .collect();

    let y_axis = Axis::default()
        .title("Bandwidth")
        .style(Style::default().fg(Color::Gray))
        .labels(y_labels)
        .bounds([0.0, y_max]);

    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .title(chart_title)
                .borders(Borders::ALL),
        )
        .x_axis(x_axis)
        .y_axis(y_axis);

    f.render_widget(chart, area);
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

    let actions = vec!["Kill Process", "Custom Command", "Alert"];
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

fn render_bandwidth_mode(f: &mut Frame, app: &App) {
    // Update chart datasets before rendering
    // We can't call update_chart_datasets here due to borrowing, so we'll need to call it from main

    // Layout: Title, Chart (70%), Compact Table (rest), Totals, Footer
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),               // Title
                Constraint::Percentage(70),          // Chart
                Constraint::Min(0),                  // Table
                Constraint::Length(3),               // Totals
                Constraint::Length(3),               // Footer / Alert
            ]
            .as_ref(),
        )
        .split(f.size());

    // Title
    let title = Block::default().title("Monitetoring – Bandwidth View (Press 'b' to close)").borders(Borders::ALL);
    f.render_widget(title, main_chunks[0]);

    // Chart
    render_charts(f, app, main_chunks[1]);

    // Full process table (same columns as normal view)
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
    
    f.render_stateful_widget(table, main_chunks[2], &mut table_state);

    // Totals (reuse existing helper)
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
    f.render_widget(totals, main_chunks[3]);

    // Footer / Alerts
    if let Some(msg) = &app.last_alert_message {
        let alert_message = Paragraph::new(msg.as_str())
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Last Alert"));
        f.render_widget(alert_message, main_chunks[4]);
    } else {
        let footer_text = if app.bandwidth_mode && app.chart_type == ChartType::SystemStacked {
            "q: quit | b: toggle view | t: chart type | m: metrics | ↑/↓: select | Enter: actions"
        } else {
            "q: quit | b: toggle view | t: chart type | ↑/↓: select | Enter: actions"
        };
        let footer = Paragraph::new(footer_text)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, main_chunks[4]);
    }
}

fn render_system_overview_mode(f: &mut Frame, app: &App) {
    // Main layout: Title + 3 sections
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),  // Title
            Constraint::Min(0),     // Main dashboard area
            Constraint::Length(9),  // Alert progress bars section (taller)
            Constraint::Length(3),  // Footer
        ])
        .split(f.size());

    // Title with current settings
    let title_text = format!(
        "System Overview Dashboard | Data Quota: {} | +/-: adjust | r: reset",
        format_bytes(app.total_quota_threshold)
    );
    let title = Block::default().title(title_text).borders(Borders::ALL);
    f.render_widget(title, main_chunks[0]);

    // Split main area vertically: gauge on top, rest below
    let dashboard_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),  // Bandwidth gauge on top
            Constraint::Min(0),     // Rest below
        ])
        .split(main_chunks[1]);
        
    // Split bottom area horizontally: protocol+breakdown box and system info box
    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(75),  // Protocol box gets more space
            Constraint::Percentage(25),  // System info smaller, rightmost
        ])
        .split(dashboard_chunks[1]);

    // Draw outer block for protocol distribution/breakdown
    let proto_block = Block::default().title("Protocol Distribution").borders(Borders::ALL);
    // Calculate inner area before moving proto_block
    let proto_inner = proto_block.inner(bottom_chunks[0]);
    f.render_widget(proto_block, bottom_chunks[0]);

    // Split inner area horizontally: chart left, legend right (legend appears top-right)
    let protocol_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(70), // Chart area
            Constraint::Percentage(30), // Legend area on right
        ])
        .split(proto_inner);

    // Calculate system totals - TOTAL bandwidth since program start
    let (total_sent, total_received, total_sent_rate, total_received_rate) = app.totals();
    let total_bandwidth = total_sent + total_received;
    let total_rate = total_sent_rate + total_received_rate;
    
    // Use quota threshold for display
    let quota_ratio = (total_bandwidth as f64 / app.total_quota_threshold as f64).min(1.0);
    
    // Check if quota is exceeded
    let quota_exceeded = total_bandwidth > app.total_quota_threshold;
    
    // 1. Total Data Usage Gauge (top section)
    let gauge_color = if quota_exceeded {
        // Blink effect - alternate between red and yellow
        if std::time::Instant::now().elapsed().as_millis() % 1000 < 500 {
            Color::Red
        } else {
            Color::Yellow
        }
    } else if total_bandwidth > (app.total_quota_threshold as f64 * 0.8) as u64 {
        Color::Yellow
    } else {
        Color::Green
    };

    let bandwidth_gauge = Gauge::default()
        .block(Block::default().title("Total Data Usage Since Start").borders(Borders::ALL))
        .gauge_style(Style::default().fg(gauge_color).bg(Color::Black))
        .percent((quota_ratio * 100.0) as u16)
        .label(format!(
            "Used: {} | Rate: {}/s | Quota: {}", 
            format_bytes(total_bandwidth),
            format_bytes(total_rate),
            format_bytes(app.total_quota_threshold)
        ));
    f.render_widget(bandwidth_gauge, dashboard_chunks[0]);

    // 2. Protocol Distribution Bar Chart (top part of protocol area)
    let protocol_data = if total_rate > 0 {
        vec![
            ("TCP", app.system_stats.tcp_rate),
            ("UDP", app.system_stats.udp_rate),
            ("ICMP", app.system_stats.icmp_rate),
            ("Other", app.system_stats.other_rate),
        ]
    } else {
        vec![("No data", 0)]
    };

    let max_protocol_rate = protocol_data.iter().map(|(_, rate)| *rate).max().unwrap_or(1);
    
    // Build colored bars without value numbers
    let bars: Vec<Bar<'_>> = vec![
        Bar::default()
            .value(app.system_stats.tcp_rate)
            .label("TCP".into())
            .text_value(String::new()) // hide numeric value
            .style(Style::default().fg(Color::Red)),
        Bar::default()
            .value(app.system_stats.udp_rate)
            .label("UDP".into())
            .text_value(String::new())
            .style(Style::default().fg(Color::Green)),
        Bar::default()
            .value(app.system_stats.icmp_rate)
            .label("ICMP".into())
            .text_value(String::new())
            .style(Style::default().fg(Color::Yellow)),
        Bar::default()
            .value(app.system_stats.other_rate)
            .label("Other".into())
            .text_value(String::new())
            .style(Style::default().fg(Color::Magenta)),
    ];

    let bar_group = BarGroup::default().bars(&bars);

    let protocol_chart = BarChart::default()
        .data(bar_group)
        .bar_width(12)
        .bar_gap(2)
        .max(max_protocol_rate)
        .value_style(Style::default().fg(Color::Black)) // Hidden
        .label_style(Style::default().fg(Color::White));
    f.render_widget(protocol_chart, protocol_chunks[0]);
    
    // 3. Protocol Breakdown Table (right part of protocol area)
    let protocol_rows: Vec<Row> = vec![
        Row::new(vec![
            Cell::from(Span::styled("■ TCP", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))),
            Cell::from(format_bytes(app.system_stats.tcp_rate)),
            Cell::from(app.system_stats.tcp_packets.to_string()),
            Cell::from(format!("{:.1}%", if total_rate > 0 { (app.system_stats.tcp_rate as f64 / total_rate as f64) * 100.0 } else { 0.0 })),
        ]),
        Row::new(vec![
            Cell::from(Span::styled("■ UDP", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))),
            Cell::from(format_bytes(app.system_stats.udp_rate)),
            Cell::from(app.system_stats.udp_packets.to_string()),
            Cell::from(format!("{:.1}%", if total_rate > 0 { (app.system_stats.udp_rate as f64 / total_rate as f64) * 100.0 } else { 0.0 })),
        ]),
        Row::new(vec![
            Cell::from(Span::styled("■ ICMP", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Cell::from(format_bytes(app.system_stats.icmp_rate)),
            Cell::from(app.system_stats.icmp_packets.to_string()),
            Cell::from(format!("{:.1}%", if total_rate > 0 { (app.system_stats.icmp_rate as f64 / total_rate as f64) * 100.0 } else { 0.0 })),
        ]),
        Row::new(vec![
            Cell::from(Span::styled("■ Other", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))),
            Cell::from(format_bytes(app.system_stats.other_rate)),
            Cell::from(app.system_stats.other_packets.to_string()),
            Cell::from(format!("{:.1}%", if total_rate > 0 { (app.system_stats.other_rate as f64 / total_rate as f64) * 100.0 } else { 0.0 })),
        ]),
    ];

    let protocol_table = Table::new(
        protocol_rows,
        [
            Constraint::Length(8),  // Protocol name
            Constraint::Length(10), // Rate
            Constraint::Length(8),  // Packets
            Constraint::Length(6),  // Percentage
        ]
    )
    .header(Row::new(vec!["Proto", "Rate/s", "Packets", "%"]).style(Style::default().add_modifier(Modifier::BOLD)))
    .style(Style::default().fg(Color::White));
    
    f.render_widget(protocol_table, protocol_chunks[1]);

    // 4. System Information (right section)
    let uptime = app.start_time.elapsed();
    let uptime_text = format!("{}h {}m {}s", 
        uptime.as_secs() / 3600,
        (uptime.as_secs() % 3600) / 60,
        uptime.as_secs() % 60);
    
    let process_count = app.stats.len();
    let active_alerts = app.alerts.len();
    
    let threshold_status = if quota_exceeded { "QUOTA EXCEEDED!" } else { "Normal" };
    let threshold_color = if quota_exceeded { Color::Red } else { Color::Green };
    
    let info_text = vec![
        Line::from(format!("Uptime: {}", uptime_text)),
        Line::from(format!("Active Processes: {}", process_count)),
        Line::from(format!("Alert Rules: {}", active_alerts)),
        Line::from(vec![
            Span::raw("Quota Status: "),
            Span::styled(threshold_status, Style::default().fg(threshold_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from("Controls:"),
        Line::from("  +/-: Adjust quota (±100MB)"),
        Line::from("  r: Reset exceeded state"),
        Line::from("  Esc: Return to main"),
        Line::from(""),
        Line::from("Note:"),
        Line::from("  Alert action will cause"),
        Line::from("  processes to blink red"),
        Line::from("  in the main view when"),
        Line::from("  their thresholds are"),
        Line::from("  exceeded."),
    ];

    let info_paragraph = Paragraph::new(Text::from(info_text))
        .block(Block::default().title("System Info & Controls").borders(Borders::ALL));
    f.render_widget(info_paragraph, bottom_chunks[1]);

    // 5. Alert Progress Bars Section
    if !app.alerts.is_empty() {
        let alert_items: Vec<Line> = app.alerts.iter()
            .filter_map(|(pid, alert)| {
                if let Some(process_info) = app.stats.get(pid) {
                    let current_usage = process_info.sent + process_info.received;
                    let progress = (current_usage as f64 / alert.threshold_bytes as f64).min(1.0);
                    let progress_percent = (progress * 100.0) as usize;
                    
                    let bar_length = 20;
                    let filled = (progress * bar_length as f64) as usize;
                    let bar = "█".repeat(filled) + &"░".repeat(bar_length - filled);
                    
                    // Color (with blink when exceeded)
                    let color = if progress >= 1.0 {
                        // Blink red/yellow
                        if std::time::Instant::now().elapsed().as_millis() % 1000 < 500 {
                            Color::Red
                        } else {
                            Color::Yellow
                        }
                    } else if progress > 0.9 {
                        Color::Red
                    } else if progress > 0.7 {
                        Color::Yellow
                    } else {
                        Color::Green
                    };

                    Some(Line::from(vec![
                        Span::raw(format!("{}: ", process_info.name)),
                        Span::styled(format!("[{}] {}% ", bar, progress_percent), Style::default().fg(color)),
                        Span::raw(format!("({})", format_bytes(current_usage))),
                    ]))
                } else {
                    None
                }
            })
            .collect();

        if !alert_items.is_empty() {
            let alert_paragraph = Paragraph::new(Text::from(alert_items))
                .block(Block::default().title("Alert Thresholds").borders(Borders::ALL));
            f.render_widget(alert_paragraph, main_chunks[2]);
        }
    } else {
        let no_alerts = Paragraph::new("No alert thresholds configured")
            .block(Block::default().title("Alert Thresholds").borders(Borders::ALL));
        f.render_widget(no_alerts, main_chunks[2]);
    }

    // Footer
    let footer_text = "q: quit | +/-: threshold | r: reset | Esc: return to main | System alerts will blink in main view";
    let footer = Paragraph::new(footer_text)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, main_chunks[3]);
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
                    if app.selected_alert_action < 2 {
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
                            2 => {
                                // Alert - just parse threshold
                                (parse_input_to_bytes(&app.alert_input), AlertAction::SystemAlert)
                            },
                            _ => (1024 * 1024, AlertAction::Kill),
                        };
                        
                        let new_alert = Alert {
                            process_pid: pid,
                            threshold_bytes: threshold,
                            action: action.clone(),
                        };
                        app.alerts.insert(pid, new_alert);
                        
                        // Add to system alerts if it's a system alert
                        if let AlertAction::SystemAlert = action {
                            app.system_alerts.insert(pid);
                        }
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
                let mut num_actions = 2; // Kill, Edit
                if let Some(pid) = app.selected_process {
                    if app.alerts.contains_key(&pid) {
                        num_actions = 3; // Add Remove option
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
                                            AlertAction::SystemAlert => {
                                                app.alert_input = format_bytes(alert.threshold_bytes);
                                                2
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
                                    app.system_alerts.remove(&pid);
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
                    KeyCode::Char('b') => {
                        app.bandwidth_mode = !app.bandwidth_mode;
                    }
                    KeyCode::Char('t') => {
                        // Toggle chart type only when in bandwidth mode
                        if app.bandwidth_mode {
                            app.chart_type = match app.chart_type {
                                ChartType::ProcessLines => ChartType::SystemStacked,
                                ChartType::SystemStacked => ChartType::ProcessLines,
                            };
                        }
                    }
                    KeyCode::Char('m') => {
                        // Toggle metrics mode only when in bandwidth mode with stacked chart
                        if app.bandwidth_mode && app.chart_type == ChartType::SystemStacked {
                            app.metrics_mode = match app.metrics_mode {
                                MetricsMode::Combined => MetricsMode::SendOnly,
                                MetricsMode::SendOnly => MetricsMode::ReceiveOnly,
                                MetricsMode::ReceiveOnly => MetricsMode::Combined,
                            };
                        }
                    }
                    KeyCode::Char('o') => {
                        app.mode = AppMode::SystemOverview;
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
        AppMode::SystemOverview => {
            match key {
                KeyCode::Char('q') => return true,
                KeyCode::Esc => {
                    app.mode = AppMode::Normal;
                }
                KeyCode::Char('r') => {
                    // Reset threshold exceeded state
                    app.threshold_exceeded = false;
                    app.threshold_exceeded_time = None;
                }

                KeyCode::Char('+') | KeyCode::Char('=') => {
                    // Increase quota by 100MB
                    app.total_quota_threshold += 100 * 1024 * 1024;
                }
                KeyCode::Char('-') => {
                    // Decrease quota by 100MB (min 100MB)
                    if app.total_quota_threshold > 100 * 1024 * 1024 {
                        app.total_quota_threshold -= 100 * 1024 * 1024;
                    }
                }
                _ => {}
            }
        }
    }
    false
}

pub fn update_chart_datasets(app: &mut App) {
    if app.chart_type == ChartType::SystemStacked && !app.system_bandwidth_history.is_empty() {
        // Get top 5 processes by recent activity for readability
        let mut top_processes: Vec<(i32, u64)> = app.stats.iter()
            .map(|(pid, info)| (*pid, info.sent_rate + info.received_rate))
            .collect();
        top_processes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let top_pids: Vec<i32> = top_processes.into_iter().take(5).map(|(pid, _)| pid).collect();

        // Available colors for assignment
        let available_colors = [
            Color::Red, Color::Green, Color::Blue, Color::Yellow, Color::Magenta,
            Color::Cyan, Color::LightRed, Color::LightGreen, Color::LightBlue, Color::LightYellow,
            Color::LightMagenta, Color::LightCyan, Color::DarkGray, Color::Gray, Color::White
        ];
        
        let mut new_datasets = Vec::new();

        for &pid in &top_pids {
            let process_name = app.stats.get(&pid)
                .map(|info| info.name.clone())
                .unwrap_or_else(|| format!("PID {}", pid));

            // Get or assign a persistent color for this process
            let process_color = if let Some(&existing_color) = app.process_colors.get(&process_name) {
                existing_color
            } else {
                // Find a color that's not already in use, or cycle through if all are used
                let used_colors: HashSet<Color> = app.process_colors.values().cloned().collect();
                let new_color = available_colors.iter()
                    .find(|&&color| !used_colors.contains(&color))
                    .copied()
                    .unwrap_or(available_colors[app.process_colors.len() % available_colors.len()]);
                
                app.process_colors.insert(process_name.clone(), new_color);
                new_color
            };

            let process_data: Vec<(f64, f64)> = app.system_bandwidth_history.iter()
                .map(|(timestamp, snapshot)| {
                    let rate = snapshot.iter()
                        .find(|(p, _, _)| *p == pid)
                        .map(|(_, sent, recv)| {
                            match app.metrics_mode {
                                MetricsMode::Combined => sent + recv,
                                MetricsMode::SendOnly => *sent,
                                MetricsMode::ReceiveOnly => *recv,
                            }
                        })
                        .unwrap_or(0.0);
                    (*timestamp, rate)
                })
                .collect();

            if !process_data.is_empty() {
                new_datasets.push((process_name, process_data, process_color));
            }
        }
        
        app.chart_datasets = new_datasets;
    } else {
        app.chart_datasets.clear();
    }
}